# -*- coding: utf-8 -*-
"""
Serwer do aplikacji Ghost Notes.
Przechowuje TYLKO zaszyfrowane dane - nie zna hasel ani tresci notatek i czatu.
Tylko biblioteka standardowa Pythona. Uruchom: python serwer_notatki.py
"""
import json, sqlite3, hashlib, hmac, time, threading, os, uuid, socket
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("GHOST_PORT", "8765"))
BAZA = os.environ.get("GHOST_BAZA", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghost_serwer.db"))
MAKS_ROZMIAR = 1_000_000      # maks. rozmiar zapytania (bajty)
MAKS_WIADOMOSC = 20_000       # maks. rozmiar jednej zaszyfrowanej wiadomosci
MAKS_NOTATKA = 500_000        # maks. rozmiar jednej zaszyfrowanej notatki
LIMIT_BLEDOW = 10             # zle hasla z jednego IP w ciagu 10 minut -> blokada
LIMIT_WIADOMOSCI = 30         # wiadomosci na minute z jednej przestrzeni

_blokada = threading.Lock()
_bledy = {}        # ip -> [czasy]
_wysylki = {}      # space -> [czasy]


def baza():
    db = sqlite3.connect(BAZA, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def przygotuj_baze():
    db = baza()
    db.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS spaces(id TEXT PRIMARY KEY, auth TEXT NOT NULL, created REAL);
    CREATE TABLE IF NOT EXISTS notes(id TEXT PRIMARY KEY, space TEXT NOT NULL, blob TEXT,
        version INTEGER NOT NULL, updated REAL NOT NULL, deleted INTEGER DEFAULT 0);
    CREATE INDEX IF NOT EXISTS ix_notes ON notes(space, updated);
    CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY AUTOINCREMENT, space TEXT NOT NULL,
        blob TEXT NOT NULL, ts REAL NOT NULL);
    CREATE INDEX IF NOT EXISTS ix_msgs ON msgs(space, id);
    """)
    db.commit()
    db.close()


class Blad(Exception):
    def __init__(self, kod, tekst):
        self.kod, self.tekst = kod, tekst


def _okno(slownik, klucz, sekundy):
    teraz = time.time()
    lista = [t for t in slownik.get(klucz, []) if teraz - t < sekundy]
    slownik[klucz] = lista
    return lista


def sprawdz_dostep(db, dane, ip):
    space = str(dane.get("space", ""))
    auth = str(dane.get("auth", ""))
    if len(space) != 64 or len(auth) != 64:
        raise Blad(400, "zle dane")
    with _blokada:
        if len(_okno(_bledy, ip, 600)) >= LIMIT_BLEDOW:
            raise Blad(429, "za duzo blednych prob, poczekaj 10 minut")
    w = db.execute("SELECT auth FROM spaces WHERE id=?", (space,)).fetchone()
    if not w:
        raise Blad(404, "nie ma takiej przestrzeni")
    if not hmac.compare_digest(w["auth"], hashlib.sha256(auth.encode()).hexdigest()):
        with _blokada:
            _bledy.setdefault(ip, []).append(time.time())
        raise Blad(403, "zle haslo")
    return space


def api_join(db, d, ip):
    space = str(d.get("space", ""))
    auth = str(d.get("auth", ""))
    if len(space) != 64 or len(auth) != 64:
        raise Blad(400, "zle dane")
    w = db.execute("SELECT 1 FROM spaces WHERE id=?", (space,)).fetchone()
    if not w:
        if not d.get("create"):
            raise Blad(404, "nie ma takiej przestrzeni - zaznacz 'nowa', zeby ja utworzyc")
        db.execute("INSERT INTO spaces VALUES(?,?,?)",
                   (space, hashlib.sha256(auth.encode()).hexdigest(), time.time()))
        db.commit()
        return {"ok": True, "created": True}
    sprawdz_dostep(db, d, ip)
    return {"ok": True, "created": False}


def api_notes(db, d, ip):
    space = sprawdz_dostep(db, d, ip)
    since = float(d.get("since", 0))
    rows = db.execute("SELECT id, blob, version, updated, deleted FROM notes "
                      "WHERE space=? AND updated>? ORDER BY updated", (space, since)).fetchall()
    return {"ok": True, "notes": [dict(r) for r in rows], "now": time.time()}


def api_note_save(db, d, ip):
    space = sprawdz_dostep(db, d, ip)
    nid = str(d.get("id") or uuid.uuid4().hex)
    blob = str(d.get("blob", ""))
    if len(blob) > MAKS_NOTATKA:
        raise Blad(413, "notatka za duza")
    base = int(d.get("base_version", 0))
    w = db.execute("SELECT space, version FROM notes WHERE id=?", (nid,)).fetchone()
    teraz = time.time()
    if w:
        if w["space"] != space:
            raise Blad(403, "brak dostepu")
        if w["version"] != base:
            raise Blad(409, "ktos zmienil te notatke w miedzyczasie")
        db.execute("UPDATE notes SET blob=?, version=?, updated=?, deleted=0 WHERE id=?",
                   (blob, base + 1, teraz, nid))
        wersja = base + 1
    else:
        db.execute("INSERT INTO notes VALUES(?,?,?,?,?,0)", (nid, space, blob, 1, teraz))
        wersja = 1
    db.commit()
    return {"ok": True, "id": nid, "version": wersja}


def api_note_delete(db, d, ip):
    space = sprawdz_dostep(db, d, ip)
    nid = str(d.get("id", ""))
    w = db.execute("SELECT space, version FROM notes WHERE id=?", (nid,)).fetchone()
    if not w or w["space"] != space:
        raise Blad(404, "nie ma takiej notatki")
    db.execute("UPDATE notes SET blob='', deleted=1, version=version+1, updated=? WHERE id=?",
               (time.time(), nid))
    db.commit()
    return {"ok": True}


def api_msgs(db, d, ip):
    space = sprawdz_dostep(db, d, ip)
    after = int(d.get("after", 0))
    if after <= 0:   # pierwsze wejscie: ostatnie 100 wiadomosci
        rows = db.execute("SELECT * FROM (SELECT id, blob, ts FROM msgs WHERE space=? "
                          "ORDER BY id DESC LIMIT 100) ORDER BY id", (space,)).fetchall()
    else:
        rows = db.execute("SELECT id, blob, ts FROM msgs WHERE space=? AND id>? "
                          "ORDER BY id LIMIT 200", (space, after)).fetchall()
    return {"ok": True, "msgs": [dict(r) for r in rows]}


def api_msg_send(db, d, ip):
    space = sprawdz_dostep(db, d, ip)
    blob = str(d.get("blob", ""))
    if not blob or len(blob) > MAKS_WIADOMOSC:
        raise Blad(413, "wiadomosc pusta albo za dluga")
    with _blokada:
        if len(_okno(_wysylki, space, 60)) >= LIMIT_WIADOMOSCI:
            raise Blad(429, "za szybko, zwolnij")
        _wysylki[space].append(time.time())
    cur = db.execute("INSERT INTO msgs(space, blob, ts) VALUES(?,?,?)", (space, blob, time.time()))
    db.commit()
    return {"ok": True, "id": cur.lastrowid}


TRASY = {"/api/join": api_join, "/api/notes": api_notes, "/api/note_save": api_note_save,
         "/api/note_delete": api_note_delete, "/api/msgs": api_msgs, "/api/msg_send": api_msg_send}


class Obsluga(BaseHTTPRequestHandler):
    server_version = "GhostNotes/1.0"

    def log_message(self, fmt, *args):
        pass  # cisza w konsoli

    def _odpowiedz(self, kod, obj):
        dane = json.dumps(obj).encode()
        self.send_response(kod)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(dane)))
        self.end_headers()
        self.wfile.write(dane)

    def do_GET(self):
        self._odpowiedz(200, {"ok": True, "app": "ghost-notes"})

    def do_POST(self):
        fn = TRASY.get(self.path)
        if not fn:
            return self._odpowiedz(404, {"ok": False, "error": "nieznany adres"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n > MAKS_ROZMIAR:
                raise Blad(413, "za duze zapytanie")
            d = json.loads(self.rfile.read(n) or b"{}")
            db = baza()
            try:
                wynik = fn(db, d, self.client_address[0])
            finally:
                db.close()
            self._odpowiedz(200, wynik)
        except Blad as e:
            self._odpowiedz(e.kod, {"ok": False, "error": e.tekst})
        except Exception as e:
            self._odpowiedz(500, {"ok": False, "error": "blad serwera: %s" % e})


def moj_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def start(port=PORT):
    przygotuj_baze()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Obsluga)
    return srv


if __name__ == "__main__":
    srv = start()
    print("Serwer Ghost Notes dziala.")
    print("Adres do wpisania w aplikacji:  http://%s:%d" % (moj_ip(), PORT))
    print("Zatrzymanie: Ctrl+C (albo przycisk stop w Pydroid)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
