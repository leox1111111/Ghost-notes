# -*- coding: utf-8 -*-
"""
Ghost Notes - tajne notatki i czat (Kivy; Android APK albo Pydroid 3).
- tajny kod (klawiatura PIN), blokada po zlych probach, auto-blokada
- prywatne notatki w lokalnej bazie, zaszyfrowane
- wspolne przestrzenie: wspolne notatki + czat, szyfrowane na telefonie
- opcjonalny serwer uruchamiany na jednym z telefonow
"""
import os, json, time, hmac, hashlib, base64, sqlite3, threading, uuid, socket
import urllib.request, urllib.error

WERSJA = "1.0"
KATALOG = os.path.dirname(os.path.abspath(__file__))

# ======================================================================
#  SZYFROWANIE: PBKDF2-SHA256 -> klucze; HMAC-SHA256 CTR + HMAC (szyfr z uwierzytelnieniem)
# ======================================================================
ITERACJE = 150_000


def wyprowadz(haslo, sol):
    return hashlib.pbkdf2_hmac("sha256", haslo.encode("utf-8"), sol, ITERACJE)


def _h(klucz, dane):
    return hmac.new(klucz, dane, hashlib.sha256).digest()


class Klucz:
    def __init__(self, master):
        self.enc = _h(master, b"enc")
        self.mac = _h(master, b"mac")

    def _strumien(self, nonce, n):
        out = bytearray()
        i = 0
        while len(out) < n:
            out += _h(self.enc, nonce + i.to_bytes(8, "big"))
            i += 1
        return bytes(out[:n])

    def _xor(self, dane, nonce):
        if not dane:
            return b""
        ks = self._strumien(nonce, len(dane))
        return (int.from_bytes(dane, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(dane), "big")

    def szyfruj(self, tekst):
        nonce = os.urandom(16)
        ct = self._xor(tekst.encode("utf-8"), nonce)
        tag = _h(self.mac, b"v1" + nonce + ct)
        return base64.b64encode(b"v1" + nonce + ct + tag).decode()

    def odszyfruj(self, s):
        raw = base64.b64decode(s)
        if len(raw) < 50 or raw[:2] != b"v1":
            raise ValueError("zly format")
        nonce, ct, tag = raw[2:18], raw[18:-32], raw[-32:]
        if not hmac.compare_digest(tag, _h(self.mac, b"v1" + nonce + ct)):
            raise ValueError("zle haslo albo uszkodzone dane")
        return self._xor(ct, nonce).decode("utf-8")

    def szyfruj_obj(self, obj):
        return self.szyfruj(json.dumps(obj, ensure_ascii=False))

    def odszyfruj_obj(self, s):
        return json.loads(self.odszyfruj(s))


def id_przestrzeni(nazwa):
    return hashlib.sha256(b"ghost-notes-id:" + nazwa.strip().lower().encode("utf-8")).hexdigest()


class Przestrzen:
    def __init__(self, nazwa, haslo):
        self.nazwa = nazwa.strip()
        n = self.nazwa.lower().encode("utf-8")
        master = wyprowadz(haslo, hashlib.sha256(b"ghost-notes-sol:" + n).digest())
        self.id = id_przestrzeni(self.nazwa)
        self.auth = _h(master, b"auth").hex()
        self.klucz = Klucz(master)


# ======================================================================
#  LOKALNA BAZA
# ======================================================================
class Magazyn:
    def __init__(self, plik):
        self.db = sqlite3.connect(plik, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS config(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS notes(id TEXT PRIMARY KEY, blob TEXT NOT NULL, updated REAL);
        CREATE TABLE IF NOT EXISTS spaces(id TEXT PRIMARY KEY, blob TEXT NOT NULL);
        """)
        self.db.commit()

    def get(self, k, dom=None):
        with self.lock:
            w = self.db.execute("SELECT v FROM config WHERE k=?", (k,)).fetchone()
        return w[0] if w else dom

    def set(self, k, v):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO config VALUES(?,?)", (k, str(v)))
            self.db.commit()

    def jest_kod(self):
        return self.get("pin_check") is not None

    def ustaw_kod(self, kod):
        sol = os.urandom(16)
        master = wyprowadz(kod, sol)
        self.set("pin_salt", sol.hex())
        self.set("pin_check", _h(master, b"check").hex())
        return Klucz(master)

    def sprawdz_kod(self, kod):
        do_kiedy = float(self.get("blokada_do", 0))
        if time.time() < do_kiedy:
            return None, "Zablokowane. Spróbuj za %d s" % int(do_kiedy - time.time() + 1)
        master = wyprowadz(kod, bytes.fromhex(self.get("pin_salt")))
        if hmac.compare_digest(_h(master, b"check").hex(), self.get("pin_check")):
            self.set("bledy", 0)
            return Klucz(master), ""
        bledy = int(self.get("bledy", 0)) + 1
        self.set("bledy", bledy)
        if bledy >= 5:
            czas = 30 * (2 ** min(bledy - 5, 6))
            self.set("blokada_do", time.time() + czas)
            return None, "Zły kod. Blokada na %d s" % czas
        return None, "Zły kod (%d/5)" % bledy

    def zmien_kod(self, stary, nowy_kod):
        with self.lock:
            notes = self.db.execute("SELECT id, blob FROM notes").fetchall()
            spaces = self.db.execute("SELECT id, blob FROM spaces").fetchall()
        n = [(i, stary.odszyfruj(b)) for i, b in notes]
        s = [(i, stary.odszyfruj(b)) for i, b in spaces]
        nowy = self.ustaw_kod(nowy_kod)
        with self.lock:
            for i, t in n:
                self.db.execute("UPDATE notes SET blob=? WHERE id=?", (nowy.szyfruj(t), i))
            for i, t in s:
                self.db.execute("UPDATE spaces SET blob=? WHERE id=?", (nowy.szyfruj(t), i))
            self.db.commit()
        return nowy

    def notatki(self, klucz):
        with self.lock:
            rows = self.db.execute("SELECT id, blob, updated FROM notes ORDER BY updated DESC").fetchall()
        out = []
        for i, b, u in rows:
            try:
                d = klucz.odszyfruj_obj(b)
            except Exception:
                d = {"title": "(nie da się odczytać)", "text": ""}
            d["id"], d["updated"] = i, u
            out.append(d)
        return out

    def zapisz_notatke(self, klucz, nid, tytul, tekst):
        nid = nid or uuid.uuid4().hex
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO notes VALUES(?,?,?)",
                            (nid, klucz.szyfruj_obj({"title": tytul, "text": tekst}), time.time()))
            self.db.commit()
        return nid

    def usun_notatke(self, nid):
        with self.lock:
            self.db.execute("DELETE FROM notes WHERE id=?", (nid,))
            self.db.commit()

    def przestrzenie(self, klucz):
        with self.lock:
            rows = self.db.execute("SELECT id, blob FROM spaces").fetchall()
        out = []
        for i, b in rows:
            try:
                out.append(klucz.odszyfruj_obj(b))
            except Exception:
                pass
        return sorted(out, key=lambda d: d["name"].lower())

    def dodaj_przestrzen(self, klucz, prz, haslo):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO spaces VALUES(?,?)",
                            (prz.id, klucz.szyfruj_obj({"name": prz.nazwa, "password": haslo})))
            self.db.commit()

    def usun_przestrzen(self, sid):
        with self.lock:
            self.db.execute("DELETE FROM spaces WHERE id=?", (sid,))
            self.db.commit()


# ======================================================================
#  SIEC
# ======================================================================
class BladSieci(Exception):
    pass


def zapytanie(serwer, sciezka, prz, **dane):
    dane.update(space=prz.id, auth=prz.auth)
    req = urllib.request.Request(serwer.rstrip("/") + sciezka, data=json.dumps(dane).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error", str(e))
        except Exception:
            msg = str(e)
        raise BladSieci(msg)
    except Exception:
        raise BladSieci("Brak połączenia z serwerem")


def moj_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ======================================================================
#  WYGLAD
# ======================================================================
from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.core.text import LabelBase
from kivy.metrics import dp, sp
from kivy.animation import Animation
from kivy.graphics import Color, RoundedRectangle, Ellipse, Line, Rectangle
from kivy.uix.widget import Widget
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.switch import Switch
from kivy.uix.modalview import ModalView
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.screenmanager import ScreenManager, Screen, FadeTransition

LabelBase.register(name="Ikony", fn_regular=os.path.join(KATALOG, "assets", "icons.ttf"))
IK = dict(back="", add="", lock="", settings="", send="",
          search="", delete="", refresh="", chat="", group="",
          note="", check="", backspace="", dns="", person="",
          key="", shield="", close="", login="")

BG = (0.055, 0.06, 0.08, 1)
SURF = (0.10, 0.11, 0.15, 1)
SURF2 = (0.15, 0.16, 0.22, 1)
ACC = (0.55, 0.49, 0.96, 1)
ACC2 = (0.31, 0.82, 0.72, 1)
RED = (0.92, 0.36, 0.42, 1)
TXT = (0.95, 0.95, 0.98, 1)
MUTED = (0.58, 0.60, 0.68, 1)
PALETA = [(0.55, 0.49, 0.96, 1), (0.31, 0.72, 0.65, 1), (0.95, 0.55, 0.30, 1), (0.90, 0.40, 0.60, 1),
          (0.35, 0.60, 0.95, 1), (0.45, 0.75, 0.35, 1)]
Window.clearcolor = BG
Window.softinput_mode = "below_target"


def hexk(c):
    return "%02x%02x%02x" % tuple(int(x * 255) for x in c[:3])


def kolor_dla(tekst):
    return PALETA[sum(ord(c) for c in (tekst or "?")) % len(PALETA)]


def ik(nazwa, rozmiar=22):
    return "[font=Ikony][size=%d]%s[/size][/font]" % (int(sp(rozmiar)), IK[nazwa])


def esc(s):
    return str(s).replace("&", "&amp;").replace("[", "&bl;").replace("]", "&br;")


def kiedy(t):
    if not t:
        return ""
    lt = time.localtime(t)
    if time.strftime("%d%m%Y", lt) == time.strftime("%d%m%Y"):
        return time.strftime("%H:%M", lt)
    return time.strftime("%d.%m %H:%M", lt)


def tlo(w, kolor, r=dp(16)):
    with w.canvas.before:
        w._tlo_c = Color(*kolor)
        w._tlo_r = RoundedRectangle(pos=w.pos, size=w.size, radius=[r])
    w.bind(pos=lambda *_: setattr(w._tlo_r, "pos", w.pos), size=lambda *_: setattr(w._tlo_r, "size", w.size))


class RBtn(ButtonBehavior, Label):
    """Zaokraglony przycisk z opcjonalna ikona."""
    def __init__(self, tekst="", ikona=None, akcja=None, kolor=SURF2, kolor_txt=TXT, r=dp(16),
                 rozmiar=16, **kw):
        t = esc(tekst)
        if ikona:
            t = ik(ikona, rozmiar + 6) + ("  " + t if tekst else "")
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(54))
        super().__init__(text=t, markup=True, color=kolor_txt, font_size=sp(rozmiar), bold=True, **kw)
        self.kolor = kolor
        tlo(self, kolor, r)
        if akcja:
            self.bind(on_release=lambda *_: akcja())

    def on_state(self, w, v):
        k = self.kolor
        self._tlo_c.rgba = (k[0] * 0.75, k[1] * 0.75, k[2] * 0.75, k[3]) if v == "down" else k


def ik_btn(nazwa, akcja, kolor=(0, 0, 0, 0), kolor_txt=TXT, rozmiar=dp(46)):
    return RBtn(ikona=nazwa, akcja=akcja, kolor=kolor, kolor_txt=kolor_txt, r=rozmiar / 2,
                size_hint=(None, None), size=(rozmiar, rozmiar), rozmiar=18)


def napis(tekst, rozmiar=15, kolor=TXT, bold=False, wys=None, halign="left", **kw):
    l = Label(text=tekst, font_size=sp(rozmiar), color=kolor, bold=bold, halign=halign,
              valign="middle", size_hint_y=None, markup=True, **kw)
    if wys:
        l.height = wys
        l.shorten = True
        l.shorten_from = "right"
        l.bind(size=lambda w, v: setattr(w, "text_size", w.size))
    else:
        l.bind(width=lambda w, v: setattr(w, "text_size", (v, None)),
               texture_size=lambda w, v: setattr(w, "height", v[1]))
    return l


class Pole(TextInput):
    """Pole tekstowe z zaokraglonym tlem (obrazek 9-slice) i podswietleniem przy pisaniu."""
    def __init__(self, podp="", haslo=False, wiele=False, r=dp(14), kolor=SURF, **kw):
        kw.setdefault("font_size", sp(16))
        tlo_img = os.path.join(KATALOG, "assets", "pole.png") if kolor else ""
        super().__init__(hint_text=podp, password=haslo, multiline=wiele, background_normal=tlo_img,
                         background_active=tlo_img, background_color=kolor or (0, 0, 0, 0),
                         border=(34, 34, 34, 34), foreground_color=TXT, cursor_color=ACC,
                         hint_text_color=MUTED, padding=(dp(14), dp(14)), write_tab=False, **kw)
        if not wiele:
            self.size_hint_y = None
            self.height = dp(52)
        self._rr = r
        with self.canvas.after:
            self._ramka_c = Color(0, 0, 0, 0)
            self._ramka = Line(rounded_rectangle=(0, 0, 10, 10, 1), width=dp(1.2))
        self.bind(pos=self._r, size=self._r, focus=self._f)

    def _r(self, *a):
        r = min(self._rr, self.height / 2 - 1, self.width / 2 - 1)
        self._ramka.rounded_rectangle = (self.x, self.y, self.width, self.height, max(r, 1))

    def _f(self, w, v):
        self._ramka_c.rgba = (ACC[0], ACC[1], ACC[2], 0.8) if (v and self.background_normal) else (0, 0, 0, 0)


class Avatar(Label):
    def __init__(self, tekst="?", ikona=None, kolor=None, rozm=dp(46), **kw):
        t = ik(ikona, 22) if ikona else esc((tekst or "?").strip()[:1].upper() or "?")
        super().__init__(text=t, markup=True, bold=True, font_size=sp(19), color=(1, 1, 1, 1),
                         size_hint=(None, None), size=(rozm, rozm), **kw)
        with self.canvas.before:
            Color(*(kolor or kolor_dla(tekst)))
            self._e = Ellipse(pos=self.pos, size=self.size)
        self.bind(pos=lambda *_: setattr(self._e, "pos", self.pos))


class Duszek(Widget):
    """Logo: duszek rysowany wektorowo."""
    def __init__(self, rozm=dp(96), kolor=ACC, **kw):
        super().__init__(size_hint=(None, None), size=(rozm, rozm * 1.1), **kw)
        self.kolor = kolor
        self.bind(pos=self.rys, size=self.rys)

    def rys(self, *a):
        x, y, w, h = self.x, self.y, self.width, self.height
        r = w / 6
        self.canvas.clear()
        with self.canvas:
            Color(*self.kolor)
            RoundedRectangle(pos=(x, y + r), size=(w, h - r), radius=[w / 2, w / 2, 0, 0])
            for i in range(3):
                Ellipse(pos=(x + i * w / 3, y), size=(w / 3, 2 * r))
            Color(*BG)
            for i in range(2):
                Ellipse(pos=(x + w * (0.26 + 0.32 * i), y + h * 0.52), size=(w * 0.16, w * 0.2))


class Karta(ButtonBehavior, BoxLayout):
    def __init__(self, tytul, opis, akcja, av_tekst=None, av_ikona=None, av_kolor=None, prawy="", **kw):
        super().__init__(orientation="horizontal", size_hint_y=None, height=dp(78),
                         padding=(dp(12), dp(10)), spacing=dp(12), **kw)
        tlo(self, SURF, dp(20))
        self.add_widget(Avatar(av_tekst if av_tekst is not None else tytul, av_ikona, av_kolor,
                               pos_hint={"center_y": 0.5}))
        kol = BoxLayout(orientation="vertical", spacing=dp(2))
        gora = BoxLayout(size_hint_y=None, height=dp(28))
        gora.add_widget(napis("[b]%s[/b]" % esc(tytul or "(bez tytułu)"), 17, wys=dp(28)))
        if prawy:
            gora.add_widget(napis(prawy, 12, MUTED, wys=dp(28), halign="right", size_hint_x=0.35))
        kol.add_widget(gora)
        kol.add_widget(napis(esc(opis), 13, MUTED, wys=dp(22)))
        self.add_widget(kol)
        self.bind(on_release=lambda *_: akcja())

    def on_state(self, w, v):
        self._tlo_c.rgba = SURF2 if v == "down" else SURF


def lista():
    sv = ScrollView(do_scroll_x=False, bar_color=ACC, bar_inactive_color=(1, 1, 1, 0.1), bar_width=dp(3))
    g = GridLayout(cols=1, spacing=dp(10), size_hint_y=None, padding=(0, dp(4), 0, dp(90)))
    g.bind(minimum_height=g.setter("height"))
    sv.add_widget(g)
    return sv, g


def pusto(tekst):
    box = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(260), spacing=dp(14),
                    padding=(dp(20), dp(40), dp(20), 0))
    a = AnchorLayout(size_hint_y=None, height=dp(110))
    a.add_widget(Duszek(dp(80), (ACC[0], ACC[1], ACC[2], 0.35)))
    box.add_widget(a)
    box.add_widget(napis(tekst, 15, MUTED, halign="center"))
    return box


def naglowek(tytul, wstecz=None, akcje=(), podtytul=None):
    b = BoxLayout(size_hint_y=None, height=dp(62), spacing=dp(6))
    if wstecz:
        b.add_widget(ik_btn("back", wstecz))
    kol = BoxLayout(orientation="vertical")
    kol.add_widget(napis("[b]%s[/b]" % esc(tytul), 23, wys=dp(36 if podtytul else 62)))
    if podtytul:
        kol.add_widget(napis(podtytul, 12, MUTED, wys=dp(22)))
    b.add_widget(kol)
    for a in akcje:
        b.add_widget(ik_btn(a[0], a[1], kolor_txt=a[2] if len(a) > 2 else TXT))
    return b


def fab(ikona, akcja):
    b = RBtn(ikona=ikona, akcja=akcja, kolor=ACC, r=dp(30), size_hint=(None, None),
             size=(dp(62), dp(62)), rozmiar=22, pos_hint={"right": 0.95, "y": 0.13})
    return b


def toast(tekst, kolor=SURF2):
    l = Label(text=tekst, font_size=sp(15), color=TXT, size_hint=(None, None), padding=(dp(20), dp(12)))
    l.texture_update()
    l.size = (l.texture_size[0], l.texture_size[1])
    tlo(l, kolor, dp(20))
    l.pos = (Window.width / 2 - l.width / 2, dp(120))
    l.opacity = 0
    Window.add_widget(l)
    a = Animation(opacity=1, d=0.15) + Animation(d=1.6) + Animation(opacity=0, d=0.4)
    a.bind(on_complete=lambda *_: Window.remove_widget(l))
    a.start(l)


def dialog(tytul, tekst, akcje):
    """akcje: [(tekst, fn, kolor)]"""
    mv = ModalView(size_hint=(0.88, None), height=dp(240), background="", background_color=(0, 0, 0, 0),
                   overlay_color=(0, 0, 0, 0.65), auto_dismiss=True)
    box = BoxLayout(orientation="vertical", padding=dp(20), spacing=dp(12))
    tlo(box, SURF, dp(24))
    box.add_widget(napis("[b]%s[/b]" % esc(tytul), 19))
    box.add_widget(napis(esc(tekst), 15, MUTED))
    box.add_widget(Widget())
    rz = BoxLayout(size_hint_y=None, height=dp(52), spacing=dp(10))
    for t, fn, k in akcje:
        rz.add_widget(RBtn(t, akcja=(lambda fn=fn: (mv.dismiss(), fn and fn())), kolor=k))
    box.add_widget(rz)
    mv.add_widget(box)
    mv.open()


def blad(m):
    toast(m, (0.45, 0.16, 0.2, 0.97))


def w_tle(praca, gotowe, przy_bledzie=None):
    def run():
        try:
            w = praca()
            Clock.schedule_once(lambda dt: gotowe(w))
        except Exception as e:
            msg = str(e)
            Clock.schedule_once(lambda dt: (przy_bledzie or blad)(msg))
    threading.Thread(target=run, daemon=True).start()


class Ekran(Screen):
    @property
    def app(self):
        return App.get_running_app()

    def buduj(self, *widgety, dol=None, przycisk=None, padding=None):
        self.clear_widgets()
        root = FloatLayout()
        zew = BoxLayout(orientation="vertical")
        box = BoxLayout(orientation="vertical", spacing=dp(12),
                        padding=padding or (dp(16), dp(8), dp(16), dp(10)))
        for w in widgety:
            box.add_widget(w)
        zew.add_widget(box)
        if dol:
            zew.add_widget(dol)
        root.add_widget(zew)
        if przycisk:
            root.add_widget(przycisk)
        self.add_widget(root)

    def wstecz(self):
        return False


# ---------------- ekran: tajny kod ----------------
class Kropki(Widget):
    def __init__(self, **kw):
        super().__init__(size_hint=(None, None), size=(dp(260), dp(26)), **kw)
        self.n = 0
        self.kolor = ACC
        self.bind(pos=self.rys, size=self.rys)

    def ustaw(self, n, kolor=ACC):
        self.n, self.kolor = n, kolor
        self.rys()

    def rys(self, *a):
        self.canvas.clear()
        sloty = max(4, self.n)
        d, gap = dp(14), dp(14)
        x0 = self.center_x - (sloty * d + (sloty - 1) * gap) / 2
        with self.canvas:
            for i in range(sloty):
                if i < self.n:
                    Color(*self.kolor)
                    Ellipse(pos=(x0 + i * (d + gap), self.center_y - d / 2), size=(d, d))
                else:
                    Color(MUTED[0], MUTED[1], MUTED[2], 0.6)
                    Line(circle=(x0 + i * (d + gap) + d / 2, self.center_y, d / 2 - dp(1)), width=dp(1.3))


class EkranKod(Ekran):
    def on_enter(self, *a):
        self.pin = ""
        self.etap = "otworz" if self.app.mag.jest_kod() else "nowy"
        self.pierwszy = ""
        self.zajety = False
        logo = AnchorLayout(size_hint_y=None, height=dp(120))
        logo.add_widget(Duszek(dp(84)))
        self.tytul = napis("", 15, MUTED, halign="center", wys=dp(24))
        self.kropki = Kropki()
        kr = AnchorLayout(size_hint_y=None, height=dp(40))
        kr.add_widget(self.kropki)
        self.info = napis("", 14, RED, halign="center", wys=dp(24))
        k = dp(74)
        siatka = GridLayout(cols=3, spacing=dp(18), size_hint=(None, None), width=3 * k + 2 * dp(18),
                            height=4 * k + 3 * dp(18))
        for c in "123456789":
            siatka.add_widget(RBtn(c, akcja=lambda c=c: self.cyfra(c), kolor=SURF, r=k / 2, rozmiar=26,
                                   size_hint=(None, None), size=(k, k)))
        siatka.add_widget(RBtn(ikona="backspace", akcja=self.cofnij, kolor=BG, r=k / 2,
                               size_hint=(None, None), size=(k, k), kolor_txt=MUTED))
        siatka.add_widget(RBtn("0", akcja=lambda: self.cyfra("0"), kolor=SURF, r=k / 2, rozmiar=26,
                               size_hint=(None, None), size=(k, k)))
        siatka.add_widget(RBtn(ikona="check", akcja=self.ok, kolor=ACC, r=k / 2,
                               size_hint=(None, None), size=(k, k)))
        kl = AnchorLayout(size_hint_y=None, height=siatka.height)
        kl.add_widget(siatka)
        self.buduj(Widget(), logo, napis("[b]Ghost Notes[/b]", 28, halign="center", wys=dp(44)),
                   self.tytul, kr, self.info, kl, Widget())
        self.odswiez()

    def odswiez(self):
        self.tytul.text = {"otworz": "Podaj tajny kod", "nowy": "Ustaw tajny kod (min. 4 cyfry)",
                           "powtorz": "Powtórz kod"}[self.etap]
        self.kropki.ustaw(len(self.pin))

    def cyfra(self, c):
        if self.zajety or len(self.pin) >= 12:
            return
        self.pin += c
        self.info.text = ""
        self.odswiez()

    def cofnij(self):
        self.pin = self.pin[:-1]
        self.odswiez()

    def trzes(self, msg):
        self.info.text = msg
        self.kropki.ustaw(len(self.pin), RED)
        x = self.kropki.x
        a = Animation(x=x + dp(12), d=0.05) + Animation(x=x - dp(12), d=0.05) + \
            Animation(x=x + dp(6), d=0.05) + Animation(x=x, d=0.05)
        a.bind(on_complete=lambda *_: (setattr(self, "pin", ""), self.odswiez()))
        a.start(self.kropki)

    def ok(self):
        if self.zajety:
            return
        if self.etap == "nowy":
            if len(self.pin) < 4:
                return self.trzes("Min. 4 cyfry")
            self.pierwszy, self.pin, self.etap = self.pin, "", "powtorz"
            return self.odswiez()
        if self.etap == "powtorz":
            if self.pin != self.pierwszy:
                self.etap = "nowy"
                return self.trzes("Kody się różnią, od nowa")
            self.zajety = True
            self.info.text = ""
            self.tytul.text = "Szyfruję..."
            kod = self.pin
            return w_tle(lambda: self.app.mag.ustaw_kod(kod), self.app.odblokuj)
        if not self.pin:
            return
        self.zajety = True
        self.tytul.text = "Sprawdzam..."
        kod = self.pin

        def gotowe(w):
            self.zajety = False
            klucz, msg = w
            if klucz:
                self.app.odblokuj(klucz)
            else:
                self.odswiez()
                self.trzes(msg)
        w_tle(lambda: self.app.mag.sprawdz_kod(kod), gotowe)


# ---------------- ekran glowny ----------------
def zakladka(ikona, tekst, aktywna, akcja):
    k = ACC if aktywna else MUTED
    b = RBtn(akcja=akcja, kolor=SURF, r=0, size_hint_y=None, height=dp(64), kolor_txt=k)
    b.text = "%s\n[size=%d]%s[/size]" % (ik(ikona, 24), int(sp(12)), tekst)
    b.halign = "center"
    return b


class EkranGlowny(Ekran):
    zakl = "moje"
    fraza = ""

    def on_enter(self, *a):
        self.odswiez()

    def odswiez(self):
        a = self.app
        dol = BoxLayout(size_hint_y=None, height=dp(64))
        tlo(dol, SURF, 0)
        dol.add_widget(zakladka("note", "Moje notatki", self.zakl == "moje", lambda: self.przelacz("moje")))
        dol.add_widget(zakladka("group", "Wspólne", self.zakl == "wsp", lambda: self.przelacz("wsp")))
        akcje = [("settings", lambda: a.idz("ustawienia")), ("lock", a.zablokuj, ACC)]
        sv, g = lista()
        if self.zakl == "moje":
            notes = a.mag.notatki(a.klucz)
            szukaj = Pole("Szukaj w notatkach", text=self.fraza)
            szukaj.bind(text=lambda w, v: self.filtruj(v, g, notes))
            self.filtruj(self.fraza, g, notes)
            self.buduj(naglowek("Moje notatki", akcje=akcje,
                                podtytul="%d notatek, zaszyfrowane" % len(notes)),
                       szukaj, sv, dol=dol, przycisk=fab("add", lambda: a.edytuj_moja(None)))
        else:
            prz = a.mag.przestrzenie(a.klucz)
            for d in prz:
                g.add_widget(Karta(d["name"], "wspólne notatki i czat", lambda d=d: a.otworz_przestrzen(d)))
            if not prz:
                g.add_widget(pusto("Nie masz jeszcze wspólnych przestrzeni.\nDotknij +, żeby utworzyć "
                                   "albo dołączyć."))
            self.buduj(naglowek("Wspólne", akcje=akcje, podtytul="notatki i czat ze znajomymi"),
                       sv, dol=dol, przycisk=fab("add", lambda: a.idz("dolacz")))

    def filtruj(self, fraza, g, notes):
        self.fraza = fraza
        g.clear_widgets()
        n = 0
        for d in notes:
            if fraza and fraza.lower() not in (d["title"] + " " + d["text"]).lower():
                continue
            n += 1
            g.add_widget(Karta(d["title"], d["text"][:80].replace("\n", "  ") or "pusta notatka",
                               lambda d=d: self.app.edytuj_moja(d), prawy=kiedy(d["updated"])))
        if not n:
            g.add_widget(pusto("Nic nie znaleziono." if fraza else
                               "Pusto tutaj.\nDotknij +, żeby dodać pierwszą notatkę."))

    def przelacz(self, z):
        self.zakl = z
        self.odswiez()


# ---------------- edytor ----------------
class EkranEdytor(Ekran):
    def on_enter(self, *a):
        e = self.app.edycja
        self.oryg = (e.get("title", ""), e.get("text", ""))
        self.tytul = Pole("Tytuł", text=e.get("title", ""), font_size=sp(22), kolor=None)
        self.tytul.bold = True
        self.tekst = Pole("Zacznij pisać...", wiele=True, text=e.get("text", ""), kolor=SURF, r=dp(20))
        if e["typ"] == "wsp":
            pt = self.app.prz.nazwa
            if e.get("by"):
                pt += "  ·  %s, %s" % (e["by"], kiedy(e.get("t")))
        else:
            pt = "prywatna, zaszyfrowana"
        akcje = [("check", self.zapisz, ACC2)]
        if e.get("id"):
            akcje.append(("delete", lambda: dialog("Usunąć notatkę?", "Tego nie da się cofnąć.",
                                                   [("Anuluj", None, SURF2), ("Usuń", self.usun, RED)]), RED))
        self.buduj(naglowek("Notatka" if e["typ"] == "moja" else "Wspólna notatka", self.wstecz, akcje,
                            podtytul=pt), self.tytul, self.tekst)

    def zmieniona(self):
        return (self.tytul.text, self.tekst.text) != self.oryg

    def wstecz(self):
        cel = "przestrzen" if self.app.edycja["typ"] == "wsp" else "glowny"
        if self.zmieniona() and (self.tytul.text.strip() or self.tekst.text.strip()):
            self.zapisz(lambda: self.app.idz(cel))
        else:
            self.app.idz(cel)
        return True

    def zapisz(self, potem=None):
        a, e = self.app, self.app.edycja
        if not (self.tytul.text.strip() or self.tekst.text.strip()):
            return toast("Pusta notatka")
        if e["typ"] == "moja":
            e["id"] = a.mag.zapisz_notatke(a.klucz, e.get("id"), self.tytul.text, self.tekst.text)
            self.oryg = (self.tytul.text, self.tekst.text)
            toast("Zapisano")
            return potem() if potem else None
        blob = a.prz.klucz.szyfruj_obj({"title": self.tytul.text, "text": self.tekst.text,
                                        "by": a.nick(), "t": time.time()})

        def gotowe(w):
            e["id"], e["version"] = w["id"], w["version"]
            self.oryg = (self.tytul.text, self.tekst.text)
            toast("Zapisano we wspólnych")
            if potem:
                potem()

        def zle(m):
            if "zmienil" in m:
                dialog("Konflikt", "Ktoś zmienił tę notatkę w międzyczasie. Skopiuj swój tekst, "
                       "wróć i otwórz ją ponownie.", [("OK", None, ACC)])
            else:
                blad(m)
        w_tle(lambda: zapytanie(a.serwer(), "/api/note_save", a.prz, id=e.get("id"), blob=blob,
                                base_version=e.get("version", 0)), gotowe, zle)

    def usun(self):
        a, e = self.app, self.app.edycja
        if e["typ"] == "moja":
            a.mag.usun_notatke(e["id"])
            toast("Usunięto")
            a.idz("glowny")
        else:
            w_tle(lambda: zapytanie(a.serwer(), "/api/note_delete", a.prz, id=e["id"]),
                  lambda w: (toast("Usunięto"), a.idz("przestrzen")))


# ---------------- dolaczanie ----------------
class EkranDolacz(Ekran):
    nowa = False

    def on_enter(self, *a):
        self.nazwa = Pole("Nazwa przestrzeni, np. paczka")
        self.haslo = Pole("Hasło przestrzeni (min. 8 znaków)", haslo=True)
        self.przyc = RBtn("", akcja=self.dolacz, kolor=ACC)
        self.tryb = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        self.rysuj_tryb()
        info = BoxLayout(orientation="vertical", size_hint_y=None, padding=dp(16), spacing=dp(6))
        tlo(info, SURF, dp(20))
        t = napis("%s  Hasło nigdy nie trafia na serwer. Kto zna nazwę i hasło, widzi notatki i czat. "
                  "Przekaż je znajomym osobiście." % ik("shield", 18), 13, MUTED)
        info.add_widget(t)
        t.bind(height=lambda w, v: setattr(info, "height", v + dp(32)))
        self.buduj(naglowek("Wspólna przestrzeń", lambda: self.app.idz("glowny")), self.tryb, info,
                   self.nazwa, self.haslo, self.przyc, Widget())

    def rysuj_tryb(self):
        self.tryb.clear_widgets()
        for tekst, wart in (("Dołącz", False), ("Utwórz nową", True)):
            self.tryb.add_widget(RBtn(tekst, akcja=lambda w=wart: self.ustaw(w), height=dp(48),
                                      kolor=ACC if self.nowa == wart else SURF,
                                      kolor_txt=TXT if self.nowa == wart else MUTED))
        self.przyc.text = "%s  %s" % (ik("add" if self.nowa else "login", 22),
                                      "Utwórz przestrzeń" if self.nowa else "Dołącz")

    def ustaw(self, w):
        self.nowa = w
        self.rysuj_tryb()

    def wstecz(self):
        self.app.idz("glowny")
        return True

    def dolacz(self):
        a = self.app
        nazwa, haslo, nowa = self.nazwa.text.strip(), self.haslo.text, self.nowa
        if not nazwa or len(haslo) < 8:
            return blad("Podaj nazwę i hasło (min. 8 znaków)")
        self.przyc.text = "Łączę..."

        def praca():
            prz = Przestrzen(nazwa, haslo)
            return prz, zapytanie(a.serwer(), "/api/join", prz, create=nowa)

        def gotowe(w):
            prz, odp = w
            a.mag.dodaj_przestrzen(a.klucz, prz, haslo)
            a.cache_prz[prz.id] = prz
            a.prz = prz
            a.idz("przestrzen")
            toast("Utworzono \"%s\"" % prz.nazwa if odp.get("created") else "Dołączono do \"%s\"" % prz.nazwa)

        def zle(m):
            self.rysuj_tryb()
            if "nie ma takiej" in m:
                m = "Nie ma takiej przestrzeni. Wybierz \"Utwórz nową\"."
            blad(m)
        w_tle(praca, gotowe, zle)


# ---------------- przestrzen ----------------
class EkranPrzestrzen(Ekran):
    def on_enter(self, *a):
        a = self.app
        self.sv, self.g = lista()
        akcje = [("refresh", self.pobierz), ("delete", lambda: dialog(
            "Usunąć z listy?", "Przestrzeń zniknie tylko z Twojej listy. Możesz dołączyć ponownie.",
            [("Anuluj", None, SURF2), ("Usuń", self.zapomnij, RED)]), MUTED)]
        czat = Karta("Czat", "dotknij, żeby pisać ze znajomymi", lambda: a.idz("czat"),
                     av_ikona="chat", av_kolor=ACC2)
        self.buduj(naglowek(a.prz.nazwa, self.wstecz, akcje, podtytul="wspólna przestrzeń"),
                   czat, napis("[b]WSPÓLNE NOTATKI[/b]", 12, MUTED, wys=dp(20)), self.sv,
                   przycisk=fab("add", lambda: a.edytuj_wsp(None)))
        self.g.add_widget(napis("Wczytuję...", 14, MUTED, halign="center", wys=dp(60)))
        self.pobierz()

    def wstecz(self):
        self.app.idz("glowny")
        return True

    def pobierz(self):
        a, prz = self.app, self.app.prz

        def praca():
            w = zapytanie(a.serwer(), "/api/notes", prz, since=0)
            out = []
            for n in w["notes"]:
                if n["deleted"]:
                    continue
                try:
                    d = prz.klucz.odszyfruj_obj(n["blob"])
                except Exception:
                    d = {"title": "(nie da się odczytać)", "text": ""}
                d.update(id=n["id"], version=n["version"], updated=n["updated"])
                out.append(d)
            return sorted(out, key=lambda d: -d["updated"])

        def gotowe(notes):
            self.g.clear_widgets()
            for d in notes:
                self.g.add_widget(Karta(d["title"], "%s: %s" % (d.get("by", "?"), d["text"][:70].replace("\n", "  ")),
                                        lambda d=d: a.edytuj_wsp(d), av_tekst=d.get("by", "?"),
                                        prawy=kiedy(d["updated"])))
            if not notes:
                self.g.add_widget(pusto("Brak wspólnych notatek.\nDotknij +, żeby dodać."))

        def zle(m):
            self.g.clear_widgets()
            self.g.add_widget(pusto(m))
        w_tle(praca, gotowe, zle)

    def zapomnij(self):
        self.app.mag.usun_przestrzen(self.app.prz.id)
        self.app.idz("glowny")


# ---------------- czat ----------------
def dymek(nick, tekst, t, ja):
    wiersz = BoxLayout(size_hint_y=None, spacing=dp(8))
    if ja:
        tresc = "%s\n[size=%d][color=ddddff]%s[/color][/size]" % (esc(tekst), int(sp(11)), kiedy(t))
    else:
        tresc = "[b][color=%s]%s[/color][/b]\n%s\n[size=%d][color=9a9db0]%s[/color][/size]" % (
            hexk(kolor_dla(nick)), esc(nick), esc(tekst), int(sp(11)), kiedy(t))
    l = Label(text=tresc, markup=True, font_size=sp(15), color=TXT, size_hint=(None, None),
              halign="left", valign="top", padding=(dp(14), dp(10)))
    maks = Window.width * 0.72
    l.texture_update()
    if l.texture_size[0] > maks:
        l.text_size = (maks - dp(28), None)
        l.texture_update()
    l.size = l.texture_size
    tlo(l, ACC if ja else SURF2, dp(18))
    wiersz.height = l.height
    if ja:
        wiersz.add_widget(Widget())
        wiersz.add_widget(l)
    else:
        av = Avatar(nick, rozm=dp(34))
        kol = BoxLayout(orientation="vertical", size_hint=(None, None), size=(dp(34), l.height))
        kol.add_widget(Widget())
        kol.add_widget(av)
        wiersz.add_widget(kol)
        wiersz.add_widget(l)
        wiersz.add_widget(Widget())
    return wiersz


class EkranCzat(Ekran):
    def on_enter(self, *a):
        a = self.app
        self.ostatnie = 0
        self.trwa = False
        self.sv = ScrollView(do_scroll_x=False, bar_width=dp(3), bar_color=ACC)
        self.g = GridLayout(cols=1, spacing=dp(8), size_hint_y=None, padding=(0, dp(8)))
        self.g.bind(minimum_height=self.g.setter("height"))
        self.sv.add_widget(self.g)
        self.wpis = Pole("Wiadomość...", r=dp(26))
        self.wpis.bind(on_text_validate=lambda *_: self.wyslij())
        pasek = BoxLayout(size_hint_y=None, height=dp(52), spacing=dp(10))
        pasek.add_widget(self.wpis)
        pasek.add_widget(RBtn(ikona="send", akcja=self.wyslij, kolor=ACC, r=dp(26),
                              size_hint=(None, None), size=(dp(52), dp(52))))
        self.buduj(naglowek("Czat", self.wstecz, podtytul=a.prz.nazwa), self.sv, pasek)
        self.pobierz()
        self.zegar = Clock.schedule_interval(lambda dt: self.pobierz(), 2.5)

    def on_leave(self, *a):
        self.zegar.cancel()

    def wstecz(self):
        self.app.idz("przestrzen")
        return True

    def pobierz(self):
        if self.trwa:
            return
        self.trwa = True
        a, prz, od = self.app, self.app.prz, self.ostatnie

        def gotowe(w):
            self.trwa = False
            for m in w["msgs"]:
                if m["id"] <= self.ostatnie:
                    continue
                self.ostatnie = m["id"]
                try:
                    d = prz.klucz.odszyfruj_obj(m["blob"])
                    self.g.add_widget(dymek(d.get("nick", "?"), d.get("text", ""), m["ts"],
                                            d.get("nick") == a.nick()))
                except Exception:
                    self.g.add_widget(napis("(nie da się odczytać)", 13, MUTED, halign="center"))
            if w["msgs"]:
                Clock.schedule_once(lambda dt: setattr(self.sv, "scroll_y", 0), 0.05)

        def zle(m):
            self.trwa = False
        w_tle(lambda: zapytanie(a.serwer(), "/api/msgs", prz, after=od), gotowe, zle)

    def wyslij(self):
        tekst = self.wpis.text.strip()
        if not tekst:
            return
        a = self.app
        self.wpis.text = ""
        blob = a.prz.klucz.szyfruj_obj({"nick": a.nick(), "text": tekst})
        w_tle(lambda: zapytanie(a.serwer(), "/api/msg_send", a.prz, blob=blob), lambda w: self.pobierz())
        Clock.schedule_once(lambda dt: setattr(self.wpis, "focus", True), 0.15)


# ---------------- ustawienia ----------------
def sekcja(tytul, ikona, *widgety):
    box = BoxLayout(orientation="vertical", size_hint_y=None, padding=dp(16), spacing=dp(10))
    tlo(box, SURF, dp(22))
    box.add_widget(napis("%s  [b]%s[/b]" % (ik(ikona, 18), tytul), 16, wys=dp(28)))
    for w in widgety:
        box.add_widget(w)
    box.bind(minimum_height=box.setter("height"))
    return box


class EkranUstawienia(Ekran):
    def on_enter(self, *a):
        m, app = self.app.mag, self.app
        self.nick = Pole("Twój nick w czacie", text=m.get("nick", ""), kolor=SURF2)
        self.serwer = Pole("http://192.168.1.10:8765", text=m.get("serwer", ""), kolor=SURF2)
        self.host = Switch(active=app.serwer_dziala(), size_hint_x=None, width=dp(90))
        self.host.bind(active=lambda w, v: self.przelacz_host(v))
        self.host_info = napis("", 13, ACC2)
        self.minuty = Pole("3", text=m.get("auto_blokada", "3"), input_filter="int", kolor=SURF2)
        self.stary = Pole("Obecny kod", haslo=True, input_filter="int", kolor=SURF2)
        self.nowy = Pole("Nowy kod (min. 4 cyfry)", haslo=True, input_filter="int", kolor=SURF2)
        self.nowy2 = Pole("Powtórz nowy kod", haslo=True, input_filter="int", kolor=SURF2)
        hrz = BoxLayout(size_hint_y=None, height=dp(44))
        hrz.add_widget(napis("Serwer na tym telefonie", 15, wys=dp(44)))
        hrz.add_widget(self.host)
        sv, g = lista()
        g.padding = (0, dp(4), 0, dp(30))
        g.add_widget(sekcja("Profil", "person", self.nick))
        g.add_widget(sekcja("Serwer", "dns", napis("Adres serwera (wspólne notatki i czat)", 13, MUTED),
                            self.serwer, hrz, self.host_info))
        g.add_widget(sekcja("Bezpieczeństwo", "shield", napis("Auto-blokada po (minutach)", 13, MUTED),
                            self.minuty, napis("Zmiana tajnego kodu", 13, MUTED), self.stary, self.nowy,
                            self.nowy2, RBtn("Zmień kod", ikona="key", akcja=self.zmien_kod, kolor=SURF2)))
        g.add_widget(napis("Ghost Notes %s  ·  szyfrowanie na telefonie" % WERSJA, 12, MUTED,
                           halign="center", wys=dp(30)))
        self.opis_hosta()
        self.buduj(naglowek("Ustawienia", self.wstecz, [("check", self.zapisz, ACC2)]), sv)

    def opis_hosta(self):
        if self.app.serwer_dziala():
            self.host_info.text = ("Działa. Znajomi wpisują u siebie adres:\n[b]http://%s:8765[/b]\n"
                                   "Aplikacja musi być otwarta, żeby serwer działał." % moj_ip())
        else:
            self.host_info.text = "Włącz, jeśli ten telefon ma być serwerem dla znajomych."

    def przelacz_host(self, v):
        try:
            if v:
                self.app.start_serwera()
                self.serwer.text = "http://127.0.0.1:8765"
                self.app.mag.set("serwer", self.serwer.text)
            else:
                self.app.stop_serwera()
        except Exception as e:
            blad("Nie udało się: %s" % e)
            self.host.active = False
        self.opis_hosta()

    def zapisz(self):
        m = self.app.mag
        s = self.serwer.text.strip()
        if s and not s.startswith("http"):
            s = "http://" + s
        m.set("serwer", s)
        m.set("nick", self.nick.text.strip()[:30])
        m.set("auto_blokada", max(1, int(self.minuty.text or 3)))
        toast("Zapisano")
        self.app.idz("glowny")

    def wstecz(self):
        self.app.idz("glowny")
        return True

    def zmien_kod(self):
        a = self.app
        stary, nowy, nowy2 = self.stary.text, self.nowy.text, self.nowy2.text
        if len(nowy) < 4 or nowy != nowy2:
            return blad("Nowy kod: min. 4 cyfry, oba pola takie same")

        def praca():
            k, msg = a.mag.sprawdz_kod(stary)
            if not k:
                raise Exception(msg)
            return a.mag.zmien_kod(k, nowy)

        def gotowe(k):
            a.klucz = k
            for p in (self.stary, self.nowy, self.nowy2):
                p.text = ""
            toast("Kod zmieniony")
        w_tle(praca, gotowe)


# ---------------- aplikacja ----------------
class GhostNotes(App):
    title = "Ghost Notes"

    def build(self):
        self.icon = os.path.join(KATALOG, "assets", "icon.png")
        self.mag = Magazyn(os.path.join(self.user_data_dir, "ghost_notes.db"))
        self.klucz = None
        self.prz = None
        self.cache_prz = {}
        self.edycja = {}
        self.srv = None
        self.ostatni_dotyk = time.time()
        self.sm = ScreenManager(transition=FadeTransition(duration=0.12))
        for nazwa, klasa in [("kod", EkranKod), ("glowny", EkranGlowny), ("edytor", EkranEdytor),
                             ("dolacz", EkranDolacz), ("przestrzen", EkranPrzestrzen),
                             ("czat", EkranCzat), ("ustawienia", EkranUstawienia)]:
            self.sm.add_widget(klasa(name=nazwa))
        Window.bind(on_touch_down=self._dotyk, on_keyboard=self._klawisz)
        Clock.schedule_interval(self._pilnuj, 5)
        if self.mag.get("hostuj") == "1":
            try:
                self.start_serwera()
            except Exception:
                pass
        return self.sm

    # --- serwer wbudowany ---
    def serwer_dziala(self):
        return self.srv is not None

    def start_serwera(self):
        if self.srv:
            return
        import serwer
        serwer.BAZA = os.path.join(self.user_data_dir, "ghost_serwer.db")
        self.srv = serwer.start(8765)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.mag.set("hostuj", 1)

    def stop_serwera(self):
        if self.srv:
            srv, self.srv = self.srv, None
            threading.Thread(target=srv.shutdown, daemon=True).start()
        self.mag.set("hostuj", 0)

    def _dotyk(self, *a):
        self.ostatni_dotyk = time.time()

    def _klawisz(self, win, key, *a):
        self.ostatni_dotyk = time.time()
        if key == 27:   # przycisk Wstecz na Androidzie
            ekran = self.sm.current_screen
            if self.sm.current in ("glowny", "kod"):
                return False
            return ekran.wstecz()
        return False

    def _pilnuj(self, dt):
        if self.klucz and time.time() - self.ostatni_dotyk > 60 * int(self.mag.get("auto_blokada", 3)):
            self.zablokuj()

    def on_pause(self):
        return True

    def on_resume(self):
        self._pilnuj(0)

    def idz(self, ekran):
        if self.sm.current == ekran:
            self.sm.current_screen.on_enter()
        self.sm.current = ekran

    def odblokuj(self, klucz):
        self.klucz = klucz
        self.ostatni_dotyk = time.time()
        if not self.mag.get("nick"):
            self.idz("ustawienia")
            toast("Ustaw nick i serwer, żeby używać wspólnych")
        else:
            self.idz("glowny")

    def zablokuj(self):
        self.klucz = None
        self.prz = None
        self.cache_prz = {}
        self.edycja = {}
        self.idz("kod")

    def serwer(self):
        s = self.mag.get("serwer", "")
        if not s:
            raise BladSieci("Ustaw adres serwera w Ustawieniach")
        return s

    def nick(self):
        return self.mag.get("nick", "") or "anonim"

    def edytuj_moja(self, n):
        self.edycja = dict(n or {}, typ="moja")
        self.idz("edytor")

    def edytuj_wsp(self, n):
        self.edycja = dict(n or {}, typ="wsp")
        self.idz("edytor")

    def otworz_przestrzen(self, d):
        def praca():
            return self.cache_prz.get(id_przestrzeni(d["name"])) or Przestrzen(d["name"], d["password"])

        def gotowe(prz):
            self.cache_prz[prz.id] = prz
            self.prz = prz
            self.idz("przestrzen")
        toast("Otwieram...")
        w_tle(praca, gotowe)


if __name__ == "__main__":
    GhostNotes().run()
