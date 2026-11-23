# Ghost Notes

Tajne notatki i czat. Szyfrowanie na telefonie, serwer widzi tylko zaszyfrowane dane.

## Pobieranie
Najnowsze APK: zakładka **Releases** po prawej, plik `GhostNotes.apk`.

## Funkcje
- tajny kod (klawiatura PIN), blokada po 5 złych próbach, auto-blokada
- prywatne notatki zaszyfrowane w lokalnej bazie
- wspólne przestrzenie: wspólne notatki i czat (nazwa + hasło przestrzeni)
- serwer można włączyć na jednym telefonie (Ustawienia, "Serwer na tym telefonie")

## Pliki
- `main.py` - aplikacja (Kivy; działa też w Pydroid 3)
- `serwer.py` - serwer (można też uruchomić osobno: `python serwer.py`)
- `buildozer.spec` - ustawienia APK
- `.github/workflows/apk.yml` - GitHub buduje APK przy każdej zmianie
