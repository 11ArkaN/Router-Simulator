# Granice projektu, checkpointu i terminala

## Decyzja

Przenośny `ProjectManifestV1` jest publicznym kontraktem warstwy aplikacyjnej. React nie jest właścicielem jego danych, ale aplikacja przeglądarkowa jest jedyną warstwą, która zna jednocześnie konfigurację rdzenia, topologię, notatki, układ paneli, pliki capture i mechanizm pobierania pliku. Funkcje `project_export` i `project_import` pozostają z tego powodu w module persistence.

Rdzeń C++ udostępnia wąskie operacje konfiguracji, capture i checkpointu. Nie udostępnia funkcji C, która nazywa snapshot operacyjny projektem. Taki wynik pomijałby część manifestu i łamałby kontrakt importu.

Stan CLI ma dwóch właścicieli:

- C++ posiada silnik, workflow, candidate, running, prompt, kontekst i znaczenie komend.
- Adapter terminala posiada niewysłany tekst, pozycję kursora, trzy historie, pager i oczekujące bajty wejścia.

Checkpoint C++ zapisuje pierwszą grupę. Wersjonowany wrapper `.netsim` zapisuje drugą jako `CliPresentationStateV1`. Import waliduje obie części przed zmianą aktywnego runtime.

## Niezmienniki

- Stan prezentacji nie może zmienić konfiguracji, RIB, FIB, ARP ani sprzętu.
- Projekt bez checkpointu nie może zawierać stanu prezentacji terminala.
- Niekompatybilny checkpoint może zostać pominięty wyłącznie po jawnej zgodzie użytkownika.
- Każdy tekst przywracany do terminala podlega limitom wygenerowanego profilu.
- UI nie przesyła każdego znaku przez asynchroniczny `postMessage`.
- Publiczny C ABI `cli_push_input` przyjmuje fragmenty bajtów, zachowuje niepełną linię i przesyła do runtime wyłącznie zakończone komendy.

## Skutki

Format projektu pozostaje kompletny bez zależności C++ od DOM i storage. Edycja znaku nie płaci kosztu dwóch kolejek Worker, a przenośny checkpoint zachowuje aktywną pracę terminalową. Zmiana formatu prezentacji wymaga nowej wersji i migracji niezależnej od strukturalnego ABI rdzenia.
