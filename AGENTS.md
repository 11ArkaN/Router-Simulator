# Zasady pracy w repozytorium

## Priorytety

Decyzje implementacyjne podejmuj w tej kolejności:

1. zgodność ze źródłami i poprawność zachowania,
2. bezpieczeństwo danych i stabilność runtime,
3. modularność i jednoznaczna własność stanu,
4. wydajność potwierdzona pomiarem,
5. minimalna liczba wykonywalnych linii kodu.

## Architektura

- Każdy moduł ma mieć mały, jawny kontrakt i jednego właściciela modyfikowalnego stanu.
- Zależności między modułami prowadź przez wersjonowane typy, komunikaty lub wąskie interfejsy.
- Nowa funkcja nie może wymagać modyfikowania niepowiązanych modułów.
- Nie twórz globalnego zegara symulacji, kolejki przyszłych zdarzeń ani funkcji Run, Pause, Step, przewijania lub mnożnika czasu.
- Informacja sieciowa między urządzeniami zawsze przechodzi jako zakodowana ramka lub pakiet przez port, kolejkę i łącze.
- Rdzeń nie może zależeć od Reacta, DOM, IndexedDB, OPFS, xterm.js ani hostingu.
- MD-CLI i classic CLI są dwoma silnikami terminala tego samego routera i tej samej sesji. Nie przedstawiaj ich jako dwóch globalnych trybów aplikacji.

## Wielowątkowość

- Pierwszy uruchamialny runtime musi korzystać z WebAssembly threads, pthreads i SharedArrayBuffer.
- Nie dodawaj jednowątkowego trybu awaryjnego. Brak cross-origin isolation ma zakończyć start czytelnym błędem.
- Runtime ma działać poza wątkiem UI i posiadać co najmniej osobny shard control plane oraz shard forwarding/link.
- Preferuj SPSC. MPSC stosuj tylko z udokumentowanym uzasadnieniem. W pierwszym etapie nie używaj MPMC.
- Każdy współdzielony typ musi opisywać właściciela, kierunek przepływu, gwarancję pamięci i zachowanie przy przepełnieniu.

## Wydajność i rozmiar kodu

- Optymalizuj od początku układ danych, liczbę alokacji, kopiowanie pakietów, synchronizację i częstotliwość aktualizacji UI.
- Nie deklaruj poprawy wydajności bez benchmarku albo profilu. Zachowuj wynik bazowy i próg regresji.
- Minimalizuj wykonywalne linie kodu przez współdzielenie mechanizmów i danych, nie przez code golf, makra ukrywające logikę ani łączenie odpowiedzialności.
- Komentarze, testy, schematy i rekordy źródeł nie podlegają minimalizacji.
- React nie może otrzymywać zdarzenia dla każdego pakietu. UI konsumuje ograniczone częstotliwościowo projekcje stanu.

## Komentarze

- Każdy moduł rozpoczynaj komentarzem nagłówkowym opisującym odpowiedzialność, właściciela stanu i dozwolony kierunek zależności.
- Publiczne API dokumentuj przez preconditions, postconditions, kody błędów, własność pamięci i shard affinity.
- Każda struktura współbieżna musi wskazywać producenta, konsumenta, pojemność, kolejność, politykę przepełnienia i użyte memory ordering.
- Komentuj decyzje, nie oczywistą składnię.
- Opisuj niezmienniki, własność stanu, affinity wątku, memory ordering, zachowanie przy przeciążeniu, źródło zgodności i założenie wydajnościowe.
- Przy nietrywialnym kodzie wyjaśnij, dlaczego wybrany mechanizm jest bezpieczny i co mogłoby go naruszyć.
- Nie zostawiaj komentarzy powtarzających nazwę funkcji lub pojedynczą instrukcję.

## Zgodność

- Nie zgaduj zachowania SR OS, komend, wartości domyślnych ani ograniczeń platformy.
- Funkcja produkcyjna wymaga rekordu w katalogu źródeł, testu oraz wpisu w macierzy możliwości.
- Niezaimplementowana funkcja ma zwrócić jawny błąd. No-op zakończony sukcesem jest zabroniony.
- Profil bazowy to Nokia SR OS 26.7.R1, lecz w interfejsie nie używaj logo Nokia.

## Styl

- W tworzonych artefaktach nie umieszczaj metatekstu.
- Nie używaj długiego myślnika ani jego wariantów.
- Używaj prostego łącznika `-` tylko tam, gdzie jest potrzebny.

## Weryfikacja zmiany

- Zmiana funkcjonalna musi zawierać test na odpowiednim poziomie.
- Przed zakończeniem uruchom formatowanie, analizę statyczną, testy, benchmarki objęte zmianą i build produkcyjny.
- Dla zmian UI sprawdź działanie w prawdziwej przeglądarce przy aktywnym cross-origin isolation.
