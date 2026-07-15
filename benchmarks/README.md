# Benchmarki

Każdy pomiar zapisuje środowisko, liczbę iteracji oraz medianę siedmiu osobnych procesów. Kontrola porównuje względny kształt trzech niezależnych wyników po normalizacji wspólnej zmiany taktowania procesora. Regresja pojedynczej ścieżki przekraczająca 10 procent wymaga uzasadnienia albo poprawy przed scaleniem. Dwukrotne wspólne spowolnienie nadal zatrzymuje test, nawet jeżeli proporcje wyników się nie zmieniły.

Benchmark mierzy osobno kodowanie ARP i ICMP, ścisłą ścieżkę przekazywania IPv4 oraz księgowanie deadline łącza bez oczekiwania. Obejmuje to parsowanie, kontrolę checksum, kopiowanie ramki, zmianę Ethernet, zmniejszenie TTL, ponowne obliczenie checksum, przyjęcie uchwytu do medium i odbiór według jego deadline. Rzeczywiste oczekiwanie na propagację jest weryfikowane testem normatywnym, ponieważ czas ustawiony przez użytkownika nie jest kosztem obliczeniowym kodu.

Baza z 2026-07-15 odpowiada kodekom o zmiennej długości ICMP, obsłudze pól fragmentacji IPv4 oraz lokalnemu stanowi checkpointu łącza. Mediany wynoszą 73,5667 ns dla kodowania, 86,8019 ns dla forwardingu i 4,38456 ns dla księgowania łącza w środowisku zapisanym w pliku bazy.
