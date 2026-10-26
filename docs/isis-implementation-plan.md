# Plan implementacji IS-IS

## 1. Zakres i warunki ukończenia

Profil zgodności: Nokia SR OS 26.7.R1, Base router, istniejące profile 7750 SR-1, SR-7 i SR-12.

IS-IS powstaje w C++20 jako protokół rozproszony działający w czasie rzeczywistym. Każdy router i każda instancja mają własne sąsiedztwa, bazę LSP, timery, flooding i obliczenia SPF. Informacje między urządzeniami przechodzą wyłącznie jako zakodowane ramki przez porty, kolejki, łącza i przełączniki Ethernet.

Uzgodniony zakres zawiera:

- L1, L2 i L1/L2, sieci P2P i LAN, DIS oraz pseudonode.
- Integrated IS-IS dla IPv4 i IPv6, wspólną topologię oraz MT0 i MT2.
- Wiele instancji i udokumentowane sposoby ich rozdzielania na wspólnym medium.
- IPv4 unnumbered z rzeczywistym przekazywaniem pakietów.
- Pełny cykl IIH, LSP, CSNP i PSNP, synchronizację baz i obsługę awarii.
- Samodzielne rozszerzenia Base wymienione w sekcji 4.
- Polityki, leaking L1/L2, redystrybucję, ECMP, ważony ECMP i IP LFA.
- Uwierzytelnianie, keychains i GR helper zgodne z profilem SR OS.
- Pełną wspieraną konfigurację i diagnostykę obu CLI.
- Przenośną konfigurację, checkpoint aktywnego protokołu i trzy dema.

Konfiguracja IS-IS pozostaje funkcją MD-CLI i classic CLI. Oba silniki korzystają z tej samej konfiguracji routera, zachowując własną składnię i semantykę sesji. Topologia, istniejące widoki i przechwyty pokazują rzeczywiste efekty protokołu. Nie powstaje formularz konfiguracji IS-IS.

Współpraca z zewnętrznym FRRouting, SR-SIM lub sprzętem jest opcjonalnym przyszłym etapem. Odbiór wymaga własnego kodu wszystkich warstw IS-IS, poprawnych ramek, testów i laboratoriów wewnątrz aplikacji. Nie wymaga mostu do zewnętrznej sieci.

Etapy wykonania mają własne testy i działające wyniki. Ukończenie całego zakresu wymaga zamknięcia wszystkich pozycji wspieranej macierzy. Żadna z nich nie może pozostać atrapą, udanym no-op ani funkcją częściową.

## 2. Źródła i przypięcie wydania

### 2.1. Modele YANG

Oficjalne repozytorium modeli: [7x50_YangModels](https://github.com/nokia/7x50_YangModels).

Przypięcie modeli:

| Wartość | Identyfikator |
| --- | --- |
| Tag wydania | `sros_26.7.r1` |
| Obiekt tagu | `37b90279a2efcaf8ebbde11bf20367655641e158` |
| Commit modeli | `6656cbb0905c7b952afaa1d7c2b63aa4da6cc5f7` |
| Katalog modeli w tym commicie | `YANG/` |
| Rewizja głównych modeli IS-IS | `2026-07-08` |

Główne źródła:

- [nokia-conf-router-isis.yang](https://github.com/nokia/7x50_YangModels/blob/6656cbb0905c7b952afaa1d7c2b63aa4da6cc5f7/YANG/nokia-submodule/nokia-conf-router-isis.yang).
- [nokia-state-router-isis.yang](https://github.com/nokia/7x50_YangModels/blob/6656cbb0905c7b952afaa1d7c2b63aa4da6cc5f7/YANG/nokia-submodule/nokia-state-router-isis.yang).
- [nokia-conf-router.yang](https://github.com/nokia/7x50_YangModels/blob/6656cbb0905c7b952afaa1d7c2b63aa4da6cc5f7/YANG/nokia-submodule/nokia-conf-router.yang).
- [nokia-sros-yang-extensions.yang](https://github.com/nokia/7x50_YangModels/blob/6656cbb0905c7b952afaa1d7c2b63aa4da6cc5f7/YANG/nokia-sros-yang-extensions.yang).
- Wszystkie importowane typy, podmoduły, modele polityk, keychains i operacji potrzebne do wspieranego drzewa.

Lokalny katalog `.tmp-yang-audit/7x50_YangModels/latest_sros_26.7/` zawiera późniejszą rewizję modelu IS-IS `2026-09-02`. Nie jest podstawą zgodności R1. Indeksy z tego katalogu wymagają ponownego wygenerowania z przypiętego commitu.

Pobieranie źródeł podczas developmentu zapisuje pochodzenie i SHA-256 każdego użytego modelu oraz jego zależności. Repozytorium przechowuje własne dane zgodności, powiązania i odnośniki. Modele producenta pozostają w lokalnym cache zgodnie z polityką publicznej dystrybucji. Produkcja nie pobiera YANG ani dokumentacji.

YANG wyznacza wspólne drzewo konfiguracji i stanu, nazwy, klucze, typy, zakresy, jednostki, wartości domyślne, referencje i ograniczenia. Generator uwzględnia rozszerzenia restartu i niezmienności oraz ograniczenia wynikające z zależności modelu.

Publiczne modele nie zawierają pełnego odwzorowania classic CLI. MD-CLI korzysta z nazw i drzewa YANG oraz udokumentowanych reguł tego silnika. Classic CLI otrzymuje jawne powiązanie z tym samym drzewem, potwierdzone w referencji classic. Przykładowo YANG `area-address` i classic `area-id` nie mogą zostać uznane za ten sam token wejściowy.

Operatory usuwania, shutdown, kolejność zależności, dynamiczne wartości domyślne, raporty i błędy wymagają źródeł zachowania właściwych dla danego CLI. Nierozstrzygnięta rozbieżność blokuje udostępnienie danej komendy.

### 2.2. Dokumentacja produktu

- [SR OS 26.7, IS-IS](https://documentation.nokia.com/sr/26-7/7x50-shared/unicast-routing-protocols/is-is.html).
- [MD-CLI Command Reference 26.7](https://documentation.nokia.com/sr/26-7/7750-sr/titles/md-cli-command-reference.html).
- [MD-CLI, router](https://documentation.nokia.com/sr/26-7/7750-sr/books/md-cli-command-reference/router-router_0.html).
- [Classic CLI, helper-disable](https://documentation.nokia.com/sr/26-7/7750-sr/cli-books/classic-cli-command-reference/classic-h-commands.html).
- [Classic CLI, standard-multi-instance](https://documentation.nokia.com/sr/26-7/7750-sr/cli-books/classic-cli-command-reference/classic-s-commands-src--4.html).
- [Classic CLI, link-group](https://documentation.nokia.com/sr/26-7/7750-sr/cli-books/classic-cli-command-reference/classic-l-commands-lfa--2.html).

Każda komenda otrzymuje dokładny odnośnik do swojej sekcji referencji. Ogólny adres książki nie wystarcza jako jedyne potwierdzenie konkretnego błędu, wartości domyślnej lub operatora usuwania.

### 2.3. Normy protokołu

Przed implementacją bazowych FSM, floodingu i starzenia trzeba pozyskać oraz sprawdzić pełny tekst [ISO/IEC 10589:2002](https://www.iso.org/standard/30932.html), właściwe poprawki i normatywne zależności Ethernet/LLC. Podczas planowania potwierdzono oficjalną publikację, ale nie pozyskano pełnego tekstu. RFC 1195 uzupełnia ISO 10589 i nie zastępuje całej normy bazowej.

Początkowy katalog norm:

| Źródło | Zachowanie do powiązania z implementacją |
| --- | --- |
| [RFC 1195](https://www.rfc-editor.org/rfc/rfc1195.html) | Integrated IS-IS dla IPv4 |
| [RFC 5303](https://www.rfc-editor.org/rfc/rfc5303.html) | Three-way handshake P2P |
| [RFC 5309](https://www.rfc-editor.org/rfc/rfc5309.html) | P2P po LAN, adresowanie i next-hop |
| [RFC 5305](https://www.rfc-editor.org/rfc/rfc5305.html) | Rozszerzona osiągalność i metryki |
| [RFC 5308](https://www.rfc-editor.org/rfc/rfc5308.html) | IPv6 |
| [RFC 5120](https://www.rfc-editor.org/rfc/rfc5120.html) | Multi-topology |
| [RFC 5302](https://www.rfc-editor.org/rfc/rfc5302.html) | Informacje o prefiksach i przejścia między poziomami |
| [RFC 5301](https://www.rfc-editor.org/rfc/rfc5301.html) | Dynamic hostname |
| [RFC 5304](https://www.rfc-editor.org/rfc/rfc5304.html) | Uwierzytelnianie kryptograficzne |
| [RFC 5310](https://www.rfc-editor.org/rfc/rfc5310.html) | Uwierzytelnianie ogólne |
| [RFC 6232](https://www.rfc-editor.org/rfc/rfc6232.html) | Purge Originator Identification |
| [RFC 6233](https://www.rfc-editor.org/rfc/rfc6233.html) | Purge i uwierzytelnianie |
| [RFC 5306](https://www.rfc-editor.org/rfc/rfc5306.html) | Sygnalizacja restartu |
| [RFC 5286](https://www.rfc-editor.org/rfc/rfc5286.html) | IP LFA |
| [RFC 8202](https://www.rfc-editor.org/rfc/rfc8202.html) | Wiele instancji |
| [RFC 5311](https://www.rfc-editor.org/rfc/rfc5311.html) | Rozszerzona przestrzeń LSP |
| [RFC 7981](https://www.rfc-editor.org/rfc/rfc7981.html) | Router capability |
| [RFC 7794](https://www.rfc-editor.org/rfc/rfc7794.html) | Atrybuty prefiksów |
| [RFC 9885](https://www.rfc-editor.org/rfc/rfc9885.html) | Wieloczęściowe TLV |

Przed zamknięciem macierzy sprawdzić erraty, dokumenty aktualizujące i zgodność wybranego kodowania z wydaniem R1. Domyślne wartości i ograniczenia SR OS pochodzą ze źródeł produktu. Wartości służące ograniczeniu zasobów emulatora mają osobne pochodzenie projektowe.

## 3. Zamknięta macierz zgodności

Inwentaryzacja przechodzi przez całe użyte drzewo YANG, łącznie z konfiguracją, stanem, operacjami i zależnościami. Nie może ograniczać się do wybranych przykładów poleceń.

Planowane dane audytu:

- `sources/yang/26.7.R1.lock.yaml` przechowuje pochodzenie i hashe źródeł.
- `schemas/cli/isis-26.7.R1-coverage.yaml` przypisuje węzły i komendy do zachowań, testów oraz wyłączeń.
- `schemas/cli/26.7.R1.yaml` pozostaje właścicielem produkcyjnej gramatyki obu silników.
- `schemas/cli/info-renderers.yaml` rejestruje właścicieli renderowania konfiguracji.
- `sources/catalog.yaml` i `sources/capabilities.yaml` zachowują swoje obecne role źródeł i statusu możliwości.

Każda pozycja macierzy zawiera co najmniej:

```text
feature_id
yang_revision_and_path
device_profile_and_routing_context
md_cli_path_and_variants
classic_cli_path_and_variants
parameter_types_keys_ranges_units_defaults
presence_choice_leafref_and_cardinality_constraints
configuration_context_and_workflow
runtime_owner_and_shard_affinity
packet_effects_and_state_effects
operational_fields_counters_and_filters
delete_no_shutdown_reset_and_dependency_semantics
restart_annotations_and_identity_effects
source_ids_and_exact_sections
implementation_paths_and_test_ids
capability_status_and_exclusion_dependency
```

Generator i walidator odrzucają:

- Węzeł nieuwzględniony w inwentaryzacji oraz zgubiony podczas rozwijania grupowań lub zależności.
- Komendę bez potwierdzonego powiązania z modelem lub źródłem jej odrębnej składni.
- Wspieraną pozycję bez implementacji, testu i wpisu możliwości.
- Udokumentowaną formę usunięcia bez jej semantyki i testów.
- Operator edycji oznaczony jako kontekst albo składnik promptu.
- Brak renderera `info` dla wspieranej rodziny w którymkolwiek silniku.
- Rozbieżne typy, wartości domyślne lub klucze między CLI, kontraktami i modelem.
- Widoczną w pomocy funkcję zależną od niewdrożonego podsystemu.

Każde wyłączenie ma nazwę zależności i test jawnego błędu po ręcznym wpisaniu komendy. Brak źródła jest nierozstrzygniętą pozycją zgodności, którą trzeba wyjaśnić przed końcowym odbiorem.

## 4. Pełny zakres funkcjonalny Base

| Rodzina | Wymagane zachowanie |
| --- | --- |
| Tożsamość | System ID, router ID, adresy obszarów, kolizje, zmiany tożsamości i wymagane restarty |
| Instancje | Cały zakres ID `0..127`, osobne sąsiedztwa i LSDB, standardowe i historyczne rozdzielanie zgodne z R1 |
| Interfejsy | P2P, LAN, passive, system, ustawienia per poziom, rzeczywiste zależności sprzętu i stanu administracyjnego |
| Unnumbered | Wybór adresu pożyczonego, next-hop, ARP, trasy i przesyłanie IPv4 |
| Sąsiedztwa | IIH, three-way, L1/L2, warunki zgodności, timery, padding, MRU/MTU i błędy |
| LAN | Wybór i zmiana DIS, preemption, pseudonode, niezależność poziomów i usuwanie starego pseudonode |
| LSDB | Instalacja, porównanie, aging, refresh, purge, fragmenty, własne LSP, sequence wrap i utrzymanie zero-age |
| Synchronizacja | CSNP/PSNP, podział CSNP, retransmisje, potwierdzenia i odzyskiwanie po utracie ramek |
| Flooding | Pacing, limity pracy, mesh groups i blokowanie zgodne z normą |
| Metryki | Narrow, wide, tryby przejściowe, IPv6 MT, reference-bandwidth i bezpieczne sumowanie |
| Topologie | Wspólna IPv4/IPv6 oraz MT0/MT2, różna dostępność rodzin IP i prawidłowe reguły sąsiedztwa |
| Hierarchia | L1/L2, internal/external, up/down, attached, trasa domyślna i polityki przejścia między poziomami |
| Prefiksy | Agregacja, tagi, import/export, conditional advertisement, passive-only i unreachable prefix advertisement |
| Overload | Ręczny i startowy overload, max-metric, prefix/export limits, błędy FIB oraz wpływ na tranzyt i ogłoszenia |
| Rozszerzenia | Hostname, router capability, atrybuty prefiksów, source router ID i POI |
| Przestrzeń LSP | Additional system ID, Virtual IS, Alias ID i ograniczenia zawartości dodatkowych LSP |
| Wieloczęściowe TLV | Odrębne zasady podziału, łączenia, walidacji i liczników względem fragmentacji LSP |
| Link groups | Członkowie, progi operacyjne, histereza i zmiany metryk per poziom i rodzina, bez zależności od LAG |
| Polityki i trasy | Współistnienie z connected, static, OSPFv2, OSPFv3 i innymi instancjami IS-IS |
| Ścieżki | ECMP, ważony ECMP, polityki next-hop i rzeczywiste IP LFA |
| Uwierzytelnianie | Metody i kodowania R1, dziedziczenie, osobne klasy PDU, keychain i zmiana kluczy |
| Restart | GR helper, jego wejście, wyjście, timeout, anulowanie i diagnostyka |
| Zarządzanie | Oba CLI, konfiguracja i operacje, pomoc, completion, renderowanie, usuwanie i błędy |

Zakres identyfikatorów instancji w YANG nie jest dowodem obsługi 128 jednoczesnych procesów na urządzeniu. Liczba aktywnych procesów emulatora otrzymuje jawny limit ustalony pomiarem.

## 5. Wyłączenia i granice zależności

| Gałąź | Granica tego etapu |
| --- | --- |
| `apply-groups` i wyłączenia grup | Osobna przyszła funkcja wspólnego systemu konfiguracji |
| BFD | Brak rzeczywistego podsystemu BFD |
| VPRN | Brak wymaganej instancji usługowej i jej płaszczyzny przekazywania |
| LDP, synchronizacja LDP, over-RSVP | Brak wymaganych protokołów i tuneli |
| MPLS TE, shortcuts i forwarding adjacencies | Brak pełnej sygnalizacji i przekazywania przez tunele |
| SR-MPLS, SRv6, SID i mapping server | Brak odpowiedniej płaszczyzny przekazywania |
| Remote LFA i TI-LFA | Brak wymaganej infrastruktury tuneli naprawczych |
| BIER, BGP-LS i konsumenci BGP | Brak odpowiednich protokołów i konsumentów informacji |
| Multicast MT3/MT4 | Poza uzgodnionym zakresem unicast MT0/MT2 |
| CLNS jako ruch użytkowy | Zakres przekazywania zawiera IPv4 i IPv6. Wymagane kodowania identyfikacji IS-IS pozostają częścią protokołu |
| Restarting-router GR | Profil SR OS potwierdza rolę helper |
| FRR i most do sieci zewnętrznej | Opcjonalny przyszły etap interoperacyjności |

Przed generowaniem produkcyjnej powierzchni zamknąć osobno klasyfikację TE, SRLG, flex-algo, delay i SD/SF. Rozdzielić kodowanie informacji, pochodzenie rzeczywistych atrybutów oraz funkcję ich konsumenta. Ogłoszenie TLV nie potwierdza działania TE, wyznaczania tuneli ani pomiaru BER.

Samodzielne kodowanie i utrzymywanie informacji IS-IS może być wspierane tylko z kompletnym źródłem, rzeczywistym właścicielem danych, efektem pakietowym i testem. Gałęzie wymagające brakujących pomiarów, osobnych topologii forwarding lub tuneli otrzymują jawne wyłączenie. Nie powstają fikcyjne wartości sensorów ani wyniki obliczeń.

Nie odrzucać całego UPA ze względu na brak BGP. Samodzielne ogłaszanie, utrzymywanie i leaking unreachable prefixes należą do zakresu IS-IS. Zależni konsumenci pozostają wyłączeni.

Nieznane i niewspierane TLV przy odbiorze podlegają regułom normy dotyczącym walidacji, przechowywania i floodingu. Brak własnej konfiguracji rozszerzenia nie uprawnia do niszczenia prawidłowej zawartości LSP.

## 6. Moduły i właściciele stanu

### 6.1. Podział odpowiedzialności

| Właściciel | Stan i odpowiedzialność |
| --- | --- |
| Supervisor i sesje CLI | Transakcje konfiguracji, walidacja referencji i zlecenia wersjonowanych zmian |
| Pthread IS-IS | Wszystkie procesy IS-IS laboratorium, FSM, LSDB, flooding, timery, SPF i stan GR helper |
| Właściciel interfejsów | Tożsamość interfejsu, adresy, unnumbered, zależności sprzętu i projekcje operacyjne |
| Forwarding shard | Klasyfikacja ramek, punt IS-IS, wysyłanie przez wskazany interfejs i FIB |
| Link shard | Kolejki, serializacja i dostarczenie ramek przez medium |
| Właściciel RIB | Scalenie kandydatów wszystkich protokołów i wybór tras |
| Właściciel polityk i vault | Niezmienne generacje polityk i chronione referencje do kluczy |
| Koordynator checkpointu | Spójny snapshot wszystkich właścicieli i komunikatów |
| React | Ograniczone częstotliwością projekcje stanu i sterowanie projektem |

Jeden dodatkowy pthread IS-IS obsługuje wiele routerów i instancji. Nie powstaje wątek per router ani per instancja. Pula Emscripten uwzględnia tego właściciela przed startem i nie tworzy go dopiero przy pierwszej komendzie.

Brak cross-origin isolation, SharedArrayBuffer albo startu wymaganego właściciela zatrzymuje uruchomienie z jawnym błędem. Nie powstaje fallback jednowątkowy. Liczba wątków w README, profilu i testach musi wynikać z rzeczywistej polityki startowej, z uwzględnieniem istniejącego wątku OSPF.

Moduły protokołu i testy otrzymują domenę `core/src/isis/` oraz `core/tests/isis/`. Publiczne kontrakty pozostają pod `core/include/router/`. Adapter obu CLI ma własną odpowiedzialność w domenie `cli`. Pure codecs nie zależą od runtime, sesji ani UI.

Małe wspólne kontrakty ramek, tras i polityk mogą zostać wydzielone z obecnych nazw OSPF. IS-IS nie może zależeć od FSM, LSDB ani prywatnych typów OSPF. Współdzielenie nie może łączyć właścicieli stanów obu protokołów.

Każdy moduł zaczyna się komentarzem odpowiedzialności, właściciela i dozwolonego kierunku zależności. API opisuje warunki wejścia, wynik, błędy, pamięć i shard affinity. Zmiany obejmują tylko moduły potrzebne do danego kontraktu i jego integracji.

### 6.2. Komunikacja współbieżna

- Supervisor jest jedynym producentem kolejki poleceń do właściciela IS-IS.
- Każdy forwarding shard ma osobną parę SPSC z właścicielem IS-IS.
- IS-IS przekazuje kompletne generacje kandydatów przez osobny kanał do właściciela RIB.
- Zapytania diagnostyczne zwracają niezmienne snapshoty, bez pożyczania mutowalnych wskaźników.
- Każdy kanał opisuje producenta, konsumenta, pojemność, kolejność, release/acquire, zwrot bufora i reakcję na pełną kolejkę.
- Powiadomienie po publikacji zamyka wyścig między sprawdzeniem kolejki a uśpieniem odbiorcy.
- Stable handles zawierają generację. Opóźniona wiadomość nie może trafić do odtworzonego pod tym samym indeksem obiektu.

Preferowane są uchwyty do niezmiennych buforów. Każde faktyczne kopiowanie bajtów jest jawne i mierzone. Obecny wzorzec kanału OSPF kopiuje użyte bajty do slotu protokołu, więc samo powielenie tego kontraktu nie daje zero-copy.

Przy przepełnieniu ingress stosuje się zdefiniowane odrzucenie i licznik. Egress wymaga jawnego backpressure lub normatywnego odrzucenia z możliwością ponowienia przez właściciela. Konfiguracja i publikacja tras nie mogą zgubić części transakcji ani pozostawić udanego komunikatu bez wykonanego efektu.

### 6.3. Czas i sprawiedliwy przydział pracy

Każdy proces używa hostowego `steady_clock`, lokalnych deadline i generacji anulowania. Praca nad pakietami, timerami, floodingiem i SPF ma ograniczoną porcję, aby jeden router lub instancja nie blokowały pozostałych.

Właściciel zasypia do najbliższego własnego deadline lub powiadomienia. Nie powstaje globalny zegar symulacji, centralna kolejka przyszłych zdarzeń, polling bez oczekiwania, Run, Pause, Step, przewijanie czasu ani mnożnik prędkości.

Wstrzykiwany zegar jest wyłącznie zależnością testów natywnych. Produkcyjny protokół nie otrzymuje sterowania czasem od React.

### 6.4. Punkty integracji

| Obszar | Istniejące moduły i wymagane rozszerzenie |
| --- | --- |
| Ramki | `core/include/router/packet.hpp`, `core/src/forwarding/packet.cpp`: Length/LLC i wspólne kodowanie |
| Demultipleksacja i medium | `router_forwarder.cpp`, `network_plane.cpp`, `multi_device_fabric.hpp`, `ethernet_switch.cpp`: prawidłowy punt, egress i lokalny scope |
| Interfejsy | `runtime_supervisor_interfaces.cpp`, `interface_identity.hpp`, `router_forwarder.hpp`: unnumbered i logiczne next-hop |
| Proces protokołu | Nowe publiczne kontrakty IS-IS i domena `core/src/isis/`, z odrębnymi testami |
| Wątki | `shard_policy.hpp`, startup supervisor, profil i ustawienia puli Emscripten: dodatkowy właściciel i jego cykl życia |
| Trasy | `multi_device_routing.hpp`, `multi_device_routing.cpp`, `route_policy.hpp` i właściciele publikacji: IS-IS, wagi, polityki next-hop i scalenie generacji |
| Konfiguracja i CLI | `device.hpp`, `lab_runtime.cpp`, nowy adapter IS-IS w `cli`, schema i renderery: jedna konfiguracja obu silników |
| Kontrakty przeglądarki | `packages/contracts/src/lab-project-v4.ts` i `apps/web/src/runtime/multi-router-client.ts`: typowana intencja, walidacja i sygnatura autosave |
| Snapshot i zapis | `lab_checkpoint.cpp`, `runtime_supervisor_checkpoint.cpp`, `apps/web/src/persistence.ts`, schematy runtime i checkpoint: wersje, spójny zapis i atomowy import |
| Projekcje i capture | Istniejące kontrakty telemetry oraz pipeline PCAPNG: ograniczone snapshoty i rzeczywiste bajty |
| Dema | `packages/contracts/src/demo-labs-v5.ts`, katalog i uruchamianie dem w `apps/web/src/ui/` |
| Budowanie i weryfikacja | `core/CMakeLists.txt`, native/Wasm runners, generatory profili, `tools/check-dependencies.mjs`, walidatory źródeł i nowe benchmarki |

Przed implementacją potwierdzić te punkty względem bieżącego drzewa i uzupełnić granice zależności dla nowych nagłówków. Nowe kontrakty współbieżne i zmiany decyzji architektonicznych wymagają odpowiedniego ADR. Nie kopiować historycznych numerów ABI ani zestawu wątków z dawnych planów.

## 7. Ethernet, klasyfikacja i interfejsy

### 7.1. Pełna ścieżka ramki

```text
proces IS-IS
  -> koder PDU i ramki 802.3/LLC
  -> SPSC egress
  -> forwarding i wskazany lokalny interfejs
  -> kolejka portu
  -> link i opcjonalny przełącznik
  -> kolejka portu odbiorczego
  -> klasyfikacja Length/Type, LLC i instancji
  -> SPSC ingress
  -> dekoder i proces IS-IS odbiorcy
```

Proces IS-IS koduje pełną ramkę przy użyciu wspólnego kodeka i niezmiennej projekcji lokalnego interfejsu. Odpowiada za nagłówek i padding zgodny z normą. Forwarding sprawdza aktualność interfejsu i przekazuje ramkę do zwykłej kolejki, bez powtórnego kodowania jej nagłówka. Nie powstają równoległe, rozbieżne kodery.

Dekoder rozróżnia Length/Type, kontroluje długości, LLC, identyfikator protokołu, dopełnienie i granice bufora. Zachowuje wymagane reguły tagowania i konwencję capture dotyczącą FCS. Nie interpretuje IS-IS jako IP protocol 89 ani jako transportu UDP/TCP.

Adresy multicast dla P2P, poziomów i wariantów multi-instance pochodzą ze źródeł. Filtr MAC musi dopuścić właściwe ramki IS-IS także bez adresu IP na interfejsie. Przełącznik przenosi je przez zwykłą ścieżkę L2.

Punt otrzymuje router handle, logiczny interface ID, fizyczny port i generację konfiguracji. Klasyfikacja wyłącznie numerem portu nie wystarcza dla logicznych interfejsów. Powiązania Base i istniejących interfejsów usługowych wymagają potwierdzenia w modelu R1 i zgodności obecnego data plane. Nie dodaje się nieudokumentowanej obsługi IES, SAP, VLAN ani LAG przez samo przypisanie flagi na porcie.

Przechwyty link, ingress, egress i CPM obserwują te same rzeczywiste bajty. Proces nie generuje syntetycznych rekordów capture. Informacje o sąsiadach i topologii pochodzą z odebranych PDU i LSDB, bez dostępu do grafu edytora.

### 7.2. IPv4 unnumbered

Wspólna konfiguracja interfejsu rozróżnia adres własny i pożyczony. Wariant źródła z adresu, nazwanego interfejsu lub `system` musi odpowiadać YANG i zasadom produktu.

Implementacja zawiera:

- Walidację referencji, zmian i usunięcia interfejsu będącego źródłem adresu.
- Właściwy wybór adresu źródłowego i aktualizację po zmianie źródła.
- Oddzielenie adresu lokalnego od identyfikacji łącza i osiągalności sąsiada.
- ARP i next-hop zgodne z P2P Ethernet oraz informacją odebraną przez IS-IS.
- Brak fikcyjnej trasy connected dla nieistniejącej podsieci na łączu.
- Właściwy logiczny scope next-hop w IPv4 i IPv6, także przy nakładających się adresach pożyczonych.
- CLI, projekcję do forwarding, przenośny zapis, checkpoint i liczniki błędów.
- Test rzeczywistego ruchu w obie strony przez co najmniej dwa łącza unnumbered.

Sąsiedztwo IS-IS na porcie bez IPv4 i poprawne przekazywanie IPv4 przez unnumbered są osobnymi warunkami odbioru.

## 8. Pakiety i sąsiedztwa

Kodery i dekodery zawierają wszystkie wymagane warianty IIH, LSP, CSNP i PSNP oraz wspierane TLV i sub-TLV. Walidacja wersji, typu PDU, długości, ID length, poziomu, instancji, obszaru, checksum i uwierzytelniania poprzedza zmianę stanu.

FSM interfejsów i sąsiadów mają tabelę wszystkich normatywnych zdarzeń i przejść. Osobne testy sprawdzają:

- P2P three-way, restart sąsiada, asymetrię i jednostronne dostarczanie ramek.
- LAN L1/L2, wybór DIS, preemption, remisy, zmianę priorytetu i utratę DIS.
- Powstanie, zmianę i purge pseudonode.
- Zgodność adresów obszarów, identyfikatorów i obsługiwanych topologii.
- Reguły single topology i MT przy różnej dostępności IPv4/IPv6.
- Hello i holding timers, padding, MRU mismatch oraz strict adjacency checks.
- Passive interfejs i passive per poziom, z właściwym ogłaszaniem adresów.
- Port down, shutdown, wyjęcie karty lub MDA, usunięcie interfejsu i zmianę medium.
- Standardowe i historyczne multi-instance, warianty multicast i niedozwolone kombinacje ustawień.

Zmiana konfiguracji działa zgodnie z adnotacjami modelu: modyfikacja w miejscu, restart automatyczny albo wymagany restart ręczny. Sam test utworzenia obiektu nie potwierdza tej semantyki.

## 9. LSDB, flooding i rozszerzenia

LSDB posiada jawne klucze instancji, poziomu i LSP ID. Właściciel zachowuje oryginalne bajty potrzebne do floodingu i raportów. Dane z dekodera nie mogą wskazywać na zwrócony bufor odbiorczy.

Implementacja zawiera:

- Porównanie wersji LSP, duplikaty, starsze i nowsze ogłoszenia.
- Generowanie i odświeżanie własnych LSP oraz reakcję na ich odbiór z sieci.
- CSNP i PSNP, żądania brakujących informacji, potwierdzenia i retransmisje.
- Zasady LAN i P2P, w tym udokumentowane `csnp-on-p2p`.
- Flooding po właściwych interfejsach, pacing oraz mesh-group i mesh-group blocked.
- Lifetime, minimum remaining lifetime, purge, zero-age retention i usunięcie bazy.
- Checksum errors i zachowanie opcji `ignore-lsp-errors` zgodne ze źródłem.
- Skok numeru sekwencyjnego, wyczerpanie, restart i anulowanie nieaktualnych timerów.
- Fragmentację LSP, zmianę MTU i ponowną generację po zmianie zawartości.
- Additional system ID, Virtual IS, Alias ID i powiązanie rozszerzonych LSP.
- Wieloczęściowe TLV z walidacją kompletności i duplikatów, osobno od fragmentacji LSP.
- Hostname cache, router capability, prefix attributes, source router ID i POI.
- Link groups, ich progi, histerezę i wpływ na metryki przy zmianie liczby aktywnych członków.

Limity LSDB, fragmentów, rozmiaru PDU, kolejek retransmisji i rozszerzeń pochodzą z profilu i źródeł. Przekroczenie nie może nadpisać żywego LSP ani opublikować niepełnego wyniku jako kompletnego.

## 10. SPF, polityki, RIB i FIB

### 10.1. Obliczenia IS-IS

SPF korzysta wyłącznie z własnej bazy. Obliczenia rozróżniają poziom, topologię i rodzinę adresów. Obejmują narrow/wide i tryby przejściowe, internal/external, up/down, attached i overload.

Wymagane są agregacja IPv4/IPv6, leaking, domyślna trasa L1, ignorowanie lub tłumienie attached, reference-bandwidth, tagi, conditional advertisement i passive-only według odpowiednich źródeł.

Pełny lub częściowy SPF ma prawdziwą przyczynę i licznik. Nie raportować wykonania częściowego algorytmu, jeśli cały graf został policzony ponownie. Optymalizacja wymaga porównania wyniku z pełnym SPF i pomiaru kosztu.

### 10.2. Wspólny wybór tras

Obecny `RouteSource` i walidatory przyjmują connected, static, OSPF i OSPF3. IS-IS otrzymuje własną tożsamość i atrybuty ścieżki. Klasyfikacja L1/L2 i internal/external nie jest kodowana przez `OspfPathType`.

Kandydat trasy zachowuje rodzinę, prefiks, źródło, instancję, poziom, topologię, typ, preference, metryki, tagi, next-hop z logicznym scope i wymagane wagi. Właściwe reguły wyboru pochodzą ze źródeł SR OS. Kolejność wstawiania nie może zastępować tie-break.

Właściciel RIB scala najnowsze kompletne generacje wszystkich protokołów. Pusta generacja IS-IS wycofuje tylko jego trasy. Starsza generacja ani odbudowa connected/static nie mogą odtworzyć wycofanego kandydata lub zgubić tras OSPF. FIB pozostaje własnością forwarding.

Polityki rozpoznają IS-IS i jego instancje oraz wymagane atrybuty poziomu i ścieżki. Import do lokalnego RIB, export do LSP i leaking są osobnymi operacjami. Domyślne decyzje i dozwolone mutacje wynikają ze źródeł właściwych dla danego punktu zastosowania. Nie kopiować automatycznie zachowania polityk OSPF.

Redystrybucja connected, static, OSPFv2, OSPFv3 i innych instancji wymaga rzeczywistej polityki i właściwej informacji o pochodzeniu. Testy dwukierunkowej redystrybucji oraz leaking sprawdzają up/down, tagi, wycofanie tras i zapobieganie ponownemu wprowadzeniu tej samej informacji.

### 10.3. ECMP, wagi i LFA

Zwykły i ważony ECMP mają produkcyjny wybór next-hop w forwarding. Testy mierzą rozkład wielu przepływów zgodnie z udokumentowaną metodą, zachowanie jednego przepływu, usunięcie ścieżki i zmianę wag. Wyświetlenie liczby w konfiguracji nie jest dowodem działania wagi.

Szablony next-hop i ich referencje są częścią wspólnego systemu polityk. Walidacja, zmiana, shutdown i usuwanie referencji nie mogą pozostawiać nieaktualnych wag ani alternatyw w FIB.

IP LFA zawiera normatywny wybór alternatyw, wykluczenia per poziom, interfejs i politykę, dostępne tryby ochrony oraz preferencje wymagane w R1. Backup pozostaje odrębny od zwykłego ECMP. Forwarding używa go po rzeczywistym wykryciu niedostępności ścieżki podstawowej, przed zakończeniem ponownego SPF. Odbiór potwierdza to ruchem i generacjami FIB.

Overload, prefix-limit, export-limit i błędy instalacji FIB mają testy granic, wycofania, ponawiania i odzyskania. Częściowa publikacja nie może ukryć błędu zasobów.

## 11. Uwierzytelnianie i GR helper

Metody, kodowania i zakresy kluczy są ograniczone do potwierdzonego R1: hasło oraz odpowiednie warianty HMAC-MD5, HMAC-SHA-1 i HMAC-SHA-256. Każdy wariant otrzymuje własne źródło, fixture i test błędnego klucza.

Implementacja zachowuje dziedziczenie global, level, interface i interface-level oraz osobne reguły Hello, CSNP i PSNP. Opcje sprawdzania i wyłączenia sprawdzania mają dokładną semantykę produktu.

Keychain obsługuje wybór aktywnego klucza, okresy akceptacji, zmianę kluczy i brak poprawnego aktywnego klucza. Nie przechodzi samoczynnie na komunikację nieuwierzytelnioną. Kolejność padding, checksum i wyliczenia uwierzytelnienia jest sprawdzana dla każdego kodera, w tym purge.

Materiał kluczy przechowuje istniejący vault przez chronione referencje. Nowe logi, snapshoty, raporty CLI i zwykły zapis intencji nie ujawniają sekretów. Eksport korzysta z istniejącej ochrony sekretów, a bufor tymczasowy ma jawny czas życia.

GR helper odbiera i wysyła wymagane informacje restartu, utrzymuje odpowiedni stan pomocnika, kończy pomoc po timeout i anuluje ją przy zdarzeniach wymaganych przez źródła. Konfiguracja, liczniki i raporty są zgodne z rolą helper. Przywrócenie checkpointu nie jest deklarowane jako restarting-router GR.

## 12. MD-CLI i classic CLI

Każda wspierana rodzina otrzymuje:

- Konfigurację z root oraz z każdego udokumentowanego kontekstu.
- Pomoc i Tab/Space completion z właściwymi typami, kluczami i separatorami.
- Własne renderowanie `info` i `info detail`, z właściwymi wartościami domyślnymi i kontekstem.
- Odpowiednie polecenia `show`, `clear`, `monitor` i `debug`, gdy istnieją w źródłach R1.
- Właściwe filtry, detail, duże i puste tabele, pager oraz kończenie monitorowania.
- Czytelny błąd nieprawidłowych parametrów, zależności lub niewspieranej funkcji.
- Pełny cykl utworzenia, zmiany, shutdown, wznowienia, resetu i usunięcia.

MD-CLI zachowuje implicit Base, oba workflow konfiguracji, candidate, validate, commit i discard. Raport konfiguracji korzysta z właściwego datastore. Classic CLI wykonuje poprawne zmiany natychmiast. Przełączenie silnika i komenda inline odnoszą się do tej samej sesji i routera.

Usuwanie jest sprawdzane dla całej wygenerowanej powierzchni. Testy zawierają względne, absolutne i środkowe położenie operatora, zakaz wejścia do kontekstu operatora, warunki shutdown, referencje, cascade i przywrócenie wartości domyślnych. Konkretna semantyka pochodzi z danego węzła, a nie z globalnego przepisywania `delete` na `no`.

Diagnostyka pokazuje rzeczywiste stany i przyczyny: PDU, odrzucenia, authentication errors, adjacency changes, DIS, retransmisje, purge, sequence errors, kolejki, SPF log, hostname, raw LSDB, topology, received area addresses, LFA coverage i link-group status. Każdy parametr ma właściciela, źródło i test. Stan niedostępny nie jest zastępowany wymyśloną wartością.

Debug działa na ograniczonych buforach z filtrem i jawnym licznikiem utraconych zdarzeń. Włączenie debug lub monitor nie może generować zdarzenia React dla każdego pakietu ani zablokować protokołu.

## 13. Projekty i checkpointy

### 13.1. Konfiguracja przenośna

Intencja zapisuje instancje, interfejsy, unnumbered, poziomy, topologie, polityki, wagi, link groups, ustawienia uwierzytelniania przez referencje i wszystkie pozostałe wspierane ustawienia.

Import samej konfiguracji uruchamia nowy proces, który buduje sąsiedztwa i trasy przez rzeczywiste ramki. Nie tworzy sztucznej LSDB z grafu zapisanej topologii.

Przed zmianą wersji przeprowadzić audyt rzeczywistych kontraktów i wygenerowanych stałych. Podstawą rozpoznania wersji nie może być nazwa pliku. Obecny kod deklaruje project 5 i checkpoint ABI 8, a część nazw plików zachowuje starsze numery.

Uzgodniona polityka odrzuca nieobsługiwane starsze wersje. Ten etap nie dodaje migratora projektu ani żywego checkpointu. Zachować istniejącą, jawną ścieżkę odzyskania kompatybilnej konfiguracji, jeśli aktualny format pozwala ją bezpiecznie wydzielić. Odrzucony import nie zmienia aktywnego laboratorium.

### 13.2. Ciągłość aktywnego protokołu

Checkpoint zawiera:

- Tożsamości, generacje procesów, interfejsów i sąsiadów.
- FSM, stan DIS i pseudonode oraz GR helper.
- Całą LSDB, oryginalne bajty, fragmenty i rozszerzoną przestrzeń LSP.
- Kolejki floodingu, żądania, potwierdzenia i retransmisje.
- Własne numery sekwencyjne, refresh, aging, purge i pozostałe deadline.
- Spójny stan obliczeń lub jawny punkt ich ponownego rozpoczęcia bez częściowej publikacji.
- Pełne generacje kandydatów, RIB/FIB, backup i wagi.
- Bufory i komunikaty znajdujące się między shardami.
- Liczniki i ustawienia diagnostyki, bez ujawnienia sekretów.

Koordynator obejmuje dodatkowy pthread barierą tego samego snapshot epoch co pozostałych właścicieli. Żadna odebrana lub wysłana ramka nie może zniknąć ani zostać dostarczona podwójnie na skutek niespójnego snapshotu.

Zapisywane są pozostałe czasy i generacje timerów. Czas protokołu jest zamrożony podczas nieobecności runtime. Odtworzenie nie generuje zaległych fikcyjnych ramek za okres zamkniętej aplikacji.

Restore odtwarza high-water marks i właścicieli przed przyjęciem nowych generacji tras. Testy porównują wykonanie ciągłe z odtworzeniem podczas synchronizacji, zmiany DIS, retransmisji, zmiany klucza i awarii.

## 14. Zasoby i pomiary

Pozostają limity laboratorium: 16 routerów, 16 hostów, 64 łącza i cztery sesje terminalowe na router. Obowiązuje istniejący limit pamięci współdzielonej z ADR-0004. Nie wolno zwiększać go ani osłabiać progów w celu ukrycia regresji.

Przed udostępnieniem funkcji trzeba liczbowo ustalić w profilu:

- Maksymalną liczbę aktywnych instancji na router i laboratorium.
- Pojemność LSDB, fragmentów i rozszerzonej przestrzeni LSP.
- Liczbę sąsiadów, interfejsów, węzłów i krawędzi SPF.
- Pojemności kolejek PDU, retransmisji, generacji tras i debug.
- Limit pracy w turze, częstotliwość snapshotów i maksymalny koszt diagnostyki.

Limity emulatora powstają z pomiarów i są jawnie odróżnione od limitów SR OS. Infrastruktura zachowuje cały zakres ID instancji. Nie alokuje z góry maksymalnej LSDB dla każdego niewłączonego identyfikatora i portu.

Nowy benchmark IS-IS zawiera zimny start, ustaloną pracę, masową zmianę LSP, awarię, ponowne dołączenie i checkpoint. Maksymalna zadeklarowana skala jest wykonywana w całości, z wieloma instancjami i równoległym OSPFv2/OSPFv3. Osobny test dotyczy ważonego ECMP i LFA.

Mierzone są:

- Czas osiągnięcia sąsiedztw i zgodności LSDB.
- Konwergencja i rekonwergencja z uwzględnieniem skonfigurowanych timerów.
- Koszt SPF, kodowania, floodingu i obciążenie wątku.
- Pamięć, alokacje, kopie pakietów, zajętość i przepełnienia kolejek.
- Wpływ na forwarding, OSPF, sesje CLI i projekcje UI.
- Rozmiar i czas checkpointu oraz odtworzenia.

Pierwszy pomiar stanowi zachowaną bazę przed optymalizacją. Progi nowych pomiarów zostają ustalone przed końcowym odbiorem, z warunkami środowiska i powtórzeń. Istniejące progi regresji pozostają obowiązujące. Nie wolno deklarować przyspieszenia bez porównania do bazy ani automatycznie przepisywać bazy po niepowodzeniu.

## 15. Dema

| Demo | Topologia i wynik |
| --- | --- |
| P2P dual-stack | Co najmniej trzy routery, IPv4/IPv6, preferowana droga i zapas. Awaria łącza zmienia rzeczywistą ścieżkę ruchu |
| LAN i DIS | Co najmniej trzy routery na istniejącym switchu, wspólny segment, wybór i zmiana DIS oraz pseudonode w LSDB |
| Hierarchia L1/L2 | Co najmniej dwa obszary L1 połączone przez L2, polityka leaking lub agregacji, attached/default i wycofanie po awarii |

Dema korzystają z typowanej intencji i zwykłego uruchamiania projektu. Nie wstrzykują gotowych sąsiadów, baz ani tras. Zachowują potwierdzenie zastąpienia laboratorium użytkownika, świeże identyfikatory i istniejące zasady zapisu.

## 16. Testy

### 16.1. Kodeki i FSM

- Bajtowe fixtures wszystkich PDU, formatów osiągalności, checksum, uwierzytelniania i multicast.
- Uszkodzone długości, TLV, fragmenty, duplikaty, nieznane rozszerzenia i niepoprawne kombinacje.
- Każde przejście FSM, restart, asymetria, holding time, poziomy i instancje.
- DIS, preemption, pseudonode i zmiany składu LAN.
- Native injected clocks: expiry, anulowanie, stale generation i równoczesne deadline.
- LSDB: starszy/nowszy LSP, własny LSP, purge, refresh, sequence exhaustion i zmiana MTU.
- Rozszerzona przestrzeń LSP, wieloczęściowe TLV, mesh groups i link groups.
- Wszystkie metody uwierzytelniania, zmiana klucza i purge.
- GR helper, timeout i wymagane anulowanie.

### 16.2. Routing i współbieżność

- Osobne oczekiwane grafy L1/L2 i MT0/MT2, rozłączenie rodziny IP i nieosiągalne cele.
- Narrow/wide, overflow metryk, attached/default, overload, agregacja i leaking.
- Polityki, tagi, unreachable prefixes i wzajemna redystrybucja z OSPF.
- ECMP, rozkład ważony, polityki next-hop, awaria podstawy i użycie LFA.
- Wielu producentów reprezentowanych przez osobne SPSC, brak wyścigu publikacji i powiadomienia.
- Pełna kolejka, wyczerpanie buforów, zamykanie procesu, usuwanie urządzenia i odrzucenie starego handle.
- Zmieszane generacje protokołów, puste wycofanie i brak częściowego FIB.
- Brak głodzenia innych instancji, OSPF i ruchu użytkowego przy floodingu.

### 16.3. Integracja produkcyjnej ścieżki

Test integracyjny tworzy rzeczywistych właścicieli i przenosi ramki przez fabric. Bezpośrednie połączenie dwóch obiektów FSM nie zastępuje tej warstwy.

- P2P i LAN z sąsiedztwami, zgodnością LSDB i trasami.
- Wiele obszarów, topologii i instancji, także na wspólnym medium.
- Unnumbered, system i passive oraz właściwa granica logicznego interfejsu.
- Ruch IPv4/IPv6 przez nauczone trasy, ECMP, wagi i LFA.
- Awarie link, port, router, switch, karta i MDA oraz ponowne dołączenie.
- Autentyczne IIH/LSP/CSNP/PSNP w PCAPNG, dekodowane przez lokalny TShark.
- Błędne klucze, niezgodności obszarów, MTU, poziomów i trybów instancji.

### 16.4. CLI i trwały zapis

- Test wygenerowanej macierzy dla każdego wspieranego węzła i obu silników.
- Wejście krok po kroku, pełna komenda, ścieżka względna i absolutna oraz przełączenie silnika.
- Oba workflow MD, candidate/running, walidacja, commit/discard i classic immediate apply.
- Rzeczywiste sekwencje klawiszy, help, completion, pager i głębokie `info`.
- Wszystkie formy usuwania, resetu, shutdown i referencji, także błędy bez mutacji.
- Puste i duże raporty, filtry, monitor i debug.
- Portable round-trip i checkpoint podczas aktywnej wymiany.
- Nieobsługiwana wersja, uszkodzenie, błędny sekret i atomowe odrzucenie importu.
- Brak sekretów w zwykłej intencji, raportach i logach.
- Uruchomienie każdego dema i ochrona istniejącego laboratorium.

### 16.5. Ręczny odbiór w przeglądarce

Odbiór używa aktualnego produktu z aktywną cross-origin isolation. Topologia powstaje przez kontrolki aplikacji. Gotowe dema i stare skrypty nie zastępują topologii użytkownika.

1. Zbudować laboratorium z 16 routerami, hostami i co najmniej dwoma switchami, w istniejących limitach.
2. Skonfigurować P2P, LAN, L1/L2, single topology i MT oraz wiele instancji przez oba CLI.
3. Sprawdzić unnumbered, system/passive, zwykły i ważony ECMP, LFA oraz polityki z OSPF.
4. Wykonać dodatnie i ujemne próby konfiguracji, pomocy, completion, `info`, diagnostyki i usuwania.
5. Sprawdzić ping IPv4/IPv6, zmianę DIS, utratę łącza, karty i odbudowę protokołu.
6. Zweryfikować uwierzytelnianie i zmianę kluczy w czasie pracy.
7. Przechwycić ruch i sprawdzić eksport PCAPNG.
8. Sprawdzić autosave, reload, checkpoint, eksport/import oraz odrzucenie niezgodnego pliku.
9. Uruchomić i sprawdzić każde nowe demo.
10. Sprawdzić błędy przeglądarki i runtime, izolację, przewijanie terminala oraz responsywność przy maksymalnej zadeklarowanej skali.

## 17. Kolejność wykonania

| Etap | Zakres prac | Bramka odbioru |
| --- | --- | --- |
| 1 | Pełny ISO 10589, przypięte YANG, źródła CLI i inwentaryzacja | Każdy węzeł sklasyfikowany, brak zgadywanych defaultów i składni |
| 2 | Macierz zgodności, typowana konfiguracja i kontrakty ramek/tras | Testy walidacji, obu adapterów CLI i wersjonowania |
| 3 | Length/LLC, multicast, punt, dedykowany worker i SPSC | Bajtowe testy oraz rzeczywista wymiana PDU przez link |
| 4 | FSM P2P/LAN, poziomy, DIS i instancje | Sąsiedztwa tworzone tylko z odebranych ramek i pełne testy przejść |
| 5 | LSDB, CSNP/PSNP, flooding, aging i rozszerzenia LSP | Zgodne bazy po utracie ramek, restarcie i zmianie DIS |
| 6 | SPF IPv4/IPv6, MT, hierarchia, metryki i polityki | Oczekiwane trasy obliczone z własnej bazy |
| 7 | Unnumbered, RIB/FIB, OSPF, wagi i LFA | Rzeczywisty ruch, backup i brak regresji innych protokołów |
| 8 | Pozostałe samodzielne rozszerzenia, auth i GR helper | Pełne testy źródłowych zachowań i błędów |
| 9 | Cała diagnostyka i lifecycle obu CLI | Zamknięte wszystkie wspierane pozycje macierzy |
| 10 | Intencja, checkpoint i trzy dema | Round-trip, ciągłość i rzeczywiste działanie dem |
| 11 | Pomiary, maksimum zasobów i Browser Use | Ustalone liczbowo limity oraz zachowane progi regresji |
| 12 | Audyt źródeł, README i pełna weryfikacja | Wszystkie końcowe kryteria spełnione |

Oba CLI i testy powstają przy pierwszym pionowym przekroju danej funkcji. Etap 9 zamyka kompletność, a nie odkłada całego zarządzania na koniec. Kontenery placeholder nie trafiają do pomocy ani UI.

Unnumbered i rozszerzenia wspólnego routingu mają osobne testowane kroki. Zmiany w OSPF obejmują wyłącznie współdzielone kontrakty i zachowanie wymagane do współistnienia protokołów.

## 18. Końcowe kryteria odbioru

- Pełny zakres wspieranej macierzy ma źródła, produkcyjne zachowanie i testy.
- Każdy węzeł użytego drzewa YANG jest rozliczony. Każde wyłączenie ma konkretną zależność.
- Obie gramatyki są powiązane z exact YANG R1 i właściwą referencją CLI.
- Nie ma wspieranych pozycji schema-only, experimental ani partially-implemented.
- Informacje sieciowe przechodzą wyłącznie przez prawdziwe ramki, porty, kolejki i łącza.
- Działa osobny właściciel IS-IS, stała pula pthread i wymagane SharedArrayBuffer.
- RIB/FIB zachowuje pełne generacje wszystkich protokołów, logiczny scope, wagi i backup.
- Działają dual-stack, L1/L2, LAN, unnumbered, wiele instancji i wymagane rozszerzenia.
- Każda wspierana komenda obu CLI ma prawdziwy efekt albo rzeczywisty raport.
- Pełny lifecycle usuwania i resetu jest sprawdzany dla wygenerowanej powierzchni.
- Checkpoint zachowuje aktywny protokół, a błędny import nie zmienia laboratorium.
- Trzy dema działają przez normalny runtime.
- Maksymalna zadeklarowana skala przechodzi pomiary bez ukrytej utraty komunikatów i regresji istniejących progów.
- Browser Use potwierdza bieżący produkt, oba CLI, awarie, capture i zapis.
- README opisuje wynikowy, rzeczywisty zakres i ograniczenia.
- Katalog źródeł, macierz możliwości, generated drift i granice zależności przechodzą wymagane sprawdzenia.

Przed każdym przyszłym commitem implementacji obowiązuje weryfikacja dokładnego staged tree zgodna z AGENTS.md. Po zmianie lock inputs lub instalacji trzeba wykonać wymagane `pnpm toolchain:bootstrap` i `pnpm dependencies:bootstrap`. Następnie obowiązują pełne `pnpm verify`, `git diff --check` i przegląd `git status --short`. Niepowodzenie blokuje commit, bez osłabiania testów, warningów, sanitizerów i progów.
