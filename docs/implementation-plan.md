# Specyfikacja implementacyjna lokalnego emulatora sieci i Nokia SR OS

**Status:** dokument wykonawczy dla implementacji  
**Bazowe wydanie SR OS:** Nokia SR OS 26.7.R1  
**Data bazowa dokumentu:** 2026-07-14  
**Docelowe środowisko:** przeglądarka, statyczny hosting Vercel, brak klasycznego backendu  
**Rdzeń:** C++20, Emscripten, WebAssembly, pthreads, współdzielona pamięć  
**Frontend:** React, Vite, TanStack Router, React Flow, xterm.js

---

## 0. Kontrakt wykonawczy dla Codex

Ten dokument jest nadrzędną specyfikacją architektoniczną i implementacyjną projektu. Kod ma być rozwijany zgodnie z następującymi zasadami:

1. Nie wolno zgadywać zachowania SR OS, protokołu, formatu pakietu, komendy CLI, wartości domyślnej ani ograniczenia platformowego. Każdy taki element musi mieć źródło w normie, RFC, oficjalnej dokumentacji Nokia, oficjalnym modelu YANG albo zweryfikowanym zachowaniu SR-SIM, vSIM lub fizycznego urządzenia.
2. Każda implementowana komenda, węzeł konfiguracji, stan operacyjny, protokół i funkcja sprzętowa musi mieć wpis w katalogu źródeł projektu.
3. Jeżeli zachowanie nie jest potwierdzone, funkcję należy oznaczyć jako nieobsługiwaną albo eksperymentalną. Nie wolno implementować pozornie działających komend, które kończą się bez realnego wpływu na urządzenie.
4. Zmiana implementująca funkcję musi zawierać jednocześnie testy, źródła, aktualizację macierzy możliwości i dokumentację ograniczeń.
5. Kod rdzenia nie może zależeć od DOM, Reacta, Vercela, IndexedDB ani xterm.js. Ten sam rdzeń musi kompilować się natywnie oraz do WebAssembly.
6. Nie wolno wprowadzić globalnego zegara symulowanego, osi czasu, centralnego schedulera przyszłych zdarzeń, przycisków Run, Pause, Step, mnożnika prędkości, przewijania czasu ani ukrytego odpowiednika tych mechanizmów.
7. Nie wolno wykonywać bezpośrednich wywołań pomiędzy urządzeniami w celu przekazania informacji sieciowej. Każda informacja sieciowa musi przejść przez prawidłowo zakodowaną ramkę lub pakiet, port, kolejki i łącze.
8. Wielowątkowość, współdzielona pamięć i podział na control plane oraz forwarding plane są wymaganiami od pierwszej działającej wersji, a nie późniejszą optymalizacją.
9. MD-CLI i classic CLI są wymagane od pierwszego pionowego przekroju. Oba muszą mieć własną semantykę sesji, parser, prompt, pomoc, uzupełnianie, historię, pager i model stosowania konfiguracji.
10. Dokładność wejścia terminalowego jest częścią zgodności. Testy muszą obejmować sekwencje klawiszy i zmiany ekranu, a nie tylko wynik po przekazaniu pełnego tekstu komendy.
11. Implementacja ma być dzielona na małe, testowalne kroki. Nie należy tworzyć szerokich atrap dla wielu funkcji. Lepszy jest wąski podzbiór działający zgodnie ze źródłami.
12. Narzędzia pomocnicze mogą analizować oficjalną dokumentację podczas developmentu, ale aplikacja produkcyjna nie może zależeć od pobierania lub scrapowania dokumentacji w czasie działania.
13. Nie wolno kopiować dużych fragmentów dokumentacji producenta do repozytorium. W repozytorium mają znajdować się własne schematy, metadane, identyfikatory źródeł, krótkie niezbędne teksty kompatybilności i linki do źródeł.
14. Każda decyzja odbiegająca od tego dokumentu wymaga osobnego ADR z uzasadnieniem, oceną wpływu na zgodność oraz testem migracyjnym.

W tym dokumencie słowa **MUSI**, **NIE WOLNO**, **POWINNO** i **MOŻE** mają znaczenie normatywne.

---

## 1. Cel produktu

Celem jest zbudowanie działającego lokalnie środowiska sieciowego, w którym użytkownik:

- tworzy topologię z urządzeń i fizycznych połączeń,
- dobiera chassis, CPM, karty, moduły i porty,
- konfiguruje urządzenia Nokia SR OS przez MD-CLI i classic CLI,
- obserwuje rzeczywiste stany operacyjne urządzeń,
- uruchamia protokoły, usługi i mechanizmy sieciowe,
- generuje ruch, wykonuje ping i traceroute,
- przechwytuje ruch na żywo i eksportuje PCAPNG,
- wywołuje awarie i zmiany sprzętowe podczas pracy,
- zapisuje laboratorium lokalnie i przenosi je jako plik projektu.

Projekt może być nazywany symulatorem w warstwie produktu, ale technicznie ma zachowywać się jak **wielowątkowy emulator urządzeń sieciowych działający w czasie rzeczywistym**. Nie ma być środowiskiem dydaktycznym z osią czasu ani wizualnym odtwarzaniem pojedynczych zdarzeń.

### 1.1. Główna definicja realizmu

Realizm oznacza zgodność zachowania obserwowalnego przez użytkownika i inne urządzenia:

- prawidłowe bajty ramek i pakietów,
- prawidłowe kolejki, limity, przepustowość i opóźnienia,
- właściwe maszyny stanów i timery protokołów,
- prawidłową separację konfiguracji, control plane i data plane,
- prawidłowe RIB, wybór trasy, FIB i rozwiązywanie next-hop,
- rzeczywiste pakiety protokołów przesyłane przez sieć,
- właściwą kolejność zmian operacyjnych po awarii,
- zgodne zachowanie CLI, promptów, pomocy i błędów,
- zgodne zależności i ograniczenia platformy Nokia,
- możliwie zgodne dane wyświetlane przez polecenia `show`, `info` i odpowiedniki MD-CLI.

Nie należy deklarować zgodności cykl-po-cyklu z konkretnym ASIC, dokładnej wielkości wszystkich buforów ani dokładnych czasów programowania hardware, jeżeli nie istnieją wiarygodne dane pomiarowe. Takie wartości muszą być opisane jako profilowane przybliżenie.

### 1.2. Długoterminowy zakres

Architektura ma umożliwić dodawanie całego ekosystemu funkcji SR OS, między innymi:

- Ethernet, VLAN, QinQ, bridge domains, FDB,
- LAG, LACP, LLDP,
- IPv4, IPv6, ARP, ND, ICMP, UDP, TCP,
- statyczny routing, ECMP, polityki, route leaking,
- BFD, OSPFv2, OSPFv3, IS-IS, BGP,
- MPLS, LDP, RSVP-TE, SR-MPLS, segment routing,
- multicast i PIM,
- SAP, SDP, IES, VPRN, VPLS, Epipe, Ipipe,
- EVPN, VXLAN i usługi operatorskie,
- QoS, ACL, policery, shapers, schedulery, WRED,
- HA, CPM redundancy, NSF, NSR i nonstop forwarding,
- NETCONF, gNMI, YANG oraz telemetrię,
- funkcje BNG, subscriber management, ISA i ESA w dalszych etapach.

Nie oznacza to implementowania wszystkiego w pierwszym wydaniu. Oznacza to, że fundament nie może wymagać przebudowy po dodaniu kolejnych klas funkcji.

---

## 2. Twarde niezmienniki architektury

### 2.1. Brak osi czasu i symulowanego zegara

W produkcyjnym rdzeniu nie mogą istnieć publiczne ani ukryte odpowiedniki:

```text
SimulationClock
VirtualTime
ScheduledEvent
GlobalEventHeap
runUntil
stepEvent
stepDuration
pauseSimulation
speedMultiplier
fastForward
rewind
```

Jedynym zegarem działania jest monotoniczny zegar hosta:

```cpp
using RuntimeClock = std::chrono::steady_clock;
```

Konsekwencje:

- Hello OSPF skonfigurowane na 10 sekund jest wysyłane po rzeczywistym upływie około 10 sekund.
- Timeout BFD jest oceniany względem rzeczywistego zegara monotonicznego.
- Czas inicjalizacji karty jest prawdziwym oczekiwaniem w aktywnym laboratorium.
- Propagation delay 2 ms oznacza, że odbiorca nie otrzyma ramki przed upływem 2 ms czasu rzeczywistego.
- Zamrożenie karty przeglądarki nie jest przeskokiem czasu sieci. Jest utratą ciągłości działania runtime i musi być zgłoszone.

Dopuszczalne są zegary testowe w natywnych testach jednostkowych. Nie mogą być dostępne z interfejsu użytkownika ani używane do produkcyjnego wykonania laboratorium.

### 2.2. Kolejki urządzenia są obowiązkowe

Zakaz globalnej kolejki zdarzeń nie oznacza zakazu kolejek. Rzeczywiste urządzenia posiadają kolejki i bufory, dlatego rdzeń musi modelować:

- RX ring portu,
- ingress queue,
- kolejki fabric,
- egress QoS queues,
- kolejkę nadajnika portu,
- CPM punt queue,
- kolejki IPC procesów,
- bufory TCP i UDP,
- listę ramek aktualnie przesyłanych lub propagujących się na konkretnym kierunku łącza,
- kolejki operacji programowania FIB,
- kolejki żądań resource managera.

Są to stany modelowanego urządzenia i medium, nie narzędzia przewijania czasu.

### 2.3. Brak magicznej komunikacji

Każdy router zna wyłącznie własny stan oraz dane otrzymane przez:

- pakiety,
- lokalne IPC pomiędzy własnymi modułami,
- lokalną konfigurację,
- lokalne sygnały sprzętowe,
- lokalne API operacyjne.

Nie wolno:

- przekazać obiektu `OspfHello` bezpośrednio do procesu OSPF sąsiada,
- przekazać obiektu `BgpUpdate` przez wewnętrzny bus pomiędzy routerami,
- uruchomić algorytmu na globalnym grafie edytora i wpisać trasy do wszystkich urządzeń,
- uzyskać MAC next-hop bez ARP lub ND,
- zmienić FIB bez udziału RIB, wyboru tras i programowania data plane,
- uznać portu za operacyjnie działający wyłącznie dlatego, że jest administracyjnie włączony.

### 2.4. Wielowątkowość od początku

Pierwszy działający build musi używać:

- WebAssembly threads,
- SharedArrayBuffer,
- pthread pool,
- co najmniej dwóch niezależnych domen wykonawczych rdzenia,
- współdzielonych struktur komunikacyjnych bez kopiowania każdego pakietu przez `postMessage`.

Wielowątkowość nie oznacza jednego Workera na router, proces lub port. Runtime ma posiadać stałą pulę fizycznych wątków i dużą liczbę logicznych komponentów przypisanych do shardów.

### 2.5. Jeden właściciel modyfikowalnego stanu

Każdy fragment modyfikowalnego stanu ma dokładnie jednego właściciela. Przykłady:

- proces OSPF jest właścicielem swojej LSDB,
- route manager jest właścicielem wybranego RIB,
- adjacency manager jest właścicielem ARP i ND,
- forwarding complex jest właścicielem lokalnych liczników i lokalnego stanu pipeline,
- scheduler portu jest właścicielem swoich kolejek egress,
- kierunek łącza jest właścicielem transmisji i ramek w locie,
- session manager jest właścicielem stanu danej sesji CLI.

Inny komponent przesyła żądanie do właściciela. Nie otrzymuje mutowalnego wskaźnika do jego struktur.

### 2.6. Oba CLI od pierwszego pionowego przekroju

MD-CLI i classic CLI są odrębnymi interfejsami semantycznymi. Współdzielą kanoniczny model urządzenia, ale nie mogą być jednym parserem z innymi aliasami.

Pierwszy pionowy przekrój nie jest ukończony bez:

- poprawnych promptów obu CLI,
- pomocy kontekstowej,
- uzupełniania,
- historii,
- edycji linii,
- pagera,
- nawigacji po kontekście,
- przełączania silnika,
- minimalnego zestawu komend konfiguracyjnych i operacyjnych,
- zgodnej różnicy pomiędzy transakcyjnym MD-CLI i natychmiastowym classic CLI.

---

## 3. Hierarchia źródeł i polityka zgodności

### 3.1. Kolejność źródeł

Przy implementowaniu zachowania należy stosować następującą kolejność:

1. Normatywna norma IEEE, IETF RFC albo inny oficjalny standard.
2. Oficjalna dokumentacja Nokia dla przypiętego wydania SR OS.
3. Oficjalne modele Nokia YANG oraz oficjalne command reference.
4. Zachowanie SR-SIM, vSIM albo fizycznego urządzenia w kontrolowanym laboratorium.
5. Oficjalne rejestry IANA.
6. Oficjalne dokumentacje implementacyjnych narzędzi, na przykład Emscripten, WHATWG, MDN, Vercel i TanStack.
7. Wireshark, publiczne capture i inne implementacje wyłącznie jako wtórna walidacja.
8. Blogi, fora i materiały społecznościowe nigdy nie są źródłem normatywnym.

Jeżeli RFC i dokumentacja Nokia różnią się w zakresie zachowania platformy, należy:

- zachować zgodność protokołu na przewodzie,
- zastosować udokumentowane zachowanie Nokia w lokalnej polityce, domyślnych wartościach i CLI,
- opisać rozbieżność w katalogu źródeł,
- dodać test zgodności dla obu poziomów.

### 3.2. Przypięcie wydania

Pierwszym profilem wydania jest:

```text
vendor: Nokia
nos: SR OS
release: 26.7.R1
reference-date: 2026-07-09
```

Wszystkie komendy, wartości domyślne i możliwości muszą być wersjonowane. Nie wolno tworzyć jednego bezczasowego profilu `sros`, który miesza zachowania z wielu wydań.

Planowane typy profili:

```text
ReleaseProfile
PlatformProfile
HardwareProfile
FeatureCapabilityProfile
CliCommandProfile
DefaultValueProfile
TimingProfile
ResourceProfile
```

### 3.3. Katalog źródeł

Każda funkcja implementowana w repozytorium musi posiadać rekord, na przykład:

```yaml
id: nokia.sros.26_7.md_cli.command_completion
kind: cli-behavior
release: 26.7.R1
platforms: [all-supported]
source_type: nokia-official-doc
source_url: https://documentation.nokia.com/sr/26-7/7x50-shared/md-cli-user/navigate.html
section: Command completion
last_verified_at: 2026-07-14
implementation:
  - core/management/cli-md/completion.cpp
  - schemas/cli/md/26.7/completion.yaml
tests:
  - tests/cli/md/completion_tab_space_enter.transcript.yaml
status: implemented
notes: Variable parameters are completed only by Tab.
```

Minimalne pola:

```text
id
kind
release
platforms
source_type
source_url
section
rfc_refs
yang_path
last_verified_at
implementation
tests
status
notes
```

CI musi odrzucać zmianę, która dodaje komendę lub feature bez źródła albo źródło bez odpowiadającego testu.

### 3.4. Macierz stanu funkcji

Dozwolone statusy:

```text
planned
researched
schema-only
partially-implemented
implemented
verified-srsim
verified-hardware
unsupported
experimental
```

`schema-only` nie może powodować pojawienia się komendy w produkcyjnym autocompletion, jeżeli wykonanie nie istnieje. Komenda może pojawić się dopiero po spełnieniu minimalnego kontraktu funkcji.

### 3.5. Zakaz no-op compatibility

Komenda nie może zwrócić sukcesu i nic nie zrobić. Dopuszczalne wyniki są następujące:

- wykonano i zmieniono stan zgodnie ze źródłami,
- wykonano operację odczytową,
- odrzucono z właściwym komunikatem,
- jawnie zgłoszono brak obsługi.

Dla funkcji niezaimplementowanej należy użyć kontrolowanego błędu kompatybilności, a nie udawać działanie.

---

## 4. Wybrany stos technologiczny

### 4.1. Frontend

```text
React
TypeScript
Vite
TanStack Router
React Flow
xterm.js
Canvas 2D lub WebGL dla szybkozmiennej telemetrii
useSyncExternalStore dla subskrypcji runtime
```

TanStack Query nie jest częścią ścieżki runtime. Może zostać użyty później do danych chmurowych, galerii projektów lub kont użytkowników.

TanStack Start nie jest wyborem bazowym. Aplikacja jest statycznym SPA i nie wymaga SSR, server actions ani server loaders.

### 4.2. Rdzeń

```text
C++20
CMake
Emscripten
WebAssembly
pthreads
Shared WebAssembly Memory
natywny build testowy dla Linux/macOS/Windows
```

Zalecane flagi Emscripten:

```text
-pthread
-sPTHREAD_POOL_SIZE=<wyrażenie zależne od hardwareConcurrency>
-sPROXY_TO_PTHREAD
-sALLOW_MEMORY_GROWTH=0 dla stabilnego shared-memory ABI w pierwszej wersji
```

Wielkość pamięci powinna być wybrana przy inicjalizacji na podstawie profilu laboratorium. Późniejsze wsparcie bezpiecznego wzrostu pamięci wymaga osobnego ADR.

### 4.3. Dlaczego nie TypeScript w gorącym rdzeniu

TypeScript pozostaje właściwym językiem UI i warstwy aplikacyjnej, ale nie jest wybrany dla packet path, ponieważ projekt wymaga od początku:

- prawdziwych współdzielonych struktur pamięci,
- jawnej kontroli alokacji,
- pthreads,
- stabilnego modelu layoutu danych,
- sanitizerów w buildzie natywnym,
- braku presji GC na ścieżce pakietowej,
- bezblokadowych lub niskoblokadowych ringów,
- tych samych komponentów w przeglądarce i natywnych testach.

### 4.4. Dlaczego C++20 i Emscripten

Emscripten posiada dojrzałe wsparcie pthreads oparte na Web Workers i SharedArrayBuffer. Pozwala utworzyć pulę wątków przy starcie oraz przenieść główny runtime poza wątek UI.

Źródło:

- https://emscripten.org/docs/porting/pthreads.html

Rust pozostaje możliwym wariantem przyszłym, lecz nie jest wyborem bazowym dla pierwszej implementacji współdzielonego, długowiecznego runtime z pthread-style actor shards. Materiały referencyjne:

- https://rustwasm.github.io/docs/wasm-bindgen/
- https://docs.rs/wasm-bindgen-rayon

### 4.5. Hosting i persystencja

```text
Vercel: wyłącznie statyczne pliki
IndexedDB: projekty i metadane
OPFS: snapshoty, duże capture, eksporty i dane binarne
plik .netsim: przenośny format projektu
```

Nie ma funkcji serwerowej utrzymującej aktywny runtime. Obliczenia, pamięć i storage znajdują się na urządzeniu użytkownika.

---

## 5. Architektura wysokiego poziomu

```text
Przeglądarka

+--------------------------------------------------------------+
| Main thread                                                  |
|                                                              |
| React                                                        |
| TanStack Router                                              |
| React Flow                                                   |
| xterm.js                                                     |
| UI state i rendering                                         |
+------------------------------+-------------------------------+
                               |
                               | boot RPC, terminal bytes,
                               | shared-memory offsets,
                               | niskoczęstotliwościowe control
                               v
+--------------------------------------------------------------+
| WebAssembly runtime thread                                   |
|                                                              |
| RuntimeSupervisor                                            |
| Lab lifecycle                                                |
| Device registry                                              |
| CLI session registry                                         |
| Storage bridge                                               |
+------------------------------+-------------------------------+
                               |
                  Shared WebAssembly Memory
                               |
        +----------------------+----------------------+
        |                      |                      |
        v                      v                      v
+---------------+      +---------------+      +---------------+
| Control shard |      | Forwarding    |      | Link/fabric   |
|               |      | shard         |      | shard         |
| CPM           |      | FC pipelines  |      | port TX/RX    |
| protocols     |      | FIB lookup    |      | serialization |
| RIB           |      | adjacency     |      | propagation   |
| CLI/config    |      | ACL/QoS       |      | fabric queues |
+---------------+      +---------------+      +---------------+
        |                      |                      |
        +----------------------+----------------------+
                               |
                         bounded rings
```

W większych laboratoriach istnieje wiele shardów control, forwarding i link. Kategorie nie muszą odpowiadać dokładnie fizycznym wątkom. Każdy shard posiada przypisanie do jednego wątku wykonawczego, a runtime może umieszczać wiele shardów na jednym pthread.

### 5.1. Warstwy systemu

```text
UI
Runtime bridge
Live multithreaded runtime
Device model
Hardware and resource model
Data plane
Network stack and sockets
Routing infrastructure
Protocol daemons
Services
Management and CLI
Persistence and captures
Profiles and capability matrix
```

### 5.2. Granica UI i rdzenia

UI nie jest źródłem prawdy dla:

- stanu interfejsów,
- RIB i FIB,
- sąsiedztw protokołów,
- ARP, ND i FDB,
- kolejek,
- stanów sprzętu,
- sesji CLI,
- konfiguracji candidate i running,
- statystyk data plane.

UI otrzymuje projekcje stanu i wysyła komendy. Rdzeń waliduje każdą operację.

---

## 6. Runtime czasu rzeczywistego

### 6.1. Model działania wątku

Każdy worker wykonuje pracę gotową teraz, a gdy nie ma pracy, zasypia do:

- przyjścia wiadomości do mailboxa,
- przyjścia pakietu do ringa,
- upływu lokalnego deadline procesu,
- sygnału zakończenia,
- zmiany stanu sprzętu.

Schemat:

```cpp
while (!stop_requested()) {
    drain_mailboxes_with_budget();
    run_ready_components_with_budget(RuntimeClock::now());

    auto deadline = next_local_deadline();
    wait_for_signal_or_deadline(deadline);
}
```

Nie istnieje jedna globalna lista wszystkich przyszłych czynności sieci. Każdy długowieczny komponent posiada lokalne timery, podobnie jak proces w systemie operacyjnym.

### 6.2. Deadline timerów

Timer powinien przechowywać:

```cpp
struct Deadline {
    RuntimeClock::time_point due;
    TimerToken token;
    uint64_t generation;
};
```

`generation` zapobiega wykonaniu anulowanego lub zastąpionego timera bez kosztownego usuwania wpisu ze struktury lokalnej.

Dopuszczalne są lokalne struktury timerów procesu lub shardu, na przykład min-heap albo timer wheel. Nie są one globalną osią czasu. Służą wyłącznie do usypiania procesu do jego rzeczywistego deadline.

### 6.3. Budżety pracy

Każdy worker musi posiadać budżet pracy, aby pojedynczy komponent nie zagłodził innych. Budżety dzielą się na:

- budżet runtime hosta, zapewniający responsywność,
- budżet modelowanego urządzenia, reprezentujący limity CPM, FC lub innego zasobu.

Nie wolno mieszać tych dwóch wartości.

Przykład:

```text
Host runtime:
  worker scheduling lag p99: 1.8 ms

Modeled CPM:
  work queue utilization: 72%
  punt drops: 0
```

### 6.4. Runtime lag

Każde wykonanie timera powinno mierzyć:

```text
deadline
actual_start
host_lag = actual_start - deadline
```

Runtime udostępnia:

- p50, p95, p99 i maximum host lag,
- długość przerw wykonania,
- liczbę przekroczonych deadline,
- stan `healthy`, `degraded`, `invalid-continuity`.

Przeciążenie hosta nie może automatycznie generować alarmu CPU na emulowanym routerze. Są to odrębne domeny.

### 6.5. Uśpienie i wybudzanie

Worker powinien używać mechanizmów blokujących zamiast aktywnego polling loop. W Wasm zastosować pthread condition variables, futex albo bezpośrednio mechanizm oparty na `Atomics.wait()` i `Atomics.notify()`.

Źródła:

- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Atomics/wait
- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer

### 6.6. Zamrożenie karty

Przeglądarka może zamrozić lub usunąć kartę z pamięci. W takim przypadku:

1. Aplikacja zapisuje checkpoint na `visibilitychange`, `pagehide` i przed kontrolowanym zatrzymaniem.
2. Po wznowieniu porównuje monotoniczne znaczniki działania i wykrywa nieciągłość.
3. Nie wykonuje skumulowanych timerów tak, jakby sieć działała w tle.
4. Oznacza sesję jako `runtime-continuity-lost`.
5. Odtwarza ostatni spójny checkpoint albo przeprowadza kontrolowany restart urządzeń.
6. Pokazuje użytkownikowi stan operacyjny, nie oś czasu.

Źródło:

- https://developer.chrome.com/docs/web-platform/page-lifecycle-api

### 6.7. Testowy zegar ręczny

Build natywny może posiadać `ManualClock` dla szybkich testów FSM. Obowiązują ograniczenia:

- nie jest kompilowany do produkcyjnego UI,
- nie wpływa na API laboratorium,
- nie jest nazywany trybem symulacji,
- test musi także istnieć w wariancie integracyjnym z `steady_clock` dla krytycznych timerów.

---

## 7. Wielowątkowość i model aktorowy

### 7.1. Logiczny komponent

Podstawową jednostką jest logiczny komponent z własnością stanu:

```cpp
struct ComponentRuntime {
    ComponentId id;
    ShardId owner_shard;
    MailboxId mailbox;
    ComponentKind kind;
    ComponentMetrics metrics;
};
```

Przykładowe komponenty:

```text
ConfigManager
CliSession
HardwareReconciler
InterfaceManager
RouteManager
FibProgrammingAgent
AdjacencyManager
OspfProcess
BgpPeer
BfdSession
ForwardingComplex
PortScheduler
LinkDirection
FabricPlane
CaptureSession
```

Komponent przetwarza wiadomości sekwencyjnie w swoim shardzie. Różne komponenty mogą pracować równolegle.

### 7.2. Stała pula wątków

Liczba pthreadów jest ustalana przy starcie aplikacji na podstawie:

- `navigator.hardwareConcurrency`,
- minimalnego wymogu aplikacji,
- limitu pamięci,
- ustawień profilu wydajnościowego.

Przykładowa polityka początkowa:

```text
available <= 4: 2 runtime threads
available 5-8: 4 runtime threads
available > 8: 6 runtime threads
```

Jeden logiczny router nie otrzymuje automatycznie jednego wątku. Jeden protokół nie otrzymuje własnego Web Workera. Assignment ma być stabilny i obserwowalny.

### 7.3. Affinity

Stateful component jest przypięty do shardu. Migracja shardu pomiędzy pthreadami może zostać dodana później, ale nie może następować w trakcie obsługi wiadomości ani bez bezpiecznego punktu quiescence.

Korzyści:

- zachowana kolejność,
- mniejsza liczba blokad,
- lepsza lokalność cache,
- łatwiejsze testy,
- łatwe przypisanie opóźnień i zasobów do właściwej domeny.

### 7.4. Mailboxy

Mailboxy są ograniczonymi ring bufferami. Każdy typ kolejki musi mieć jawnie zdefiniowane:

- właściciela producenta i konsumenta,
- pojemność,
- jednostkę limitu, liczba elementów lub bajty,
- politykę przepełnienia,
- licznik dropów,
- kolejność pamięci atomowej,
- zachowanie przy shutdown.

Preferencje:

```text
SPSC: tam, gdzie architektura pozwala
MPSC: dla wielu producentów do jednego właściciela
MPMC: tylko po udokumentowanym uzasadnieniu
```

### 7.5. Prace czyste obliczeniowo

SPF, kompilacja polityk, budowa immutable FIB i duża serializacja mogą zostać zlecone compute poolowi:

```text
owning process
  -> submit immutable input + generation
  -> pure compute job
  -> return result
  -> owner verifies generation
  -> owner commits result or discards stale result
```

Worker obliczeniowy nie modyfikuje bezpośrednio LSDB, RIB ani FIB aktywnego urządzenia.

### 7.6. Brak semantyki zależnej od wyścigu hosta

Współdzielona pamięć i atomiki mogą prowadzić do niedeterministycznej kolejności. Semantyka sieci nie może zależeć od przypadkowej kolejności niezabezpieczonych zapisów.

Źródło referencyjne:

- https://webassembly.org/docs/nondeterminism/

Każdy konflikt semantyczny musi zostać rozstrzygnięty przez:

- pojedynczego właściciela,
- numer generacji,
- monotoniczny numer wejścia w obrębie źródła,
- jawne priorytety protokołu,
- kolejność narzuconą przez właściwy FSM.

### 7.7. Shutdown

Zatrzymanie laboratorium powinno być kontrolowane:

```text
stop accepting external commands
quiesce protocol outputs
close sockets
flush or discard queues according to policy
stop captures
persist state
release packet references
join pthreads or park pool
```

Nie wolno pozostawiać descriptorów pakietów, zablokowanych futexów ani dangling pointers.

---

## 8. Współdzielona pamięć

### 8.1. Segmenty pamięci

```text
Runtime control block
Component registry
Packet slab allocator
Packet descriptors
Mailbox rings
FIB immutable arenas
Counter pages
Telemetry pages
CLI input/output rings
Capture rings
String and schema arenas
```

Każdy segment posiada wersję ABI, rozmiar, alignment oraz identyfikator właściciela.

### 8.2. Pakiety

Podstawowa struktura:

```cpp
struct PacketDescriptor {
    uint64_t packet_id;
    uint64_t parent_packet_id;
    uint64_t flow_id;
    uint32_t buffer_offset;
    uint32_t data_offset;
    uint32_t data_length;
    uint32_t wire_length;
    uint32_t metadata_offset;
    std::atomic<uint32_t> ref_count;
    uint32_t flags;
};
```

Pakiet jest rzeczywistym buforem bajtów. Parsed views są nietrwałymi widokami na offsety, a nie rozbudowanym grafem obiektów.

### 8.3. Alokacja

Wymagania:

- rozmiary klas bloków,
- per-thread free lists,
- zwrot bloku do właściciela przez ring,
- brak globalnego mutexa na każdej alokacji,
- liczniki high-watermark,
- kontrolowane zachowanie przy wyczerpaniu,
- sanitizer-friendly wariant natywny.

### 8.4. Replikacja

Broadcast, multicast i flooding powinny korzystać z:

- wspólnego immutable payload,
- osobnego descriptora dla każdej kopii,
- wspólnego `parent_packet_id`,
- copy-on-write dla nagłówków modyfikowanych niezależnie,
- osobnych drop reason dla każdej kopii.

### 8.5. FIB

Aktywny FIB forwarding complex jest immutable:

```cpp
std::atomic<const FibGeneration*> active_fib;
```

Aktualizacja:

1. FIB compiler buduje nową generację poza gorącą ścieżką.
2. Programming agent przesyła operację do określonego FC.
3. FC waliduje zasoby i instaluje generację.
4. Wskaźnik aktywnej generacji zmienia się atomowo.
5. Stara generacja jest zwalniana po zakończeniu wszystkich odczytów, przez epoch reclamation albo RCU-like mechanism.

Lookup pakietu nie bierze globalnego `RwLock`.

### 8.6. ABI UI

UI nie powinien czytać dowolnych struktur C++. Rdzeń publikuje wersjonowane telemetry pages oraz stabilny C ABI:

```text
initialize_runtime
get_runtime_capabilities
open_lab
close_lab
open_cli_session
push_cli_input
read_cli_output
submit_ui_command
get_telemetry_page
request_snapshot
export_capture
```

Offsety, rozmiary i wersje muszą być walidowane po obu stronach.

---

## 9. Model pakietów i kodeki

### 9.1. Wymagania

Pakiet nie może być tylko obiektem logicznym typu:

```text
srcIp, dstIp, protocol
```

Rdzeń musi obsługiwać prawdziwe bajty, aby możliwe były:

- checksumy,
- błędne długości,
- nieznane pola,
- opcje i rozszerzenia,
- fragmentacja,
- niepoprawne pakiety,
- interoperacyjność,
- eksport PCAPNG,
- fuzzing parserów,
- zgodność z Wiresharkiem.

### 9.2. Początkowe kodeki

```text
Ethernet II
802.1Q
ARP
IPv4
ICMPv4
UDP
```

Następne:

```text
IPv6
ICMPv6
Neighbor Discovery
TCP
MPLS label stack
LLC dla IS-IS
BFD
OSPF
IS-IS
BGP
LDP
RSVP
EVPN/VXLAN control and data formats
```

### 9.3. Parser

Parser powinien:

- wykonywać bounds checking przed każdym odczytem,
- nie zakładać alignmentu wejścia,
- rozróżniać `malformed`, `unsupported` i `valid`,
- nie alokować na hot path,
- zwracać offsety nagłówków,
- zapewniać jawne kody błędów,
- być fuzzowany.

### 9.4. Checksumy

Implementacja checksum musi mieć:

- normatywne wektory testowe,
- testy incremental update dla TTL,
- testy odd/even payload,
- testy fragmentów,
- benchmarki natywne i Wasm.

### 9.5. PCAPNG

Capture zapisuje:

- timestamp monotoniczny i mapowanie do czasu ściennego sesji,
- ingress lub egress point,
- interface ID,
- direction,
- original length,
- captured length,
- drop context, jeżeli capture odbywa się przed dropem,
- opcjonalny identyfikator pakietu wewnętrznego jako custom option.

Eksport musi być poprawnie odczytywany przez Wireshark.

---

## 10. Porty, łącza i kolejki

### 10.1. Link full-duplex

Każde połączenie full-duplex składa się z dwóch niezależnych kierunków:

```text
A -> B
B -> A
```

Każdy kierunek ma osobno:

```text
bitrate
propagation_delay
oper_state
transmitter_state
queue_capacity_bytes
frames_in_flight
loss_model
jitter_model
error_counters
capture_taps
```

### 10.2. Serializacja

Czas zajęcia nadajnika wynika z liczby bitów na medium:

```text
serialization_duration = wire_bits / bitrate
```

Model czasu transmisji powinien jawnie określać, czy uwzględnia:

- preambułę,
- SFD,
- FCS,
- inter-frame gap,
- tagi VLAN,
- overhead medium.

Pierwsza wersja używa store-and-forward. Cut-through jest capability profilu i osobnym behavior module.

### 10.3. Działanie na żywo

Port scheduler nie planuje globalnego zdarzenia. Posiada lokalny stan nadajnika i deadline zakończenia bieżącej transmisji. Po jego upływie:

- zwalnia nadajnik,
- przekazuje ramkę do modelu medium,
- rozpoczyna następną ramkę, jeżeli kolejka nie jest pusta,
- zasypia, gdy nie ma pracy.

Kierunek łącza posiada lokalne ramki w locie i budzi się w chwili najbliższego rzeczywistego terminu dostarczenia.

### 10.4. Kolejki

Pierwsza dyscyplina:

```text
FIFO
limit w bajtach
tail drop
```

Model musi być rozszerzalny do:

```text
multiple traffic classes
strict priority
WRR
WFQ-like scheduling
shaping
policing
WRED
hierarchical QoS
per-FC and per-port resource limits
```

Każda kolejka publikuje:

- current bytes,
- current packets,
- high watermark,
- enqueued,
- dequeued,
- dropped by reason,
- residence-time histogram.

### 10.5. Awaria łącza

Polityka musi jawnie określać:

- los ramki aktualnie transmitowanej,
- los ramek w egress queue,
- los ramek w propagacji,
- czas wykrycia carrier loss,
- powiadomienie interface managera,
- powiadomienie LACP, BFD i protokołów routingu.

Pierwsza wersja może przyjąć:

```text
current transmission: aborted and dropped
queued frames: dropped with port-down reason
in-flight frames: delivered only if failure occurred after full emission, otherwise dropped
remote carrier: changes according to link fault propagation profile
```

Ta polityka musi być testowana i wersjonowana.


---

## 11. Model sprzętu Nokia SR OS

### 11.1. Oddzielne drzewa stanu

Każde urządzenie Nokia musi posiadać co najmniej następujące widoki:

```text
PhysicalInventory
ProvisionedConfiguration
IntendedConfiguration
OperationalState
```

Dla MD-CLI dochodzą:

```text
BaselineConfiguration
CandidateConfiguration
RunningConfiguration
```

Znaczenie:

- `PhysicalInventory`: co jest fizycznie wyposażone, włożone lub obecne.
- `ProvisionedConfiguration`: jaki typ elementu został skonfigurowany przez administratora.
- `IntendedConfiguration`: efektywny wynik konfiguracji, defaultów, dziedziczenia i transformacji.
- `OperationalState`: aktualny stan rzeczywiście działających komponentów.
- `BaselineConfiguration`: stan, względem którego prowadzona jest edycja MD.
- `CandidateConfiguration`: niezatwierdzone zmiany sesji lub trybu.
- `RunningConfiguration`: zatwierdzona konfiguracja aktywna.

Nie wolno łączyć `equipped`, `provisioned`, `admin` i `oper` w jedno pole.

### 11.2. Hierarchia sprzętowa

Model musi obsługiwać elastyczną hierarchię:

```text
Device
  Chassis
    CPM slot
      CPM
    Card slot
      Card / IOM / XCM
        ForwardingComplex
        XIOM slot
          XIOM
        MDA/XMA slot
          MDA/XMA
            Connector
              Channel
                Port
    FabricPlane
```

Nie każda platforma używa każdego poziomu. Profil platformy wybiera właściwą strukturę.

### 11.3. HardwarePath

Nie wolno zakodować identyfikatora portu wyłącznie jako trzy liczby.

```cpp
enum class PathSegmentKind {
    Chassis,
    CpmSlot,
    CardSlot,
    XiomSlot,
    MdaSlot,
    Connector,
    Channel,
    Port,
    ForwardingComplex,
    FabricPlane
};

struct PathSegment {
    PathSegmentKind kind;
    uint16_t index;
};

struct HardwarePath {
    SmallVector<PathSegment, 8> segments;
};
```

Przykłady renderowania przez profil:

```text
slot:1 / mda:1 / port:1                  -> 1/1/1
slot:1 / mda:1 / connector:1 / channel:1 -> 1/1/c1/1
```

Parser i formatter nazw są elementem profilu wydania i platformy.

### 11.4. Ortogonalne stany sprzętu

```cpp
enum class PresenceState {
    Absent,
    Present
};

enum class ProvisioningState {
    Unprovisioned,
    Compatible,
    Mismatch,
    Unsupported
};

enum class AdminState {
    Disabled,
    Enabled
};

enum class LifecycleState {
    Cold,
    Initializing,
    Ready,
    Failed,
    Restarting,
    Removing
};

enum class OperState {
    Down,
    Up,
    Degraded
};

struct HardwareStatus {
    PresenceState presence;
    ProvisioningState provisioning;
    AdminState admin;
    LifecycleState lifecycle;
    OperState oper;
    OperReason reason;
};
```

Przykład prawidłowego stanu:

```text
presence: present
provisioning: compatible
admin: enabled
lifecycle: initializing
oper: down
reason: firmware-loading
```

### 11.5. Preprovisioning i obecność portu

Po poprawnym sprovisionowaniu nadrzędnej hierarchii konfiguracja portu może istnieć nawet wtedy, gdy fizyczny moduł jest nieobecny. Port nie powinien być tworzony dopiero po osiągnięciu `MDA up`.

Przykład:

```text
provisioned card: zgodna
provisioned MDA: zgodna
physical MDA: absent
port config 1/1/1: istnieje
port admin: up
port oper: down
oper reason: hardware-not-equipped
```

Po włożeniu zgodnego modułu istniejąca konfiguracja jest używana podczas inicjalizacji.

### 11.6. Reconciler

`HardwareReconciler` porównuje inventory, provisioning i profile. Nie używa globalnej kolejki zdarzeń. Jest długowiecznym komponentem reagującym na:

- zmianę inventory,
- commit konfiguracji,
- admin-state,
- zakończenie rzeczywistego czasu inicjalizacji,
- awarię,
- restart,
- zmianę capabilities.

Przykładowa sekwencja:

```text
insert card
  -> presence present
  -> compare provisioned type
  -> mismatch or compatible
  -> if compatible and admin enabled: initializing
  -> wait actual boot duration
  -> self tests
  -> operational up or failed
```

### 11.7. Profile danych i moduły zachowania

Typowy sprzęt jest opisany deklaratywnie:

```yaml
id: nokia.7750-sr-7
release: 26.7.R1
kind: chassis
card_slots:
  - index: 1
    allowed_types: [iom-example]
  - index: 2
    allowed_types: [iom-example]
cpm_slots:
  - index: A
  - index: B
fabric_planes:
  - index: 0
    capacity_bps: 400000000000
```

Profil opisuje:

- sloty i kompatybilność,
- porty i konektory,
- forwarding complexes,
- przepustowości,
- limity zasobów,
- czasy inicjalizacji,
- wartości domyślne,
- dostępne funkcje,
- format nazw,
- mapowanie portów do FC.

Nietypowe zachowanie może wymagać skompilowanego `BehaviorModule`. Nie należy zakładać, że każda przyszła karta będzie wyłącznie nowym JSON-em.

### 11.8. Minimalny katalog początkowy

Pierwszy pionowy przekrój powinien zawierać:

1. Jedną platformę zintegrowaną z auto-equipped i auto-provisioned hardware.
2. Jedną platformę modularną inspirowaną rodziną 7750 SR.
3. Jeden typ karty modularnej.
4. Dwa typy MDA/XMA albo modułów portowych.
5. Porty Ethernet 1G lub 10G z bezpiecznie skalowalnym profilem timingowym.
6. Co najmniej dwa forwarding complexes w jednym profilu testowym, nawet jeśli profil użytkowy zaczyna od jednego.

Nazwy handlowe i dokładne limity muszą być używane wyłącznie wtedy, gdy potwierdzają je oficjalne źródła.

### 11.9. Oficjalne źródła sprzętowe

Bazowe materiały Nokia SR OS 26.7.R1:

- Interface Configuration Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/interface-configuration.html
- Configuration overview: https://documentation.nokia.com/sr/26-7/7750-sr/books/interface-configuration/configuration-overview.html
- Deploy preprovisioned components: https://documentation.nokia.com/sr/26-7/7x50-shared/interface-configuration/deploy-preprovisioned-components.html
- Ports: https://documentation.nokia.com/sr/26-7/7750-sr/books/interface-configuration/ports.html
- Datapath mapping: https://documentation.nokia.com/sr/26-7/7750-sr/books/interface-configuration/fp4-datapath-mapp.html
- LAG: https://documentation.nokia.com/sr/26-7/7750-sr/books/interface-configuration/lag.html
- Fabric speed: https://documentation.nokia.com/sr/26-7/7750-sr/books/interface-configuration/sett-fabric-speed.html
- System Management Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/system-management.html
- Basic System Configuration Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/basic-system-configuration.html

---

## 12. Control plane, data plane i fabric

### 12.1. Podział urządzenia

```text
Chassis
  CPM domain
    management
    configuration
    CLI sessions
    route manager
    protocol daemons
    FIB compiler
    alarms

  Forwarding domain
    FC0
      ingress pipelines
      FIB generation
      adjacency snapshot
      egress pipelines
      port groups
    FC1
      ingress pipelines
      FIB generation
      adjacency snapshot
      egress pipelines
      port groups

  Fabric domain
    plane 0
    plane 1
```

### 12.2. Data plane per forwarding complex

Nie istnieje jeden mutowalny FIB współdzielony przez cały router. CPM utrzymuje wybrany RIB i kompiluje FIB, a każdy FC instaluje własną immutable generację.

```text
Protocol RIBs
      |
      v
Route Manager
      |
      v
Selected RIB per routing instance
      |
      v
FIB Compiler
      |
      +--> FC0 programming queue
      +--> FC1 programming queue
      +--> FC2 programming queue
```

Każdy FC może chwilowo posiadać inną generację. To pozwala modelować:

- czas programowania,
- limit zasobów,
- częściowe niepowodzenie,
- awarię karty,
- utrzymanie forwardingu podczas restartu control plane,
- przyszłe NSF i NSR.

### 12.3. Ścieżka pakietu tranzytowego

```text
PHY RX
  -> port RX ring
  -> ingress forwarding complex
  -> frame validation
  -> Ethernet parser
  -> VLAN/SAP/service classification
  -> ingress ACL
  -> ingress policer/QoS
  -> L2, L3 lub MPLS decision
  -> FIB/FDB/label lookup
  -> adjacency resolution result
  -> header rewrite
  -> local egress or fabric
  -> destination forwarding complex
  -> egress ACL/QoS
  -> egress scheduler
  -> port serializer
  -> link direction
  -> remote PHY RX
```

Jako modularny wzorzec logiczny można wykorzystywać podział parser, ingress, replication, egress i deparser opisany przez P4-16. Nie jest to deklaracja, że wewnętrzny ASIC Nokia działa dokładnie jak P4.

Źródło:

- https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html

### 12.4. Punt path

Pakiet do control plane przechodzi:

```text
ingress FC
  -> local destination or protocol classification
  -> CPM filter
  -> control-plane policer
  -> bounded punt queue
  -> CPM receive dispatcher
  -> socket demultiplexer
  -> protocol daemon or management service
```

To jest wymagane dla:

- OSPF i IS-IS,
- BFD,
- ARP i ND local processing,
- ICMP do adresu routera,
- TCP BGP,
- SSH i management,
- protection przed przeciążeniem CPM.

### 12.5. Ruch generowany lokalnie

Proces protokołu nie wysyła bezpośrednio na remote link:

```text
protocol daemon
  -> socket API
  -> network output
  -> routing lookup
  -> adjacency
  -> local output policy
  -> egress FC
  -> queue
  -> port
  -> link
```

### 12.6. Fabric

Model fabric musi od początku dopuszczać:

```text
multiple planes
plane redundancy
per-plane capacity
linecard-to-plane mapping
load distribution
oversubscription
queueing
backpressure
plane failure
```

Pierwsza implementacja może używać jednej aktywnej płaszczyzny z FIFO, ale interfejs nie może zakładać jednej płaszczyzny na zawsze.

### 12.7. Drop reasons

Minimalny katalog:

```text
invalid-fcs
frame-too-short
frame-too-long
ingress-mtu-exceeded
unknown-ethertype
vlan-not-allowed
sap-not-found
ingress-acl-denied
ingress-policer-drop
fdb-miss-policy-drop
no-route
unresolved-adjacency
ttl-expired
hop-limit-expired
invalid-ip-checksum
fragmentation-needed
fib-resource-missing
fabric-queue-full
egress-queue-full
egress-acl-denied
port-oper-down
link-oper-down
cpm-policer-drop
cpm-queue-full
packet-memory-exhausted
```

Każdy drop musi wskazywać komponent, punkt pipeline i licznik.

---

## 13. Network stack i warstwa socketów

### 13.1. Cel

Protokoły muszą korzystać ze wspólnej warstwy komunikacyjnej, tak jak procesy w NOS. Nie mogą implementować własnego skrótu do portu ani sąsiada.

### 13.2. Socket API

Docelowe typy:

```text
RawEthernetSocket
RawIpSocket
UdpSocket
TcpSocket
MplsPacketSocket
RoutingSocket
ManagementSocket
```

Mapowanie protokołów:

```text
LACP     -> Raw Ethernet slow protocols
LLDP     -> Raw Ethernet
IS-IS    -> Raw Ethernet / LLC
OSPF     -> Raw IP
BFD      -> UDP
BGP      -> TCP
LDP      -> UDP discovery + TCP session
PIM      -> Raw IP
RSVP     -> Raw IP
```

### 13.3. Routing instance

Każdy socket jest związany z:

```text
device
routing instance / VRF
local address or interface
protocol
security and control-plane class
```

Nie należy zakładać jednego globalnego RIB ani jednej globalnej przestrzeni socketów na urządzenie.

### 13.4. Warstwy początkowe

Pionowy przekrój:

```text
Ethernet
ARP
IPv4
ICMPv4
UDP foundation
```

Kolejne:

```text
IPv6
ICMPv6
Neighbor Discovery
TCP
MPLS
GRE
IP-in-IP
VXLAN
```

### 13.5. ARP i adjacency

Brak wpisu adjacency nie może zostać rozwiązany magicznie. Przebieg:

```text
FIB result references next-hop
  -> adjacency missing
  -> adjacency manager creates resolving state
  -> actual ARP Request generated
  -> packet traverses local output and link
  -> ARP Reply traverses ingress path
  -> adjacency state updated
  -> new immutable adjacency generation installed in FC
  -> pending packets handled according to explicit policy
```

Polityka oczekujących pakietów musi określać:

- limit liczby lub bajtów,
- timeout,
- drop reason,
- zachowanie wielu flow,
- reakcję na ARP failure.

Normatywne źródło ARP:

- https://www.rfc-editor.org/rfc/rfc826.html

### 13.6. IPv4 forwarding

Bazowe wymagania routera IPv4 opierają się na RFC 1812:

- weryfikacja nagłówka,
- local delivery lub forwarding,
- longest-prefix match,
- decrement TTL,
- aktualizacja checksumy,
- MTU i fragmentacja,
- ICMP errors,
- source address selection,
- reakcja na stan interfejsu.

Źródło:

- https://www.rfc-editor.org/rfc/rfc1812.html

### 13.7. TCP

BGP i LDP wymagają prawdziwego modelu TCP. Minimalny TCP nie może być transportem obiektowym. Powinien obsługiwać:

```text
SYN handshake
sequence numbers
ACK
retransmission
RTO
receive window
ordered byte stream
connection close
reset
basic congestion behavior sufficient for protocol sessions
```

Normatywne źródło:

- https://www.rfc-editor.org/rfc/rfc9293.html

---

## 14. Infrastruktura routingu

### 14.1. Warstwy RIB

```text
Connected RIB
Static RIB
OSPF RIB
IS-IS RIB
BGP Adj-RIB-In
BGP Loc-RIB candidates
LDP and label databases
Service route sources
        |
        v
Route Selection Manager
        |
        v
Selected RIB per routing instance
        |
        v
Next-hop resolution
        |
        v
FIB Compiler
        |
        v
Per-FC programming agents
```

### 14.2. Route candidate

```cpp
struct RouteCandidate {
    RouteOwner owner;
    RoutingInstanceId routing_instance;
    IpPrefix prefix;
    NextHopSpec next_hop;
    uint32_t preference;
    uint64_t metric;
    ProtocolAttributesRef attributes;
    PolicyTraceRef policy_trace;
    uint64_t generation;
};
```

### 14.3. Wybrana trasa

Wybrana trasa zawiera co najmniej:

```text
source protocol
preference
metric
effective next-hops
recursive resolution chain
outgoing interfaces
ECMP group
installation state per FC
resource state
reason when inactive
```

### 14.4. Recursive next-hop resolution

Resolution manager musi:

- wykrywać pętle,
- śledzić zależności,
- przeliczać tylko zależne trasy,
- obsługiwać zmiany adjacency,
- publikować generacje,
- rozróżniać route active i installed.

### 14.5. FIB programming

Zmiana RIB nie zmienia natychmiast pakietowego lookupu. Przebieg:

```text
selected route change
  -> compile desired FIB delta
  -> reserve resources
  -> enqueue programming operation per FC
  -> apply with profile-defined throughput and latency
  -> atomically activate generation
  -> report installed or failed state
```

Czas programowania jest rzeczywistym czasem runtime. Wartość pochodzi z jawnego profilu lub jest oznaczona jako modelowe przybliżenie.

### 14.6. Common policy engine

Jeden silnik polityk powinien służyć:

```text
BGP import/export
OSPF redistribution
IS-IS redistribution
LDP policy
route leaking
PIM policy
EVPN and service routes
static route policy where applicable
```

Silnik ma posiadać:

- skompilowaną reprezentację immutable,
- trace decyzji,
- generacje,
- walidację typów,
- obsługę prefix lists, communities i atrybutów,
- capability gating per release.

Nie należy implementować osobnego interpretera filtrów dla każdego protokołu.

### 14.7. Resource manager

Wspólny resource manager śledzi:

```text
IPv4 FIB entries
IPv6 FIB entries
next-hop entries
ECMP groups
MAC entries
MPLS labels
ACL/TCAM entries
queues
policers
shapers
protocol sessions
subscriber hosts
service instances
```

Alokacja zasobu ma wynik:

```text
reserved
installed
released
rejected-capacity
rejected-capability
failed-hardware
```

---

## 15. Procesy protokołów

### 15.1. Kontrakt procesu

Każdy protokół jest długowiecznym procesem logicznym:

```cpp
class ProtocolProcess {
public:
    virtual void start(ProtocolContext&) = 0;
    virtual void stop() = 0;
    virtual void on_packet(SocketPacket&&) = 0;
    virtual void on_interface_change(const InterfaceChange&) = 0;
    virtual void on_config_change(const ConfigDelta&) = 0;
    virtual void on_timer(TimerToken) = 0;
    virtual void collect_state(StateWriter&) const = 0;
};
```

Proces:

- ma własny FSM i stan,
- używa prawdziwych pakietów,
- używa real-time deadline,
- publikuje trasy przez routing socket,
- nie modyfikuje FIB,
- nie zna globalnej topologii,
- raportuje stany operacyjne i statystyki.

### 15.2. BFD

BFD jest dobrym pierwszym dynamicznym protokołem, ponieważ testuje:

- real-time timers,
- krótki interval,
- actual packet path,
- punt i control plane,
- FSM,
- wpływ na protokoły klientów.

Źródło:

- https://www.rfc-editor.org/rfc/rfc5880.html

### 15.3. OSPF

OSPF musi mieć:

```text
interface FSM
neighbor FSM
Hello and Dead timers
DD exchange
LSR, LSU, LSAck
LSDB
LSA aging
flooding
SPF scheduling
OSPF RIB
route installation requests
```

Nie wolno liczyć tras bez przejścia przez własną LSDB routera.

Źródła:

- OSPFv2: https://www.rfc-editor.org/rfc/rfc2328.html
- OSPFv3: https://www.rfc-editor.org/rfc/rfc5340.html

### 15.4. IS-IS

IS-IS wymaga:

```text
raw L2 packet path
adjacency FSM
IIH
LSP
CSNP and PSNP
LSP database
aging
SPF
level 1 and level 2
integrated IP routing
```

Źródło:

- https://www.rfc-editor.org/rfc/rfc1195.html

### 15.5. BGP

BGP musi mieć:

```text
one FSM per peer
TCP transport
OPEN
KEEPALIVE
UPDATE
NOTIFICATION
Adj-RIB-In
policy evaluation
Loc-RIB interaction
Adj-RIB-Out
MRAI and protocol timers
capability negotiation
route refresh later
```

Źródła:

- BGP-4: https://www.rfc-editor.org/rfc/rfc4271.html
- secure eBGP default policy: https://www.rfc-editor.org/rfc/rfc8212.html

### 15.6. MPLS i LDP

Podstawy:

- MPLS architecture: https://www.rfc-editor.org/rfc/rfc3031.html
- LDP: https://www.rfc-editor.org/rfc/rfc5036.html

MPLS data plane musi istnieć przed pełnym LDP. Label forwarding jest lokalnym lookupem w FC i może korzystać z osobnych zasobów niż IP FIB.

### 15.7. Segment routing

Źródła:

- Segment Routing Architecture: https://www.rfc-editor.org/rfc/rfc8402.html
- Segment Routing with MPLS data plane: https://www.rfc-editor.org/rfc/rfc8660.html

### 15.8. Kolejność implementacji protokołów

```text
Ethernet
ARP
IPv4
ICMPv4
UDP
VLAN and bridge forwarding
Static routing
LLDP
LACP
IPv6 and ND
BFD
OSPFv2
IS-IS
TCP
BGP
MPLS data plane
LDP
RSVP-TE
SR-MPLS
PIM
services and EVPN
```

Kolejność może być modyfikowana wyłącznie przy zachowaniu zależności.

---

## 16. Usługi i funkcje operatorskie

### 16.1. Model usług

Docelowy model obejmuje:

```text
Base router
IES
VPRN
VPLS
Epipe
Ipipe
SAP
SDP
spoke SDP
mesh SDP
EVPN instances
subscriber interfaces
```

Interfejs fizyczny, network interface, system interface, SAP i service attachment są odrębnymi obiektami.

### 16.2. SAP i SDP

SAP klasyfikuje lokalne przyłącze klienta do usługi. SDP opisuje transport usługi pomiędzy routerami. Nie wolno sprowadzić ich do aliasów VLAN lub tunnel ID.

### 16.3. EVPN i L3VPN

Źródła normatywne:

- BGP/MPLS L3VPN: https://www.rfc-editor.org/rfc/rfc4364.html
- EVPN: https://www.rfc-editor.org/rfc/rfc7432.html
- VPLS using BGP: https://www.rfc-editor.org/rfc/rfc4761.html
- VPLS using LDP: https://www.rfc-editor.org/rfc/rfc4762.html
- VXLAN: https://www.rfc-editor.org/rfc/rfc7348.html

### 16.4. Dokumentacja Nokia dla funkcji

- Router Configuration Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/router-configuration.html
- Unicast Routing Protocols Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/unicast-routing-protocols.html
- MPLS Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/mpls.html
- Segment Routing and PCE Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/segment-routing-pce-user.html
- Multicast Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/multicast.html
- QoS Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/qos.html
- Services Overview: https://documentation.nokia.com/sr/26-7/7750-sr/titles/services-overview.html
- Layer 2 Services and EVPN Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/layer-2-services-evpn.html
- Layer 3 Services Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/layer-3-services.html
- Standards and protocol support: https://documentation.nokia.com/sr/26-7/7750-sr/books/common/dita_standards-5.html

---

## 17. Konfiguracja i model zarządzania

### 17.1. Kanoniczny model

Oba CLI, a później NETCONF i gNMI, muszą operować na jednym typowanym modelu semantycznym:

```text
CanonicalConfigurationTree
CanonicalOperationalTree
SchemaRegistry
ValidationEngine
ActivationPlanner
```

CLI nie modyfikuje bezpośrednio obiektów data plane. Tworzy typowane zmiany konfiguracji.

### 17.2. Warstwy konfiguracji

```text
CLI text or management request
  -> syntax parser
  -> typed edit operations
  -> schema validation
  -> reference validation
  -> release/platform capability validation
  -> module-specific validation
  -> candidate or immediate running transaction
  -> activation plan
  -> commands to owning runtime components
  -> operational convergence
```

### 17.3. MD datastore

MD-CLI musi modelować co najmniej:

```text
baseline
candidate
running
intended
operational
```

Candidate może być powiązany z sesją lub trybem zgodnie z dokumentacją. Commit jest atomowy z perspektywy running configuration, lecz skutki operacyjne zachodzą na żywo i mogą mieć własny czas.

### 17.4. Classic immediate apply

Classic CLI stosuje zmiany natychmiast w kolejności poleceń. Każde polecenie powinno przechodzić przez małą transakcję na running configuration:

```text
parse
validate current context
validate command
apply to running
build activation delta
notify runtime
return prompt or error
```

Kolejność ma znaczenie. Nie wolno buforować serii classic commands i stosować ich jak MD commit, chyba że konkretna komenda oficjalnie zapewnia taką semantykę.

### 17.5. Loose i strict references

Model musi pozwalać na różne reguły referencji:

- classic może dopuszczać luźniejsze zależności i inną kolejność tworzenia,
- MD korzysta z rygorystyczniejszej walidacji modelu,
- różnice muszą być odwzorowane w adapterze CLI i validation policy,
- kanoniczny model nie może usuwać informacji potrzebnej do obsługi obu zachowań.

### 17.6. Management modes

Należy obsłużyć wersjonowany profil trybu zarządzania:

```text
classic
mixed
model-driven
```

Profil określa:

- które CLI może czytać,
- które CLI może zapisywać,
- format saved configuration,
- zasady konfliktu,
- dostępność NETCONF i gNMI,
- zachowanie przełączania silników.

Oficjalne źródło:

- https://documentation.nokia.com/sr/26-7/7x50-shared/system-management/model-driven-management-interfaces.html

### 17.7. YANG

MD schema powinna być projektowana tak, aby możliwe było wykorzystanie oficjalnych modeli Nokia YANG. Nie należy ręcznie kodować całego drzewa w tysiącach warunków.

Docelowe pipeline build-time:

```text
Nokia YANG source/reference metadata
  -> schema normalizer
  -> release capability filter
  -> internal schema IR
  -> generated C++ validators
  -> generated CLI completion metadata
  -> generated TypeScript inspector metadata
```

Ze względu na licencje i dystrybucję repozytorium nie może bezrefleksyjnie kopiować całych modeli, jeżeli warunki nie pozwalają. Narzędzie powinno obsługiwać lokalne dostarczenie oficjalnych modeli przez developera.

Oficjalny Nokia YANG Browser:

- https://yangbrowser.nokia.com/sros

Nokia MD-CLI Explorer:

- https://documentation.nokia.com/sr/26-7/mdcli-explorer/index.html

Normatywne źródła:

- NETCONF: https://www.rfc-editor.org/rfc/rfc6241.html
- YANG 1.1: https://www.rfc-editor.org/rfc/rfc7950.html
- NMDA: https://www.rfc-editor.org/rfc/rfc8342.html
- With-defaults capability: https://www.rfc-editor.org/rfc/rfc6243.html

### 17.8. Activation plan

Commit lub classic command nie powinien dowolnie wywoływać komponentów. Validation engine tworzy uporządkowany `ActivationPlan`:

```cpp
struct ActivationPlan {
    ConfigRevision from;
    ConfigRevision to;
    vector<ActivationOperation> operations;
    vector<ResourceReservation> reservations;
    RollbackPolicy rollback;
};
```

Przykład konfiguracji interfejsu:

```text
update running config
  -> interface manager validates parent port
  -> connected route candidate appears
  -> route manager recalculates
  -> FIB compiler creates delta
  -> FC programming starts
  -> protocol daemons receive interface event
  -> operational tree converges
```

### 17.9. Atomiczność i rollback

Należy rozróżnić:

- atomowość zapisu running datastore,
- asynchroniczną aktywację w runtime,
- możliwość niepowodzenia zasobu,
- operational failure po poprawnym commit.

Commit może być poprawny konfiguracyjnie, a urządzenie może pokazać operacyjnie `down` z powodu braku hardware. Nie należy automatycznie cofać poprawnej konfiguracji tylko dlatego, że sprzęt jest nieobecny.

---

## 18. Wspólna architektura CLI

### 18.1. Terminal

xterm.js jest wyłącznie emulatorem terminala i rendererem. Nie implementuje semantyki SR OS i nie może być połączony z shellem systemu hosta.

Źródło bezpieczeństwa:

- https://xtermjs.org/docs/guides/security/

Przepływ:

```text
browser key input
  -> xterm.js onData bytes
  -> shared CLI input ring
  -> C++ CliSession
  -> line editor and CLI engine
  -> terminal output byte stream
  -> shared CLI output ring
  -> xterm.js write
```

### 18.2. Dlaczego line editor w rdzeniu

Line editor i state machine sesji powinny działać w C++:

- ten sam kod w Wasm i testach natywnych,
- dokładne testy bajtów i kursora,
- brak rozbieżności między UI i parserem,
- możliwość wielu sesji,
- łatwe golden transcripts,
- zachowanie podczas zmiany engine,
- kontrola pagera i historii.

### 18.3. Dwa silniki

```text
CliSession
  CommonTerminalState
  AuthenticationContext
  EnvironmentSettings
  PagerState
  HistoryState
  EngineSelector
      |
      +--> MdCliEngine
      +--> ClassicCliEngine
```

Wspólne mogą być:

- transport terminalowy,
- bufor linii,
- niskopoziomowe ruchy kursora,
- historia jako mechanizm,
- pager jako mechanizm,
- autoryzacja,
- wyjście VT.

Odrębne muszą być:

- gramatyka,
- kontekst,
- prompt,
- completion semantics,
- help semantics,
- model konfiguracji,
- błędy,
- skróty komend,
- navigation,
- aliasy,
- default handling.

### 18.4. Stan sesji

```cpp
struct CliSessionState {
    SessionId id;
    DeviceId device;
    CliEngineKind engine;
    AuthContext auth;
    TerminalDimensions dimensions;
    LineEditorState editor;
    PagerState pager;
    HistoryState md_history;
    HistoryState classic_history;
    MdContext md_context;
    ClassicContext classic_context;
    EnvironmentSettings environment;
    uint64_t output_sequence;
};
```

Konteksty MD i classic pozostają zachowane przy przełączeniu engine.

### 18.5. Raw key contract

Testy CLI muszą obsługiwać wejścia:

```text
printable UTF-8 bytes
Tab
Space
Enter
Backspace
Delete
Arrow keys
Home/End
Ctrl combinations
Alt combinations
terminal resize
Ctrl-C during command
Ctrl-C during pagination
```

Nie wolno testować wyłącznie przez funkcję `execute("show ...")`.

### 18.6. Terminal output

Rdzeń może emitować pełny strumień VT albo typowane operacje terminalowe. Dla zgodności i prostoty pierwszej wersji zalecany jest strumień bajtów VT z osobnym kanałem metadanych testowych.

Wyjście musi uwzględniać:

- echo wejścia,
- przesuwanie kursora,
- kasowanie,
- zawijanie,
- prompt,
- pager,
- bell,
- komunikaty błędów,
- przerwanie Ctrl-C.

### 18.7. Katalog komend

Każdy command node powinien mieć:

```yaml
id: cli.md.configure.router.interface
engine: md
release: 26.7.R1
path: /configure router interface
keywords: [configure, router, interface]
parameters: []
completion:
  tab: true
  space: true
  enter: true
help:
  summary: "..."
permissions: []
platform_capabilities: []
handler: configure_router_interface
source_ids: []
golden_transcripts: []
```

Classic ma osobny schema format, ponieważ wspiera abbreviations, konteksty i inne reguły parametrów.

---

## 19. MD-CLI od pierwszego wydania

### 19.1. Oficjalne źródła

- MD-CLI User Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/md-cli-user.html
- Navigating the MD-CLI: https://documentation.nokia.com/sr/26-7/7x50-shared/md-cli-user/navigate.html
- Editing configuration: https://documentation.nokia.com/sr/26-7/7x50-shared/md-cli-user/edit-configuration.html
- Switching between engines: https://documentation.nokia.com/sr/26-7/7x50-shared/md-cli-user/switch-between-classic-cli-md-cli-engines.html
- Creating MD-CLI configuration from classic CLI: https://documentation.nokia.com/sr/26-7/7x50-shared/md-cli-user/creating-md-cli-configuration-from-classic-cli.html
- MD-CLI Command Reference: https://documentation.nokia.com/sr/26-7/7750-sr/titles/md-cli-command-reference.html
- MD-CLI Explorer: https://documentation.nokia.com/sr/26-7/mdcli-explorer/index.html

### 19.2. Prompt

MD-CLI używa dwuliniowego promptu. Implementacja musi odwzorować elementy dokumentowane dla wydania, między innymi:

- stan baseline,
- wskaźnik niezacommitowanych zmian,
- tryb konfiguracji,
- bieżącą ścieżkę,
- aktywny CPM,
- użytkownika,
- nazwę systemu,
- znak końcowy promptu.

Przykładowy model, nie tekst do zakodowania bez golden transcript:

```text
[ex:/configure router "Base"]
A:admin@router#
```

Prompt formatter musi być generacyjny i korzystać ze stanu sesji. Dokładne spacing, nawiasy, symbole i skróty trybów muszą pochodzić z oficjalnej dokumentacji i testów SR-SIM.

Dla baseline 26.7.R1 należy jawnie odwzorować udokumentowane wskaźniki pierwszej linii promptu, w tym:

```text
!  stan związany z baseline lub zmianą baseline, zgodnie z kontekstem dokumentacji
*  niezacommitowane zmiany candidate
(ex) tryb exclusive
(gl) tryb global
(pr) tryb private
(ro) tryb read-only
```

W implicit workflow oznaczenie trybu i ścieżki występuje w formie dokumentowanej przez MD-CLI, na przykład jako część nawiasowego path promptu. Druga linia zawiera identyfikator CPM, użytkownika, nazwę systemu i końcowy znak promptu. Znaczenia symboli nie wolno upraszczać do jednego ogólnego `dirty` boolean.

### 19.3. Pomoc kontekstowa

`?` jest pomocą kontekstową i działa bez Enter. Musi uwzględniać:

- pustą linię,
- częściowe słowo,
- pełne słowo,
- pozycję parametru,
- bieżący path,
- uprawnienia,
- platform capabilities,
- aliasy,
- wartości dynamiczne.

Pomoc nie może pokazywać komendy niedostępnej na bieżącej platformie lub w trybie sesji.

### 19.4. Command completion

Domyślne MD-CLI command completion obejmuje:

- Tab,
- Spacebar,
- Enter.

Mechanizmy te są niezależnie konfigurowalne przez ustawienia środowiska. Implementacja ma modelować `environment command-completion` i warianty zachowania.

Variable parameter completion jest uruchamiane przez Tab. Dynamiczne wartości mogą pochodzić z candidate i running configuration, zgodnie z kontekstem.

### 19.5. Enter

Enter nie jest zawsze prostym odpowiednikiem wykonania pełnego bufora. W zależności od stanu komendy może:

- uzupełnić jednoznaczny keyword,
- wykonać poprawną komendę,
- pokazać błąd niekompletnej lub niejednoznacznej komendy,
- przejść do kontekstu.

Zachowanie musi być testowane dla każdego command node.

### 19.6. Nawigacja

Należy obsłużyć:

- absolute path,
- relative path,
- przejście do rodzica,
- przejście do root,
- wejście do list elementów,
- wyświetlanie path w prompt,
- skróty udokumentowane przez MD-CLI.

Nie wolno projektować nawigacji na podstawie shellowego `cd`, jeżeli nie odpowiada dokumentacji.

### 19.7. Tryby konfiguracji

Model ma uwzględnić:

```text
private
exclusive
global
read-only
```

oraz rozróżnienie explicit i implicit workflow, zgodnie z aktualnym przewodnikiem.

Przykładowe wymagania architektoniczne:

- separate candidate per private session,
- exclusive lock urządzenia lub właściwego datastore,
- global shared candidate semantics,
- read-only mode bez commit,
- compare i discard,
- conflict handling,
- zachowanie promptu per mode.

Dokładne reguły muszą być pozyskane z sekcji Editing configuration oraz zweryfikowane transcriptami.

### 19.8. Candidate i commit

Wymagane operacje minimalne:

```text
configure private/exclusive/global/read-only
edit-config
commit
compare
discard
validate
info
info detail
exit/back navigation as documented
```

Nie każda musi być pełna w pierwszym sprincie, lecz pionowy przekrój wymaga działającego candidate, compare, commit i discard dla obsługiwanego poddrzewa.

### 19.9. Historia, aliasy i środowisko

MD-CLI powinien mieć:

- niezależną historię sesji,
- udokumentowany limit i konfigurację,
- nawigację Ctrl/Arrow zgodnie ze źródłem,
- aliasy uczestniczące w Tab i `?`,
- ustawienia environment,
- pager i output modifiers,
- terminal width i length.

### 19.10. Błędy

Każda kategoria błędu powinna mieć stabilny kod wewnętrzny i renderer zgodny z wydaniem:

```text
unknown command
ambiguous command
incomplete command
invalid parameter
range violation
reference violation
capability violation
candidate conflict
commit validation failure
permission denied
```

Tekst kompatybilności powinien być potwierdzony golden transcript.

---

## 20. Classic CLI od pierwszego wydania

### 20.1. Oficjalne źródła

- Classic CLI Command Reference Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/classic-cli-command-reference.html
- Classic CLI overview: https://documentation.nokia.com/sr/26-7/7x50-shared/classic-cli-command-reference/classic-cli-overview.html
- Clear, Monitor, Show and Tools Command Reference: https://documentation.nokia.com/sr/26-7/7750-sr/titles/clear-monitor-show-tools-commands.html
- Nokia reference documentation category: https://documentation.nokia.com/sr/26-7/7750-sr/html/product/reference.html

### 20.2. Kontekst hierarchiczny

Classic CLI ma hierarchiczne, odwrócone drzewo kontekstów. Sesja przechowuje stos kontekstu, a prompt zawiera bieżącą lokalizację.

Przykład formy:

```text
A:router-name>config>router>if#
```

Prompt powinien modelować:

- aktywny CPM,
- hostname,
- skróconą ścieżkę kontekstu,
- `#` dla istniejącego kontekstu,
- `$` dla nowo utworzonego kontekstu, jeżeli dotyczy,
- `*` dla niezapisanych zmian zgodnie z ustawieniem `saved-ind-prompt`.

Dokładne formaty muszą mieć testy dla obsługiwanego poddrzewa.

### 20.3. Pomoc

Należy obsłużyć co najmniej:

```text
help
help globals
help edit
help special-characters
?
command ?
string?
command string?
```

`?` ma działać kontekstowo bez Enter tam, gdzie dokumentacja to określa.

### 20.4. Completion i abbreviations

Classic CLI uruchamia completion przez:

- Tab,
- Spacebar.

Obsługuje skracanie jednoznacznych słów komend. Parser nie może wymagać pełnego keywordu, jeżeli skrót jest jednoznaczny.

Completion musi uwzględniać:

- kontekst,
- uprawnienia,
- dostępność platformową,
- parametry,
- przypadki, w których completion jest wyłączone, na przykład określone zakresy.

### 20.5. Immediate configuration

Classic CLI stosuje zmianę na żywo po wykonaniu komendy. Przykład konsekwencji:

```text
shutdown
  -> running changes immediately
  -> interface manager receives delta
  -> oper state changes
  -> routes and protocols react live
```

Nie ma candidate i commit dla typowych classic commands.

### 20.6. Global commands

Pierwszy shell mechanics milestone powinien obsługiwać zgodnie ze źródłami:

```text
back
exit
pwc
history
help
environment-related commands
show/info appropriate to context
```

Lista pełna pochodzi z command reference. Nie należy zakładać nazw na podstawie innych vendorów.

### 20.7. Edycja linii

Docelowo należy odwzorować udokumentowane skróty, między innymi kategorie:

```text
Ctrl-C, Ctrl-D, Ctrl-U, Ctrl-K
Ctrl-A, Ctrl-E
Ctrl-P, Ctrl-N
Ctrl-B, Ctrl-F
Ctrl-W, Ctrl-T, Ctrl-Z, Ctrl-L
Alt-B, Alt-F, Alt-C, Alt-L, Alt-D
```

Dokładne znaczenie każdego skrótu musi zostać przepisane do własnego testu na podstawie oficjalnej sekcji `help edit` lub command reference. Nie wolno przypisywać zachowania wyłącznie na podstawie Bash lub readline.

### 20.8. Pager

Classic pager jest kontrolowany ustawieniami środowiska, w tym `more`. Pager musi reagować na:

- Space,
- Enter,
- quit,
- Ctrl-C,
- resize terminala,
- zmianę liczby linii.

Dokładne znaki i prompt pagera wymagają golden transcript.

### 20.9. Błędy

Dla nieprawidłowej komendy classic CLI dokumentuje między innymi formę:

```text
Error: Bad command.
```

Nie należy używać tego tekstu do wszystkich błędów. Każdy przypadek musi mieć właściwy renderer i test.

### 20.10. Saved indicator

Classic CLI powinien rozróżniać running i zapisany stan, jeżeli obsługiwany profil oraz komendy save to przewidują. Wskaźnik `*` w prompt jest zależny od environment i stanu zmian.


---

## 21. Przełączanie MD-CLI i classic CLI

### 21.1. Oficjalne źródło

- https://documentation.nokia.com/sr/26-7/7x50-shared/md-cli-user/switch-between-classic-cli-md-cli-engines.html

### 21.2. Wymagane zachowanie

Jeżeli oba silniki są autoryzowane, należy obsłużyć:

```text
//
/!md-cli
/!classic-cli
//command
// command
```

### 21.3. `//`

Samo `//` przełącza aktywny engine. Każdy engine zachowuje własny kontekst i historię.

Przykład semantyczny:

```text
MD context: /configure router "Base" interface "to-R2"
Classic context: config>router>if

switch to classic
  -> restore Classic context

switch to MD
  -> restore MD context
```

### 21.4. Jednorazowe wykonanie w drugim engine

`//command` lub `// command` wykonuje jedną komendę w drugim silniku, po czym wraca do bieżącego.

Wymagania:

- bieżący engine nie zmienia trwałego kontekstu,
- komenda drugiego engine korzysta z jego zachowanego kontekstu zgodnie z dokumentacją,
- pagination działa,
- confirmation działa,
- Ctrl-C działa,
- uncommitted MD changes pozostają zachowane,
- po prefiksie jednorazowej komendy nie ma zwykłego completion ani pomocy `?`, jeżeli dokumentacja tak stanowi,
- komunikaty INFO i MINOR muszą zostać odwzorowane przez transcript tests.

### 21.5. Autoryzacja

Engine switch musi respektować:

- prawa użytkownika,
- management mode,
- dostępność engine,
- blokady sesji,
- stan konfiguracji MD.

Brak uprawnienia nie może prowadzić do cichego fallbacku.

---

## 22. Macierz zgodności CLI

Repozytorium ma utrzymywać maszynowo czytelną macierz:

```yaml
release: 26.7.R1
platform: 7750-sr-profile-1
management_mode: model-driven
features:
  md_cli:
    read: true
    write: true
    switch_to_classic: false
  classic_cli:
    read: profile-dependent
    write: false
```

Macierz musi rozróżniać:

- release,
- platformę,
- management mode,
- rolę użytkownika,
- engine,
- command path,
- operation: read, edit, execute,
- implementation status.

Completion i `?` filtrują wyniki według tej samej macierzy, której używa wykonanie. Nie mogą pokazywać komendy, która potem jest odrzucana jako nieistniejąca, chyba że realny SR OS zachowuje się tak z powodu autoryzacji.

---

## 23. Testy zgodności terminala

### 23.1. Golden transcript

Format testu powinien zapisywać:

```yaml
id: md.completion.tab.basic
source_ids:
  - nokia.sros.26_7.md_cli.command_completion
initial:
  engine: md
  terminal:
    columns: 100
    rows: 30
  device_state_fixture: minimal-router
steps:
  - input_bytes: "show rout"
  - key: TAB
  - expect_screen_contains: "show router"
  - expect_cursor: { row: 1, column: 11 }
  - key: QUESTION_MARK
  - expect_screen_fixture: md/show-router-help.txt
  - key: ENTER
  - expect_prompt_fixture: md/operational-prompt.txt
```

### 23.2. Rejestrowanie oracle

Narzędzie `transcript-recorder` powinno pozwalać ręcznie rejestrować sesję z:

- SR-SIM,
- vSIM,
- fizycznym SR OS.

Rejestruje:

- bajty wysłane,
- bajty odebrane,
- rozmiar terminala,
- czas względny dla pagera i timeoutów,
- wersję SR OS,
- platformę,
- management mode,
- konfigurację startową.

Nie należy automatycznie przyjmować każdego terminalowego escape sequence jako semantycznie wymaganego. Golden fixture powinien normalizować elementy niestabilne, takie jak bieżący czas, ale zachowywać prompt, spacing, cursor i tekst.

### 23.3. Zakres pierwszych testów MD

```text
empty ?
partial keyword ?
Tab unique completion
Tab ambiguous completion
Space completion
Enter completion
variable completion with Tab
command unavailable by capability
prompt in operational mode
prompt in private mode
candidate dirty marker
compare
commit success
commit validation failure
discard
history previous/next
cursor movement
Ctrl-C line cancel
pager navigation
terminal resize
engine switch
one-shot cross-engine command
```

### 23.4. Zakres pierwszych testów classic

```text
help
help globals
help edit
?
partial?
command ?
Tab completion
Space completion
unique abbreviation
ambiguous abbreviation
context entry
back
exit
pwc
new context marker
saved indicator
immediate configuration effect
invalid command exact error
history
editing key combinations
pager
Ctrl-C
engine switch
```

### 23.5. Screen model

Test harness powinien posiadać mały emulator terminala VT, aby porównywać końcowy ekran i pozycję kursora. Samo porównanie raw bytes może być zbyt kruche, a samo porównanie tekstu nie wykrywa błędów edycji.

---

## 24. Minimalny wspólny zakres CLI dla pierwszego pionowego przekroju

Zakres ma być wąski, ale kompletny. Każda funkcja musi działać przez oba CLI zgodnie z ich semantyką.

### 24.1. System

```text
system name / hostname
show system information
show version/profile
show card
show mda/module
show port
show alarms
```

### 24.2. Hardware

```text
provision card type
provision MDA/XMA/module type
admin enable/disable or shutdown/no shutdown
inspect equipped versus provisioned
inspect operational reason
```

Fizyczne insert/remove odbywa się w chassis UI, nie przez nieudokumentowaną komendę CLI.

### 24.3. Port

```text
port context
admin state
MTU where supported
basic description
show port detail
counters
```

### 24.4. Router Base

```text
system interface
network interface
IPv4 address
bind to port
admin state
connected routes
static route
show route
show FIB
show ARP
```

### 24.5. Narzędzia

```text
ping
traceroute after prerequisites
start/stop capture through UI and optional supported tools command
show capture status as project-specific extension only if clearly namespaced
```

Nie należy wprowadzać fikcyjnej Nokia command dla funkcji UI. Funkcje projektu, które nie mają odpowiednika SR OS, powinny pozostawać w interfejsie graficznym albo w osobnym, wyraźnie oznaczonym namespace narzędziowym.

### 24.6. Mapowanie semantyczne

Przykład, bez narzucania niezweryfikowanej składni:

```text
MD edit
  -> candidate change
  -> compare
  -> commit
  -> running update

Classic command
  -> immediate running update
```

Oba prowadzą do tego samego kanonicznego stanu, ale inną drogą i z innym terminalowym zachowaniem.

### 24.7. Definition of Done dla komendy

Komenda jest ukończona, gdy posiada:

- source record,
- schema node,
- parser tests,
- completion tests,
- help tests,
- permission/capability tests,
- execution handler,
- state transition test,
- exact error tests,
- golden transcript,
- dokumentację statusu,
- zgodne zachowanie w drugim CLI, jeżeli istnieje odpowiednik.

---

## 25. Frontend

### 25.1. Moduły UI

```text
Lab browser
Topology editor
Device palette
Chassis and inventory view
Device inspector
Port and interface panels
CLI terminal workspace
Routing state viewer
Protocol state viewer
Live capture viewer
Alarms and runtime health
Project import/export
Settings and compatibility report
```

### 25.2. Routing aplikacji

Proponowane trasy TanStack Router:

```text
/
/labs
/labs/:labId
/labs/:labId/topology
/labs/:labId/device/:deviceId
/labs/:labId/device/:deviceId/chassis
/labs/:labId/device/:deviceId/cli/:sessionId
/labs/:labId/device/:deviceId/routes
/labs/:labId/device/:deviceId/protocols
/labs/:labId/captures
/labs/:labId/alarms
/labs/:labId/runtime
/settings
```

Źródło TanStack Router:

- https://tanstack.com/router/latest/docs/framework/react/overview

### 25.3. React Flow

React Flow odpowiada za:

- urządzenia jako nodes,
- połączenia jako edges,
- porty jako identyfikowane handles,
- drag and drop,
- selection,
- topology editing.

Źródła:

- Handles: https://reactflow.dev/learn/customization/handles
- Performance: https://reactflow.dev/learn/advanced-use/performance

Nie wolno aktualizować całej tablicy nodes dla każdego licznika lub pakietu.

### 25.4. Telemetria

Szybkozmienne dane powinny być publikowane przez shared telemetry pages. UI używa:

- `useSyncExternalStore`,
- wąskich selectorów,
- atomowych numerów generacji,
- snapshotów stabilnych na czas renderu.

Przykładowe częstotliwości:

```text
port oper state: natychmiastowa delta
protocol state: natychmiastowa delta
counters: 2-10 Hz
queue utilization visualization: do 30 Hz
runtime health: 1-2 Hz
large tables: on demand
```

### 25.5. Canvas lub WebGL

Canvas overlay może przedstawiać:

- live utilization,
- kierunek ruchu,
- alarmy,
- sampled traffic indicators,
- queue pressure.

Nie ma animacji każdego pakietu jako elementu DOM i nie ma osi czasu. Packet inspection odbywa się przez live capture.

### 25.6. Terminal workspace

Workspace powinien obsługiwać:

- wiele sesji do jednego urządzenia,
- wiele urządzeń,
- resize,
- copy/paste,
- scrollback,
- reconnect do lokalnej sesji po re-renderze,
- widoczny engine i management mode bez zmieniania promptu producenta,
- osobne ostrzeżenie projektu poza terminalem, jeżeli funkcja jest częściowo wspierana.

Dane terminalowe są niezaufane. Nie mogą być interpretowane jako HTML.

### 25.7. TanStack Query

TanStack Query nie jest używany do wysokoczęstotliwościowych danych runtime. Może służyć w przyszłości do:

- konta,
- galerii laboratoriów,
- katalogu zdalnych profili,
- synchronizacji cloud save.

Źródło:

- https://tanstack.com/query/latest/docs/framework/react/overview

### 25.8. TanStack Start

Nie jest wymagany w bazowym wdrożeniu. Materiał referencyjny:

- https://tanstack.com/start/latest/docs/framework/react/overview

---

## 26. Persystencja lokalna

### 26.1. IndexedDB

IndexedDB przechowuje:

```text
project metadata
topology definitions
device running configs
MD candidate metadata if safely recoverable
physical inventory
UI layout
profile references
commit history metadata
capture index
checkpoint index
```

Źródło:

- https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API

### 26.2. OPFS

OPFS przechowuje:

```text
large binary checkpoints
PCAPNG chunks
packet capture ring spill files
compiled profile cache
large table snapshots
export staging files
```

Źródło:

- https://developer.mozilla.org/en-US/docs/Web/API/File_System_API/Origin_private_file_system

### 26.3. Autosave

Autosave następuje:

- po MD commit,
- po poprawnym classic config command,
- po zmianie physical inventory,
- po kontrolowanym power transition,
- okresowo dla runtime checkpoint,
- przed `pagehide`, jeżeli czas na to pozwala.

Nie należy zapisywać całego snapshotu po każdym pakiecie.

### 26.4. Format `.netsim`

Przenośny projekt jest kontenerem ZIP lub równoważnym:

```text
manifest.json
topology.json
inventory/
  device-1.json
configuration/
  device-1-running.json
  device-1-saved-classic.cfg
  device-1-md.cfg
profiles/
  lock.json
runtime/
  optional-checkpoint.bin
captures/
  optional-capture.pcapng
sources/
  compatibility-report.json
```

Manifest zawiera:

```text
format version
created with build
engine ABI version
profile release lock
project UUID
checksums
optional migration history
```

### 26.5. Migracje

Każda zmiana formatu wymaga:

- versioned migration,
- rollback or failure message,
- testu ze starym fixture,
- zachowania oryginalnego pliku do czasu zakończenia importu,
- raportu utraconych capabilities.

### 26.6. Blokada laboratorium

Jedno laboratorium nie powinno być aktywnie modyfikowane przez dwa taby bez koordynacji. Użyć Web Locks API albo BroadcastChannel do:

- active runtime lease,
- read-only secondary tab,
- takeover po potwierdzeniu,
- wykrycia stale lease.

### 26.7. Opcjonalne udostępnianie małego projektu w URL

Dla małych, nieaktywnych topologii można później dodać eksport definicji projektu do fragmentu URL:

```text
serialize selected project definition
compress in browser
base64url encode
place after #
```

Fragment nie jest wysyłany w żądaniu HTTP. Funkcja musi mieć twardy limit rozmiaru, nie może obejmować capture, sekretów, bieżącego runtime ani dużych konfiguracji i nie zastępuje pliku `.netsim`. Jest to funkcja późniejsza, nie część pierwszego pionowego przekroju.

---

## 27. Statyczne wdrożenie Vercel

### 27.1. Zakres hostingu

Vercel serwuje wyłącznie:

```text
index.html
CSS
JavaScript
WebAssembly
pthread worker scripts
profile JSON
schema metadata
icons and local fonts
service worker assets
```

Symulacja nie działa w Vercel Functions.

### 27.2. Wymagane nagłówki

SharedArrayBuffer wymaga secure context i cross-origin isolation. Bazowy `vercel.json`:

```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Cross-Origin-Opener-Policy",
          "value": "same-origin"
        },
        {
          "key": "Cross-Origin-Embedder-Policy",
          "value": "require-corp"
        }
      ]
    }
  ],
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```

W praktyce należy dodać precyzyjne reguły cache dla hashed assets i nie cache'ować `index.html` w sposób blokujący aktualizacje.

### 27.3. Kontrola startowa

Aplikacja MUSI sprawdzić:

```ts
if (!window.crossOriginIsolated) {
  throw new Error("Multithreaded runtime requires cross-origin isolation");
}

if (typeof SharedArrayBuffer === "undefined") {
  throw new Error("SharedArrayBuffer is unavailable");
}
```

Następnie wykonuje pthread smoke test i raportuje capability failure, zamiast cicho uruchamiać tryb jednowątkowy.

### 27.4. Same-origin assets

Ze względu na COEP wszystkie zasoby krytyczne powinny być hostowane z tego samego originu. Dotyczy to:

- Wasm,
- worker scripts,
- xterm assets,
- fontów,
- ikon,
- profili,
- schema files.

### 27.5. PWA

Service worker może zapewniać offline cache statycznych zasobów. Nie może być traktowany jako proces utrzymujący aktywną sieć po zamknięciu strony.

### 27.6. Oficjalne źródła Vercel i web platform

- Vite on Vercel: https://vercel.com/docs/frameworks/frontend/vite
- `vercel.json`: https://vercel.com/docs/project-configuration/vercel-json
- Rewrites: https://vercel.com/docs/routing/rewrites
- Hobby plan: https://vercel.com/docs/plans/hobby
- WebSockets and Functions: https://vercel.com/docs/functions/websockets
- COOP/COEP explanation: https://web.dev/articles/why-coop-coep
- Web Workers specification: https://html.spec.whatwg.org/multipage/workers.html

### 27.7. Ograniczenie planu Hobby

Plan Hobby należy traktować jako hosting osobisty i niekomercyjny zgodnie z aktualnymi warunkami Vercel. Projekt powinien mieć łatwy statyczny build również dla innych CDN i self-hostingu.

---

## 28. Obserwowalność i zdrowie runtime

### 28.1. Metryki hosta

```text
pthread count
worker utilization
host scheduling lag
mailbox fill and drops
packet pool usage
allocation failures
shared memory usage
telemetry overwrite count
capture backlog
browser lifecycle state
```

### 28.2. Metryki modelowanego urządzenia

```text
CPM utilization model
punt queue
protocol process queues
RIB size
FIB size per FC
FIB programming queue
port queues
fabric queues
resource manager usage
alarms
packet drops by reason
```

Dwie grupy muszą być prezentowane osobno.

### 28.3. Structured trace

Wewnętrzny trace diagnostyczny nie jest osią czasu użytkownika. Powinien mieć ring buffer i kategorie:

```text
runtime
hardware
configuration
routing
protocol
forwarding
queue
capture
cli
```

Trace służy debugowaniu i może być eksportowany jako diagnostyka. Domyślnie nie zapisuje payloadów ani danych wrażliwych.

### 28.4. Alarmy

Alarm ma:

```text
source component
severity
probable cause
first occurrence
last occurrence
count
cleared state
operational impact
source documentation ID
```

Przykłady:

```text
card-type-mismatch
mda-absent
fib-capacity-exceeded
fabric-plane-down
cpm-punt-congestion
runtime-continuity-lost
host-timing-degraded
```

Alarm hosta musi być wyraźnie oznaczony jako host runtime, nie alarm SR OS.

---

## 29. Bezpieczeństwo

### 29.1. Brak shell access

CLI jest emulatorem SR OS. Nie ma żadnego dostępu do:

- `/bin/sh`,
- PowerShell,
- systemu plików hosta poza kontrolowanym storage API,
- procesów systemowych,
- interfejsów sieciowych hosta.

### 29.2. Nieufne dane

Za nieufne należy uznać:

- importowane `.netsim`,
- nazwy urządzeń,
- tekst konfiguracji,
- terminal output,
- PCAP,
- profile zewnętrzne,
- schema metadata.

Wymagane:

- ścisłe schematy,
- limity rozmiarów,
- brak `eval`,
- brak renderowania terminala jako HTML,
- path traversal protection w kontenerze projektu,
- zip bomb protection,
- checksumy,
- version gates.

### 29.3. Parsery pakietów

Parsery są powierzchnią ataku nawet w lokalnej aplikacji, ponieważ importowany capture lub projekt może zawierać złośliwe dane. Wymagane są fuzzing, bounds checking i sanitizery.

### 29.4. Profile zachowania

Profile JSON nie mogą wstrzykiwać kodu. Nietypowy behavior module jest kompilowany i wybierany przez zaufany identyfikator capabilities.

### 29.5. CSP

Wdrożenie powinno docelowo używać Content Security Policy zgodnej z Wasm i Workerami, bez `unsafe-eval`, o ile toolchain na to pozwala. Wszelkie odstępstwa wymagają ADR.

---

## 30. Granice realizmu i duże prędkości

### 30.1. Packet-level fidelity

Każdy pakiet wygenerowany przez:

- protocol daemon,
- ping,
- traceroute,
- host application,
- ARP lub ND,
- DHCP,
- użytkownika,
- test interoperacyjny,

przechodzi indywidualnie przez pełny packet path.

### 30.2. Line rate

Przeglądarka nie jest w stanie utworzyć setek milionów minimalnych ramek na sekundę dla portów 100G lub wyższych. Nie wolno deklarować fizycznego packet-per-packet line rate dla takich profili.

### 30.3. Aggregate background load

Dopuszczalny jest jawnie oznaczony generator `AggregateLoad`, który:

- zużywa bitrate,
- wpływa na kolejki i QoS,
- wpływa na drop probability i opóźnienie,
- nie tworzy osobnego bufora dla każdej minimalnej ramki,
- nie jest używany dla control plane,
- nie jest ukrywany jako pełna packet fidelity,
- publikuje informację o trybie reprezentacji obciążenia.

To nie jest przyspieszanie czasu ani DES. Jest to analityczna reprezentacja wysokiego wolumenu ruchu w działającym na żywo medium.

### 30.4. Capability report

Każde laboratorium powinno pokazywać:

```text
packet-level flows
aggregate-load flows
host capacity estimate
runtime health
capture fidelity
modeled hardware timing confidence
```


---

## 31. Struktura repozytorium

```text
repo/
  apps/
    web/
      src/
        app/
        routes/
        topology/
        chassis/
        device-inspector/
        terminal/
        captures/
        routing-state/
        protocol-state/
        runtime-health/
        storage/
        wasm-bridge/
      public/
      vite.config.ts
      package.json

  packages/
    ui-protocol/
      src/
        commands.ts
        telemetry.ts
        cli.ts
        capabilities.ts

    project-format/
      src/
        manifest.ts
        migrations.ts
        validation.ts

    profile-schema/
      src/
        release.ts
        platform.ts
        hardware.ts
        capabilities.ts

  core/
    CMakeLists.txt

    runtime/
      supervisor/
      pthread-pool/
      shards/
      components/
      mailboxes/
      deadlines/
      runtime-health/
      shutdown/

    memory/
      packet-slab/
      descriptors/
      arenas/
      rings/
      reclamation/
      telemetry-pages/

    hardware/
      inventory/
      provisioning/
      reconciler/
      chassis/
      cpm/
      cards/
      forwarding-complexes/
      xiom/
      mda-xma/
      connectors/
      ports/
      fabric/
      resources/

    dataplane/
      packet/
      ethernet/
      vlan/
      classification/
      acl/
      qos/
      l2-forwarding/
      l3-forwarding/
      mpls/
      punt/
      egress/
      drops/

    netstack/
      sockets/
      arp/
      nd/
      ipv4/
      ipv6/
      icmpv4/
      icmpv6/
      udp/
      tcp/
      gre/
      vxlan/

    routing/
      instances/
      rib/
      route-selection/
      next-hop-resolution/
      adjacency/
      policies/
      fib-compiler/
      fib-programming/

    protocols/
      lldp/
      lacp/
      bfd/
      ospf/
      isis/
      bgp/
      ldp/
      rsvp/
      pim/

    services/
      sap/
      sdp/
      ies/
      vprn/
      vpls/
      epipe/
      ipipe/
      evpn/

    management/
      schema/
      configuration/
      activation/
      operational-state/
      authorization/
      cli-common/
      cli-md/
      cli-classic/
      netconf/
      gnmi/
      alarms/

    capture/
      taps/
      rings/
      pcapng/
      filters/

    storage/
      snapshots/
      serialization/
      migrations/

    wasm/
      exports/
      bootstrap/
      shared-abi/

  profiles/
    releases/
      sros-26.7/
        release.yaml
        defaults.yaml
        management-modes.yaml
        command-capabilities.yaml

    platforms/
      integrated-example/
      modular-example/

    cards/
    modules/
    forwarding-complexes/
    fabrics/
    timing/
    resources/

  schemas/
    source-catalog/
    ipc/
    cli/
      md/
        26.7/
      classic/
        26.7/
    config-ir/
    operational-ir/
    profile/

  tools/
    schema-compiler/
    command-catalog/
    source-validator/
    transcript-recorder/
    transcript-runner/
    pcap-validator/
    profile-linter/
    project-migrator/
    benchmark-runner/

  tests/
    unit/
    native/
    browser/
    concurrency/
    fuzz/
    packet-vectors/
    cli/
      md/
      classic/
      engine-switch/
    scenarios/
    interoperability/
    srsim-differential/
    pcap/
    performance/
    fixtures/

  docs/
    architecture/
    adr/
    sources/
    compatibility/
    development/

  cmake/
  scripts/
  .github/workflows/
  pnpm-workspace.yaml
  CMakePresets.json
  vercel.json
```

### 31.1. Monorepo

Frontend i narzędzia TypeScript używają `pnpm workspaces`. Rdzeń używa CMake. Root scripts powinny udostępniać jednolite komendy:

```text
pnpm install
pnpm dev
pnpm build
pnpm test
pnpm test:browser
pnpm test:cli
pnpm lint
pnpm source:validate
pnpm core:configure:native
pnpm core:test:native
pnpm core:build:wasm
pnpm bench
```

### 31.2. Buildy rdzenia

```text
native-debug
native-asan
native-ubsan
native-tsan
native-release
wasm-debug
wasm-release
wasm-pthreads-test
```

ASAN i TSAN nie muszą działać jednocześnie w jednym buildzie.

### 31.3. Wersjonowanie ABI

Współdzielone ABI UI-Wasm ma:

```text
major version
minor version
build hash
profile schema version
project format version
```

UI nie otwiera runtime z niezgodnym major ABI.

---

## 32. Interfejsy modułów

### 32.1. FeatureModule

```cpp
class FeatureModule {
public:
    virtual ~FeatureModule() = default;

    virtual ModuleId id() const = 0;
    virtual ValidationResult validate_config(
        const ConfigView& current,
        const ConfigDelta& delta,
        const CapabilityView& capabilities) const = 0;

    virtual ActivationResult apply_config(
        const ActivationOperation& operation,
        RuntimeContext& runtime) = 0;

    virtual void start(RuntimeContext& runtime) = 0;
    virtual void stop(StopReason reason) = 0;

    virtual void write_operational_state(
        OperationalStateWriter& writer) const = 0;

    virtual void write_counters(
        CounterWriter& writer) const = 0;
};
```

### 32.2. PacketConsumer

```cpp
class PacketConsumer {
public:
    virtual PacketDisposition receive(
        PacketHandle packet,
        const PacketIngressContext& context) = 0;
};
```

### 32.3. RouteProducer

```cpp
class RouteProducer {
public:
    virtual void publish_route_delta(RouteDelta&& delta) = 0;
    virtual void withdraw_all(RouteOwner owner) = 0;
};
```

### 32.4. InterfaceObserver

```cpp
class InterfaceObserver {
public:
    virtual void on_interface_state(
        const InterfaceStateChange& change) = 0;
};
```

### 32.5. Socket ownership

Socket handle jest lokalnym identyfikatorem w obrębie urządzenia. Proces nie przechowuje wskaźnika do portu remote ani remote process.

### 32.6. Generation checks

Każda dłuższa praca posiada input generation. Wynik jest odrzucany, jeżeli stan właściciela zmienił się przed powrotem.

---

## 33. Testowanie i walidacja

### 33.1. Warstwy testów

```text
unit tests
component tests
native integration tests
Wasm browser tests
concurrency stress tests
packet vector tests
parser fuzzing
CLI golden transcripts
scenario tests
protocol interoperability tests
SR-SIM differential tests
hardware differential tests
performance regression tests
```

### 33.2. Natywny build

Każdy komponent niezależny od browsera musi być testowalny natywnie. Natywny build umożliwia:

- AddressSanitizer,
- UndefinedBehaviorSanitizer,
- ThreadSanitizer,
- szybkie testy,
- fuzzing,
- profilowanie CPU i pamięci,
- deterministyczne fixtures.

### 33.3. Fuzzing

Obowiązkowe cele fuzzingu:

```text
Ethernet parser
ARP parser
IPv4 parser
ICMP parser
IPv6 parser
TCP parser
MPLS parser
protocol packet parsers
MD-CLI lexer/parser
classic CLI lexer/parser
project import
profile parser
PCAPNG parser if import is supported
```

Każdy parser musi przejść długotrwały fuzz run w CI okresowym.

### 33.4. Packet vectors

Wektory muszą zawierać:

- poprawne minimalne pakiety,
- maksymalne długości,
- malformed lengths,
- checksum errors,
- nested tags,
- unknown protocols,
- fragmentation,
- TTL and hop-limit cases,
- MTU behavior.

### 33.5. Scenariusze

Scenariusz jest deklaratywny:

```yaml
id: ipv4.static-routing.live-ping
profile_lock: sros-26.7
nodes: []
links: []
initial_inventory: []
initial_configs: []
actions:
  - at_real_time_after_start_ms: 0
    kind: power-on
  - wait_for_operational:
      condition: all-required-ports-up
      timeout_ms: 60000
  - cli_transcript: fixtures/...
  - command: ping
assertions:
  - arp_entry_exists
  - route_installed_on_fc
  - icmp_reply_received
  - pcap_matches_filter
```

Pole `at_real_time_after_start_ms` w testach integracyjnych nie jest osią czasu produktu. Jest timeoutem i kolejnością automatyzacji testu.

### 33.6. SR-SIM jako oracle

SR-SIM służy do porównania:

- konfiguracji,
- walidacji,
- defaultów,
- promptów i CLI,
- outputu komend,
- stanów protokołów,
- RIB i FIB,
- packet formats,
- reakcji na zmianę konfiguracji.

Nie jest źródłem dokładnego hardware timing, ponieważ Nokia wskazuje różnice wynikające z braku hardware data path.

Źródła:

- Overview: https://documentation.nokia.com/sr/25-7/7x50-shared/srsim-installation-setup/sr-sim-overview.html
- Deployment options: https://documentation.nokia.com/sr/25-7/7x50-shared/srsim-installation-setup/sr-sim-deployment-options.html
- Functional models: https://documentation.nokia.com/sr/25-7/7x50-shared/srsim-installation-setup/sr-sim-functional-models.html
- Data path interfaces: https://documentation.nokia.com/sr/25-7/7x50-shared/srsim-installation-setup/data-path-interfaces.html
- Guide title: https://documentation.nokia.com/sr/25-7/7750-sr/titles/sr-sim-installation-setup.html
- Guide PDF: https://documentation.nokia.com/sr/25-7/7750-sr/pdf/SR-SIM_Installation_and_Setup_Guide_25.7.R1.pdf

### 33.7. Differential runner

Narzędzie powinno:

1. Załadować ten sam logiczny scenariusz do emulatora i SR-SIM.
2. Wykonać odpowiednie komendy dla każdego systemu.
3. Normalizować pola niestabilne, na przykład timestamp.
4. Porównać:
   - terminal transcript,
   - operational state,
   - RIB/FIB,
   - packet capture,
   - alarms.
5. Wygenerować raport rozbieżności z source IDs.

### 33.8. Wireshark

Każdy nowy kodek protokołu powinien mieć test, w którym PCAPNG jest analizowany przez `tshark` w CI, jeżeli licencja i środowisko CI na to pozwalają.

### 33.9. Testy wielowątkowe

Minimalne przypadki:

```text
mailbox ordering per producer
bounded queue overflow
packet refcount under replication
safe FIB generation swap
epoch reclamation
concurrent card removal and packet forwarding
CPM restart while FC forwards
simultaneous CLI sessions
MD exclusive lock
classic write during mixed mode
protocol timer and packet arrival race
shutdown with busy queues
```

### 33.10. Testy wydajności

Benchmarki:

```text
packet slab alloc/free
SPSC and MPSC ring
Ethernet parse
IPv4 lookup
FIB generation swap
packet through 1 FC
packet through fabric and 2 FCs
ARP resolution
CLI completion on large schema
screen renderer transcript
PCAPNG writer
```

CI powinno wykrywać istotne regresje, ale progi browserowe muszą uwzględniać zmienność runnera.

### 33.11. Brak flaky timing tests

Testy real-time muszą używać rozsądnych timeoutów i warunków operacyjnych, a nie `sleep(10ms)` jako jedynego assertion. Dla krytycznej semantyki istnieją osobno szybkie testy z ManualClock oraz live integration tests.

---

## 34. Pierwszy pionowy przekrój

### 34.1. Topologia referencyjna

```text
Host A
  |
Router R1, modular Nokia profile
  |
Router R2, modular Nokia profile
  |
Host B
```

Dopuszczalny wcześniejszy smoke scenario:

```text
Host A - Router R1 - Host B
```

Końcowy pionowy przekrój wymaga co najmniej dwóch routerów, aby przetestować dwa niezależne control i data plane.

### 34.2. Wymagany sprzęt

Każdy router posiada:

```text
chassis
CPM
jedną kartę
co najmniej jeden forwarding complex
dwa moduły portowe lub dwa porty na module
fabric abstraction
physical inventory
provisioned config
```

Co najmniej jeden profil testowy powinien posiadać dwa FC, aby przetestować fabric path.

### 34.3. Wymagany packet path

Ping musi spowodować:

```text
route lookup on source
ARP miss
actual ARP Request
serialization and propagation
ARP processing on router
ARP Reply
ICMP Echo Request
router FIB lookup
TTL decrement
checksum update
next-hop ARP if needed
fabric crossing if selected egress is on another FC
egress queue
second link
ICMP Echo Reply
```

### 34.4. Wymagane CLI

Użytkownik może skonfigurować R1 przez MD-CLI, R2 przez classic CLI, albo odwrotnie. Wynik semantyczny jest zgodny, ale zachowanie sesji pozostaje natywne dla engine.

Wymagane mechanics:

```text
MD two-line prompt
Classic hierarchical prompt
?
help where appropriate
Tab completion
Space completion according to engine
Enter completion according to MD settings
history
line editing subset
pager
context navigation
// switch
one-shot cross-engine command
MD candidate, compare, commit, discard
Classic immediate apply
```

### 34.5. Wymagane capture

Użytkownik może uruchomić live capture na:

- wybranym link direction,
- ingress port,
- egress port,
- CPM punt path.

Capture pokazuje ARP i ICMP oraz eksportuje poprawny PCAPNG.

### 34.6. Wymagane awarie

Podczas działającego ping:

1. Użytkownik usuwa kartę albo wyłącza port.
2. Port oper przechodzi down.
3. Interfejs L3 przechodzi down.
4. Connected route jest wycofana.
5. FIB jest przeprogramowany.
6. Pakiety są dropowane z właściwym reason.
7. Alarm jest generowany.
8. CLI `show` odzwierciedla equipped, provisioned i operational state.

### 34.7. Restart CPM

Minimalny model restartu CPM:

- CLI sesja jest zrywana lub zachowuje się zgodnie z profilem,
- control plane przestaje obsługiwać nowe pakiety,
- istniejące FC nie kasują automatycznie aktywnego FIB,
- forwarding istniejących tras może trwać,
- brak nowych adjacency lub protokół może wpłynąć po timeoutach,
- ponowna inicjalizacja CPM synchronizuje stan.

Pełne NSF i NSR są późniejszym etapem, ale model nie może ich uniemożliwić.

### 34.8. Kryteria ukończenia

Pionowy przekrój jest ukończony, gdy:

- działa ze statycznego Vercel deployment,
- `crossOriginIsolated` jest true,
- pthread smoke test potwierdza realną równoległość,
- control i forwarding/link wykonują się w niezależnych shardach,
- oba CLI spełniają transcript tests dla wspólnego subsetu,
- ping przechodzi przez prawdziwe bajty pakietów,
- RIB i FIB są odrębne,
- FIB istnieje per FC,
- ARP jest rzeczywistą wymianą pakietów,
- kolejki i serializacja wpływają na czas,
- PCAPNG jest poprawny,
- awaria sprzętu powoduje kaskadę,
- projekt można zapisać, zamknąć, zaimportować i odtworzyć,
- nie ma żadnego API Run, Pause, Step lub speed multiplier.

---

## 35. Etapy implementacji

### Etap 0. Repozytorium, źródła i reguły

Zakres:

```text
pnpm workspace
Vite React shell
CMake native library
Emscripten toolchain
source catalog schema
capability schema
ADR template
CI skeleton
formatting and linting
```

Definition of Done:

- `pnpm build` tworzy statyczny frontend,
- native C++ test przechodzi,
- source validator działa na przykładowym rekordzie,
- CI wykonuje TypeScript i C++ checks,
- brak packet/runtime logic.

### Etap 1. Cross-origin isolation i pthread smoke test

Zakres:

```text
vercel.json
SharedArrayBuffer capability gate
Emscripten pthread pool
PROXY_TO_PTHREAD
shared counter test
worker wake/sleep test
runtime capability report
```

Definition of Done:

- lokalny dev server i Vercel preview mają COOP/COEP,
- `crossOriginIsolated` jest true,
- minimum dwa pthreads wykonują równoległe zadania,
- brak jednowątkowego fallbacku,
- UI pokazuje diagnostykę startową.

### Etap 2. Runtime, shardy i pamięć

Zakres:

```text
RuntimeSupervisor
ComponentId and ShardId
fixed pthread pool
SPSC/MPSC rings
futex wake/sleep
steady_clock deadlines
runtime lag metrics
packet slab skeleton
shared telemetry ABI
controlled shutdown
```

Definition of Done:

- 100000 nieaktywnych komponentów nie powoduje busy loop,
- wiadomość budzi właściwy shard,
- overflow ma licznik i politykę,
- TSAN build nie raportuje znanych race,
- host lag jest mierzalny.

### Etap 3. Terminal i oba shell mechanics

Zakres:

```text
xterm bridge
CliSession
VT output
line editor
MD prompt skeleton
Classic prompt skeleton
?
help
Tab and Space completion foundations
history
pager
engine switch
transcript runner
```

Bez konfiguracji sieciowej, ale z małym testowym command tree.

Definition of Done:

- sekwencje klawiszy przechodzą przez C++,
- ekran i cursor są testowane,
- MD i classic zachowują osobne konteksty,
- `//` działa,
- Ctrl-C i resize działają.

### Etap 4. Kanoniczna konfiguracja i minimalne schematy CLI

Zakres:

```text
canonical config tree
operational tree
schema registry
source-linked command nodes
MD candidate/running
classic immediate apply
validation phases
activation plan
management modes skeleton
```

Definition of Done:

- ten sam parametr można ustawić przez oba CLI,
- MD wymaga commit,
- classic stosuje natychmiast,
- compare i discard działają,
- unsupported command nie pojawia się w completion.

### Etap 5. Hardware inventory i provisioning

Zakres:

```text
HardwarePath
chassis profiles
inventory tree
provisioned tree
orthogonal state dimensions
reconciler
real boot timers
card/module/port CLI subset
chassis UI
alarms
```

Definition of Done:

- insert/remove działa live,
- mismatch pozostaje offline,
- port config może istnieć przy absent hardware,
- show/info pokazuje właściwe widoki,
- profile są wersjonowane.

### Etap 6. Packet memory, Ethernet, port i link

Zakres:

```text
packet slab
packet descriptor
Ethernet codec
port RX/TX rings
FIFO byte queue
tail drop
serializer
full-duplex link
real propagation delay
capture tap
PCAPNG writer
```

Definition of Done:

- ramka przechodzi przez dwa fizyczne endpointy,
- bitrate wpływa na transmit time,
- queue overflow daje drop,
- PCAPNG otwiera się w Wiresharku,
- nie ma globalnego event heap.

### Etap 7. FC, fabric, punt i hardware resources

Zakres:

```text
ForwardingComplex
basic ingress/egress pipeline
fabric plane
local output and punt
CPM queue
resource manager skeleton
immutable generation infrastructure
```

Definition of Done:

- ramka może przejść między dwoma FC,
- fabric ma limit i kolejkę,
- punt przechodzi przez policer i bounded queue,
- packet path nie używa globalnych locków.

### Etap 8. IPv4 pionowy przekrój

Zakres:

```text
ARP
IPv4
ICMPv4
network interface
system interface
connected routes
static routes
route selection
adjacency
FIB compiler
per-FC FIB programming
ping
show route/FIB/ARP
```

Definition of Done:

- spełnione kryteria z sekcji 34,
- oba CLI konfigurują całość,
- awaria hardware powoduje prawidłową kaskadę,
- capture zawiera ARP i ICMP.

### Etap 9. L2

Zakres:

```text
VLAN
QinQ foundation
bridge domain
FDB learning and aging
unknown unicast flooding
broadcast
static LAG
LACP
LLDP
```

Definition of Done:

- loop rzeczywiście powoduje flooding i obciążenie,
- LAG jest osobnym logical object,
- LACP używa prawdziwych slow protocol frames.

### Etap 10. IPv6

Zakres:

```text
IPv6
ICMPv6
ND
SLAAC where in scope
IPv6 RIB/FIB
IPv6 CLI and show
```

### Etap 11. BFD, OSPF i IS-IS

Zakres:

```text
BFD FSM
OSPFv2
OSPFv3 after IPv6 readiness
IS-IS
protocol RIBs
SPF compute jobs
failure convergence
```

Definition of Done:

- sąsiedztwa powstają wyłącznie przez pakiety,
- brak globalnej wiedzy topologicznej,
- route changes przechodzą przez RIB/FIB.

### Etap 12. TCP, BGP i policy engine

Zakres:

```text
TCP stream
BGP FSM
Adj-RIB-In/Out
Loc-RIB integration
common policy engine
communities and attributes foundation
```

### Etap 13. MPLS i segment routing

Zakres:

```text
MPLS data plane
label resources
LDP
RSVP-TE
SR-MPLS
label stack capture and show
```

### Etap 14. Services i EVPN

Zakres:

```text
SAP
SDP
IES
VPRN
VPLS
Epipe/Ipipe
EVPN
VXLAN where supported
```

### Etap 15. QoS, multicast, management i HA

Zakres:

```text
hierarchical QoS
ACL and TCAM resources
PIM and multicast
NETCONF
gNMI
telemetry
CPM redundancy
NSF/NSR behavior
saved configuration semantics
```

---

## 36. Pierwsze zadania dla Codex

Codex powinien rozpocząć w następującej kolejności. Każde zadanie ma kończyć się działającym kodem i testem.

### Zadanie 1. Szkielet monorepo

Utwórz:

```text
pnpm-workspace.yaml
apps/web
packages/ui-protocol
packages/project-format
core/CMakeLists.txt
CMakePresets.json
vercel.json
```

Dodaj root scripts i minimalne README developerskie.

### Zadanie 2. Source catalog

Utwórz JSON Schema lub równoważny schemat dla rekordów źródeł. Dodaj:

- loader,
- validator,
- CI command,
- dwa rekordy MD-CLI,
- dwa rekordy classic CLI,
- jeden rekord Emscripten pthreads.

### Zadanie 3. Cross-origin isolated Vite app

Dodaj:

- React shell,
- runtime prerequisites page,
- sprawdzenie `crossOriginIsolated`,
- sprawdzenie SharedArrayBuffer,
- diagnostykę `hardwareConcurrency`,
- Vercel headers,
- lokalny dev server z tymi samymi nagłówkami.

### Zadanie 4. Emscripten pthread proof

Zbuduj mały C++ runtime, który:

- uruchamia main poza UI thread,
- ma pulę co najmniej dwóch pthreadów,
- wykonuje niezależne zadania,
- zapisuje wynik do shared memory,
- budzi uśpiony worker,
- publikuje telemetry page do Reacta.

### Zadanie 5. Shared ABI

Zdefiniuj:

```text
RuntimeAbiHeader
CapabilityPage
TelemetryPageHeader
CommandRingHeader
CliInputRingHeader
CliOutputRingHeader
```

Dodaj alignment assertions, endian assumptions, ABI version check i testy C++/TypeScript.

### Zadanie 6. Shard runtime

Zaimplementuj:

- `ComponentId`,
- `ShardId`,
- fixed assignment,
- SPSC ring,
- MPSC ring,
- wait/notify,
- controlled stop,
- host lag metrics.

### Zadanie 7. xterm raw bridge

Dodaj xterm.js. Każde `onData` ma trafić do CLI input ring. Nie implementuj lokalnego parsera linii w React.

### Zadanie 8. CliSession i test terminala

W C++ utwórz:

- line buffer,
- cursor movement,
- backspace,
- Enter,
- Tab event,
- `?` event,
- Ctrl-C,
- VT output.

Dodaj native transcript runner i prosty VT screen model.

### Zadanie 9. Dwa minimalne engine

Utwórz:

```text
MdCliEngine
ClassicCliEngine
```

Każdy ma inny prompt i mały, statyczny command tree z `help`, `?`, completion i context. Zaimplementuj `//` oraz zachowanie osobnych kontekstów.

### Zadanie 10. Golden fixtures ze źródeł

Przygotuj pierwsze fixtures na podstawie oficjalnej dokumentacji oraz ręcznej sesji SR-SIM, jeżeli środowisko jest dostępne. Każdy fixture ma source IDs.

### Zadanie 11. Canonical config proof

Dodaj jedno pole, na przykład system name, dostępne w obu CLI:

- MD: candidate, compare, commit, discard,
- classic: immediate apply.

Prompt ma aktualizować hostname zgodnie z aktywnym stanem.

### Zadanie 12. Hardware profile proof

Dodaj minimalne chassis, card i module profile. Zaimplementuj inventory, provisioning i mismatch. Bez packet path.

Nie rozpoczynaj OSPF, BGP ani pełnego React Flow przed ukończeniem powyższych zadań.

---

## 37. ADR wymagane przed dalszą implementacją

Należy utworzyć co najmniej następujące Architecture Decision Records:

```text
ADR-0001 Product is a live real-time emulator, not DES
ADR-0002 C++20 and Emscripten pthreads
ADR-0003 Fixed thread pool and shard ownership
ADR-0004 Shared packet memory and descriptor model
ADR-0005 Immutable per-FC FIB generations
ADR-0006 Separate MD and classic CLI engines
ADR-0007 Canonical configuration and operational trees
ADR-0008 Source provenance and release pinning
ADR-0009 Static Vercel deployment with COOP/COEP
ADR-0010 Local persistence and .netsim format
ADR-0011 No direct device-to-device calls
ADR-0012 Packet-level fidelity and aggregate high-rate load boundary
ADR-0013 Native build as primary verification environment
ADR-0014 SR-SIM differential testing policy
```

Każdy ADR zawiera:

```text
context
decision
alternatives
consequences
security impact
compatibility impact
test obligations
migration conditions
```

---

## 38. Definition of Done projektu i funkcji

### 38.1. Kod

- kompiluje się natywnie i do Wasm, jeżeli moduł należy do rdzenia,
- ma brak ostrzeżeń w przyjętym profilu,
- przechodzi formatter i linter,
- nie wprowadza globalnego mutable singleton bez ADR,
- nie alokuje na hot path bez uzasadnienia i benchmarku.

### 38.2. Zgodność

- źródła są zapisane,
- release i platforma są określone,
- capability matrix jest zaktualizowana,
- CLI help/completion nie pokazuje nieaktywnej funkcji,
- packet behavior ma normatywne wektory,
- różnice wobec SR-SIM są opisane.

### 38.3. Testy

- unit tests,
- integration test,
- error path,
- concurrency test, jeżeli dotyczy,
- golden transcript dla CLI,
- capture test dla protokołu,
- sanitizer pass dla kodu C++.

### 38.4. Obserwowalność

- liczniki,
- drop reason,
- operational state,
- alarm lub error reporting,
- runtime health impact.

### 38.5. Dokumentacja

- source record,
- public capability status,
- known limitations,
- migration note, jeżeli format zmienił się.


---

## 39. Jawnie odrzucone rozwiązania

Nie należy implementować:

1. Globalnego discrete-event simulation schedulera.
2. Wirtualnego czasu i centralnego event heap.
3. Osi czasu, Run, Pause, Step, 1x, 10x, fast-forward lub rewind.
4. Jednego Web Workera dla całego rdzenia.
5. Jednego Web Workera albo pthreada na router, port lub protokół.
6. TypeScript-only packet forwarding core.
7. Bezpośrednich wywołań pomiędzy urządzeniami.
8. Globalnego algorytmu routingu znającego graf React Flow.
9. Jednego uniwersalnego obiektu `Interface` dla portu, LAG, VLAN, IP i SAP.
10. Jednego globalnego FIB dla całego routera.
11. Globalnego locka na FIB lookup.
12. CLI modyfikującego bezpośrednio FIB lub protocol state.
13. Jednego parsera udającego jednocześnie MD i classic CLI.
14. Komend zgodności, które zwracają sukces bez działania.
15. Tworzenia portu dopiero po osiągnięciu `MDA up`.
16. Płaskiego enumu łączącego presence, provisioning, admin, lifecycle i oper.
17. Założenia, że każdy sprzęt da się opisać wyłącznie JSON-em.
18. Animowania każdego pakietu przez React state lub DOM.
19. Wysyłania każdego pakietu do UI przez `postMessage`.
20. Nielimitowanych capture buffers.
21. Przechowywania całego projektu wyłącznie w localStorage.
22. Runtime w Vercel Functions.
23. Service workera udającego działający router po zamknięciu strony.
24. Deklaracji packet-per-packet line rate dla 100G, 400G lub 800G bez pomiarów.
25. Kopiowania dużych fragmentów dokumentacji Nokia do repozytorium.
26. Używania blogów jako normatywnego źródła komend lub protokołu.
27. Cichego jednowątkowego fallbacku.
28. Ukrywania host runtime lag jako modelowanego przeciążenia urządzenia.

---

## 40. Macierz norm i standardów

Poniższa lista jest minimalnym katalogiem normatywnym. Implementacja powinna dodawać kolejne dokumenty wraz z rozszerzaniem zakresu.

### 40.1. Ethernet, bridging i link aggregation

- IEEE 802.3 Ethernet: https://standards.ieee.org/ieee/802.3/10422/
- IEEE 802.1Q Bridges and Bridged Networks: https://standards.ieee.org/standard/802_1Q-2018.html
- IEEE 802.1AX Link Aggregation: https://standards.ieee.org/ieee/802.1AX/6768/
- IEEE 802 overview: https://standards.ieee.org/featured/ieee-802/

Zakres implementacyjny:

```text
Ethernet frame format
MAC behavior
full-duplex assumptions
VLAN tagging
bridging and FDB
LAG and LACP
wire overhead and link timing
```

### 40.2. IPv4 i podstawy transportu

- ARP, RFC 826: https://www.rfc-editor.org/rfc/rfc826.html
- Requirements for IPv4 Routers, RFC 1812: https://www.rfc-editor.org/rfc/rfc1812.html
- UDP, RFC 768: https://www.rfc-editor.org/rfc/rfc768.html
- TCP, RFC 9293: https://www.rfc-editor.org/rfc/rfc9293.html
- DHCPv4, RFC 2131: https://www.rfc-editor.org/rfc/rfc2131.html

### 40.3. IPv6

- IPv6 Specification, RFC 8200: https://www.rfc-editor.org/rfc/rfc8200.html
- Neighbor Discovery, RFC 4861: https://www.rfc-editor.org/rfc/rfc4861.html
- ICMPv6, RFC 4443: https://www.rfc-editor.org/rfc/rfc4443.html
- DHCPv6, RFC 8415: https://www.rfc-editor.org/rfc/rfc8415.html

### 40.4. Routing

- OSPFv2, RFC 2328: https://www.rfc-editor.org/rfc/rfc2328.html
- OSPFv3, RFC 5340: https://www.rfc-editor.org/rfc/rfc5340.html
- Integrated IS-IS, RFC 1195: https://www.rfc-editor.org/rfc/rfc1195.html
- BGP-4, RFC 4271: https://www.rfc-editor.org/rfc/rfc4271.html
- Default EBGP Route Propagation Behavior, RFC 8212: https://www.rfc-editor.org/rfc/rfc8212.html
- BFD, RFC 5880: https://www.rfc-editor.org/rfc/rfc5880.html
- VRRPv3, RFC 5798: https://www.rfc-editor.org/rfc/rfc5798.html

### 40.5. MPLS, traffic engineering i segment routing

- MPLS Architecture, RFC 3031: https://www.rfc-editor.org/rfc/rfc3031.html
- LDP Specification, RFC 5036: https://www.rfc-editor.org/rfc/rfc5036.html
- RSVP-TE, RFC 3209: https://www.rfc-editor.org/rfc/rfc3209.html
- Segment Routing Architecture, RFC 8402: https://www.rfc-editor.org/rfc/rfc8402.html
- Segment Routing with MPLS Data Plane, RFC 8660: https://www.rfc-editor.org/rfc/rfc8660.html

### 40.6. Multicast

- PIM-SM, RFC 7761: https://www.rfc-editor.org/rfc/rfc7761.html

### 40.7. VPN i overlay

- BGP/MPLS IP VPNs, RFC 4364: https://www.rfc-editor.org/rfc/rfc4364.html
- EVPN, RFC 7432: https://www.rfc-editor.org/rfc/rfc7432.html
- VPLS using BGP, RFC 4761: https://www.rfc-editor.org/rfc/rfc4761.html
- VPLS using LDP, RFC 4762: https://www.rfc-editor.org/rfc/rfc4762.html
- VXLAN, RFC 7348: https://www.rfc-editor.org/rfc/rfc7348.html

### 40.8. Management

- NETCONF, RFC 6241: https://www.rfc-editor.org/rfc/rfc6241.html
- With-defaults, RFC 6243: https://www.rfc-editor.org/rfc/rfc6243.html
- YANG 1.1, RFC 7950: https://www.rfc-editor.org/rfc/rfc7950.html
- NMDA, RFC 8342: https://www.rfc-editor.org/rfc/rfc8342.html

### 40.9. IANA

- Protocol registries: https://www.iana.org/protocols
- Assigned Internet Protocol Numbers: https://www.iana.org/assignments/protocol-numbers
- Service Name and Transport Protocol Port Number Registry: https://www.iana.org/assignments/service-names-port-numbers

Nie należy wpisywać magicznych numerów protokołów, Ethertype ani portów bez odwołania do właściwego rejestru lub normy.

---

## 41. Oficjalny katalog dokumentacji Nokia

### 41.1. Baseline SR OS 26.7.R1

#### CLI i zarządzanie

- MD-CLI User Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/md-cli-user.html
- MD-CLI navigation: https://documentation.nokia.com/sr/26-7/7x50-shared/md-cli-user/navigate.html
- MD-CLI editing configuration: https://documentation.nokia.com/sr/26-7/7x50-shared/md-cli-user/edit-configuration.html
- Engine switching: https://documentation.nokia.com/sr/26-7/7x50-shared/md-cli-user/switch-between-classic-cli-md-cli-engines.html
- Classic to MD configuration guidance: https://documentation.nokia.com/sr/26-7/7x50-shared/md-cli-user/creating-md-cli-configuration-from-classic-cli.html
- MD-CLI Command Reference: https://documentation.nokia.com/sr/26-7/7750-sr/titles/md-cli-command-reference.html
- MD-CLI Explorer: https://documentation.nokia.com/sr/26-7/mdcli-explorer/index.html
- Classic CLI Command Reference: https://documentation.nokia.com/sr/26-7/7750-sr/titles/classic-cli-command-reference.html
- Classic CLI overview: https://documentation.nokia.com/sr/26-7/7x50-shared/classic-cli-command-reference/classic-cli-overview.html
- Clear, Monitor, Show and Tools Command Reference: https://documentation.nokia.com/sr/26-7/7750-sr/titles/clear-monitor-show-tools-commands.html
- Product reference category: https://documentation.nokia.com/sr/26-7/7750-sr/html/product/reference.html
- Model-driven management interfaces: https://documentation.nokia.com/sr/26-7/7x50-shared/system-management/model-driven-management-interfaces.html
- Nokia YANG Browser: https://yangbrowser.nokia.com/sros

#### System i sprzęt

- System Management Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/system-management.html
- Basic System Configuration Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/basic-system-configuration.html
- Interface Configuration Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/interface-configuration.html
- Configuration overview: https://documentation.nokia.com/sr/26-7/7750-sr/books/interface-configuration/configuration-overview.html
- Deploy preprovisioned components: https://documentation.nokia.com/sr/26-7/7x50-shared/interface-configuration/deploy-preprovisioned-components.html
- Ports: https://documentation.nokia.com/sr/26-7/7750-sr/books/interface-configuration/ports.html
- FP4 datapath mapping: https://documentation.nokia.com/sr/26-7/7750-sr/books/interface-configuration/fp4-datapath-mapp.html
- LAG: https://documentation.nokia.com/sr/26-7/7750-sr/books/interface-configuration/lag.html
- Fabric speed: https://documentation.nokia.com/sr/26-7/7750-sr/books/interface-configuration/sett-fabric-speed.html

#### Routing, MPLS i usługi

- Router Configuration Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/router-configuration.html
- Unicast Routing Protocols Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/unicast-routing-protocols.html
- MPLS Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/mpls.html
- Segment Routing and PCE Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/segment-routing-pce-user.html
- Multicast Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/multicast.html
- QoS Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/qos.html
- Services Overview: https://documentation.nokia.com/sr/26-7/7750-sr/titles/services-overview.html
- Layer 2 Services and EVPN Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/layer-2-services-evpn.html
- Layer 3 Services Guide: https://documentation.nokia.com/sr/26-7/7750-sr/titles/layer-3-services.html
- Standards and protocol support: https://documentation.nokia.com/sr/26-7/7750-sr/books/common/dita_standards-5.html

### 41.2. SR-SIM

- Overview: https://documentation.nokia.com/sr/25-7/7x50-shared/srsim-installation-setup/sr-sim-overview.html
- Deployment options: https://documentation.nokia.com/sr/25-7/7x50-shared/srsim-installation-setup/sr-sim-deployment-options.html
- Functional models: https://documentation.nokia.com/sr/25-7/7x50-shared/srsim-installation-setup/sr-sim-functional-models.html
- Data path interfaces: https://documentation.nokia.com/sr/25-7/7x50-shared/srsim-installation-setup/data-path-interfaces.html
- Guide title: https://documentation.nokia.com/sr/25-7/7750-sr/titles/sr-sim-installation-setup.html
- Guide PDF: https://documentation.nokia.com/sr/25-7/7750-sr/pdf/SR-SIM_Installation_and_Setup_Guide_25.7.R1.pdf

### 41.3. Starsze linki wykorzystane podczas wcześniejszego researchu

Poniższe linki są zachowane dla pełnej ścieżki źródeł, ale nie są baseline implementacyjnym. W przypadku konfliktu należy używać przypiętego wydania 26.7.R1.

- SR OS 26.3 configuration overview: https://documentation.nokia.com/sr/26-3/7750-sr/books/interface-configuration/configuration-overview.html
- SR OS 26.3 LAG: https://documentation.nokia.com/sr/26-3/7750-sr/books/interface-configuration/lag.html
- SR OS 26.3 management configuration quick reference: https://documentation.nokia.com/sr/26-3/7750-sr/books/peering-quick-reference/configuring_management.html
- SR OS 26.3 initialization and boot options: https://documentation.nokia.com/sr/26-3/7x50-shared/basic-system-configuration/system-initialization-and-boot-options.html
- SR OS 26.3 MD-CLI editing: https://documentation.nokia.com/sr/26-3/7x50-shared/md-cli-user/edit-configuration.html
- SR OS 26.3 port cross-connect and forwarding complex reference: https://documentation.nokia.com/sr/26-3/7750-sr/books/interface-configuration/port-cross-connect.html
- SR OS 25.7 system management: https://documentation.nokia.com/sr/25-7/7x50-shared/basic-system-configuration/system-management.html

---

## 42. Dokumentacja frameworków i platformy

### 42.1. Browser i Wasm

- Emscripten pthreads: https://emscripten.org/docs/porting/pthreads.html
- SharedArrayBuffer: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer
- Atomics.wait: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Atomics/wait
- Web Workers specification: https://html.spec.whatwg.org/multipage/workers.html
- Page Lifecycle API: https://developer.chrome.com/docs/web-platform/page-lifecycle-api
- COOP and COEP: https://web.dev/articles/why-coop-coep
- IFrame credentialless, pomocniczy materiał web-platform wykorzystany we wcześniejszym researchu: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/IFrame_credentialless
- WebAssembly nondeterminism: https://webassembly.org/docs/nondeterminism/
- wasm-bindgen reference: https://rustwasm.github.io/docs/wasm-bindgen/
- wasm-bindgen-rayon reference: https://docs.rs/wasm-bindgen-rayon

### 42.2. Frontend

- TanStack Router: https://tanstack.com/router/latest/docs/framework/react/overview
- TanStack Query: https://tanstack.com/query/latest/docs/framework/react/overview
- TanStack Start: https://tanstack.com/start/latest/docs/framework/react/overview
- React Flow handles: https://reactflow.dev/learn/customization/handles
- React Flow performance: https://reactflow.dev/learn/advanced-use/performance
- xterm.js security: https://xtermjs.org/docs/guides/security/

### 42.3. Storage

- IndexedDB: https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API
- OPFS: https://developer.mozilla.org/en-US/docs/Web/API/File_System_API/Origin_private_file_system

### 42.4. Vercel

- Vite deployment: https://vercel.com/docs/frameworks/frontend/vite
- Project configuration: https://vercel.com/docs/project-configuration/vercel-json
- Rewrites: https://vercel.com/docs/routing/rewrites
- Hobby plan: https://vercel.com/docs/plans/hobby
- WebSockets and Functions: https://vercel.com/docs/functions/websockets

### 42.5. Pipeline model

- P4-16 specification: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html

---

## 43. Ryzyka i strategie ograniczania

### 43.1. Zakres całego SR OS

Ryzyko: pełna funkcjonalność SR OS jest ogromna.

Strategia:

- capability matrix,
- pionowe przekroje,
- wspólne fundamenty,
- brak no-op command breadth,
- release pinning,
- osobny status każdej funkcji.

### 43.2. Dokładność CLI

Ryzyko: dokumentacja nie opisuje każdego terminalowego detalu.

Strategia:

- transcript recorder,
- SR-SIM/vSIM oracle,
- exact screen tests,
- source provenance,
- wersjonowane renderery.

### 43.3. Browser scheduling

Ryzyko: karta może zostać opóźniona lub zamrożona.

Strategia:

- host lag metrics,
- lifecycle detection,
- checkpoint,
- continuity invalidation,
- brak fałszywego catch-up.

### 43.4. Shared memory bugs

Ryzyko: race, UAF, ABA, błędne memory order.

Strategia:

- single-owner state,
- minimalny zestaw lock-free primitives,
- TSAN native build,
- epoch reclamation,
- formalnie opisane invariants,
- stress tests.

### 43.5. Pamięć

Ryzyko: packet capture i duża topologia wyczerpią pamięć.

Strategia:

- bounded buffers,
- packet pools,
- capture ring limits,
- OPFS spill,
- high watermark,
- admission control przed uruchomieniem labu.

### 43.6. COEP i zewnętrzne zasoby

Ryzyko: zasoby third-party zostaną zablokowane.

Strategia:

- self-host critical assets,
- test preview deployment,
- CSP/COEP CI checks,
- brak zależności runtime od zewnętrznego CDN.

### 43.7. Zgodność timingowa

Ryzyko: brak publicznych danych o hardware.

Strategia:

- jawny poziom confidence,
- wartości profilowane,
- pomiary laboratoryjne,
- brak nieuzasadnionych deklaracji exact timing.

### 43.8. Wydajność packet path

Ryzyko: przeglądarka nie utrzyma dużego packet rate.

Strategia:

- C++ Wasm,
- packet slabs,
- zero-copy descriptors,
- immutable FIB,
- batch telemetry,
- aggregate background load,
- benchmark gates.

### 43.9. Licencje dokumentacji i modeli

Ryzyko: nieuprawniona redystrybucja materiałów Nokia.

Strategia:

- linki i source IDs,
- własne implementacje,
- minimalne teksty kompatybilności,
- lokalne narzędzia importu modeli,
- przegląd licencji przed commitowaniem danych.

---

## 44. Glosariusz

**Baseline configuration**  
Konfiguracja bazowa używana przy pracy z candidate.

**Candidate configuration**  
Niezatwierdzone zmiany MD-CLI.

**Canonical configuration**  
Wspólny typowany model semantyczny, na który mapują się oba CLI.

**CPM**  
Domena control plane i management urządzenia Nokia.

**Data plane**  
Ścieżka przetwarzania i przekazywania pakietów.

**Forwarding complex, FC**  
Jednostka data plane posiadająca lokalny pipeline, FIB i zasoby.

**Fabric**  
Wewnętrzny transport pomiędzy linecardami lub forwarding complexes.

**FIB**  
Tablica i struktury używane przez data plane do forwardingu.

**Inventory**  
Fizycznie obecne elementy urządzenia.

**Intended state**  
Efektywny wynik konfiguracji i defaultów.

**MD-CLI**  
Model-driven CLI SR OS, oparte na modelu i transakcyjnym candidate/commit.

**Classic CLI**  
Hierarchiczne CLI SR OS z natychmiastowym stosowaniem typowych zmian.

**Operational state**  
Stan rzeczywiście działających komponentów.

**Provisioned configuration**  
Konfiguracja oczekiwanego typu hardware.

**Punt**  
Przekazanie pakietu z data plane do control plane.

**RIB**  
Routing Information Base, stan tras control plane.

**Runtime host lag**  
Opóźnienie wykonania spowodowane hostem i przeglądarką, odrębne od modelowanego przeciążenia urządzenia.

**Shard**  
Sekwencyjna domena wykonawcza posiadająca grupę komponentów.

**SR-SIM**  
Oficjalna symulowana wersja SR OS używana jako oracle zachowania, z ograniczeniami hardware data path.

---

## 45. Końcowa lista kontrolna architektury

Przed rozpoczęciem implementacji protokołu należy odpowiedzieć `tak` na wszystkie właściwe pytania:

### Runtime

- Czy funkcja działa względem `steady_clock`, bez wirtualnego czasu?
- Czy nie wprowadza globalnego schedulera przyszłych zdarzeń?
- Czy stateful owner jest jednoznaczny?
- Czy mailbox jest ograniczony?
- Czy zachowanie overflow jest jawne?
- Czy host lag i device load są rozdzielone?

### Packet path

- Czy komunikacja używa rzeczywistych bajtów pakietu?
- Czy przechodzi przez socket, punt lub egress path?
- Czy uwzględnia port, kolejkę, serializację i link?
- Czy istnieje drop reason?
- Czy można przechwycić pakiet do PCAPNG?

### Routing

- Czy protokół publikuje do własnego RIB zamiast FIB?
- Czy działa route selection?
- Czy next-hop jest rozwiązywany przez adjacency?
- Czy FIB jest programowany per FC?
- Czy resource failure jest widoczny operacyjnie?

### Hardware

- Czy rozróżniono inventory i provisioned?
- Czy stany presence, provisioning, admin, lifecycle i oper są niezależne?
- Czy HardwarePath obsługuje connector/channel?
- Czy capability pochodzi z profilu release/platform?
- Czy nietypowe zachowanie jest behavior module, a nie losowym warunkiem w core?

### CLI

- Czy komenda ma oficjalne źródło?
- Czy istnieje osobno w właściwym engine?
- Czy `?`, Tab, Space i Enter zachowują się prawidłowo?
- Czy prompt i context są prawidłowe?
- Czy istnieje raw-key golden transcript?
- Czy błąd ma zgodny renderer?
- Czy MD używa candidate/commit?
- Czy classic stosuje zmianę w odpowiednim momencie?
- Czy completion respektuje capabilities i autoryzację?

### Testy

- Czy istnieje test normatywny?
- Czy parser jest fuzzowany?
- Czy istnieje test błędu i limitu?
- Czy funkcja jest sprawdzona natywnie i w Wasm?
- Czy istnieje differential test lub plan jego wykonania?
- Czy source catalog i compatibility matrix zostały zaktualizowane?

### Deployment

- Czy build działa jako statyczne SPA?
- Czy cross-origin isolation pozostaje aktywne?
- Czy zasoby są same-origin lub mają prawidłowy CORP/CORS?
- Czy nie dodano zależności od Vercel Functions?
- Czy projekt zachowuje możliwość self-hostingu?

---

## 46. Ostateczny kierunek implementacyjny

Docelowy system ma następującą tożsamość techniczną:

```text
live real-time multithreaded network appliance emulator
browser-local and backend-free
C++20 + Emscripten pthreads + Shared WebAssembly Memory
React + Vite + TanStack Router + React Flow + xterm.js
static Vercel deployment
Nokia SR OS 26.7.R1 release profile
separate MD-CLI and classic CLI engines
actual packet bytes and protocol FSMs
per-forwarding-complex data plane
schema-driven configuration
source-backed compatibility
SR-SIM differential verification
```

Najpierw należy zbudować wiarygodny runtime, pamięć, terminal i oba CLI. Następnie model sprzętu, packet path, RIB/FIB i IPv4. Dopiero na tym fundamencie należy dodawać protokoły i usługi. Każda kolejna funkcja musi korzystać z tych samych socketów, interfejsów, route managera, resource managera, konfiguracji i mechanizmów zgodności.

