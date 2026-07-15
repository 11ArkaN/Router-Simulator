# Router Simulator

Lokalny, wielowątkowy emulator urządzeń sieciowych działający w czasie rzeczywistym. Pierwszy pionowy przekrój odwzorowuje dwa hosty połączone przez router 7750 SR-7 z terminalem MD-CLI i classic CLI, rzeczywistymi ramkami Ethernet, ARP, IPv4, ICMP oraz lokalnym capture.

## Wymagania

- Node.js 22
- pnpm 11
- Emscripten z obsługą pthreads
- przeglądarka z SharedArrayBuffer i cross-origin isolation

## Uruchomienie

```powershell
pnpm install
pnpm core:test
pnpm core:manual
pnpm build
pnpm dev
```

Serwer deweloperski wysyła nagłówki COOP i COEP wymagane przez WebAssembly threads. Runtime nie uruchomi się w trybie jednowątkowym.

## Lokalny toolchain

Toolchain jest przechowywany w ignorowanym katalogu `.tools`. Polecenie `pnpm toolchain:bootstrap` instaluje tam przypięte Emscripten 6.0.3, CMake 4.4.0 i Ninja 1.13.0. Build rdzenia można powtórzyć przez `pnpm core:build`, a pomiar gorącej ścieżki przez `pnpm core:benchmark`.

Pula pthreadów powstaje przy starcie według `clamp(hardwareConcurrency - 1, 2, 4)`. Control plane i forwarding z medium mają osobnych właścicieli, a brak izolacji originu zatrzymuje uruchomienie zamiast wybierać tryb jednowątkowy.

## Dane laboratorium

IndexedDB zapisuje projekt, inventory, provisioning, konfigurację i układ. OPFS przechowuje ostatni PCAPNG oraz checkpoint strukturalny. Plik `.netsim` może zawierać sam projekt albo zgodny checkpoint z capture. Checkpoint wymaga zgodnego profilu, ABI i hasha buildu, natomiast niezgodny plik można jawnie otworzyć tylko jako projekt bez stanu operacyjnego.

Porty pojawiają się po zgodnym insert i provisioning karty oraz MDA. Insert i remove wykonuje się w inspektorze chassis, a provisioning w MD-CLI lub classic CLI tej samej sesji routera.

## Zgodność

Adresy źródeł normatywnych znajdują się w `sources/catalog.yaml`. Komentarze w kodzie wskazują rekordy przez identyfikatory `Source:`. Polecenie `pnpm sources:validate` sprawdza możliwości, profile, ścieżki implementacji, testy i identyfikatory użyte w komentarzach.

`pnpm verify` uruchamia walidację źródeł i profilu, kontrolę warstw, typecheck, testy C++ i TypeScript, kontrolę regresji benchmarku, benchmark struktur i checkpointu oraz produkcyjny build. CI dodatkowo buduje rdzeń natywnie z AddressSanitizer, UndefinedBehaviorSanitizer i ThreadSanitizer. Lokalna macierz przeglądarek obejmuje Chrome, Edge i Firefox z aktywnym `crossOriginIsolated`.
