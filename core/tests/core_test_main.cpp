// Product-runtime test entry point. Only current multi-device suites are linked,
// so an accidentally reintroduced singleton runtime cannot hide in test code.

#include <iostream>
#include <stdexcept>

void lab_runtime_tests();
void cli_tests();
void control_projection_worker_tests();
void network_plane_worker_tests();
void neighbor_discovery_packet_tests();
void packet_tests();
void ipv4_forwarded_fragmentation_tests();
void ip_address_tests();
void runtime_supervisor_tests();
void runtime_memory_growth_tests();
void wasm_api_tests();

int main() {
  try {
    ip_address_tests();
    packet_tests();
    ipv4_forwarded_fragmentation_tests();
    neighbor_discovery_packet_tests();
    // Keep the complete pre-migration terminal behavior executable while its
    // handlers are moved behind per-router multi-device session ownership.
    cli_tests();
    control_projection_worker_tests();
    network_plane_worker_tests();
    runtime_supervisor_tests();
    runtime_memory_growth_tests();
    lab_runtime_tests();
    // Exercise the final C ABI after standalone runtime fixtures have joined
    // their pthreads, so the test observes the same one-owner lifecycle as the
    // browser Worker rather than overlapping unrelated laboratories.
    wasm_api_tests();
    std::cout << "core tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
