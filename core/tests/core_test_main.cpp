// Product-runtime test entry point. Only current multi-device suites are linked,
// so an accidentally reintroduced singleton runtime cannot hide in test code.

#include <iostream>
#include <stdexcept>

void lab_runtime_tests();
void cli_tests();
void control_projection_worker_tests();
void network_plane_worker_tests();
void packet_tests();
void runtime_supervisor_tests();

int main() {
  try {
    packet_tests();
    // Keep the complete pre-migration terminal behavior executable while its
    // handlers are moved behind per-router multi-device session ownership.
    cli_tests();
    control_projection_worker_tests();
    network_plane_worker_tests();
    runtime_supervisor_tests();
    lab_runtime_tests();
    std::cout << "core tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
