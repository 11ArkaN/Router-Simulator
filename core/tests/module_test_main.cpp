// Independent module-test entry point. It links no runtime coordinator or Wasm
// ABI, proving hardware, forwarding and checkpoint boundaries are testable
// alone.

#include <iostream>
#include <stdexcept>

void capture_store_tests();
void hardware_tests();
void lab_registry_tests();
void multi_device_fabric_tests();
void multi_device_routing_tests();
void network_plane_tests();
void routing_tests();
void router_hardware_inventory_tests();
void router_forwarder_tests();
void session_workflow_tests();
void shard_policy_tests();

int main() {
  try {
    // Run low-level suites in dependency order. A thrown failure stops before a
    // higher layer can obscure which standalone contract was violated.
    capture_store_tests();
    // Legacy behavior stays executable until the catalog-backed inventories
    // pass the same lifecycle, alarm and routing assertions per router.
    hardware_tests();
    lab_registry_tests();
    multi_device_fabric_tests();
    multi_device_routing_tests();
    network_plane_tests();
    routing_tests();
    router_hardware_inventory_tests();
    router_forwarder_tests();
    session_workflow_tests();
    shard_policy_tests();
    std::cout << "module tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    // CTest treats the nonzero exit as failure and preserves the focused module
    // diagnostic written by the suite that detected the broken invariant.
    std::cerr << error.what() << '\n';
    return 1;
  }
}
