// Independent module-test entry point. It links no runtime coordinator or Wasm
// ABI, proving hardware, forwarding and checkpoint boundaries are testable
// alone.

#include <iostream>
#include <stdexcept>

void checkpoint_tests();
void hardware_tests();
void network_tests();
void project_configuration_tests();

int main() {
  try {
    // Run low-level suites in dependency order. A thrown failure stops before a
    // higher layer can obscure which standalone contract was violated.
    checkpoint_tests();
    hardware_tests();
    network_tests();
    project_configuration_tests();
    std::cout << "module tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    // CTest treats the nonzero exit as failure and preserves the focused module
    // diagnostic written by the suite that detected the broken invariant.
    std::cerr << error.what() << '\n';
    return 1;
  }
}
