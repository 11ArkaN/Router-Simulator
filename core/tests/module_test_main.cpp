// Independent module-test entry point. It links no runtime coordinator or Wasm
// ABI, proving hardware, forwarding and checkpoint boundaries are testable
// alone.

#include <iostream>
#include <stdexcept>

void checkpoint_tests();
void hardware_tests();
void network_tests();

int main() {
  try {
    checkpoint_tests();
    hardware_tests();
    network_tests();
    std::cout << "module tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
