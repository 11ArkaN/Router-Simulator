// Native PCAPNG conformance fixture. It exercises the same threaded Runtime as
// the browser, writes the immutable capture projection, and leaves structural
// and dissector validation to tshark rather than duplicating its parser.

#include "router/runtime.hpp"

#include <chrono>
#include <fstream>
#include <memory>
#include <thread>

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  auto runtime = std::make_unique<router::Runtime>();
  runtime->command("project:provisioning|iom4-e|me10-10gb-sfp+");
  runtime->command("hardware:insert-card");
  runtime->command("hardware:insert-mda:me10-10gb-sfp+");
  std::this_thread::sleep_for(std::chrono::milliseconds(3200));
  if (runtime->command("host:ping:host-a:host-b").find("1 packets received") ==
      std::string::npos) {
    return 3;
  }
  if (runtime->command("capture:prepare").rfind("capture ready:", 0) != 0) return 4;
  const auto capture = runtime->prepared_capture();
  std::ofstream output(argv[1], std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char*>(capture.data()),
               static_cast<std::streamsize>(capture.size()));
  return output ? 0 : 5;
}
