// Native PCAPNG conformance fixture for protocol 3. The fixture configures two
// independent routers through the same LabRuntime facade used by WebAssembly,
// selects a physical wire direction, and writes only captured packet bytes.

#include "router/lab_runtime.hpp"
#include "router/generated_lab_runtime_protocol.hpp"

#include <chrono>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>

namespace {

std::string message(std::initializer_list<std::string_view> fields) {
  // Netstring byte counts equal string_view sizes here because every fixture
  // value is ASCII. Production JavaScript performs the corresponding UTF-8
  // byte count for user-authored Unicode names.
  std::string result;
  for (const auto field : fields) {
    result.append(std::to_string(field.size()));
    result.push_back(':');
    result.append(field);
    result.push_back(',');
  }
  return result;
}

bool submit(router::lab::LabRuntime &runtime,
            std::initializer_list<std::string_view> fields) {
  const auto response = runtime.command(message(fields));
  if (!response.starts_with("ERROR:"))
    return true;
  // A conformance fixture must identify the rejected public operation. This
  // diagnostic does not expose implementation addresses or bypass the facade;
  // it prints only the protocol operation and its ordinary error response.
  std::cerr << "capture fixture operation '" << *fields.begin()
            << "' failed: " << response << '\n';
  return false;
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  router::lab::LabRuntime runtime;
  using namespace router::lab_runtime_protocol;

  // SR-1 fixed hardware publishes its default MDAs at creation. Running port
  // and interface intent are still explicit. Interface MAC addresses come
  // from the hardware inventory, matching the same facade used by the UI.
  if (!submit(runtime, {router_create, "r1", "7750-sr-1", "R1"}) ||
      !submit(runtime, {router_create, "r2", "7750-sr-1", "R2"}) ||
      !submit(runtime, {port_configure, "r1", "1/1/1", "1", "1500",
                        "100000", "R1 to R2"}) ||
      !submit(runtime, {port_configure, "r2", "1/1/1", "1", "1500",
                        "100000", "R2 to R1"}) ||
      !submit(runtime, {interface_configure, "r1", "to-r2", "1/1/1",
                        "10.0.0.1/30", "1"}) ||
      !submit(runtime, {interface_configure, "r2", "to-r1", "1/1/1",
                        "10.0.0.2/30", "1"}) ||
      !submit(runtime, {link_create, "r1-r2", "r1", "1/1/1", "r2",
                        "1/1/1", "100", "1"}) ||
      !submit(runtime, {capture_point_set, "link-direction", "r1-r2", "",
                        "0", "1"}) ||
      !submit(runtime, {router_ping_start, "r1", "10.0.0.2", "7"}))
    return 3;

  // Ping is asynchronous. Polling observes the real forwarding worker instead
  // of advancing a test clock or reaching directly into the destination RIB.
  bool replied{};
  for (std::size_t attempt = 0; attempt < 500 && !replied; ++attempt) {
    const auto response = runtime.command(
        message({router_ping_status, "r1", "7"}));
    replied = response.find("reply") != std::string_view::npos;
    if (!replied)
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
  }
  if (!replied)
    return 4;

  // Reapplying the same selected location is the public operation used to
  // refresh its descriptive name after a device rename. It must retain the
  // numeric interface identity and already captured records.
  if (!submit(runtime, {capture_point_set, "link-direction", "r1-r2", "",
                        "0", "1"}))
    return 7;

  const auto capture = runtime.prepare_capture();
  if (capture.empty()) {
    // The snapshot distinguishes an empty record set from a failed selected
    // location refresh without reaching into CaptureStore internals.
    std::cerr << "capture export returned no bytes after: "
              << runtime.command(message({snapshot})) << '\n';
    return 5;
  }
  std::ofstream output(argv[1], std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char *>(capture.data()),
               static_cast<std::streamsize>(capture.size()));
  return output ? 0 : 6;
}
