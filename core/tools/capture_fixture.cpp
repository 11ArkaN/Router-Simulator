// Native PCAPNG conformance fixture. It exercises the same threaded Runtime as
// the browser, writes the immutable capture projection, and leaves structural
// and dissector validation to tshark rather than duplicating its parser.

#include "router/generated_runtime_protocol.hpp"
#include "router/runtime.hpp"

#include <chrono>
#include <fstream>
#include <memory>
#include <thread>

int main(int argc, char **argv) {
  // A single explicit output path keeps the fixture deterministic for CTest
  // and prevents it from writing outside the caller-selected build directory.
  if (argc != 2)
    return 2;

  // Use production Runtime instead of calling packet encoders directly. This
  // proves capture observes frames that crossed the threaded forwarding path.
  auto runtime = std::make_unique<router::Runtime>();

  // Provisioning and physical insertion are separate operations by design.
  // Ports become operational only after both models agree and timers expire.
  runtime->command(std::string{router::runtime_protocol::project_provisioning} +
                   router::profile::line_card_type + "|" +
                   router::profile::modeled_mda_type);
  runtime->command(std::string{router::runtime_protocol::hardware_insert_card} +
                   std::to_string(router::profile::line_card_slot) + ":" +
                   router::profile::line_card_type);
  runtime->command(std::string{router::runtime_protocol::hardware_insert_mda} +
                   std::to_string(router::profile::line_card_slot) + ":" +
                   std::to_string(router::profile::mda_slot) + ":" +
                   router::profile::modeled_mda_type);
  std::this_thread::sleep_for(router::profile::card_initialization +
                              router::profile::mda_initialization +
                              router::profile::equipment_poll_interval);

  // A successful ping is the evidence that the capture contains a real packet
  // exchange rather than an empty but structurally valid PCAPNG container.
  const auto ping = std::string{router::runtime_protocol::host_ping} +
                    router::profile::host_ids.front() + ":" +
                    router::profile::host_ids.back();
  if (runtime->command(ping).find("1 packets received") == std::string::npos) {
    return 3;
  }

  // Capture preparation freezes a projection owned by Runtime. The returned
  // bytes remain stable while the control and forwarding workers continue.
  if (runtime->command(router::runtime_protocol::capture_prepare)
          .rfind("capture ready:", 0) != 0)
    return 4;

  // Binary mode is required on Windows because text translation would corrupt
  // PCAPNG block lengths and packet octets before tshark reads the fixture.
  const auto capture = runtime->prepared_capture();
  std::ofstream output(argv[1], std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char *>(capture.data()),
               static_cast<std::streamsize>(capture.size()));
  return output ? 0 : 5;
}
