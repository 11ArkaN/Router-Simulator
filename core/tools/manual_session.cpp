// Visible manual scenario for fresh hardware, mismatch, lifecycle, forwarding,
// capture and failure cascade through the real multithreaded runtime.

#include "router/generated_runtime_protocol.hpp"
#include "router/runtime.hpp"

#include <chrono>
#include <iostream>
#include <memory>
#include <string_view>
#include <thread>

int main() {
  // Runtime owns both worker threads. Keeping it on the heap avoids placing
  // the packet pool and capture storage on the comparatively small main stack.
  auto runtime = std::make_unique<router::Runtime>();

  // Every step is printed together with the backend response so this tool can
  // be used as a human-readable smoke test, not merely as a pass/fail script.
  const auto run = [&](std::string_view command) {
    std::cout << "\n>>> " << command << '\n'
              << runtime->command(std::string(command)) << '\n';
  };

  // The terminal prefix belongs to the versioned runtime protocol. Commands
  // remain plain terminal text after the prefix and are parsed only by CLI.
  const auto terminal = [](std::string_view command) {
    auto result = std::string{router::runtime_protocol::terminal_execute};
    result.append(command);
    return result;
  };

  // The manual CLI probe targets the configured endpoint address, but the
  // text is derived from the generated binary address rather than duplicated
  // in this scenario. This keeps the smoke test valid when a profile changes
  // its lab prefixes.
  const auto ipv4_text = [](router::packet::Ipv4 address) {
    return std::to_string(address[0]) + '.' + std::to_string(address[1]) + '.' +
           std::to_string(address[2]) + '.' + std::to_string(address[3]);
  };

  // Endpoints and hardware identifiers come from the selected profile. This
  // scenario therefore survives reordered hosts, slots and supported types.
  const auto host_ping = std::string{router::runtime_protocol::host_ping} +
                         router::profile::host_ids.front() + ":" +
                         router::profile::host_ids.back();
  const auto insert_card =
      std::string{router::runtime_protocol::hardware_insert_card} +
      std::to_string(router::profile::line_card_slot) + ":" +
      router::profile::line_card_type;
  const auto insert_mda = [](const char *type) {
    return std::string{router::runtime_protocol::hardware_insert_mda} +
           std::to_string(router::profile::line_card_slot) + ":" +
           std::to_string(router::profile::mda_slot) + ":" + type;
  };
  const auto show_fib =
      terminal(std::string{"show router fib "} +
               std::to_string(router::profile::line_card_slot));
  const auto cli_ping =
      terminal(std::string{"ping "} +
               ipv4_text(router::profile::host_addresses.back()) + " count 1");

  // First prove that an unprovisioned chassis does not forward or report
  // usable interfaces. This guards against implicit always-present ports.
  run(terminal("show router interface"));
  run(host_ping);

  // A supported but non-modeled MDA must remain visible as a mismatch. It may
  // never silently create ports just because it is valid physical inventory.
  run(std::string{router::runtime_protocol::project_provisioning} +
      router::profile::line_card_type + "|" +
      router::profile::modeled_mda_type);
  run(insert_card);
  run(insert_mda(router::profile::supported_mda_types.back()));
  run(terminal("show card"));
  run(terminal("show mda"));
  run(terminal("show port"));
  run(host_ping);

  // Replace the mismatch with the modeled MDA. The real-time lifecycle is
  // allowed to finish before operational forwarding assertions are observed.
  run(std::string{router::runtime_protocol::hardware_remove_mda} +
      std::to_string(router::profile::line_card_slot) + ":" +
      std::to_string(router::profile::mda_slot));
  run(insert_mda(router::profile::modeled_mda_type));
  std::this_thread::sleep_for(router::profile::card_initialization +
                              router::profile::mda_initialization +
                              router::profile::equipment_poll_interval);

  // These reads exercise the whole configuration to RIB to FIB to packet path
  // chain. ARP appears only after encoded traffic traverses both links.
  run(terminal("show router interface"));
  run(terminal("show router route-table"));
  run(show_fib);
  run(host_ping);
  // Unlike host_ping, this passes through the actual CLI grammar and output
  // renderer, including count parsing, the reply line and summary statistics.
  run(cli_ping);
  run(terminal("show router arp"));
  run(router::runtime_protocol::capture_prepare);

  // Link loss must withdraw only the affected path and be visible in the same
  // router-owned operational projections consumed by CLI and the browser.
  run(std::string{router::runtime_protocol::link_down} +
      router::profile::port_ids[router::profile::link_port_indices.back()]);
  run(terminal("show router interface"));
  run(terminal("show router route-table"));
  run(show_fib);
  run(terminal("show system alarms"));
  run(host_ping);
  run(router::runtime_protocol::snapshot);

  // Restore the medium and switch the engine inside the same terminal session
  // to verify that neither action recreates router state.
  run(std::string{router::runtime_protocol::link_up} +
      router::profile::port_ids[router::profile::link_port_indices.back()]);
  run(terminal("//"));
  run(terminal("show port"));
}
