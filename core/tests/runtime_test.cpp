// Multithreaded acceptance suite. Every integration scenario uses the same
// control and forwarding pthread owners, shared telemetry and Wasm ABI as the
// browser build; only isolated value types are tested without Runtime.

#include "router/bounded_queue.hpp"
#include "router/generated_runtime_protocol.hpp"
#include "router/link_direction.hpp"
#include "router/packet_pool.hpp"
#include "router/runtime.hpp"
#include "router/spsc_ring.hpp"

#include <atomic>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

void cli_tests();
void packet_tests();
void routing_tests();

extern "C" {
int rs_create();
const char *rs_command(const char *command);
int rs_capture_prepare();
const std::uint8_t *rs_capture_data();
std::size_t rs_capture_size();
void rs_shutdown();
const std::uint8_t *checkpoint_export();
std::size_t checkpoint_export_size();
int checkpoint_import(const std::uint8_t *, std::size_t);
int project_import(const char *);
int cli_open_session();
const char *cli_push_input(const char *);
const char *cli_read_output();
}

std::string maximum_running_project_command() {
  // Encode the largest legal port-description generation through the public
  // project ABI. This catches mailbox sizes that pass default-project tests
  // but reject a datastore accepted by the SR OS leaf bounds.
  std::vector<std::string> fields{"R1", std::to_string(router::profile::port_count)};
  for (std::size_t index = 0; index < router::profile::port_count; ++index) {
    fields.emplace_back(router::profile::port_ids[index]);
    fields.emplace_back("up");
    fields.emplace_back(std::to_string(router::profile::default_port_mtu));
    fields.emplace_back(router::profile::port_description_bytes, 'x');
  }
  fields.emplace_back(std::to_string(router::profile::endpoint_count));
  for (std::size_t index = 0; index < router::profile::endpoint_count; ++index) {
    fields.emplace_back(router::profile::interface_names[index]);
    fields.emplace_back("up");
    fields.emplace_back(router::profile::port_ids[index]);
    fields.emplace_back(router::profile::interface_addresses[index]);
  }
  fields.emplace_back("0");
  std::string command{router::runtime_protocol::project_running};
  for (const auto &field : fields)
    command += std::to_string(field.size()) + ':' + field + ',';
  return command;
}

void spsc_stress_test() {
  router::SpscRing<std::uint64_t, 1024> ring;
  constexpr std::uint64_t count = 100000;
  std::atomic_bool failed{false};
  std::thread producer([&] {
    for (std::uint64_t value = 0; value < count; ++value) {
      while (!ring.try_push(value))
        std::this_thread::yield();
    }
  });
  for (std::uint64_t expected = 0; expected < count; ++expected) {
    std::uint64_t value{};
    while (!ring.try_pop(value))
      std::this_thread::yield();
    if (value != expected)
      failed = true;
  }
  producer.join();
  if (failed)
    throw std::runtime_error(
        "SPSC release/acquire ordering lost sequence integrity");
}

void device_queue_tests() {
  router::BoundedQueue<std::uint32_t, 2> queue;
  if (!queue.try_push(11) || !queue.try_push(12) || queue.try_push(13)) {
    throw std::runtime_error("Bounded device queue did not apply tail drop");
  }
  std::uint32_t value{};
  if (!queue.try_pop(value) || value != 11 || !queue.try_pop(value) ||
      value != 12) {
    throw std::runtime_error("Bounded device queue changed FIFO order");
  }

  router::PacketPool pool;
  const auto available = pool.available();
  router::packet::Frame frame;
  frame.length = 60;
  frame.bytes[0] = 0x5a;
  const auto handle = pool.allocate(frame);
  if (!handle || pool.available() + 1 != available ||
      pool.get(*handle)[0] != 0x5a) {
    throw std::runtime_error(
        "Packet pool handle did not preserve frame ownership");
  }
  pool.release(*handle);
  if (pool.available() != available)
    throw std::runtime_error("Packet pool leaked a slot");
}

void ethernet_timing_tests() {
  using Clock = std::chrono::steady_clock;
  // IEEE 802.3 minimum start-to-start spacing at 10 Gb/s is 67.2 ns. The host
  // clock has whole nanoseconds, so conservative ceiling produces 68 ns. A
  // millisecond of propagation changes delivery latency but not this spacing.
  // LinkDirection intentionally owns a large bounded in-flight ring. Tests use
  // heap ownership just like LabNetwork::Impl so WebAssembly's small entry
  // stack is not consumed by diagnostic storage unrelated to call depth.
  auto direction = std::make_unique<router::LinkDirection>(
      router::profile::port_bits_per_second, std::chrono::milliseconds(1));
  const auto origin = Clock::time_point{};
  const auto first = direction->try_transmit({1, 60}, origin);
  const auto second = direction->try_transmit({2, 60}, origin);
  if (!first || !second ||
      std::chrono::duration_cast<std::chrono::nanoseconds>(second->started -
                                                           first->started)
              .count() != 68 ||
      std::chrono::duration_cast<std::chrono::nanoseconds>(first->delivered -
                                                           origin)
              .count() != 1000058) {
    throw std::runtime_error(
        "Ethernet serialization or propagation timing is invalid");
  }
  // Delivery cannot occur before its real deadline. Popping the first frame
  // must not expose the second one until its independent deadline arrives.
  std::uint32_t handle{};
  if (direction->pop_delivered(handle, first->delivered -
                                           std::chrono::nanoseconds(1)) ||
      !direction->pop_delivered(handle, first->delivered) || handle != 1 ||
      direction->pop_delivered(handle, first->delivered)) {
    throw std::runtime_error(
        "Link direction exposed an in-flight frame too early");
  }

  // Reconfiguration changes only later admissions. This protects the local
  // medium invariant when a project edit arrives after a frame has started but
  // before its propagation deadline. The old 100 ns frame remains due at 158
  // ns, while the next frame uses 200 ns and remains independently serialized.
  auto configurable = std::make_unique<router::LinkDirection>(
      router::profile::port_bits_per_second, std::chrono::nanoseconds(100));
  const auto before_change = configurable->try_transmit({1, 60}, origin);
  configurable->set_propagation(std::chrono::nanoseconds(200));
  const auto after_change = configurable->try_transmit({2, 60}, origin);
  if (!before_change || !after_change ||
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          before_change->delivered - origin)
              .count() != 158 ||
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          after_change->delivered - origin)
              .count() != 326) {
    throw std::runtime_error(
        "Link propagation update changed an existing deadline");
  }

  // In-flight storage is bounded independently from propagation duration. A
  // full direction rejects the new handle and leaves all admitted deadlines in
  // FIFO order, proving that a burst cannot allocate an unbounded event list.
  auto saturated = std::make_unique<router::LinkDirection>(
      router::profile::port_bits_per_second, std::chrono::seconds(1));
  for (std::uint32_t value = 0; value < router::profile::link_inflight_capacity;
       ++value) {
    if (!saturated->try_transmit({value, 60}, origin)) {
      throw std::runtime_error(
          "Link direction rejected traffic before capacity");
    }
  }
  if (saturated->try_transmit(
          {static_cast<std::uint32_t>(router::profile::link_inflight_capacity),
           60},
          origin)) {
    throw std::runtime_error(
        "Link direction did not enforce in-flight capacity");
  }
}

int main() {
  try {
    packet_tests();
    routing_tests();
    cli_tests();
    spsc_stress_test();
    device_queue_tests();
    ethernet_timing_tests();

    // Production owns Runtime through a heap allocation in the Wasm bridge.
    // Mirroring that lifecycle also keeps bounded mailbox storage off the small
    // WebAssembly entry stack.
    auto runtime = std::make_unique<router::Runtime>();
    // The terminal state is a versioned bridge contract, not presentation
    // metadata invented by React.  The second field selects the real SR OS
    // history region: MD operational and MD configuration commands do not
    // share a recall list, while classic keeps one list for all contexts.
    const auto terminal_state =
        runtime->command(router::runtime_protocol::terminal_state);
    if (terminal_state.rfind("2:md,14:md-operational,", 0) != 0) {
      throw std::runtime_error(
          "Initial terminal state did not expose the MD operational history");
    }
    const auto initial = runtime->command(router::runtime_protocol::snapshot);
    if (initial.find("\"equippedType\":null") == std::string::npos) {
      throw std::runtime_error("Initial hardware state is not absent");
    }
    if (initial.find("\"provisionedType\":null") == std::string::npos ||
        initial.find("\"ports\":[]") == std::string::npos) {
      throw std::runtime_error(
          "Fresh lab invented provisioning or hardware ports");
    }
    runtime->command(
        std::string{router::runtime_protocol::project_provisioning} +
        router::profile::line_card_type + "|" +
        router::profile::modeled_mda_type);
    runtime->command(
        std::string{router::runtime_protocol::hardware_insert_card} +
        std::to_string(router::profile::line_card_slot) + ":" +
        router::profile::line_card_type);
    runtime->command(
        std::string{router::runtime_protocol::hardware_insert_mda} +
        std::to_string(router::profile::line_card_slot) + ":" +
        std::to_string(router::profile::mda_slot) + ":" +
        router::profile::modeled_mda_type);
    // Experimental profile delays run on real steady-clock deadlines. Waiting
    // here verifies the autonomous control-shard wakeup rather than bypassing
    // lifecycle state through a test-only clock or hidden fast-forward path.
    std::this_thread::sleep_for(router::profile::card_initialization +
                                router::profile::mda_initialization +
                                router::profile::equipment_poll_interval);
    const auto equipped = runtime->command(router::runtime_protocol::snapshot);
    if (equipped.find("\"lifecycle\":\"ready\"") == std::string::npos ||
        equipped.find("\"physicalLink\":true,\"speedMbps\":") ==
            std::string::npos ||
        equipped.find(std::string{"\"id\":\""} +
                      router::profile::port_ids.back() + "\"") ==
            std::string::npos) {
      throw std::runtime_error("Equipped MDA did not create ten profile ports");
    }
    const auto invalid_links = runtime->command("project:links|-1|100");
    if (invalid_links.rfind("ERROR:", 0) != 0) {
      throw std::runtime_error(
          "Runtime accepted a negative link propagation delay");
    }
    const auto configured_links = runtime->command("project:links|100|250");
    if (configured_links.rfind("ERROR:", 0) == 0) {
      throw std::runtime_error(
          "Runtime rejected an atomic per-link timing update");
    }
    const auto invalid_host = runtime->command(
        "project:hosts|invalid|192.0.2.2/"
        "30|192.0.2.1|02:00:00:00:00:0B|198.51.100.2/30|198.51.100.1");
    if (invalid_host.rfind("ERROR:", 0) != 0) {
      throw std::runtime_error(
          "Runtime accepted malformed project endpoint data");
    }
    const auto invalid_identity = runtime->command(
        "project:hosts|01:00:5E:00:00:01|192.0.2.3/"
        "30|192.0.2.1|02:00:00:00:00:0B|198.51.100.2/30|198.51.100.1");
    if (invalid_identity.rfind("ERROR:", 0) != 0) {
      throw std::runtime_error(
          "Runtime accepted group MAC or broadcast IPv4 endpoint data");
    }
    // A pair transaction must permit a valid identity swap. Sequential endpoint
    // commands would reject the first half against the still-old second host
    // and leave control and forwarding with different project generations.
    const auto swapped = runtime->command(
        "project:hosts|02:00:00:00:00:0B|192.0.2.2/"
        "30|192.0.2.1|02:00:00:00:00:0A|198.51.100.2/30|198.51.100.1");
    if (swapped.rfind("ERROR:", 0) == 0) {
      throw std::runtime_error(
          "Atomic endpoint transaction rejected a valid identity swap");
    }
    runtime->command(
        "project:hosts|02:00:00:00:00:0C|192.0.2.2/"
        "30|192.0.2.1|02:00:00:00:00:0B|198.51.100.2/30|198.51.100.1");
    const auto ping = runtime->command("host:ping:host-a:host-b");
    if (ping.find("1 packet received") == std::string::npos) {
      // Preserve the device response in the failure so a timing, adjacency or
      // interface regression can be distinguished without a debugger.
      throw std::runtime_error("Routed ICMP path failed: " + ping);
    }
    const auto final = runtime->command("snapshot");
    if (final.find("\"captureCount\":") == std::string::npos) {
      throw std::runtime_error("Forwarded frames were not captured");
    }
    if (final.find("02:00:00:00:00:0C") == std::string::npos) {
      throw std::runtime_error(
          "Edited host MAC did not reach ARP learning in the runtime");
    }
    const auto checkpoint_view = runtime->export_checkpoint();
    const std::vector<std::uint8_t> checkpoint(checkpoint_view.begin(),
                                               checkpoint_view.end());
    runtime->command("link:down:1/1/1");
    if (!runtime->import_checkpoint(checkpoint))
      throw std::runtime_error("Structural checkpoint import failed");
    const auto restored_arp = runtime->command("terminal:show router arp");
    if (restored_arp.find("02:00:00:00:00:0c") == std::string::npos ||
        restored_arp.find("00h00m00s") != std::string::npos)
      throw std::runtime_error("Structural checkpoint did not restore active "
                               "ARP state and expiry: " +
                               restored_arp);
    const auto capture_status = runtime->command("capture:prepare");
    const auto capture = runtime->prepared_capture();
    if (capture_status.rfind("capture ready: ", 0) != 0 ||
        capture.size() < 48 || capture[0] != 0x0a || capture[1] != 0x0d ||
        capture[2] != 0x0d || capture[3] != 0x0a) {
      throw std::runtime_error("PCAPNG capture export is invalid");
    }
    const auto read32 = [&](std::size_t offset) {
      return static_cast<std::uint32_t>(capture[offset]) |
             static_cast<std::uint32_t>(capture[offset + 1]) << 8 |
             static_cast<std::uint32_t>(capture[offset + 2]) << 16 |
             static_cast<std::uint32_t>(capture[offset + 3]) << 24;
    };
    // Walk all profile capture points instead of assuming an offset. Each
    // carries if_name, so Interface ID zero can be traced to Host A egress by a
    // generic PCAPNG reader without project-specific knowledge.
    std::size_t block = 28;
    for (std::size_t interface_id = 0;
         interface_id < router::profile::capture_interface_names.size();
         ++interface_id) {
      if (read32(block) != 1 || read32(block + 4) < 32 ||
          capture[block + 16] != 2 || capture[block + 17] != 0) {
        throw std::runtime_error(
            "PCAPNG interface description is missing if_name");
      }
      block += read32(block + 4);
    }
    if (read32(block) != 6 || read32(block + 8) != 0 ||
        capture[block + 28] != 0xff || capture[block + 40] != 0x08 ||
        capture[block + 41] != 0x06 || capture[block + 66] != 192 ||
        capture[block + 67] != 0 || capture[block + 68] != 2 ||
        capture[block + 69] != 1) {
      throw std::runtime_error(
          "PCAPNG did not preserve captured ARP bytes or interface ID");
    }
    std::array<std::uint8_t, 4> observed_ttl{};
    std::size_t icmp_count = 0;
    while (block < capture.size()) {
      const auto length = read32(block + 4);
      if (length < 32 || block + length > capture.size() ||
          read32(block + length - 4) != length) {
        throw std::runtime_error(
            "PCAPNG enhanced packet block length is invalid");
      }
      const auto frame = block + 28;
      const auto interface_id = read32(block + 8);
      if (interface_id < 4 && capture[frame + 12] == 0x08 &&
          capture[frame + 13] == 0x00) {
        observed_ttl[icmp_count++] = capture[frame + 22];
      }
      block += length;
    }
    if (icmp_count != 4 ||
        observed_ttl != std::array<std::uint8_t, 4>{64, 63, 64, 63}) {
      std::ostringstream detail;
      detail << "Forwarding TTL sequence invalid: count=" << icmp_count
             << " values=";
      for (const auto ttl : observed_ttl)
        detail << static_cast<unsigned>(ttl) << ',';
      throw std::runtime_error(detail.str());
    }
    // Two probes cross both pthread domains and verify the real one-second
    // default interval without turning the deterministic suite into a
    // 99-second upper-bound test. Ctrl-C is exercised in the browser test where
    // JavaScript owns the shared cancellation producer.
    const auto long_ping =
        runtime->command("terminal:ping 198.51.100.2 count 2");
    if (long_ping.find("2 packets transmitted, 2 packets received") ==
            std::string::npos ||
        long_ping.find("ERROR: response exceeds") != std::string::npos) {
      throw std::runtime_error(
          "Long CLI output exceeded the response mailbox contract");
    }

    // Port admin state is a control-plane change whose effects must cascade
    // through interface oper state, connected RIB, FIB generation, adjacency
    // and packet drop reporting. Per Nokia facility-alarm behavior, an
    // intentional admin-down does not raise linkDown 59-2004-1.
    runtime->command("terminal://");
    runtime->command("terminal:configure port 1/1/2 shutdown");
    const auto port_failure = runtime->command("snapshot");
    const auto port_alarms =
        runtime->command("terminal:show system alarms");
    const auto arp_after_port_failure =
        runtime->command("terminal:show router arp");
    if (port_failure.find(
            "\"id\":\"1/1/2\",\"admin\":\"down\",\"oper\":\"down\"") ==
            std::string::npos ||
        port_failure.find("\"prefix\":\"198.51.100.0/30\"") !=
            std::string::npos ||
        port_alarms.find("59-2004-1") != std::string::npos ||
        arp_after_port_failure.find("198.51.100.2") != std::string::npos) {
      throw std::runtime_error(
          "Port shutdown did not complete the operational failure cascade\n" +
          port_failure + "\n" + port_alarms + "\n" +
          arp_after_port_failure);
    }
    const auto port_failed_ping =
        runtime->command("host:ping:host-a:host-b");
    if (port_failed_ping.find("Request timeout") == std::string::npos)
      throw std::runtime_error("Port shutdown left a hidden forwarding path");
    runtime->command("terminal:configure port 1/1/2 no shutdown");
    if (runtime->command("host:ping:host-a:host-b")
            .find("1 packet received") == std::string::npos)
      throw std::runtime_error("Port recovery did not reprogram the FIB");

    // Physical MDA removal is independent from provisioning. The running MDA
    // type remains configured while every child port and routed interface goes
    // operationally down and learned adjacency is invalidated.
    runtime->command(
        std::string{router::runtime_protocol::hardware_remove_mda} +
        std::to_string(router::profile::line_card_slot) + ":" +
        std::to_string(router::profile::mda_slot));
    const auto mda_failure = runtime->command("snapshot");
    const auto mda_alarms = runtime->command("terminal:show system alarms");
    if (mda_failure.find("\"equippedType\":null") == std::string::npos ||
        mda_failure.find("\"prefix\":\"192.0.2.0/30\"") !=
            std::string::npos ||
        mda_failure.find("\"prefix\":\"198.51.100.0/30\"") !=
            std::string::npos ||
        mda_failure.find("\"arp\":[]") == std::string::npos ||
        mda_alarms.find("MDA") == std::string::npos) {
      throw std::runtime_error(
          "MDA removal did not withdraw ports, routes, ARP and raise alarm");
    }
    runtime->command(
        std::string{router::runtime_protocol::hardware_insert_mda} +
        std::to_string(router::profile::line_card_slot) + ":" +
        std::to_string(router::profile::mda_slot) + ":" +
        router::profile::modeled_mda_type);
    std::this_thread::sleep_for(router::profile::mda_initialization +
                                router::profile::equipment_poll_interval);
    if (runtime->command("host:ping:host-a:host-b")
            .find("1 packet received") == std::string::npos)
      throw std::runtime_error("MDA reinsert did not restore the routed path");

    runtime->command("link:down:1/1/2");
    const auto degraded = runtime->command("snapshot");
    // Physical Link and Oper State are separate Nokia observations. The JSON
    // projection must expose the actual cable signal so an admin-down port is
    // not mistaken for a disconnected medium by the UI.
    if (degraded.find("\"id\":\"1/1/2\",\"admin\":\"up\",\"oper\":\"down\",\"physicalLink\":false,\"speedMbps\":") ==
            std::string::npos ||
        degraded.find("\"prefix\":\"192.0.2.0/30\"") == std::string::npos ||
        degraded.find("\"prefix\":\"198.51.100.0/30\"") != std::string::npos) {
      throw std::runtime_error(
          "Interface failure did not withdraw only its connected route");
    }
    const auto failed_ping = runtime->command("host:ping:host-a:host-b");
    if (failed_ping.find("Request timeout") == std::string::npos) {
      throw std::runtime_error("Ping bypassed a down routed interface");
    }
    const auto dropped = runtime->command("snapshot");
    if (dropped.find("\"lastDropReason\":\"route-miss\"") ==
            std::string::npos) {
      throw std::runtime_error(
          "Failed forwarding did not publish its drop reason");
    }
    runtime.reset();

    if (!rs_create())
      throw std::runtime_error("Wasm C ABI did not create runtime");
    if (!cli_open_session())
      throw std::runtime_error("Public CLI byte session did not open");
    // The stable C ABI receives arbitrary terminal chunks, not preassembled
    // commands. Backspace repairs the buffered keyword before CR submits it.
    cli_push_input("show system informationx");
    cli_push_input("\x7f\r");
    if (std::string_view{cli_read_output()}.find("System Information") ==
        std::string_view::npos) {
      throw std::runtime_error(
          "Public CLI input bypassed byte editing or failed to submit CR");
    }
    const auto maximum_project = maximum_running_project_command();
    if (maximum_project.size() <= 1024U ||
        maximum_project.size() >= router::profile::command_message_bytes ||
        !project_import(maximum_project.c_str())) {
      throw std::runtime_error(
          "Public project import rejected a maximum valid running datastore");
    }
    const auto provisioning =
        std::string{router::runtime_protocol::project_provisioning} +
        router::profile::line_card_type + "|" +
        router::profile::modeled_mda_type;
    const auto insert_card =
        std::string{router::runtime_protocol::hardware_insert_card} +
        std::to_string(router::profile::line_card_slot) + ":" +
        router::profile::line_card_type;
    const auto insert_mda =
        std::string{router::runtime_protocol::hardware_insert_mda} +
        std::to_string(router::profile::line_card_slot) + ":" +
        std::to_string(router::profile::mda_slot) + ":" +
        router::profile::modeled_mda_type;
    rs_command(provisioning.c_str());
    rs_command(insert_card.c_str());
    rs_command(insert_mda.c_str());
    std::this_thread::sleep_for(router::profile::card_initialization +
                                router::profile::mda_initialization +
                                router::profile::equipment_poll_interval);
    rs_command("host:ping:host-a:host-b");
    const auto *checkpoint_data = checkpoint_export();
    const auto checkpoint_size = checkpoint_export_size();
    if (!checkpoint_data || !checkpoint_size ||
        !checkpoint_import(checkpoint_data, checkpoint_size)) {
      throw std::runtime_error("Wasm checkpoint ABI failed round-trip");
    }
    if (!rs_capture_prepare() || rs_capture_size() < 48 || !rs_capture_data()) {
      throw std::runtime_error("Wasm binary capture ABI failed");
    }
    rs_shutdown();
    std::cout << "core tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
