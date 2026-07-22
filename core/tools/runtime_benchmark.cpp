// Maximum-laboratory network benchmark. It drives real ARP, Ethernet, IPv4 and
// ICMP traffic through the generated 16-router limits. Checkpoint cost remains
// a separate storage metric and is never used as packet-path performance.

#include "router/generated_device_catalog.hpp"
#include "router/generated_lab_runtime_protocol.hpp"
#include "router/lab_runtime.hpp"

#include <chrono>
#include <array>
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

std::string message(std::string_view operation,
                    const std::vector<std::string> &fields = {}) {
  std::string result;
  const auto append = [&](std::string_view field) {
    result += std::to_string(field.size()) + ':';
    result.append(field);
    result.push_back(',');
  };
  append(operation);
  for (const auto &field : fields)
    append(field);
  return result;
}

bool submit(router::lab::LabRuntime &runtime, std::string_view operation,
            const std::vector<std::string> &fields) {
  return !runtime.command(message(operation, fields)).starts_with("ERROR:");
}

struct ScenarioResult {
  std::size_t routers{};
  std::size_t links{};
  std::size_t sessions{};
  std::size_t checkpoint_bytes{};
  double checkpoint_export_ns{};
  std::size_t routed_ping_samples{};
  double routed_ping_p50_ns{};
  double routed_ping_p95_ns{};
  double routed_ping_max_ns{};
  std::size_t concurrent_ping_replies{};
  double concurrent_pings_per_second{};
  double concurrent_round_p95_ns{};
  double forwarding_fairness_ratio{};
  std::size_t captured_frames{};
  std::uint64_t dropped_packets{};
  std::uint64_t sink{};
};

std::string ipv4(std::uint32_t value) {
  // Benchmark addressing is ordinary project input. Formatting from one
  // integer keeps all next hops and interface prefixes derived from the same
  // graph record instead of maintaining a second hand-written route table.
  return std::to_string(value >> 24U) + "." +
         std::to_string((value >> 16U) & 0xffU) + "." +
         std::to_string((value >> 8U) & 0xffU) + "." +
         std::to_string(value & 0xffU);
}

double percentile(const std::vector<std::uint64_t> &sorted,
                  std::size_t numerator, std::size_t denominator) {
  if (sorted.empty())
    return 0.0;
  // Nearest-rank selection never interpolates a latency that was not observed.
  // The result remains stable for the fixed 64-sample gate.
  const auto rank =
      (sorted.size() * numerator + denominator - 1U) / denominator;
  return static_cast<double>(sorted[std::max<std::size_t>(1U, rank) - 1U]);
}

ScenarioResult run_scenario(std::size_t router_count,
                            std::size_t link_count) {
  using namespace router;
  auto runtime = std::make_unique<lab::LabRuntime>();

  // Eight equipped ports cover the maximum degree-eight scale graph. Smaller
  // scenarios use the identical hardware path and simply leave ports unbound.
  for (std::size_t index = 0; index < router_count; ++index) {
    const auto router = "r" + std::to_string(index + 1U);
    if (!submit(*runtime, lab_runtime_protocol::router_create,
                {router, "7750-sr-12", "R" + std::to_string(index + 1U)}) ||
        !submit(*runtime, lab_runtime_protocol::hardware_card_set,
                {router, "1", "iom4-e", "iom4-e"}) ||
        !submit(*runtime, lab_runtime_protocol::hardware_mda_set,
                {router, "1", "1", "me10-10gb-sfp+", "me10-10gb-sfp+"}) ||
        !submit(*runtime, lab_runtime_protocol::hardware_card_admin_set,
                {router, "1", "1"}) ||
        !submit(*runtime, lab_runtime_protocol::hardware_mda_admin_set,
                {router, "1", "1", "1"}))
      throw std::runtime_error("scale router hardware was rejected");
    for (std::size_t port = 1; port <= 8U; ++port) {
      const std::string response{runtime->command(message(
          lab_runtime_protocol::port_configure,
          {router, "1/1/" + std::to_string(port), "1", "9212", "10000",
           "scale port " + std::to_string(port)}))};
      if (response.starts_with("ERROR:"))
        throw std::runtime_error("scale router " + router + " port " +
                                 std::to_string(port) + " was rejected: " +
                                 response + " snapshot=" + std::string{
                                     runtime->command(message(
                                         lab_runtime_protocol::snapshot))});
    }
    for (std::size_t session = 0;
         session < device_catalog::maximum_sessions_per_router; ++session)
      if (!submit(*runtime, lab_runtime_protocol::session_create,
                  {"s" + std::to_string(index * 4U + session + 1U), router,
                   "operational"}))
        throw std::runtime_error("scale terminal session was rejected");
  }

  std::array<std::size_t, device_catalog::maximum_routers> next_port{};
  next_port.fill(1U);
  std::array<std::string, device_catalog::maximum_routers> ring_out_ports{};
  std::array<std::string, device_catalog::maximum_routers> ring_in_ports{};
  std::size_t created_links{};
  // Each round connects every router to one cyclic neighbor. Using each node
  // once as source and once as destination distributes endpoint ownership
  // evenly and reaches eight ports at the 64-link maximum.
  for (std::size_t offset = 1; created_links < link_count; ++offset) {
    for (std::size_t source = 0;
         source < router_count && created_links < link_count; ++source) {
      const auto destination = (source + offset) % router_count;
      if (destination == source)
        continue;
      const auto first_port = next_port[source]++;
      const auto second_port = next_port[destination]++;
      const auto first_port_id = "1/1/" + std::to_string(first_port);
      const auto second_port_id = "1/1/" + std::to_string(second_port);
      if (first_port > 8U || second_port > 8U ||
          !submit(*runtime, lab_runtime_protocol::link_create,
                  {"link" + std::to_string(created_links + 1U),
                   "r" + std::to_string(source + 1U),
                   first_port_id,
                   "r" + std::to_string(destination + 1U),
                   second_port_id, "100", "1", "0"}))
        throw std::runtime_error("scale physical link was rejected");
      // Offset one is a complete physical ring. Retaining its actual allocated
      // ports lets the 16-router workload configure L3 state without assuming
      // that a profile or topology generator assigned a particular ordinal.
      if (offset == 1U) {
        ring_out_ports[source] = first_port_id;
        ring_in_ports[destination] = second_port_id;
      }
      ++created_links;
    }
  }

  constexpr std::uint32_t iterations = 10;
  ScenarioResult result{.routers = router_count,
                        .links = created_links,
                        .sessions = router_count *
                            device_catalog::maximum_sessions_per_router};

  if (router_count == device_catalog::maximum_routers &&
      link_count == device_catalog::maximum_links) {
    // The first 16 links form a real 10 Gb/s routed ring. Every hop owns a
    // distinct /30, performs ARP and forwards encoded Ethernet and IPv4 bytes.
    // Extra links remain active at the same time, so the packet owner also
    // rotates across the complete 64-link fabric while the measurement runs.
    constexpr std::uint32_t ring_base = 0x0a400000U; // 10.64.0.0
    for (std::size_t index = 0; index < router_count; ++index) {
      const auto outgoing_network = ring_base +
                                    static_cast<std::uint32_t>(index * 4U);
      const auto incoming_index = (index + router_count - 1U) % router_count;
      const auto incoming_network = ring_base +
                                    static_cast<std::uint32_t>(incoming_index * 4U);
      const auto router = "r" + std::to_string(index + 1U);
      if (!submit(*runtime, lab_runtime_protocol::interface_configure,
                  {router, "ring-out", ring_out_ports[index],
                   ipv4(outgoing_network + 1U) + "/30", "", "", "1"}) ||
          !submit(*runtime, lab_runtime_protocol::interface_configure,
                  {router, "ring-in", ring_in_ports[index],
                   ipv4(incoming_network + 2U) + "/30", "", "", "1"}))
        throw std::runtime_error("scale routed ring interface was rejected");
    }

    // R1 reaches R9 clockwise through seven transit routers. The reverse /32
    // routes follow the same physical chain in the opposite direction. No
    // route is installed into another router by graph inspection at runtime;
    // these are ordinary per-router static configuration operations.
    constexpr std::size_t target_index = 8U;
    const auto source_address = ring_base + 1U;
    const auto target_address =
        ring_base + static_cast<std::uint32_t>((target_index - 1U) * 4U) + 2U;
    for (std::size_t index = 0; index < target_index - 1U; ++index) {
      const auto outgoing_network = ring_base +
                                    static_cast<std::uint32_t>(index * 4U);
      if (!submit(*runtime, lab_runtime_protocol::static_route_add,
                  {"r" + std::to_string(index + 1U),
                   ipv4(target_address) + "/32",
                   ipv4(outgoing_network + 2U)}))
        throw std::runtime_error("scale forward static route was rejected");
    }
    for (std::size_t index = target_index; index > 0U; --index) {
      const auto incoming_network = ring_base +
                                    static_cast<std::uint32_t>((index - 1U) * 4U);
      if (!submit(*runtime, lab_runtime_protocol::static_route_add,
                  {"r" + std::to_string(index + 1U),
                   ipv4(source_address) + "/32",
                   ipv4(incoming_network + 1U)}))
        throw std::runtime_error("scale return static route was rejected");
    }

    if (!submit(*runtime, lab_runtime_protocol::capture_point_set,
                {"link-direction", "link1", "", "0", "1"}))
      throw std::runtime_error("scale capture point was rejected");

    const auto run_ping = [&](std::uint16_t sequence) {
      const auto sequence_text = std::to_string(sequence);
      const auto started = std::chrono::steady_clock::now();
      if (!submit(*runtime, lab_runtime_protocol::router_ping_start,
                  {"r1", ipv4(target_address), sequence_text}))
        throw std::runtime_error("scale routed ping could not start");
      const auto deadline = started + std::chrono::seconds{2};
      while (std::chrono::steady_clock::now() < deadline) {
        const auto status = runtime->command(message(
            lab_runtime_protocol::router_ping_status, {"r1", sequence_text}));
        if (status == "reply")
          return static_cast<std::uint64_t>(
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  std::chrono::steady_clock::now() - started)
                  .count());
        std::this_thread::yield();
      }
      throw std::runtime_error("scale routed ping exceeded two seconds");
    };

    // The warm-up includes ARP on every physical hop. Measured samples retain
    // the learned adjacencies and therefore isolate steady packet scheduling
    // from one-time neighbor discovery without replacing the packet path.
    static_cast<void>(run_ping(1));
    std::vector<std::uint64_t> samples;
    samples.reserve(64);
    for (std::uint16_t sequence = 2; sequence <= 65U; ++sequence)
      samples.push_back(run_ping(sequence));
    std::sort(samples.begin(), samples.end());
    result.routed_ping_samples = samples.size();
    result.routed_ping_p50_ns = percentile(samples, 50, 100);
    result.routed_ping_p95_ns = percentile(samples, 95, 100);
    result.routed_ping_max_ns = static_cast<double>(samples.back());

    const auto direct_target = [&](std::size_t router_index) {
      return ring_base + static_cast<std::uint32_t>(router_index * 4U) + 2U;
    };
    const auto run_parallel_round = [&](std::uint16_t sequence,
                                        std::size_t rotation,
                                        std::array<std::uint64_t,
                                                   device_catalog::maximum_routers>
                                            &router_elapsed) {
      const auto started = std::chrono::steady_clock::now();
      for (std::size_t router_index = 0; router_index < router_count;
           ++router_index)
        if (!submit(*runtime, lab_runtime_protocol::router_ping_start,
                    {"r" + std::to_string(router_index + 1U),
                     ipv4(direct_target(router_index)),
                     std::to_string(sequence)}))
          throw std::runtime_error("parallel scale ping could not start");

      std::array<bool, device_catalog::maximum_routers> replied{};
      std::size_t reply_count{};
      const auto deadline = started + std::chrono::seconds{2};
      while (reply_count < router_count &&
             std::chrono::steady_clock::now() < deadline) {
        // Rotating the first status query prevents the benchmark itself from
        // consistently favoring a low-index router on the synchronous control
        // boundary. Packet processing remains entirely asynchronous.
        for (std::size_t probe = 0; probe < router_count; ++probe) {
          const auto router_index = (probe + rotation) % router_count;
          if (replied[router_index])
            continue;
          const auto status = runtime->command(message(
              lab_runtime_protocol::router_ping_status,
              {"r" + std::to_string(router_index + 1U),
               std::to_string(sequence)}));
          if (status == "reply") {
            replied[router_index] = true;
            ++reply_count;
            router_elapsed[router_index] += static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - started)
                    .count());
          }
        }
        std::this_thread::yield();
      }
      if (reply_count != router_count)
        throw std::runtime_error("parallel scale ping starved a router");
      return static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(
              std::chrono::steady_clock::now() - started)
              .count());
    };

    // Resolve all direct neighbors before measuring contention. Each measured
    // round then admits one Echo operation from every forwarding instance at
    // nearly the same control time and proves that all 16 complete.
    std::array<std::uint64_t, device_catalog::maximum_routers> warmup_elapsed{};
    static_cast<void>(run_parallel_round(100, 0, warmup_elapsed));
    constexpr std::size_t parallel_rounds = 64;
    std::vector<std::uint64_t> round_elapsed;
    round_elapsed.reserve(parallel_rounds);
    std::array<std::uint64_t, device_catalog::maximum_routers>
        per_router_elapsed{};
    const auto parallel_started = std::chrono::steady_clock::now();
    for (std::size_t round = 0; round < parallel_rounds; ++round)
      round_elapsed.push_back(run_parallel_round(
          static_cast<std::uint16_t>(1000U + round), round % router_count,
          per_router_elapsed));
    const auto parallel_ns = static_cast<double>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - parallel_started)
            .count());
    std::sort(round_elapsed.begin(), round_elapsed.end());
    result.concurrent_ping_replies = parallel_rounds * router_count;
    result.concurrent_pings_per_second =
        parallel_ns > 0.0
            ? static_cast<double>(result.concurrent_ping_replies) * 1e9 /
                  parallel_ns
            : 0.0;
    result.concurrent_round_p95_ns = percentile(round_elapsed, 95, 100);
    const auto [minimum_router, maximum_router] = std::minmax_element(
        per_router_elapsed.begin(),
        per_router_elapsed.begin() + static_cast<std::ptrdiff_t>(router_count));
    result.forwarding_fairness_ratio =
        *minimum_router ? static_cast<double>(*maximum_router) /
                              static_cast<double>(*minimum_router)
                        : 0.0;
    const auto snapshot = runtime->command(message(lab_runtime_protocol::snapshot));
    const auto marker = snapshot.find("\"capturedFrames\":");
    if (marker == std::string::npos)
      throw std::runtime_error("scale telemetry snapshot omitted capture count");
    const auto first_digit = marker + std::string_view{"\"capturedFrames\":"}.size();
    result.captured_frames =
        std::stoull(std::string{snapshot.substr(first_digit)});
    if (!result.captured_frames)
      throw std::runtime_error("scale traffic bypassed selected capture");
    const auto dropped_marker = snapshot.find("\"droppedPackets\":");
    if (dropped_marker == std::string::npos)
      throw std::runtime_error("scale telemetry omitted packet drop count");
    const auto dropped_digit =
        dropped_marker + std::string_view{"\"droppedPackets\":"}.size();
    result.dropped_packets =
        std::stoull(std::string{snapshot.substr(dropped_digit)});
    if (result.dropped_packets)
      throw std::runtime_error(
          "16-router measurement overloaded a modeled packet queue");
  }

  const auto started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    const auto checkpoint = runtime->export_checkpoint();
    if (checkpoint.empty())
      throw std::runtime_error("scale checkpoint export failed");
    result.checkpoint_bytes = checkpoint.size();
    result.sink += checkpoint[index % checkpoint.size()];
  }
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - started);
  result.checkpoint_export_ns =
      static_cast<double>(elapsed.count()) / iterations;
  return result;
}

} // namespace

int main() {
  try {
    const std::array scenarios{run_scenario(1, 0), run_scenario(4, 8),
                               run_scenario(16, 64)};
    const auto &scale = scenarios.back();
    // These are product acceptance floors, not claims about a physical ASIC.
    // They catch thread-pool collapse, accidental single-owner serialization,
    // starvation and millisecond polling while allowing ordinary host jitter.
    if (scale.routed_ping_samples != 64U ||
        scale.routed_ping_p95_ns > 10'000'000.0 ||
        scale.concurrent_ping_replies != 1024U ||
        scale.concurrent_pings_per_second < 100.0 ||
        scale.concurrent_round_p95_ns > 100'000'000.0 ||
        scale.forwarding_fairness_ratio > 1.10 || scale.dropped_packets)
      throw std::runtime_error("16-router packet-path performance gate failed");
    std::cout << "{\"scenarios\":[";
    for (std::size_t index = 0; index < scenarios.size(); ++index) {
      if (index)
        std::cout << ',';
      const auto &result = scenarios[index];
      std::cout << "{\"routers\":" << result.routers
                << ",\"links\":" << result.links
                << ",\"sessions\":" << result.sessions
                << ",\"checkpointBytes\":" << result.checkpoint_bytes
                << ",\"checkpointExportNs\":"
                << result.checkpoint_export_ns << ",\"sink\":"
                << result.sink << ",\"routedPingSamples\":"
                << result.routed_ping_samples << ",\"routedPingP50Ns\":"
                << result.routed_ping_p50_ns << ",\"routedPingP95Ns\":"
                << result.routed_ping_p95_ns << ",\"routedPingMaxNs\":"
                << result.routed_ping_max_ns
                << ",\"concurrentPingReplies\":"
                << result.concurrent_ping_replies
                << ",\"concurrentPingsPerSecond\":"
                << result.concurrent_pings_per_second
                << ",\"concurrentRoundP95Ns\":"
                << result.concurrent_round_p95_ns
                << ",\"forwardingFairnessRatio\":"
                << result.forwarding_fairness_ratio << ",\"capturedFrames\":"
                << result.captured_frames << ",\"droppedPackets\":"
                << result.dropped_packets << '}';
    }
    std::cout << "]}\n";
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
}
