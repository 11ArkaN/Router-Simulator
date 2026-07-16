#include "router/generated_profile.hpp"
#include "router/link_direction.hpp"
#include "router/packet.hpp"
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>

int main() {
  using namespace router::packet;
  constexpr Mac source{0x02, 0, 0, 0, 1, 1};
  constexpr Mac target{0x02, 0, 0, 0, 0, 0x0b};
  constexpr Ipv4 source_ip{198, 51, 100, 1};
  constexpr Ipv4 target_ip{198, 51, 100, 2};
  // Each timed window is deliberately long enough to amortize Windows timer
  // quantization, short scheduler interruptions and V8's last tiering work.
  // The former 200k-frame window completed in only a few milliseconds, which
  // made unrelated desktop activity large enough to move one stage by more
  // than the strict 10 percent regression limit. More samples improve the
  // measurement only; they do not change the packet path being exercised.
  constexpr std::uint32_t iterations = 1000000;
  constexpr std::uint32_t link_iterations = 10000000;
  // Ten thousand calls were insufficient to make V8 tiering deterministic on
  // a busy desktop. A warmup equal to the measured packet sample ensures all
  // three paths have reached stable optimized Wasm code before the clock
  // starts.
  constexpr std::uint32_t warmup_iterations = 200000;
  std::uint64_t sink = 0;

  // Exercise each Wasm function before measurement so Node tiering and first
  // code-page faults do not become part of a sub-microsecond packet metric.
  // Warmup results remain observable through sink, preventing elimination.
  const auto warmup_ingress =
      icmp_echo(source, target, source_ip, target_ip, false, 1);
  Frame warmup_arp;
  Frame warmup_echo;
  Frame warmup_routed;
  for (std::uint32_t index = 0; index < warmup_iterations; ++index) {
    arp_request_into(warmup_arp, source, source_ip, target_ip);
    icmp_echo_into(warmup_echo, source, target, source_ip, target_ip, false,
                   static_cast<std::uint16_t>(index));
    const auto routed =
        route_ipv4_into(warmup_routed, warmup_ingress, target, source);
    sink += warmup_arp.size() + warmup_echo.size() +
            (routed ? warmup_routed[22] : 0U);
  }
  {
    auto warmup_link = std::make_unique<router::LinkDirection>(
        router::profile::port_bits_per_second, std::chrono::nanoseconds(0));
    auto now = std::chrono::steady_clock::time_point{};
    for (std::uint32_t index = 0; index < warmup_iterations; ++index) {
      const auto admission = warmup_link->try_transmit({index, 60}, now);
      std::uint32_t delivered{};
      if (!admission ||
          !warmup_link->pop_delivered(delivered, admission->delivered))
        return 2;
      now = admission->delivered;
      sink += delivered & 1U;
    }
  }

  // Encoding measures the allocation-free builders used for ARP resolution
  // and normal 56-octet ICMP probes. Printing sink keeps all packet bytes
  // observable to the optimizer without adding volatile stores to the loop.
  const auto encode_started = std::chrono::steady_clock::now();
  Frame encoded_arp;
  Frame encoded_echo;
  for (std::uint32_t index = 0; index < iterations; ++index) {
    arp_request_into(encoded_arp, source, source_ip, target_ip);
    icmp_echo_into(encoded_echo, source, target, source_ip, target_ip, false,
                   static_cast<std::uint16_t>(index));
    sink += encoded_arp.size() + encoded_echo.size() + encoded_echo[34];
  }
  const auto encode_elapsed =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now() - encode_started);

  // Forwarding includes strict IPv4 parse, checksum validation, a fixed-frame
  // copy, Ethernet rewrite, TTL decrement and checksum recomputation. It does
  // not include real link waits, which are correctness-tested by deadlines.
  const auto ingress =
      icmp_echo(source, target, source_ip, target_ip, false, 1);
  const auto forward_started = std::chrono::steady_clock::now();
  Frame forwarded;
  for (std::uint32_t index = 0; index < iterations; ++index) {
    if (route_ipv4_into(forwarded, ingress, target, source))
      sink += forwarded[22] + forwarded[34];
  }
  const auto forward_elapsed =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now() - forward_started);

  // Link scheduling measures admission, integer wire-time calculation and
  // ordered delivery bookkeeping without sleeping. Correct physical deadlines
  // are asserted separately, so host scheduler jitter cannot corrupt this
  // metric. Heap ownership mirrors LabNetwork and avoids consuming the small
  // Wasm entry stack with the 2048-entry in-flight ring used by the link owner.
  auto link = std::make_unique<router::LinkDirection>(
      router::profile::port_bits_per_second, std::chrono::nanoseconds(0));
  auto link_now = std::chrono::steady_clock::time_point{};
  const auto link_started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < link_iterations; ++index) {
    const auto admission = link->try_transmit({index, 60}, link_now);
    std::uint32_t delivered{};
    if (!admission || !link->pop_delivered(delivered, admission->delivered))
      return 2;
    link_now = admission->delivered;
    sink += delivered & 1U;
  }
  const auto link_elapsed =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now() - link_started);

  const auto encoded_frames = static_cast<double>(iterations) * 2.0;
  std::cout << "{\"encodedFrames\":"
            << static_cast<std::uint64_t>(encoded_frames)
            << ",\"forwardedFrames\":" << iterations
            << ",\"linkFrames\":" << link_iterations
            << ",\"encodingNsPerFrame\":"
            << encode_elapsed.count() / encoded_frames
            << ",\"forwardingNsPerFrame\":"
            << static_cast<double>(forward_elapsed.count()) / iterations
            << ",\"linkSchedulingNsPerFrame\":"
            << static_cast<double>(link_elapsed.count()) / link_iterations
            << ",\"sink\":" << sink << "}\n";
}
