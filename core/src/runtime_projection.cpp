// On-demand JSON and shared-memory telemetry projection. This module reads
// control-owned state but cannot mutate configuration, hardware or forwarding.

#include "router/runtime.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace router {
namespace {

std::string ipv4_text(packet::Ipv4 address) {
  std::ostringstream out;
  out << static_cast<unsigned>(address[0]) << '.'
      << static_cast<unsigned>(address[1]) << '.'
      << static_cast<unsigned>(address[2]) << '.'
      << static_cast<unsigned>(address[3]);
  return out.str();
}

std::string ipv4_text(std::uint32_t address) {
  return ipv4_text({static_cast<std::uint8_t>(address >> 24),
                    static_cast<std::uint8_t>(address >> 16),
                    static_cast<std::uint8_t>(address >> 8),
                    static_cast<std::uint8_t>(address)});
}

std::string mac_text(packet::Mac address) {
  std::ostringstream out;
  out << std::uppercase << std::hex << std::setfill('0');
  for (std::size_t index = 0; index < address.size(); ++index) {
    if (index)
      out << ':';
    out << std::setw(2) << static_cast<unsigned>(address[index]);
  }
  return out.str();
}

std::string json_text(std::string_view value) {
  std::string result;
  result.reserve(value.size());
  for (const unsigned char byte : value) {
    switch (byte) {
    case '"':
      result += "\\\"";
      break;
    case '\\':
      result += "\\\\";
      break;
    case '\b':
      result += "\\b";
      break;
    case '\f':
      result += "\\f";
      break;
    case '\n':
      result += "\\n";
      break;
    case '\r':
      result += "\\r";
      break;
    case '\t':
      result += "\\t";
      break;
    default:
      if (byte >= 0x20)
        result.push_back(static_cast<char>(byte));
    }
  }
  return result;
}

} // namespace

void Runtime::publish_telemetry() noexcept {
  // A seqlock lets UI sample SharedArrayBuffer without a mutex. Control is the
  // sole writer. Odd sequence means update in progress, even means stable page.
  std::atomic_ref<std::uint32_t> sequence(telemetry_.sequence);
  auto generation = sequence.load(std::memory_order_relaxed);
  if (generation & 1U)
    ++generation;
  sequence.store(generation + 1U, std::memory_order_release);
  telemetry_.abi_version = 3;
  telemetry_.byte_size = sizeof(TelemetryPageV1);
  telemetry_.status = stopping_.load(std::memory_order_acquire) ? 3U : 1U;
  telemetry_.worker_count = 2;
  telemetry_.inventory_ports =
      static_cast<std::uint32_t>(state_.inventory_port_count());
  telemetry_.operational_ports = 0;
  telemetry_.port_oper_bitmap = 0;
  for (std::size_t index = 0; index < state_.inventory_port_count(); ++index) {
    if (state_.port_operational(index)) {
      ++telemetry_.operational_ports;
      telemetry_.port_oper_bitmap |= 1U << index;
    }
  }
  telemetry_.fib_generation = static_cast<std::uint32_t>(fib_generation_);
  telemetry_.control_thread_id =
      control_thread_id_.load(std::memory_order_acquire);
  telemetry_.forwarding_thread_id =
      forwarding_thread_id_.load(std::memory_order_acquire);
  telemetry_.control_wakeups = control_wakeups_.load(std::memory_order_relaxed);
  telemetry_.forwarding_wakeups =
      forwarding_wakeups_.load(std::memory_order_relaxed);
  telemetry_.max_scheduling_lag_ns =
      max_scheduling_lag_ns_.load(std::memory_order_relaxed);
  telemetry_.captured_frames = state_.operational.capture_count;
  telemetry_.capture_dropped = state_.operational.capture_dropped;
  telemetry_.dropped_packets = state_.operational.dropped_packets;
  sequence.store(generation + 2U, std::memory_order_release);
}

std::string Runtime::snapshot() {
  publish_telemetry();
  const auto &running = state_.configuration.running;
  const auto &hardware = state_.hardware;
  const auto &operational = state_.operational;
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - started_)
                           .count();
  std::ostringstream out;
  out << "{\"abiVersion\":3,\"status\":\"ready\",\"nowMs\":" << elapsed
      << ",\"hardware\":{\"chassis\":\"" << profile::chassis
      << "\",\"cpmA\":\"active-ready\""
      << ",\"card1Provisioned\":\""
      << (running.card_provisioned ? "iom4-e" : "absent")
      << "\",\"mda11Provisioned\":\""
      << (running.mda_provisioned ? "me10-10gb-sfp+" : "absent")
      << "\",\"card1\":\"" << (hardware.card.present ? "iom4-e" : "absent")
      << "\",\"mda11\":\""
      << (hardware.mda.present
              ? (hardware.mda.compatible ? "me10-10gb-sfp+" : "me1-100gb-cfp2")
              : "absent")
      << "\",\"cardLifecycle\":\""
      << hardware::lifecycle_name(hardware.card.lifecycle)
      << "\",\"mdaLifecycle\":\""
      << hardware::lifecycle_name(hardware.mda.lifecycle)
      << "\",\"cardReason\":\"" << hardware.card.reason << "\",\"mdaReason\":\""
      << hardware.mda.reason << "\"},\"ports\":[";
  for (std::size_t index = 0; index < state_.inventory_port_count(); ++index) {
    if (index)
      out << ',';
    const auto &port = running.ports[index];
    const auto &counters = operational.port_counters[index];
    out << "{\"id\":\"" << profile::port_ids[index] << "\",\"admin\":\""
        << (port.admin_enabled ? "up" : "down") << "\",\"oper\":\""
        << (state_.port_operational(index) ? "up" : "down")
        << "\",\"speedMbps\":" << profile::port_speed_mbps
        << ",\"mtu\":" << port.mtu << ",\"description\":\""
        << json_text(port.description.data())
        << "\",\"rxPackets\":" << counters.rx_packets
        << ",\"txPackets\":" << counters.tx_packets << '}';
  }
  out << "],\"arp\":[";
  bool first = true;
  for (const auto &entry : operational.arp) {
    if (!entry.valid)
      continue;
    if (!first)
      out << ',';
    first = false;
    out << "{\"address\":\"" << ipv4_text(entry.address) << "\",\"mac\":\""
        << mac_text(entry.mac) << "\",\"port\":\""
        << profile::port_ids[entry.port_index] << "\"}";
  }
  out << "],\"routes\":[";
  first = true;
  for (const auto &route : rib_.entries()) {
    if (!first)
      out << ',';
    first = false;
    const auto interface =
        std::find_if(running.interfaces.begin(),
                     running.interfaces.begin() + running.interface_count,
                     [&route](const auto &item) {
                       return item.valid && item.port_index == route.port_index;
                     });
    out << "{\"prefix\":\"";
    if (route.next_hop ||
        interface == running.interfaces.begin() + running.interface_count) {
      out << ipv4_text(route.network) << '/'
          << static_cast<unsigned>(route.prefix_length);
    } else {
      out << interface->prefix;
    }
    out << "\",\"nextHop\":\""
        << (route.next_hop ? ipv4_text(route.next_hop) : "") << "\",\"port\":\""
        << profile::port_ids[route.port_index] << "\",\"source\":\""
        << (route.next_hop ? "static" : "local") << "\"}";
  }
  out << "],\"alarms\":[";
  for (std::size_t index = 0; index < operational.alarm_count; ++index) {
    if (index)
      out << ',';
    const auto &alarm = operational.alarms[index];
    out << "{\"id\":\"" << alarm.id << "\",\"severity\":\"" << alarm.severity
        << "\",\"reason\":\"" << alarm.reason << "\"}";
  }
  out << "],\"runningConfig\":{\"systemName\":\""
      << json_text(running.system_name.data()) << "\",\"ports\":[";
  for (std::size_t index = 0; index < running.ports.size(); ++index) {
    if (index)
      out << ',';
    const auto &port = running.ports[index];
    out << "{\"id\":\"" << profile::port_ids[index] << "\",\"admin\":\""
        << (port.admin_enabled ? "up" : "down") << "\",\"mtu\":" << port.mtu
        << ",\"description\":\"" << json_text(port.description.data()) << "\"}";
  }
  out << "],\"interfaces\":[";
  for (std::size_t index = 0; index < running.interface_count; ++index) {
    if (index)
      out << ',';
    const auto &interface = running.interfaces[index];
    out << "{\"name\":\"" << interface.name << "\",\"admin\":\""
        << (interface.admin_enabled ? "up" : "down") << "\"}";
  }
  out << "],\"staticRoutes\":[";
  first = true;
  for (const auto &route : running.static_routes) {
    if (!route.valid)
      continue;
    if (!first)
      out << ',';
    first = false;
    out << "{\"prefix\":\"" << ipv4_text(route.network) << '/'
        << static_cast<unsigned>(route.prefix_length) << "\",\"nextHop\":\""
        << ipv4_text(route.next_hop) << "\"}";
  }
  out << "]},\"captureCount\":" << operational.capture_count
      << ",\"captureDropped\":" << operational.capture_dropped
      << ",\"droppedPackets\":" << operational.dropped_packets;
  if (operational.last_drop_reason) {
    out << ",\"lastDropReason\":\"" << operational.last_drop_reason << '"';
  }
  out << '}';
  return out.str();
}

} // namespace router
