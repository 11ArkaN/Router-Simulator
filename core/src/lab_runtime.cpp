// Protocol 3 implementation for the multi-router laboratory. Parsing and JSON
// rendering are control-path work. No packet buffer, forwarding pointer or
// mutable registry slot crosses this file's browser-facing boundary.

#include "router/lab_runtime.hpp"

#include "cli_internal.hpp"
#include "router/cli.hpp"
#include "router/generated_lab_runtime_protocol.hpp"
#include "router/shard_policy.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <functional>
#include <iomanip>
#include <iterator>
#include <limits>
#include <sstream>
#include <thread>

namespace router::lab {
namespace {

struct MessageFields {
  // Protocol operations currently need at most nine values. Keeping a wider
  // fixed view array leaves room for additive operations without allocating
  // for every command. Views borrow the command only for this owner turn.
  std::array<std::string_view, 24> values{};
  std::size_t count{};
};

std::optional<MessageFields> parse_message(std::string_view message) noexcept {
  MessageFields result;
  while (!message.empty()) {
    if (result.count == result.values.size())
      return std::nullopt;
    const auto colon = message.find(':');
    if (colon == std::string_view::npos || !colon)
      return std::nullopt;
    std::size_t length{};
    const auto parsed = std::from_chars(message.data(), message.data() + colon,
                                        length);
    if (parsed.ec != std::errc{} || parsed.ptr != message.data() + colon)
      return std::nullopt;
    message.remove_prefix(colon + 1U);
    if (length >= message.size() || message[length] != ',')
      return std::nullopt;
    result.values[result.count++] = message.substr(0, length);
    message.remove_prefix(length + 1U);
  }
  return result.count ? std::optional<MessageFields>{result} : std::nullopt;
}

bool next_netstring(std::string_view &message, std::string_view &value) noexcept {
  // Atomic running-configuration replacement is itself carried inside one
  // outer protocol field. Reusing netstring framing for that nested value
  // preserves arbitrary UTF-8 descriptions without inventing escaping rules.
  const auto colon = message.find(':');
  if (colon == std::string_view::npos || !colon)
    return false;
  std::size_t length{};
  const auto parsed = std::from_chars(message.data(), message.data() + colon,
                                      length);
  if (parsed.ec != std::errc{} || parsed.ptr != message.data() + colon)
    return false;
  message.remove_prefix(colon + 1U);
  if (length >= message.size() || message[length] != ',')
    return false;
  value = message.substr(0, length);
  message.remove_prefix(length + 1U);
  return true;
}

template <typename T>
bool decimal(std::string_view text, T &value) noexcept {
  // from_chars is locale independent and rejects signs, whitespace and partial
  // parses. The range check occurs in the target type used by the runtime.
  if (text.empty())
    return false;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(),
                                      value);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

bool boolean(std::string_view text, bool &value) noexcept {
  if (text == "1") {
    value = true;
    return true;
  }
  if (text == "0") {
    value = false;
    return true;
  }
  return false;
}

std::optional<std::uint32_t> ipv4(std::string_view text) noexcept {
  std::uint32_t result{};
  for (std::size_t octet = 0; octet < 4U; ++octet) {
    const auto separator = text.find('.');
    const auto token = separator == std::string_view::npos
                           ? text
                           : text.substr(0, separator);
    unsigned value{};
    if (!decimal(token, value) || value > 255U)
      return std::nullopt;
    result = result << 8U | value;
    if (octet == 3U) {
      if (separator != std::string_view::npos)
        return std::nullopt;
    } else {
      if (separator == std::string_view::npos)
        return std::nullopt;
      text.remove_prefix(separator + 1U);
    }
  }
  return result;
}

struct Prefix {
  std::uint32_t address{};
  std::uint8_t length{};
};

std::optional<Prefix> prefix(std::string_view text) noexcept {
  const auto slash = text.find('/');
  if (slash == std::string_view::npos)
    return std::nullopt;
  const auto address = ipv4(text.substr(0, slash));
  unsigned length{};
  if (!address || !decimal(text.substr(slash + 1U), length) || length > 32U)
    return std::nullopt;
  return Prefix{*address, static_cast<std::uint8_t>(length)};
}

std::optional<packet::Mac> mac_address(std::string_view text) noexcept {
  packet::Mac result{};
  for (std::size_t byte = 0; byte < result.size(); ++byte) {
    if (text.size() < 2U)
      return std::nullopt;
    unsigned value{};
    const auto parsed = std::from_chars(text.data(), text.data() + 2U, value,
                                        16);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + 2U ||
        value > 255U)
      return std::nullopt;
    result[byte] = static_cast<std::uint8_t>(value);
    if (byte + 1U == result.size()) {
      if (text.size() != 2U)
        return std::nullopt;
    } else {
      if (text.size() < 3U || text[2] != ':')
        return std::nullopt;
      text.remove_prefix(3U);
    }
  }
  // Ethernet source identity must be individual and nonzero. Locally
  // administered addresses remain valid for isolated educational labs.
  if ((result[0] & 1U) != 0U ||
      std::all_of(result.begin(), result.end(), [](auto byte) { return !byte; }))
    return std::nullopt;
  return result;
}

packet::Ipv4 ipv4_bytes(std::uint32_t value) noexcept {
  return {static_cast<std::uint8_t>(value >> 24U),
          static_cast<std::uint8_t>(value >> 16U),
          static_cast<std::uint8_t>(value >> 8U),
          static_cast<std::uint8_t>(value)};
}

std::string ipv4_text(std::uint32_t value) {
  return std::to_string(value >> 24U) + '.' +
         std::to_string(value >> 16U & 255U) + '.' +
         std::to_string(value >> 8U & 255U) + '.' +
         std::to_string(value & 255U);
}

std::string port_id(std::uint16_t ordinal) {
  // Hardware inventory uses a fixed coordinate grid, not a compact present
  // port index. Reversing that documented layout preserves the physical name
  // across MDA removal, re-equipment and checkpoint restore.
  constexpr auto per_card = device_catalog::maximum_mda_slots_per_card *
                            device_catalog::maximum_ports_per_mda;
  const auto card = ordinal / per_card + 1U;
  const auto within_card = ordinal % per_card;
  const auto mda = within_card / device_catalog::maximum_ports_per_mda + 1U;
  const auto port = within_card % device_catalog::maximum_ports_per_mda + 1U;
  return std::to_string(card) + '/' + std::to_string(mda) + '/' +
         std::to_string(port);
}

inline constexpr std::string_view table_rule{
    "==============================================================================="};
inline constexpr std::string_view row_rule{
    "-------------------------------------------------------------------------------"};

std::uint64_t configuration_key(cli_schema::CommandId id,
                                std::string_view instance = {}) noexcept {
  // Candidate conflict tracking needs a stable schema-path identity, not a
  // pointer or process-local hash seed. FNV-1a over the generated command ID
  // and list key remains deterministic in native and Wasm builds.
  std::uint64_t value = 1469598103934665603ULL;
  auto mix = [&](std::uint8_t byte) {
    value ^= byte;
    value *= 1099511628211ULL;
  };
  const auto raw = static_cast<std::uint16_t>(id);
  mix(static_cast<std::uint8_t>(raw));
  mix(static_cast<std::uint8_t>(raw >> 8U));
  for (const auto byte : instance)
    mix(static_cast<std::uint8_t>(byte));
  return value ? value : 1U;
}

CandidateMode candidate_mode(MdCliWorkflow workflow) noexcept {
  switch (workflow) {
  case MdCliWorkflow::implicit_exclusive:
  case MdCliWorkflow::explicit_exclusive:
    return CandidateMode::exclusive;
  case MdCliWorkflow::implicit_global:
  case MdCliWorkflow::explicit_global:
    return CandidateMode::global;
  case MdCliWorkflow::implicit_private:
  case MdCliWorkflow::explicit_private:
    return CandidateMode::private_candidate;
  case MdCliWorkflow::implicit_read_only:
  case MdCliWorkflow::explicit_read_only:
    return CandidateMode::read_only;
  case MdCliWorkflow::operational:
    return CandidateMode::operational;
  }
  return CandidateMode::operational;
}

MdCliWorkflow explicit_workflow(CandidateMode mode) noexcept {
  switch (mode) {
  case CandidateMode::exclusive:
    return MdCliWorkflow::explicit_exclusive;
  case CandidateMode::global:
    return MdCliWorkflow::explicit_global;
  case CandidateMode::private_candidate:
    return MdCliWorkflow::explicit_private;
  case CandidateMode::read_only:
    return MdCliWorkflow::explicit_read_only;
  case CandidateMode::operational:
    return MdCliWorkflow::operational;
  }
  return MdCliWorkflow::operational;
}

bool classic_configuration_command(cli_schema::CommandId id) noexcept {
  using enum cli_schema::CommandId;
  switch (id) {
  case configure_card_type:
  case configure_mda_type:
  case configure_system_name:
  case classic_remove_card_type:
  case classic_remove_mda_type:
  case classic_card_shutdown:
  case classic_card_no_shutdown:
  case classic_mda_shutdown:
  case classic_mda_no_shutdown:
  case classic_port_shutdown:
  case classic_port_no_shutdown:
  case classic_port_description:
  case classic_remove_port_description:
  case classic_port_mtu:
  case classic_interface_shutdown:
  case classic_interface_no_shutdown:
  case classic_interface_port:
  case classic_interface_address:
  case classic_static_route:
  case classic_remove_static_route:
    return true;
  default:
    return false;
  }
}

bool md_configuration_command(cli_schema::CommandId id) noexcept {
  using enum cli_schema::CommandId;
  switch (id) {
  case configure_card_type:
  case configure_mda_type:
  case configure_system_name:
  case md_card_enable:
  case md_card_disable:
  case md_mda_enable:
  case md_mda_disable:
  case md_port_enable:
  case md_port_disable:
  case md_port_description:
  case md_port_mtu:
  case md_interface_enable:
  case md_interface_disable:
  case md_interface_port:
  case md_interface_ipv4_primary:
  case md_static_route:
  case md_delete_card:
  case md_delete_mda:
  case md_delete_port_description:
  case md_delete_static_route:
  case md_compare:
  case md_commit:
  case md_discard:
    return true;
  default:
    return false;
  }
}

bool terminal_global_command(cli_schema::CommandId id) noexcept {
  using enum cli_schema::CommandId;
  switch (id) {
  case switch_engine:
  case help:
  case help_edit:
  case help_global:
  case help_globals:
  case help_special_characters:
  case navigate_back:
  case navigate_back_levels:
  case navigate_closing_brace:
  case navigate_exit:
  case navigate_exit_all:
  case navigate_top:
  case navigate_root:
  case navigate_classic_root:
  case md_quit_config:
  case md_configure_exclusive:
  case md_configure_global:
  case md_configure_private:
  case md_configure_read_only:
  case md_edit_config_exclusive:
  case md_edit_config_global:
  case md_edit_config_private:
  case md_edit_config_read_only:
  case md_compare:
  case md_commit:
  case md_discard:
  case ping:
  case ping_count:
  case ping_size:
  case ping_do_not_fragment:
  case ping_size_do_not_fragment:
  case ping_count_size:
  case ping_count_do_not_fragment:
  case ping_count_size_do_not_fragment:
    return true;
  default:
    return false;
  }
}

bool ping_command(cli_schema::CommandId id) noexcept {
  using enum cli_schema::CommandId;
  return id == ping || id == ping_count || id == ping_size ||
         id == ping_do_not_fragment || id == ping_size_do_not_fragment ||
         id == ping_count_size || id == ping_count_do_not_fragment ||
         id == ping_count_size_do_not_fragment;
}

void json_string(std::ostringstream &out, std::string_view text) {
  // JSON escaping is explicit because system names and descriptions originate
  // from project files. Control characters use \u00XX so a newline cannot
  // create a second JSON token or terminal line at the browser boundary.
  constexpr char hex[] = "0123456789abcdef";
  out << '"';
  for (const auto value : text) {
    const auto byte = static_cast<unsigned char>(value);
    if (value == '"' || value == '\\')
      out << '\\' << value;
    else if (byte < 0x20U)
      out << "\\u00" << hex[byte >> 4U] << hex[byte & 15U];
    else
      out << value;
  }
  out << '"';
}

std::string netstrings(std::initializer_list<std::string_view> fields) {
  std::string result;
  for (const auto field : fields) {
    result += std::to_string(field.size());
    result += ':';
    result.append(field);
    result += ',';
  }
  return result;
}

} // namespace

LabRuntime::LabRuntime() {
  // A protocol 3 laboratory starts empty. Reserving bounded control vectors now
  // keeps later device creation from reallocating unrelated object records.
  routers_.reserve(device_catalog::maximum_routers);
  hosts_.reserve(device_catalog::maximum_hosts);
  sessions_.reserve(device_catalog::maximum_routers *
                    device_catalog::maximum_sessions_per_router);
  // RuntimeSupervisor has already started the network owners. The generated
  // high-CPU policy reserves one additional pthread for the second control
  // partition; lower policies deliberately keep all control work here.
  if (select_shard_policy(std::thread::hardware_concurrency()).control > 1U)
    secondary_control_ = std::make_unique<ControlProjectionWorker>();
  telemetry_.byte_size = sizeof(TelemetryPageV5);
  telemetry_.device_directory_offset = offsetof(TelemetryPageV5, devices);
  telemetry_.session_directory_offset = offsetof(TelemetryPageV5, sessions);
  telemetry_.worker_directory_offset = offsetof(TelemetryPageV5, workers);
  telemetry_.port_bitsets_offset =
      offsetof(TelemetryPageV5, port_oper_bitsets);
  telemetry_.port_bitset_bytes_per_device = TelemetryPageV5::port_bitset_bytes;
  publish_telemetry();
}

LabRuntime::RouterIntent *LabRuntime::router(std::string_view id) noexcept {
  const auto found = std::find_if(routers_.begin(), routers_.end(),
                                  [id](const auto &item) {
                                    return item.node_id == id;
                                  });
  return found == routers_.end() ? nullptr : &*found;
}

const LabRuntime::RouterIntent *
LabRuntime::router(std::string_view id) const noexcept {
  const auto found = std::find_if(routers_.begin(), routers_.end(),
                                  [id](const auto &item) {
                                    return item.node_id == id;
                                  });
  return found == routers_.end() ? nullptr : &*found;
}

LabRuntime::HostIntent *LabRuntime::host(std::string_view id) noexcept {
  const auto found = std::find_if(hosts_.begin(), hosts_.end(),
                                  [id](const auto &item) {
                                    return item.node_id == id;
                                  });
  return found == hosts_.end() ? nullptr : &*found;
}

LabRuntime::ConfigurationIntent
LabRuntime::running_configuration(const RouterIntent &router_intent) const {
  ConfigurationIntent value;
  value.system_name = router_intent.system_name;
  value.ports = router_intent.ports;
  value.interfaces = router_intent.interfaces;
  value.routes = router_intent.routes;
  const auto *inventory = supervisor_.hardware(router_intent.handle);
  if (!inventory)
    return value;
  RouterHardwareCheckpoint hardware;
  inventory->checkpoint(hardware);
  for (std::size_t card = 0; card < hardware.cards.size(); ++card) {
    value.cards[card].provisioned = hardware.cards[card].provisioned;
    value.cards[card].admin_enabled = hardware.cards[card].admin_enabled;
    for (std::size_t mda = 0; mda < hardware.cards[card].mdas.size(); ++mda) {
      value.cards[card].mdas[mda].provisioned =
          hardware.cards[card].mdas[mda].provisioned;
      value.cards[card].mdas[mda].admin_enabled =
          hardware.cards[card].mdas[mda].admin_enabled;
    }
  }
  return value;
}

PortableConfigurationCheckpoint LabRuntime::portable_configuration(
    const ConfigurationIntent &source) const {
  PortableConfigurationCheckpoint target;
  target.system_name = source.system_name;
  for (std::size_t card = 0; card < source.cards.size(); ++card) {
    target.cards[card].provisioned = source.cards[card].provisioned;
    target.cards[card].admin_enabled = source.cards[card].admin_enabled;
    for (std::size_t mda = 0; mda < source.cards[card].mdas.size(); ++mda) {
      target.cards[card].mdas[mda].provisioned =
          source.cards[card].mdas[mda].provisioned;
      target.cards[card].mdas[mda].admin_enabled =
          source.cards[card].mdas[mda].admin_enabled;
    }
  }
  for (const auto &port : source.ports)
    target.ports.push_back({port.id, port.admin_enabled, port.mtu,
                            port.speed_mbps, port.description});
  for (const auto &interface : source.interfaces)
    target.interfaces.push_back(
        {interface.name, interface.port_id, interface.mac, interface.address,
         interface.prefix_length, interface.admin_enabled,
         interface.port_configured, interface.address_configured});
  for (const auto &route : source.routes)
    target.routes.push_back(
        {route.network, route.next_hop, route.prefix_length});
  return target;
}

bool LabRuntime::apply_configuration(RouterIntent &router_intent,
                                     const ConfigurationIntent &value) {
  // The supervisor checkpoint is the transaction boundary across registry,
  // hardware, forwarding and workflow owners. Configuration intent is copied
  // only after every owner accepts the staged candidate.
  auto backup = supervisor_.checkpoint();
  auto *inventory = supervisor_.hardware(router_intent.handle);
  if (!backup || !inventory)
    return false;
  RouterHardwareCheckpoint hardware;
  inventory->checkpoint(hardware);
  bool applied = supervisor_.set_system_name(router_intent.handle,
                                             value.system_name);
  for (std::size_t card = 0; applied && card < value.cards.size(); ++card) {
    const auto slot = static_cast<std::uint16_t>(card + 1U);
    if (value.cards[card].provisioned != hardware.cards[card].provisioned)
      applied = supervisor_.set_card(router_intent.handle, slot,
                                     value.cards[card].provisioned,
                                     hardware.cards[card].equipped) ==
                HardwareEditResult::applied;
    if (applied && value.cards[card].admin_enabled !=
                       hardware.cards[card].admin_enabled)
      applied = supervisor_.set_card_admin(router_intent.handle, slot,
                                           value.cards[card].admin_enabled) ==
                HardwareEditResult::applied;
    for (std::size_t mda = 0; applied && mda < value.cards[card].mdas.size();
         ++mda) {
      const auto mda_slot = static_cast<std::uint16_t>(mda + 1U);
      if (value.cards[card].mdas[mda].provisioned !=
          hardware.cards[card].mdas[mda].provisioned)
        applied = supervisor_.set_mda(
                      router_intent.handle, slot, mda_slot,
                      value.cards[card].mdas[mda].provisioned,
                      hardware.cards[card].mdas[mda].equipped) ==
                  HardwareEditResult::applied;
      if (applied && value.cards[card].mdas[mda].admin_enabled !=
                         hardware.cards[card].mdas[mda].admin_enabled)
        applied = supervisor_.set_mda_admin(
                      router_intent.handle, slot, mda_slot,
                      value.cards[card].mdas[mda].admin_enabled) ==
                  HardwareEditResult::applied;
    }
  }
  for (const auto &port : value.ports)
    if (applied)
      applied = supervisor_.configure_port(
                    router_intent.handle, port.id, port.admin_enabled, port.mtu,
                    port.speed_mbps) == HardwareEditResult::applied;
  for (const auto &interface : router_intent.interfaces)
    if (applied && interface.port_configured && interface.address_configured)
      applied = supervisor_.remove_interface(router_intent.handle,
                                             interface.port_id);
  for (const auto &route : router_intent.routes)
    if (applied)
      applied = supervisor_.remove_static_route(
          router_intent.handle, route.network, route.prefix_length);
  for (const auto &interface : value.interfaces) {
    if (!applied)
      break;
    if (!interface.port_configured || !interface.address_configured)
      continue;
    const auto mac = inventory->physical_mac(interface.port_id);
    applied = mac && supervisor_.configure_interface(
                         router_intent.handle, interface.port_id, *mac,
                         interface.address, interface.prefix_length,
                         interface.admin_enabled);
  }
  for (const auto &route : value.routes)
    if (applied)
      applied = supervisor_.add_static_route(
          router_intent.handle, route.network, route.prefix_length,
          route.next_hop);
  if (!applied) {
    static_cast<void>(supervisor_.restore(std::move(*backup)));
    return false;
  }
  router_intent.system_name = value.system_name;
  router_intent.ports = value.ports;
  router_intent.interfaces = value.interfaces;
  router_intent.routes = value.routes;
  return true;
}

LabRuntime::SessionIntent *LabRuntime::session(std::string_view id) noexcept {
  const auto found = std::find_if(sessions_.begin(), sessions_.end(),
                                  [id](const auto &item) {
                                    return item.session_id == id;
                                  });
  return found == sessions_.end() ? nullptr : &*found;
}

const LabRuntime::SessionIntent *
LabRuntime::session(std::string_view id) const noexcept {
  const auto found = std::find_if(sessions_.begin(), sessions_.end(),
                                  [id](const auto &item) {
                                    return item.session_id == id;
                                  });
  return found == sessions_.end() ? nullptr : &*found;
}

void LabRuntime::fail(std::string_view reason) {
  response_ = "ERROR: ";
  response_.append(reason);
}

void LabRuntime::succeed(std::string_view value) { response_.assign(value); }

bool LabRuntime::create_router(std::span<const std::string_view> fields) {
  if (fields.size() != 3U || router(fields[0]) || host(fields[0]))
    return false;
  const auto handle =
      supervisor_.create_router(fields[0], fields[1], fields[2]);
  if (!handle)
    return false;
  try {
    routers_.push_back({.handle = *handle,
                        .node_id = std::string{fields[0]},
                        .system_name = std::string{fields[2]},
                        .profile_id = std::string{fields[1]},
                        .ports = {},
                        .interfaces = {},
                        .routes = {},
                        .global_candidate = {},
                        .global_candidate_initialized = false});
    return true;
  } catch (...) {
    // Registry creation and model publication form one transaction. If text
    // allocation fails, quiesce the newly created device before reporting it.
    static_cast<void>(supervisor_.delete_router(*handle));
    return false;
  }
}

bool LabRuntime::replace_router_configuration(
    std::span<const std::string_view> fields) {
  auto *device = fields.size() == 2U ? router(fields[0]) : nullptr;
  const auto *inventory = device ? supervisor_.hardware(device->handle) : nullptr;
  if (!device || !inventory)
    return false;

  // Parse into an isolated value first. No registry, hardware, RIB or FIB
  // owner sees a partial form submission if a later record is malformed.
  auto next = running_configuration(*device);
  next.ports.clear();
  next.interfaces.clear();
  next.routes.clear();
  auto payload = fields[1];
  std::string_view value;
  if (!next_netstring(payload, value) || value.empty() || value.size() > 64U)
    return false;
  next.system_name.assign(value);

  std::size_t count{};
  if (!next_netstring(payload, value) || !decimal(value, count) ||
      count > device_catalog::maximum_ports_per_router)
    return false;
  next.ports.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    std::string_view id;
    std::string_view admin_text;
    std::string_view mtu_text;
    std::string_view speed_text;
    std::string_view description;
    bool admin{};
    unsigned mtu{};
    std::uint32_t speed{};
    if (!next_netstring(payload, id) ||
        !next_netstring(payload, admin_text) ||
        !next_netstring(payload, mtu_text) ||
        !next_netstring(payload, speed_text) ||
        !next_netstring(payload, description) || !boolean(admin_text, admin) ||
        !decimal(mtu_text, mtu) || mtu > 0xffffU ||
        !decimal(speed_text, speed) || description.size() > 80U ||
        !inventory->coordinate_ordinal(id) ||
        std::any_of(next.ports.begin(), next.ports.end(),
                    [id](const auto &item) { return item.id == id; }))
      return false;
    next.ports.push_back({std::string{id}, admin,
                          static_cast<std::uint16_t>(mtu), speed,
                          std::string{description}});
  }

  if (!next_netstring(payload, value) || !decimal(value, count) ||
      count > device_catalog::maximum_ports_per_router)
    return false;
  next.interfaces.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    std::string_view name;
    std::string_view port_id;
    std::string_view address_text;
    std::string_view admin_text;
    bool admin{};
    if (!next_netstring(payload, name) ||
        !next_netstring(payload, port_id) ||
        !next_netstring(payload, address_text) ||
        !next_netstring(payload, admin_text) || name.empty() ||
        name.size() > 64U || !boolean(admin_text, admin) ||
        std::any_of(next.interfaces.begin(), next.interfaces.end(),
                    [name](const auto &item) { return item.name == name; }))
      return false;
    const auto address = address_text.empty()
                             ? std::optional<Prefix>{}
                             : prefix(address_text);
    const auto mac = port_id.empty() ? std::optional<packet::Mac>{}
                                     : inventory->physical_mac(port_id);
    if ((!address_text.empty() && !address) || (!port_id.empty() && !mac))
      return false;
    next.interfaces.push_back(
        {.name = std::string{name},
         .port_id = std::string{port_id},
         .mac = mac.value_or(packet::Mac{}),
         .address = address ? address->address : 0U,
         .prefix_length = static_cast<std::uint8_t>(address ? address->length
                                                            : 0U),
         .admin_enabled = admin,
         .port_configured = !port_id.empty(),
         .address_configured = !address_text.empty()});
  }

  if (!next_netstring(payload, value) || !decimal(value, count) ||
      count > device_catalog::maximum_static_routes_per_router)
    return false;
  next.routes.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    std::string_view prefix_text;
    std::string_view next_hop_text;
    if (!next_netstring(payload, prefix_text) ||
        !next_netstring(payload, next_hop_text))
      return false;
    const auto destination = prefix(prefix_text);
    const auto next_hop = ipv4(next_hop_text);
    if (!destination || !next_hop || !*next_hop ||
        (destination->address & routing::prefix_mask(destination->length)) !=
            destination->address ||
        std::any_of(next.routes.begin(), next.routes.end(),
                    [&](const auto &item) {
                      return item.network == destination->address &&
                             item.prefix_length == destination->length;
                    }))
      return false;
    next.routes.push_back({destination->address, *next_hop,
                           destination->length});
  }
  // Exact exhaustion rejects appended fields from a newer or corrupted
  // payload instead of silently applying only the prefix understood here.
  return payload.empty() && apply_configuration(*device, next);
}

bool LabRuntime::create_host(std::span<const std::string_view> fields) {
  if (fields.size() != 2U || router(fields[0]) || host(fields[0]))
    return false;
  const auto handle = supervisor_.create_host(fields[0], fields[1]);
  if (!handle)
    return false;
  try {
    hosts_.push_back({.handle = *handle,
                      .node_id = std::string{fields[0]},
                      .name = std::string{fields[1]}});
    return true;
  } catch (...) {
    static_cast<void>(supervisor_.delete_host(*handle));
    return false;
  }
}

bool LabRuntime::set_card(std::span<const std::string_view> fields) {
  unsigned slot{};
  auto *device = fields.size() == 4U ? router(fields[0]) : nullptr;
  return device && decimal(fields[1], slot) && slot <= 0xffffU &&
         supervisor_.set_card(device->handle, static_cast<std::uint16_t>(slot),
                              fields[2], fields[3]) ==
             HardwareEditResult::applied;
}

bool LabRuntime::set_mda(std::span<const std::string_view> fields) {
  unsigned card{};
  unsigned mda{};
  auto *device = fields.size() == 5U ? router(fields[0]) : nullptr;
  return device && decimal(fields[1], card) && decimal(fields[2], mda) &&
         card <= 0xffffU && mda <= 0xffffU &&
         supervisor_.set_mda(device->handle, static_cast<std::uint16_t>(card),
                             static_cast<std::uint16_t>(mda), fields[3],
                             fields[4]) == HardwareEditResult::applied;
}

bool LabRuntime::configure_port(
    std::span<const std::string_view> fields) {
  bool admin{};
  unsigned mtu{};
  std::uint32_t speed{};
  auto *device = fields.size() == 6U ? router(fields[0]) : nullptr;
  if (!device || !boolean(fields[2], admin) || !decimal(fields[3], mtu) ||
      !decimal(fields[4], speed) || mtu > 0xffffU || fields[5].size() > 80U ||
      supervisor_.configure_port(device->handle, fields[1], admin,
                                 static_cast<std::uint16_t>(mtu), speed) !=
          HardwareEditResult::applied)
    return false;
  auto found = std::find_if(device->ports.begin(), device->ports.end(),
                            [id = fields[1]](const auto &item) {
                              return item.id == id;
                            });
  PortIntent value{std::string{fields[1]}, admin,
                   static_cast<std::uint16_t>(mtu), speed,
                   std::string{fields[5]}};
  if (found == device->ports.end())
    device->ports.push_back(std::move(value));
  else
    *found = std::move(value);
  return true;
}

bool LabRuntime::configure_interface(
    std::span<const std::string_view> fields) {
  bool admin{};
  auto *device = fields.size() == 5U ? router(fields[0]) : nullptr;
  const auto *inventory = device ? supervisor_.hardware(device->handle) : nullptr;
  const auto address = !fields[3].empty() ? prefix(fields[3])
                                          : std::optional<Prefix>{};
  const auto mac = inventory && !fields[2].empty()
                       ? inventory->physical_mac(fields[2])
                       : std::optional<packet::Mac>{};
  if (!device || fields[1].empty() || fields[1].size() > 64U ||
      (!fields[2].empty() && !mac) || (!fields[3].empty() && !address) ||
      !boolean(fields[4], admin))
    return false;
  auto found = std::find_if(device->interfaces.begin(),
                            device->interfaces.end(),
                            [name = fields[1]](const auto &item) {
                              return item.name == name;
                            });
  InterfaceIntent value{.name = std::string{fields[1]},
                        .port_id = std::string{fields[2]},
                        .mac = mac.value_or(packet::Mac{}),
                        .address = address ? address->address : 0U,
                        .prefix_length = static_cast<std::uint8_t>(
                            address ? address->length : 0U),
                        .admin_enabled = admin,
                        .port_configured = !fields[2].empty(),
                        .address_configured = !fields[3].empty()};
  auto backup = supervisor_.checkpoint();
  if (!backup)
    return false;
  // A partial interface is valid configuration but has no forwarding port.
  // Replacing a complete interface withdraws the old port projection before a
  // new complete projection is installed. The supervisor checkpoint rolls the
  // owner graph back if either side rejects the transaction.
  if (found != device->interfaces.end() && found->port_configured &&
      found->address_configured &&
      !supervisor_.remove_interface(device->handle, found->port_id)) {
    static_cast<void>(supervisor_.restore(std::move(*backup)));
    return false;
  }
  if (value.port_configured && value.address_configured &&
      !supervisor_.configure_interface(device->handle, value.port_id, value.mac,
                                       value.address, value.prefix_length,
                                       value.admin_enabled)) {
    static_cast<void>(supervisor_.restore(std::move(*backup)));
    return false;
  }
  if (found == device->interfaces.end())
    device->interfaces.push_back(std::move(value));
  else
    *found = std::move(value);
  return true;
}

bool LabRuntime::delete_interface(
    std::span<const std::string_view> fields) {
  auto *device = fields.size() == 2U ? router(fields[0]) : nullptr;
  if (!device)
    return false;
  const auto found = std::find_if(
      device->interfaces.begin(), device->interfaces.end(),
      [name = fields[1]](const auto &item) { return item.name == name; });
  if (found == device->interfaces.end() ||
      (found->port_configured && found->address_configured &&
       !supervisor_.remove_interface(device->handle, found->port_id)))
    return false;
  // Runtime removal succeeded before portable intent is erased. A failed
  // forwarding transaction therefore leaves the project-facing record intact
  // and visible for a retry instead of losing the user's configuration key.
  device->interfaces.erase(found);
  return true;
}

bool LabRuntime::add_static_route(
    std::span<const std::string_view> fields) {
  const auto destination = fields.size() == 3U ? prefix(fields[1]) : std::nullopt;
  const auto next_hop = fields.size() == 3U ? ipv4(fields[2]) : std::nullopt;
  auto *device = fields.size() == 3U ? router(fields[0]) : nullptr;
  if (!device || !destination || !next_hop || !*next_hop ||
      (destination->address & routing::prefix_mask(destination->length)) !=
          destination->address ||
      !supervisor_.add_static_route(device->handle, destination->address,
                                    destination->length, *next_hop))
    return false;
  StaticRouteIntent value{destination->address, *next_hop,
                          destination->length};
  auto found = std::find_if(device->routes.begin(), device->routes.end(),
                            [&](const auto &item) {
                              return item.network == value.network &&
                                     item.prefix_length == value.prefix_length;
                            });
  if (found == device->routes.end())
    device->routes.push_back(value);
  else
    *found = value;
  return true;
}

bool LabRuntime::delete_static_route(
    std::span<const std::string_view> fields) {
  const auto destination = fields.size() == 2U ? prefix(fields[1]) : std::nullopt;
  auto *device = fields.size() == 2U ? router(fields[0]) : nullptr;
  if (!device || !destination)
    return false;
  const auto found = std::find_if(
      device->routes.begin(), device->routes.end(), [&](const auto &item) {
        return item.network == destination->address &&
               item.prefix_length == destination->length;
      });
  if (found == device->routes.end() ||
      !supervisor_.remove_static_route(device->handle, destination->address,
                                       destination->length))
    return false;
  device->routes.erase(found);
  return true;
}

bool LabRuntime::create_link(std::span<const std::string_view> fields) {
  std::uint64_t delay{};
  bool admin{};
  if (fields.size() != 7U || !decimal(fields[5], delay) ||
      !boolean(fields[6], admin))
    return false;
  const auto endpoint = [this](std::string_view node_id,
                               std::string_view port_id)
      -> std::optional<LinkEndpoint> {
    if (const auto *device = router(node_id))
      return LinkEndpoint{node(device->handle), std::string{port_id}};
    if (const auto *endpoint_host = host(node_id))
      return LinkEndpoint{node(endpoint_host->handle), std::string{port_id}};
    return std::nullopt;
  };
  const auto first = endpoint(fields[1], fields[2]);
  const auto second = endpoint(fields[3], fields[4]);
  return first && second &&
         supervisor_.create_link(fields[0], *first, *second,
                                 std::chrono::nanoseconds{delay}, admin)
             .has_value();
}

bool LabRuntime::configure_host(
    std::span<const std::string_view> fields) {
  auto *endpoint = fields.size() == 5U ? host(fields[0]) : nullptr;
  const auto mac = fields.size() == 5U ? mac_address(fields[1]) : std::nullopt;
  const auto address = fields.size() == 5U ? prefix(fields[2]) : std::nullopt;
  const auto gateway = fields.size() == 5U ? ipv4(fields[3]) : std::nullopt;
  unsigned mtu{};
  if (!endpoint || !mac || !address || !gateway || !*gateway ||
      !decimal(fields[4], mtu) ||
      mtu < device_catalog::minimum_host_ipv4_mtu ||
      mtu > device_catalog::maximum_network_mtu ||
      !supervisor_.configure_host(endpoint->handle, *mac,
                                  ipv4_bytes(address->address), address->length,
                                  ipv4_bytes(*gateway),
                                  static_cast<std::uint16_t>(mtu)))
    return false;
  endpoint->mac = *mac;
  endpoint->address = ipv4_bytes(address->address);
  endpoint->gateway = ipv4_bytes(*gateway);
  endpoint->prefix_length = address->length;
  endpoint->mtu = static_cast<std::uint16_t>(mtu);
  endpoint->configured = true;
  return true;
}

bool LabRuntime::create_session(
    std::span<const std::string_view> fields) {
  auto *device = fields.size() == 3U ? router(fields[1]) : nullptr;
  if (!device || session(fields[0]))
    return false;
  const auto handle = supervisor_.create_session(device->handle, fields[0]);
  if (!handle)
    return false;
  CandidateMode mode{CandidateMode::operational};
  if (fields[2] == "global")
    mode = CandidateMode::global;
  else if (fields[2] == "exclusive")
    mode = CandidateMode::exclusive;
  else if (fields[2] == "private")
    mode = CandidateMode::private_candidate;
  else if (fields[2] == "read-only")
    mode = CandidateMode::read_only;
  else if (fields[2] != "operational") {
    static_cast<void>(supervisor_.close_session(*handle));
    return false;
  }
  if (mode != CandidateMode::operational &&
      supervisor_.enter_session_mode(*handle, mode) !=
          SessionWorkflowResult::applied) {
    static_cast<void>(supervisor_.close_session(*handle));
    return false;
  }
  try {
    SessionIntent terminal{.handle = *handle,
                           .session_id = std::string{fields[0]},
                           .cli = {},
                           .private_candidate = {},
                           .private_candidate_initialized = false,
                           .ping = {}};
    // A session requested directly in a candidate mode starts at the explicit
    // configuration root. Operational sessions enter implicit or explicit
    // workflows only through actual CLI input.
    if (mode != CandidateMode::operational)
      terminal.cli.md_workflow = explicit_workflow(mode);
    if (mode == CandidateMode::private_candidate) {
      const auto *router_intent = router(fields[1]);
      if (!router_intent) {
        static_cast<void>(supervisor_.close_session(*handle));
        return false;
      }
      terminal.private_candidate = running_configuration(*router_intent);
      terminal.private_candidate_initialized = true;
    } else if (mode != CandidateMode::operational) {
      auto *router_intent = router(fields[1]);
      if (!router_intent) {
        static_cast<void>(supervisor_.close_session(*handle));
        return false;
      }
      if (!router_intent->global_candidate_initialized ||
          mode == CandidateMode::exclusive) {
        router_intent->global_candidate =
            running_configuration(*router_intent);
        router_intent->global_candidate_initialized = true;
      }
    }
    sessions_.push_back(std::move(terminal));
    return true;
  } catch (...) {
    static_cast<void>(supervisor_.close_session(*handle));
    return false;
  }
}

std::string LabRuntime::session_state(std::string_view session_id) const {
  const auto *terminal = session(session_id);
  if (!terminal)
    return {};
  const auto *record = supervisor_.sessions().get(terminal->handle);
  const auto *device = record ? supervisor_.devices().get(record->device) : nullptr;
  if (!record || !device)
    return {};
  const auto region = terminal->cli.engine == CliEngine::classic
                          ? std::string_view{"classic"}
                          : record->mode == CandidateMode::operational
                                ? std::string_view{"md-operational"}
                                : std::string_view{"md-configuration"};
  // The established prompt renderer owns context, workflow and unsaved
  // markers. A short-lived view supplies only the selected router's current
  // name. Its profile-created defaults are never read or published.
  DeviceState view;
  view.configuration.running.system_name.fill('\0');
  std::copy(device->system_name.begin(), device->system_name.end(),
            view.configuration.running.system_name.begin());
  const auto prompt = cli_prompt(view, terminal->cli);
  const auto banner = terminal->ping.active ? std::string_view{"pending"}
                                            : std::string_view{};
  return netstrings({terminal->cli.engine == CliEngine::classic
                         ? std::string_view{"classic"}
                         : std::string_view{"md"},
                     region, banner, prompt});
}

std::string LabRuntime::execute_session(std::string_view session_id,
                                        std::string_view input) {
  auto *terminal = session(session_id);
  if (!terminal)
    return {};
  const auto *session_record = supervisor_.sessions().get(terminal->handle);
  const auto *device = session_record
                           ? supervisor_.devices().get(session_record->device)
                           : nullptr;
  // Configuration commands below update the selected router's canonical
  // intent only after the owning supervisor accepts the same mutation. Keep a
  // mutable pointer here instead of casting away constness at each commit.
  auto *intent = device ? router(device->node_id) : nullptr;
  if (!session_record || !device || !intent)
    return {};
  if (terminal->ping.active)
    return "MINOR: CLI #2069: Operation not allowed - another command is in "
           "progress" +
           session_state(session_id);
  // Shared global candidate edits can be made by another terminal. Refresh
  // prompt markers before interpreting this input so the next command and its
  // exit policy observe the router-owned datastore, not a stale session copy.
  if (const auto status = supervisor_.session_status(terminal->handle)) {
    terminal->cli.candidate_dirty = status->candidate_dirty;
    terminal->cli.candidate_outdated = status->baseline_outdated;
  }
  // This view supplies only prompt identity to the reusable CLI state machine.
  // Product configuration remains in RouterIntent and RuntimeSupervisor.
  DeviceState view;
  view.configuration.running.system_name.fill('\0');
  std::copy(device->system_name.begin(), device->system_name.end(),
            view.configuration.running.system_name.begin());
  const auto initialize_candidate = [&](CandidateMode mode) {
    if (mode == CandidateMode::private_candidate) {
      terminal->private_candidate = running_configuration(*intent);
      terminal->private_candidate_initialized = true;
    } else if (mode != CandidateMode::operational &&
               (!intent->global_candidate_initialized ||
                mode == CandidateMode::exclusive)) {
      intent->global_candidate = running_configuration(*intent);
      intent->global_candidate_initialized = true;
    }
  };
  const auto reconcile_workflow = [&](const CliSession &before,
                                      std::string &text) {
    const auto source = candidate_mode(before.md_workflow);
    const auto target = candidate_mode(terminal->cli.md_workflow);
    SessionWorkflowResult result = SessionWorkflowResult::applied;
    if (source == CandidateMode::operational &&
        target != CandidateMode::operational) {
      result = supervisor_.enter_session_mode(terminal->handle, target);
      if (result == SessionWorkflowResult::applied)
        initialize_candidate(target);
    } else if (source != CandidateMode::operational &&
               target == CandidateMode::operational) {
      result = supervisor_.leave_session_mode(terminal->handle, true);
    } else if (source != target) {
      // A dirty exclusive transition reaches this point only after the user
      // answered its session-owned confirmation. Datastore arbitration and
      // prompt workflow must either move together or both remain unchanged.
      const bool discard = before.md_exit_confirmation &&
                           !terminal->cli.md_exit_confirmation;
      result = supervisor_.transition_session_mode(terminal->handle, target,
                                                   discard);
      if (result == SessionWorkflowResult::applied && discard) {
        intent->global_candidate = running_configuration(*intent);
        intent->global_candidate_initialized = true;
      }
    }
    if (result != SessionWorkflowResult::applied) {
      terminal->cli = before;
      text = result == SessionWorkflowResult::exclusive_unavailable
                 ? "MINOR: MGMT_CORE #2052: Exclusive datastore access "
                   "unavailable - model-driven interface editing global "
                   "candidate"
                 : "MINOR: MGMT_CORE #2069: Operation not allowed";
      text += cli_prompt(view, terminal->cli);
      return false;
    }
    const auto status = supervisor_.session_status(terminal->handle);
    terminal->cli.candidate_dirty =
        status.has_value() && status->candidate_dirty;
    terminal->cli.candidate_outdated =
        status.has_value() && status->baseline_outdated;
    if (source == CandidateMode::operational &&
        target == CandidateMode::global && status && status->candidate_dirty)
      text += "\nINFO: CLI #2055: Uncommitted changes are present in the "
              "candidate configuration";
    if (source == CandidateMode::operational &&
        target == CandidateMode::global &&
        supervisor_.sessions().count(session_record->device,
                                     CandidateMode::global) > 1U)
      text += "\nINFO: CLI #2075: Other global configuration sessions are "
              "active";
    return true;
  };

  // Execution consumes the generated release grammar. The temporary view is
  // presentation-only: it supplies the selected router name to the existing
  // navigation and prompt state machine, while all persistent configuration
  // and packet state remains owned by the multi-router runtime.
  const auto engine = terminal->cli.engine;
  const auto workflow = terminal->cli.md_workflow;
  const auto effective = cli_detail::resolve_session_input(terminal->cli, input);
  auto parsed = cli_detail::parse_command(engine, workflow, input);
  if (!parsed || !terminal_global_command(parsed->spec->id))
    parsed = cli_detail::parse_command(engine, workflow, effective);
  std::string output;
  if (!parsed) {
    // Container navigation, incomplete syntax help and bad-command wording are
    // semantic CLI behavior. Running the proven session engine here cannot
    // mutate product configuration because no executable schema row matched.
    const auto before = terminal->cli;
    output = execute_cli(view, terminal->cli, std::string{input}, {});
    static_cast<void>(reconcile_workflow(before, output));
    static_cast<void>(
        supervisor_.set_cli_session(terminal->handle, terminal->cli));
    return output + session_state(session_id);
  }

  const auto session_only = [](cli_schema::CommandId id) {
    using enum cli_schema::CommandId;
    switch (id) {
    case switch_engine:
    case help:
    case help_edit:
    case help_global:
    case help_globals:
    case help_special_characters:
    case navigate_back:
    case navigate_back_levels:
    case navigate_closing_brace:
    case navigate_exit:
    case navigate_exit_all:
    case navigate_top:
    case navigate_root:
    case navigate_classic_root:
    case md_quit_config:
    case md_configure_exclusive:
    case md_configure_global:
    case md_configure_private:
    case md_configure_read_only:
    case md_edit_config_exclusive:
    case md_edit_config_global:
    case md_edit_config_private:
    case md_edit_config_read_only:
      return true;
    default:
      return false;
    }
  };
  if (session_only(parsed->spec->id)) {
    const auto before = terminal->cli;
    output = execute_cli(view, terminal->cli, std::string{input}, {});
    static_cast<void>(reconcile_workflow(before, output));
    static_cast<void>(
        supervisor_.set_cli_session(terminal->handle, terminal->cli));
  } else if (ping_command(parsed->spec->id)) {
    const auto destination_text =
        cli_detail::argument(*parsed, cli_schema::TokenKind::ipv4);
    const auto destination = destination_text ? ipv4(*destination_text)
                                              : std::optional<std::uint32_t>{};
    std::uint32_t count = profile::default_ping_count;
    std::uint32_t payload = device_catalog::default_ping_payload_octets;
    if (const auto value = cli_detail::argument(
            *parsed, cli_schema::TokenKind::count))
      if (!decimal(*value, count))
        count = 0;
    if (const auto value = cli_detail::argument(
            *parsed, cli_schema::TokenKind::size))
      if (!decimal(*value, payload))
        payload = std::numeric_limits<std::uint32_t>::max();
    if (terminal->ping.active) {
      output = "MINOR: CLI #2069: Operation not allowed - another command is "
               "in progress";
    } else if (!destination || !count ||
               count > device_catalog::maximum_ping_count ||
               payload < device_catalog::minimum_ping_payload_octets ||
               payload > device_catalog::maximum_ping_payload_octets) {
      output = "MINOR: MGMT_CORE #2301: Invalid element value";
    } else {
      auto &operation = terminal->ping;
      operation.destination = *destination;
      operation.sequence = static_cast<std::uint16_t>(operation.sequence + 1U);
      operation.payload_octets = static_cast<std::uint16_t>(payload);
      operation.requested = count;
      operation.sent = 0;
      operation.received = 0;
      operation.dont_fragment =
          parsed->spec->id == cli_schema::CommandId::ping_do_not_fragment ||
          parsed->spec->id ==
              cli_schema::CommandId::ping_size_do_not_fragment ||
          parsed->spec->id ==
              cli_schema::CommandId::ping_count_do_not_fragment ||
          parsed->spec->id ==
              cli_schema::CommandId::ping_count_size_do_not_fragment;
      operation.waiting = false;
      operation.active = true;
      operation.cancel_requested = false;
      operation.next_send = std::chrono::steady_clock::now();
      output = "PING " + std::string{*destination_text} + " " +
               std::to_string(payload) + " data bytes\n";
    }
  } else if (terminal->cli.engine == CliEngine::md &&
             md_configuration_command(parsed->spec->id)) {
    using enum cli_schema::CommandId;
    const auto id = parsed->spec->id;
    const auto mode = session_record->mode;
    auto *candidate = mode == CandidateMode::private_candidate
                          ? &terminal->private_candidate
                          : &intent->global_candidate;
    const auto argument = [&](cli_schema::TokenKind kind) {
      return cli_detail::argument(*parsed, kind);
    };
    if (mode == CandidateMode::operational ||
        mode == CandidateMode::read_only) {
      output = "MINOR: CLI #2069: Operation not allowed - currently in " +
               std::string{mode == CandidateMode::read_only ? "read-only"
                                                            : "operational"} +
               " mode";
    } else if (id == md_commit) {
      auto backup = supervisor_.checkpoint();
      const auto committed = backup ? supervisor_.commit_session(
                                          terminal->handle)
                                    : SessionWorkflowResult::invalid_session;
      if (committed == SessionWorkflowResult::applied &&
          apply_configuration(*intent, *candidate)) {
        *candidate = running_configuration(*intent);
        terminal->cli.candidate_dirty = false;
        terminal->cli.candidate_outdated = false;
      } else {
        if (backup)
          static_cast<void>(supervisor_.restore(std::move(*backup)));
        output = committed == SessionWorkflowResult::merge_conflict
                     ? "MINOR: MGMT_CORE #2320: Candidate configuration has "
                       "conflicts with running configuration"
                     : "MINOR: MGMT_CORE #2203: Candidate commit failed";
      }
    } else if (id == md_discard) {
      if (supervisor_.discard_session(terminal->handle) ==
          SessionWorkflowResult::applied) {
        *candidate = running_configuration(*intent);
        terminal->cli.candidate_dirty = false;
        terminal->cli.candidate_outdated = false;
      } else {
        output = "MINOR: MGMT_CORE #2203: Candidate discard failed";
      }
    } else if (id == md_compare) {
      const auto running = running_configuration(*intent);
      std::ostringstream comparison;
      if (candidate->system_name != running.system_name)
        comparison << "- system name \"" << running.system_name
                   << "\"\n+ system name \"" << candidate->system_name
                   << "\"\n";
      for (std::size_t card = 0; card < candidate->cards.size(); ++card)
        if (candidate->cards[card] != running.cards[card])
          comparison << "~ card " << card + 1U << "\n";
      for (const auto &port : candidate->ports) {
        const auto old = std::find_if(
            running.ports.begin(), running.ports.end(),
            [&](const auto &value) { return value.id == port.id; });
        if (old == running.ports.end() || *old != port)
          comparison << "~ port " << port.id << "\n";
      }
      for (const auto &interface : candidate->interfaces) {
        const auto old = std::find_if(
            running.interfaces.begin(), running.interfaces.end(),
            [&](const auto &value) { return value.name == interface.name; });
        if (old == running.interfaces.end() || *old != interface)
          comparison << "~ router \"Base\" interface \""
                     << interface.name << "\"\n";
      }
      for (const auto &route : candidate->routes)
        if (std::find(running.routes.begin(), running.routes.end(), route) ==
            running.routes.end())
          comparison << "+ router \"Base\" static-routes route "
                     << ipv4_text(route.network) << '/'
                     << static_cast<unsigned>(route.prefix_length) << "\n";
      output = comparison.str();
    } else {
      const auto before = *candidate;
      bool valid = true;
      std::string instance;
      for (const auto kind : {cli_schema::TokenKind::card_slot,
                              cli_schema::TokenKind::mda_slot,
                              cli_schema::TokenKind::port_id,
                              cli_schema::TokenKind::interface_name,
                              cli_schema::TokenKind::ipv4_prefix})
        if (const auto value = argument(kind)) {
          instance.push_back('/');
          instance.append(*value);
        }

      if (id == configure_system_name) {
        const auto raw = argument(cli_schema::TokenKind::system_name);
        const auto name = raw ? cli_detail::unquote(*raw) : std::string_view{};
        valid = raw && !name.empty() && name.size() <= 64U &&
                cli_detail::valid_cli_string(*raw);
        if (valid)
          candidate->system_name.assign(name);
      } else if (id == configure_card_type || id == md_delete_card ||
                 id == md_card_enable || id == md_card_disable) {
        unsigned card{};
        const auto slot = argument(cli_schema::TokenKind::card_slot);
        valid = slot && decimal(*slot, card) && card &&
                card <= device->profile->card_slots &&
                !device->profile->fixed;
        if (valid && id == configure_card_type) {
          const auto type = argument(cli_schema::TokenKind::card_type);
          valid = type && device_catalog::find_card(*device->profile, *type);
          if (valid)
            candidate->cards[card - 1U].provisioned.assign(*type);
        } else if (valid && id == md_delete_card) {
          candidate->cards[card - 1U] = {};
        } else if (valid) {
          candidate->cards[card - 1U].admin_enabled = id == md_card_enable;
        }
      } else if (id == configure_mda_type || id == md_delete_mda ||
                 id == md_mda_enable || id == md_mda_disable) {
        unsigned card{};
        unsigned mda{};
        const auto card_text = argument(cli_schema::TokenKind::card_slot);
        const auto mda_text = argument(cli_schema::TokenKind::mda_slot);
        valid = card_text && mda_text && decimal(*card_text, card) &&
                decimal(*mda_text, mda) && card && mda &&
                card <= candidate->cards.size() &&
                mda <= device_catalog::maximum_mda_slots_per_card &&
                !candidate->cards[card - 1U].provisioned.empty();
        if (valid && id == configure_mda_type) {
          const auto type = argument(cli_schema::TokenKind::mda_type);
          const auto *card_profile = device_catalog::find_card(
              *device->profile, candidate->cards[card - 1U].provisioned);
          valid = type && card_profile &&
                  device_catalog::card_supports_mda(*card_profile, *type);
          if (valid)
            candidate->cards[card - 1U].mdas[mda - 1U].provisioned.assign(
                *type);
        } else if (valid && id == md_delete_mda) {
          candidate->cards[card - 1U].mdas[mda - 1U] = {};
        } else if (valid) {
          candidate->cards[card - 1U].mdas[mda - 1U].admin_enabled =
              id == md_mda_enable;
        }
      } else if (id == md_port_enable || id == md_port_disable ||
                 id == md_port_description || id == md_delete_port_description ||
                 id == md_port_mtu) {
        const auto port_text = argument(cli_schema::TokenKind::port_id);
        const auto *inventory = supervisor_.hardware(intent->handle);
        const auto *physical = port_text && inventory
                                   ? inventory->find(*port_text)
                                   : nullptr;
        valid = port_text && physical;
        auto current = valid ? std::find_if(
                                   candidate->ports.begin(),
                                   candidate->ports.end(), [&](const auto &port) {
                                     return port.id == *port_text;
                                   })
                             : candidate->ports.end();
        if (valid && current == candidate->ports.end()) {
          candidate->ports.push_back(
              {std::string{*port_text}, physical->admin_enabled, physical->mtu,
               physical->speed_mbps, {}});
          current = std::prev(candidate->ports.end());
        }
        if (valid && (id == md_port_enable || id == md_port_disable))
          current->admin_enabled = id == md_port_enable;
        else if (valid && id == md_delete_port_description)
          current->description.clear();
        else if (valid && id == md_port_description) {
          const auto raw = argument(cli_schema::TokenKind::description);
          const auto text = raw ? cli_detail::unquote(*raw) : std::string_view{};
          valid = raw && !text.empty() && text.size() <= 80U &&
                  cli_detail::valid_cli_string(*raw);
          if (valid)
            current->description.assign(text);
        } else if (valid) {
          unsigned mtu{};
          const auto text = argument(cli_schema::TokenKind::mtu);
          valid = text && decimal(*text, mtu) &&
                  mtu >= device_catalog::minimum_network_mtu &&
                  mtu <= device_catalog::maximum_network_mtu;
          if (valid)
            current->mtu = static_cast<std::uint16_t>(mtu);
        }
      } else if (id == md_interface_enable || id == md_interface_disable ||
                 id == md_interface_port || id == md_interface_ipv4_primary) {
        const auto raw_name = argument(cli_schema::TokenKind::interface_name);
        const auto name = raw_name ? cli_detail::unquote(*raw_name)
                                   : std::string_view{};
        valid = raw_name && !name.empty() && name.size() <= 64U;
        auto current = std::find_if(
            candidate->interfaces.begin(), candidate->interfaces.end(),
            [&](const auto &value) { return value.name == name; });
        if (valid && current == candidate->interfaces.end()) {
          candidate->interfaces.push_back(
              {.name = std::string{name},
               .port_id = {},
               .mac = {},
               .address = 0,
               .prefix_length = 0,
               .admin_enabled = false,
               .port_configured = false,
               .address_configured = false});
          current = std::prev(candidate->interfaces.end());
        }
        if (valid && (id == md_interface_enable || id == md_interface_disable))
          current->admin_enabled = id == md_interface_enable;
        else if (valid && id == md_interface_port) {
          const auto value = argument(cli_schema::TokenKind::port_id);
          const auto *inventory = supervisor_.hardware(intent->handle);
          valid = value && inventory && inventory->coordinate_ordinal(*value);
          if (valid) {
            current->port_id.assign(*value);
            current->port_configured = true;
          }
        } else if (valid) {
          const auto address = argument(cli_schema::TokenKind::ipv4);
          const auto length = argument(cli_schema::TokenKind::prefix_length);
          unsigned bits{};
          const auto parsed_address = address ? ipv4(*address)
                                              : std::optional<std::uint32_t>{};
          valid = parsed_address && length && decimal(*length, bits) &&
                  bits <= 32U;
          if (valid) {
            current->address = *parsed_address;
            current->prefix_length = static_cast<std::uint8_t>(bits);
            current->address_configured = true;
          }
        }
      } else if (id == md_static_route || id == md_delete_static_route) {
        const auto destination = argument(cli_schema::TokenKind::ipv4_prefix);
        const auto parsed_destination = destination ? prefix(*destination)
                                                    : std::optional<Prefix>{};
        valid = parsed_destination.has_value();
        auto current = valid ? std::find_if(
                                   candidate->routes.begin(),
                                   candidate->routes.end(), [&](const auto &route) {
                                     return route.network ==
                                                parsed_destination->address &&
                                            route.prefix_length ==
                                                parsed_destination->length;
                                   })
                             : candidate->routes.end();
        if (valid && id == md_delete_static_route) {
          valid = current != candidate->routes.end();
          if (valid)
            candidate->routes.erase(current);
        } else if (valid) {
          const auto next_hop_text = argument(cli_schema::TokenKind::ipv4_key);
          const auto next_hop = next_hop_text
                                    ? ipv4(cli_detail::unquote(*next_hop_text))
                                    : std::optional<std::uint32_t>{};
          valid = next_hop.has_value();
          if (valid && current == candidate->routes.end())
            candidate->routes.push_back({parsed_destination->address,
                                         *next_hop,
                                         parsed_destination->length});
          else if (valid)
            current->next_hop = *next_hop;
        }
      } else {
        valid = false;
      }

      if (valid && *candidate != before) {
        const auto recorded = supervisor_.record_session_edit(
            terminal->handle, configuration_key(id, instance));
        if (recorded != SessionWorkflowResult::applied) {
          *candidate = before;
          valid = false;
        }
      }
      if (!valid) {
        *candidate = before;
        output = "MINOR: MGMT_CORE #2301: Invalid element value";
      }
      const auto status = supervisor_.session_status(terminal->handle);
      terminal->cli.candidate_dirty =
          status.has_value() && status->candidate_dirty;
      terminal->cli.candidate_outdated =
          status.has_value() && status->baseline_outdated;
    }
    static_cast<void>(
        supervisor_.set_cli_session(terminal->handle, terminal->cli));
    output += cli_prompt(view, terminal->cli);
  } else if (terminal->cli.engine == CliEngine::classic &&
             classic_configuration_command(parsed->spec->id)) {
    using enum cli_schema::CommandId;
    const auto id = parsed->spec->id;
    {
      const auto argument = [&](cli_schema::TokenKind kind) {
        return cli_detail::argument(*parsed, kind);
      };
      std::string instance;
      for (const auto kind : {cli_schema::TokenKind::card_slot,
                              cli_schema::TokenKind::mda_slot,
                              cli_schema::TokenKind::port_id,
                              cli_schema::TokenKind::interface_name,
                              cli_schema::TokenKind::ipv4_prefix}) {
        if (const auto value = argument(kind)) {
          instance.push_back('/');
          instance.append(*value);
        }
      }
      auto backup = supervisor_.checkpoint();
      // The value snapshot and workflow lock check precede mutation. Classic
      // commands are immediate, but a command that repeats the running value is
      // still a no-op and must not advance datastore revisions or the prompt's
      // unsaved marker.
      const auto before_running = running_configuration(*intent);
      const bool global_was_dirty =
          supervisor_.global_candidate_dirty(session_record->device);
      auto write = backup
                       ? supervisor_.authorize_classic_write(
                             session_record->device)
                       : SessionWorkflowResult::invalid_session;
      bool applied = write == SessionWorkflowResult::applied;

      if (applied && id == configure_system_name) {
        const auto raw = argument(cli_schema::TokenKind::system_name);
        const auto name = raw ? cli_detail::unquote(*raw) : std::string_view{};
        applied = !name.empty() && cli_detail::valid_cli_string(*raw) &&
                  supervisor_.set_system_name(intent->handle, name);
        if (applied)
          intent->system_name.assign(name);
      } else if (applied &&
                 (id == configure_card_type ||
                  id == classic_remove_card_type ||
                  id == classic_card_shutdown ||
                  id == classic_card_no_shutdown)) {
        unsigned slot{};
        const auto slot_text = argument(cli_schema::TokenKind::card_slot);
        auto state = std::make_unique<RouterHardwareCheckpoint>();
        auto *inventory = supervisor_.hardware(intent->handle);
        if (inventory)
          inventory->checkpoint(*state);
        applied = slot_text && decimal(*slot_text, slot) && slot &&
                  slot <= device_catalog::maximum_card_slots && inventory;
        if (applied && (id == classic_card_shutdown ||
                        id == classic_card_no_shutdown)) {
          applied = supervisor_.set_card_admin(
                        intent->handle, static_cast<std::uint16_t>(slot),
                        id == classic_card_no_shutdown) ==
                    HardwareEditResult::applied;
        } else if (applied) {
          const auto type = argument(cli_schema::TokenKind::card_type);
          const auto provisioned = id == configure_card_type && type
                                       ? *type
                                       : std::string_view{};
          applied = supervisor_.set_card(
                        intent->handle, static_cast<std::uint16_t>(slot),
                        provisioned, state->cards[slot - 1U].equipped) ==
                    HardwareEditResult::applied;
        }
      } else if (applied &&
                 (id == configure_mda_type ||
                  id == classic_remove_mda_type ||
                  id == classic_mda_shutdown ||
                  id == classic_mda_no_shutdown)) {
        unsigned card{};
        unsigned mda{};
        const auto card_text = argument(cli_schema::TokenKind::card_slot);
        const auto mda_text = argument(cli_schema::TokenKind::mda_slot);
        auto state = std::make_unique<RouterHardwareCheckpoint>();
        auto *inventory = supervisor_.hardware(intent->handle);
        if (inventory)
          inventory->checkpoint(*state);
        applied = card_text && mda_text && decimal(*card_text, card) &&
                  decimal(*mda_text, mda) && card && mda &&
                  card <= device_catalog::maximum_card_slots &&
                  mda <= device_catalog::maximum_mda_slots_per_card && inventory;
        if (applied && (id == classic_mda_shutdown ||
                        id == classic_mda_no_shutdown)) {
          applied = supervisor_.set_mda_admin(
                        intent->handle, static_cast<std::uint16_t>(card),
                        static_cast<std::uint16_t>(mda),
                        id == classic_mda_no_shutdown) ==
                    HardwareEditResult::applied;
        } else if (applied) {
          const auto type = argument(cli_schema::TokenKind::mda_type);
          const auto provisioned = id == configure_mda_type && type
                                       ? *type
                                       : std::string_view{};
          applied = supervisor_.set_mda(
                        intent->handle, static_cast<std::uint16_t>(card),
                        static_cast<std::uint16_t>(mda), provisioned,
                        state->cards[card - 1U].mdas[mda - 1U].equipped) ==
                    HardwareEditResult::applied;
        }
      } else if (applied &&
                 (id == classic_port_shutdown ||
                  id == classic_port_no_shutdown ||
                  id == classic_port_description ||
                  id == classic_remove_port_description ||
                  id == classic_port_mtu)) {
        const auto port_text = argument(cli_schema::TokenKind::port_id);
        auto *inventory = supervisor_.hardware(intent->handle);
        const auto *physical = port_text && inventory
                                   ? inventory->find(*port_text)
                                   : nullptr;
        auto current = port_text
                           ? std::find_if(intent->ports.begin(),
                                          intent->ports.end(), [&](const auto &item) {
                                            return item.id == *port_text;
                                          })
                           : intent->ports.end();
        bool admin = current != intent->ports.end()
                         ? current->admin_enabled
                         : physical && physical->admin_enabled;
        auto mtu = current != intent->ports.end()
                       ? current->mtu
                       : physical ? physical->mtu
                                  : device_catalog::default_network_mtu;
        auto speed = current != intent->ports.end()
                         ? current->speed_mbps
                         : physical ? physical->speed_mbps : 0U;
        std::string description = current != intent->ports.end()
                                      ? current->description
                                      : std::string{};
        if (id == classic_port_shutdown || id == classic_port_no_shutdown)
          admin = id == classic_port_no_shutdown;
        else if (id == classic_remove_port_description)
          description.clear();
        else if (id == classic_port_description) {
          const auto raw = argument(cli_schema::TokenKind::description);
          const auto value = raw ? cli_detail::unquote(*raw) : std::string_view{};
          applied = raw && !value.empty() && cli_detail::valid_cli_string(*raw) &&
                    value.size() <= 80U;
          if (applied)
            description.assign(value);
        } else {
          unsigned value{};
          const auto text = argument(cli_schema::TokenKind::mtu);
          applied = text && decimal(*text, value) &&
                    value >= device_catalog::minimum_network_mtu &&
                    value <= device_catalog::maximum_network_mtu;
          if (applied)
            mtu = static_cast<std::uint16_t>(value);
        }
        if (applied)
          applied = port_text && speed &&
                    supervisor_.configure_port(intent->handle, *port_text,
                                               admin, mtu, speed) ==
                        HardwareEditResult::applied;
        if (applied) {
          PortIntent value{std::string{*port_text}, admin, mtu, speed,
                           std::move(description)};
          if (current == intent->ports.end())
            intent->ports.push_back(std::move(value));
          else
            *current = std::move(value);
        }
      } else if (applied &&
                 (id == classic_interface_shutdown ||
                  id == classic_interface_no_shutdown ||
                  id == classic_interface_port ||
                  id == classic_interface_address)) {
        const auto name_text = argument(cli_schema::TokenKind::interface_name);
        const auto name = name_text ? cli_detail::unquote(*name_text)
                                    : std::string_view{};
        const auto current = std::find_if(
            intent->interfaces.begin(), intent->interfaces.end(),
            [&](const auto &item) { return item.name == name; });
        std::string selected_port = current == intent->interfaces.end()
                                        ? std::string{}
                                        : current->port_id;
        std::string selected_address =
            current == intent->interfaces.end() ||
                    !current->address_configured
                ? std::string{}
                : ipv4_text(current->address) + '/' +
                      std::to_string(current->prefix_length);
        bool admin = current != intent->interfaces.end() &&
                     current->admin_enabled;
        if (id == classic_interface_shutdown ||
            id == classic_interface_no_shutdown)
          admin = id == classic_interface_no_shutdown;
        else if (id == classic_interface_port) {
          const auto value = argument(cli_schema::TokenKind::port_id);
          applied = value.has_value();
          if (value)
            selected_port.assign(*value);
        } else {
          const auto value = argument(cli_schema::TokenKind::ipv4_prefix);
          applied = value.has_value();
          if (value)
            selected_address.assign(*value);
        }
        const std::array<std::string_view, 5> values{
            intent->node_id, name, selected_port, selected_address,
            admin ? std::string_view{"1"} : std::string_view{"0"}};
        applied = applied && !name.empty() && configure_interface(values);
      } else if (applied && id == classic_static_route) {
        const auto destination = argument(cli_schema::TokenKind::ipv4_prefix);
        const auto next_hop = argument(cli_schema::TokenKind::ipv4);
        const std::array<std::string_view, 3> values{
            intent->node_id, destination.value_or(std::string_view{}),
            next_hop.value_or(std::string_view{})};
        applied = add_static_route(values);
      } else if (applied && id == classic_remove_static_route) {
        const auto destination = argument(cli_schema::TokenKind::ipv4_prefix);
        const std::array<std::string_view, 2> values{
            intent->node_id, destination.value_or(std::string_view{})};
        applied = delete_static_route(values);
      }

      bool changed{};
      if (applied) {
        const auto after_running = running_configuration(*intent);
        changed = after_running != before_running;
        if (changed) {
          // Publish the path revision only after every product-state owner has
          // accepted the command. The control shard is single-owner, so no
          // candidate commit can interleave between authorization and this
          // publication point.
          write = supervisor_.classic_write(session_record->device,
                                             configuration_key(id, instance));
          applied = write == SessionWorkflowResult::applied;
          if (applied && intent->global_candidate_initialized &&
              !global_was_dirty)
            intent->global_candidate = after_running;
        }
      }

      if (!applied) {
        if (backup)
          static_cast<void>(supervisor_.restore(std::move(*backup)));
        // RouterIntent is owned by this facade rather than the supervisor
        // checkpoint. Restore its value graph explicitly so an allocation or
        // validation failure cannot leave the UI projection ahead of running.
        intent->system_name = before_running.system_name;
        intent->ports = before_running.ports;
        intent->interfaces = before_running.interfaces;
        intent->routes = before_running.routes;
        output = write == SessionWorkflowResult::running_locked
                     ? "Error: Configuration is locked by another session."
                     : "Error: Bad command.";
      } else if (changed) {
        terminal->cli.classic_unsaved = true;
      }
    }
    output += cli_prompt(view, terminal->cli);
  } else if (parsed->spec->id ==
             cli_schema::CommandId::show_system_information) {
    std::ostringstream out;
    out << "===============================================================================\n"
        << "System Information\n"
        << "===============================================================================\n"
        << "System Name            : " << device->system_name << '\n'
        << "System Type            : " << device->profile->chassis << '\n'
        << "Chassis Topology       : Standalone\n"
        << "System Version         : C-" << device->profile->release << '\n'
        << "System Active Slot     : " << device->profile->control_slot << '\n'
        << "Configuration Mode Cfg : model-driven\n"
        << "Configuration Mode Oper: model-driven\n"
        << table_rule;
    output = out.str() + cli_prompt(view, terminal->cli);
  } else if (parsed->spec->id == cli_schema::CommandId::show_card ||
             parsed->spec->id == cli_schema::CommandId::show_mda ||
             parsed->spec->id == cli_schema::CommandId::show_port ||
             parsed->spec->id == cli_schema::CommandId::show_system_alarms) {
    const auto *inventory = supervisor_.hardware(intent->handle);
    auto hardware = std::make_unique<RouterHardwareCheckpoint>();
    if (!inventory) {
      output = "MINOR: MGMT_CORE #2203: Invalid element - currently not allowed";
    } else {
      inventory->checkpoint(*hardware);
      std::ostringstream out;
      const auto id = parsed->spec->id;
      if (id == cli_schema::CommandId::show_card) {
        out << table_rule << "\nCard Summary\n" << table_rule
            << "\nSlot  Provisioned Type              Equipped Type                 Status\n"
            << row_rule;
        const auto slots = device->profile->fixed ? 1U
                                                   : device->profile->card_slots;
        for (std::size_t index = 0; index < slots; ++index) {
          const auto &card = hardware->cards[index];
          const bool matched = !card.provisioned.empty() &&
                               card.provisioned == card.equipped;
          out << '\n' << std::left << std::setw(6) << index + 1U
              << std::setw(30)
              << (card.provisioned.empty() ? "(not provisioned)"
                                           : card.provisioned)
              << std::setw(30)
              << (card.equipped.empty() ? "(not equipped)" : card.equipped)
              << (matched ? "up" : "down");
        }
        out << '\n' << table_rule;
      } else if (id == cli_schema::CommandId::show_mda) {
        out << table_rule << "\nMDA Summary\n" << table_rule
            << "\nSlot    Provisioned Type              Equipped Type                 Status\n"
            << row_rule;
        const auto slots = device->profile->fixed ? 1U
                                                   : device->profile->card_slots;
        for (std::size_t card = 0; card < slots; ++card) {
          for (std::size_t mda = 0;
               mda < device_catalog::maximum_mda_slots_per_card; ++mda) {
            const auto &value = hardware->cards[card].mdas[mda];
            if (value.provisioned.empty() && value.equipped.empty())
              continue;
            const bool matched = !value.provisioned.empty() &&
                                 value.provisioned == value.equipped;
            out << '\n' << std::left << std::setw(8)
                << (std::to_string(card + 1U) + '/' +
                    std::to_string(mda + 1U))
                << std::setw(30)
                << (value.provisioned.empty() ? "(not provisioned)"
                                              : value.provisioned)
                << std::setw(30)
                << (value.equipped.empty() ? "(not equipped)"
                                           : value.equipped)
                << (matched ? "up" : "down");
          }
        }
        out << '\n' << table_rule;
      } else if (id == cli_schema::CommandId::show_port) {
        out << table_rule << "\nPort Summary\n" << table_rule
            << "\nPort          Admin  Link  Oper  MTU    Speed       Description\n"
            << row_rule;
        std::size_t count{};
        for (std::size_t ordinal = 0;
             ordinal < device_catalog::maximum_ports_per_router; ++ordinal) {
          const auto &port = hardware->ports[ordinal];
          if (!port.present)
            continue;
          ++count;
          const auto configured = std::find_if(
              intent->ports.begin(), intent->ports.end(), [&](const auto &item) {
                return item.id == port_id(static_cast<std::uint16_t>(ordinal));
              });
          out << '\n' << std::left << std::setw(14)
              << port_id(static_cast<std::uint16_t>(ordinal))
              << std::setw(7) << (port.admin_enabled ? "Up" : "Down")
              << std::setw(6) << (port.link_signal ? "Up" : "Down")
              << std::setw(6)
              << (port.admin_enabled && port.link_signal &&
                          port.configuration_compatible
                      ? "Up"
                      : "Down")
              << std::setw(7) << port.mtu << std::setw(12)
              << (std::to_string(port.speed_mbps) + " Mb/s")
              << (configured == intent->ports.end() ? std::string_view{}
                                                     : configured->description);
        }
        out << '\n' << row_rule << "\nPorts : " << count << '\n' << table_rule;
      } else {
        struct AlarmRow {
          std::string resource;
          std::string detail;
        };
        std::vector<AlarmRow> alarms;
        const auto slots = device->profile->fixed ? 1U
                                                   : device->profile->card_slots;
        for (std::size_t card = 0; card < slots; ++card) {
          const auto &value = hardware->cards[card];
          if (!value.provisioned.empty() &&
              value.provisioned != value.equipped)
            alarms.push_back({"Card " + std::to_string(card + 1U),
                              value.equipped.empty()
                                  ? "Provisioned card is not equipped"
                                  : "Equipped card type does not match provisioning"});
          for (std::size_t mda = 0;
               mda < device_catalog::maximum_mda_slots_per_card; ++mda) {
            const auto &child = value.mdas[mda];
            if (!child.provisioned.empty() &&
                child.provisioned != child.equipped)
              alarms.push_back(
                  {"MDA " + std::to_string(card + 1U) + '/' +
                       std::to_string(mda + 1U),
                   child.equipped.empty()
                       ? "Provisioned MDA is not equipped"
                       : "Equipped MDA type does not match provisioning"});
          }
        }
        out << table_rule << "\nAlarms [Critical:0 Major:" << alarms.size()
            << " Minor:0 Warning:0 Total:" << alarms.size() << "]\n"
            << table_rule
            << "\nIndex  Severity  Resource              Details\n" << row_rule;
        for (std::size_t index = 0; index < alarms.size(); ++index)
          out << '\n' << std::left << std::setw(7) << index + 1U
              << std::setw(10) << "MAJOR" << std::setw(22)
              << alarms[index].resource << alarms[index].detail;
        out << '\n' << table_rule;
      }
      output = out.str();
    }
    output += cli_prompt(view, terminal->cli);
  } else if (parsed->spec->id ==
                 cli_schema::CommandId::show_router_interface ||
             parsed->spec->id ==
                 cli_schema::CommandId::show_router_route_table ||
             parsed->spec->id == cli_schema::CommandId::show_router_fib ||
             parsed->spec->id == cli_schema::CommandId::show_router_arp) {
    const auto operational =
        supervisor_.router_operational_state(intent->handle);
    if (!operational) {
      output = "MINOR: MGMT_CORE #2203: Invalid element - currently not allowed";
    } else {
      std::ostringstream out;
      const auto interface_for = [&](std::uint16_t ordinal)
          -> const InterfaceIntent * {
        const auto physical = port_id(ordinal);
        const auto found = std::find_if(
            intent->interfaces.begin(), intent->interfaces.end(),
            [&](const auto &item) { return item.port_id == physical; });
        return found == intent->interfaces.end() ? nullptr : &*found;
      };
      if (parsed->spec->id ==
          cli_schema::CommandId::show_router_interface) {
        out << table_rule << "\nInterface Table (Router: Base)\n" << table_rule
            << "\nInterface-Name                   Adm       Opr(v4/v6)  Mode    Port/SapId\n"
            << "   IP-Address                                                  PfxState\n"
            << row_rule;
        for (const auto &interface : intent->interfaces) {
          const auto port = std::find_if(
              operational->ports.begin(), operational->ports.end(),
              [&](const auto &value) {
                return port_id(value.ordinal) == interface.port_id;
              });
          const bool up = port != operational->ports.end() &&
                          port->operational && interface.admin_enabled;
          out << '\n' << std::left << std::setw(33) << interface.name
              << std::setw(10) << (interface.admin_enabled ? "Up" : "Down")
              << std::setw(12) << (up ? "Up/Down" : "Down/Down")
              << std::setw(8) << "Network"
              << (interface.port_configured ? interface.port_id : "n/a")
              << "\n   "
              << std::setw(61)
              << (interface.address_configured
                      ? ipv4_text(interface.address) + '/' +
                            std::to_string(interface.prefix_length)
                      : "n/a")
              << "n/a";
        }
        out << '\n' << row_rule << "\nInterfaces : "
            << intent->interfaces.size() << '\n' << table_rule;
      } else if (parsed->spec->id ==
                 cli_schema::CommandId::show_router_route_table) {
        out << table_rule << "\nRoute Table (Router: Base)\n" << table_rule
            << "\nDest Prefix[Flags]                            Type    Proto     Pref\n"
            << "      Next Hop[Interface Name]                              Metric\n"
            << row_rule;
        for (std::size_t index = 0; index < operational->fib.count; ++index) {
          const auto &route = operational->fib.routes[index];
          const auto *interface = interface_for(route.port_ordinal);
          out << '\n' << std::left << std::setw(47)
              << (ipv4_text(route.network) + '/' +
                  std::to_string(route.prefix_length))
              << std::setw(8) << (route.next_hop ? "Remote" : "Local")
              << std::setw(10) << (route.next_hop ? "Static" : "Local")
              << (route.next_hop ? 5 : 0) << "\n      " << std::setw(55)
              << (route.next_hop ? ipv4_text(route.next_hop)
                                 : interface ? interface->name : "")
              << (route.next_hop ? 1 : 0);
        }
        out << '\n' << row_rule << "\nNo. of Routes: "
            << operational->fib.count << '\n' << table_rule;
      } else if (parsed->spec->id ==
                 cli_schema::CommandId::show_router_fib) {
        const auto slot = cli_detail::argument(
            *parsed, cli_schema::TokenKind::card_slot);
        unsigned card{};
        const auto maximum = device->profile->fixed ? 1U
                                                     : device->profile->card_slots;
        if (!slot || !decimal(*slot, card) || !card || card > maximum) {
          output = "MINOR: MGMT_CORE #2301: Invalid element value";
        } else {
          out << table_rule << "\nFIB Display\n" << table_rule
              << "\nPrefix [Flags]                                              Protocol\n"
              << "  NextHop\n" << row_rule;
          std::size_t count{};
          for (std::size_t index = 0; index < operational->fib.count; ++index) {
            const auto &route = operational->fib.routes[index];
            if (route.port_ordinal /
                        (device_catalog::maximum_mda_slots_per_card *
                         device_catalog::maximum_ports_per_mda) +
                    1U !=
                card)
              continue;
            ++count;
            const auto *interface = interface_for(route.port_ordinal);
            out << '\n' << std::left << std::setw(61)
                << (ipv4_text(route.network) + '/' +
                    std::to_string(route.prefix_length))
                << (route.next_hop ? "STATIC" : "LOCAL") << "\n  "
                << (route.next_hop ? ipv4_text(route.next_hop)
                                   : ipv4_text(route.network));
            if (interface)
              out << " (" << interface->name << ')';
          }
          out << '\n' << row_rule << "\nTotal Entries : " << count << '\n'
              << table_rule;
        }
      } else {
        out << table_rule << "\nARP Table (Router: Base)\n" << table_rule
            << "\nIP Address       MAC Address         Interface\n" << row_rule;
        for (const auto &entry : operational->adjacencies) {
          const auto *interface = interface_for(entry.port_ordinal);
          out << '\n' << std::left << std::setw(17) << ipv4_text(entry.address)
              << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<unsigned>(entry.mac[0]);
          for (std::size_t byte = 1; byte < entry.mac.size(); ++byte)
            out << ':' << std::setw(2) << static_cast<unsigned>(entry.mac[byte]);
          out << std::dec << std::setfill(' ') << "  "
              << (interface ? interface->name : port_id(entry.port_ordinal));
        }
        out << '\n' << row_rule << "\nNo. of ARP Entries: "
            << operational->adjacencies.size() << '\n' << table_rule;
      }
      if (output.empty())
        output = out.str();
    }
    output += cli_prompt(view, terminal->cli);
  } else {
    // A grammar-recognized command without a protocol 3 handler is reported
    // explicitly. It is never acknowledged as a successful no-op.
    output = terminal->cli.engine == CliEngine::classic
                 ? "Error: Command is not supported in this release profile."
                 : "MINOR: CLI #2001: Command is not supported";
    output += cli_prompt(view, terminal->cli);
  }
  static_cast<void>(
      supervisor_.set_cli_session(terminal->handle, terminal->cli));
  return output + session_state(session_id);
}

std::string LabRuntime::poll_session(std::string_view session_id) {
  auto *terminal = session(session_id);
  const auto *record = terminal ? supervisor_.sessions().get(terminal->handle)
                                : nullptr;
  if (!terminal || !record)
    return {};
  auto &ping = terminal->ping;
  if (!ping.active)
    return session_state(session_id);

  const auto finish = [&] {
    ping.active = false;
    ping.waiting = false;
    const auto lost = ping.sent - ping.received;
    const auto loss = ping.sent ? lost * 100U / ping.sent : 0U;
    return "--- " + ipv4_text(ping.destination) +
           " ping statistics ---\n" + std::to_string(ping.sent) +
           " packets transmitted, " + std::to_string(ping.received) +
           " packets received, " + std::to_string(loss) + "% packet loss\n";
  };

  std::string output;
  const auto now = std::chrono::steady_clock::now();
  if (ping.cancel_requested) {
    output = finish();
  } else if (ping.waiting && supervisor_.router_ping_reply(
                                  record->device, ping.sequence)) {
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                             now - ping.sent_at)
                             .count();
    ++ping.received;
    ping.waiting = false;
    output = std::to_string(ping.payload_octets + 8U) + " bytes from " +
             ipv4_text(ping.destination) + ": icmp_seq=" +
             std::to_string(ping.sequence) + " time=" +
             std::to_string(elapsed / 1000.0) + " ms\n";
    if (ping.sent == ping.requested)
      output += finish();
    else {
      ++ping.sequence;
      // Nokia's default interval is one real second. This deadline remains in
      // the session owner; browser polling frequency cannot accelerate it.
      ping.next_send = now + device_catalog::ping_interval;
    }
  } else if (ping.waiting && now >= ping.reply_deadline) {
    ping.waiting = false;
    output = "Request timeout for icmp_seq " +
             std::to_string(ping.sequence) + "\n";
    if (ping.sent == ping.requested)
      output += finish();
    else {
      ++ping.sequence;
      ping.next_send = now + device_catalog::ping_interval;
    }
  }

  if (ping.active && !ping.waiting && now >= ping.next_send) {
    if (!supervisor_.start_router_ping(record->device, ping.destination,
                                       ping.sequence, ping.payload_octets,
                                       ping.dont_fragment)) {
      output += "connect: Network is unreachable\n";
      output += finish();
    } else {
      ++ping.sent;
      ping.waiting = true;
      ping.sent_at = now;
      ping.reply_deadline = now + device_catalog::ping_timeout;
    }
  }
  return output + session_state(session_id);
}

std::string LabRuntime::complete_session(std::string_view session_id,
                                         std::string_view input,
                                         std::string_view trigger) const {
  const auto *terminal = session(session_id);
  const auto *session_record = terminal
                                   ? supervisor_.sessions().get(terminal->handle)
                                   : nullptr;
  const auto *device = session_record
                           ? supervisor_.devices().get(session_record->device)
                           : nullptr;
  const auto *intent = device ? router(device->node_id) : nullptr;
  if (!terminal || !session_record || !device || !intent ||
      (trigger != "tab" && trigger != "question" && trigger != "space"))
    return {};

  // Completion tokenization intentionally accepts only the CLI's ASCII word
  // separator. Execution remains the authority for quoting and validation;
  // this path merely derives candidates from generated schema rows.
  std::vector<std::string_view> tokens;
  std::size_t cursor{};
  while (cursor < input.size()) {
    while (cursor < input.size() && (input[cursor] == ' ' || input[cursor] == '\t'))
      ++cursor;
    const auto begin = cursor;
    while (cursor < input.size() && input[cursor] != ' ' && input[cursor] != '\t')
      ++cursor;
    if (begin != cursor)
      tokens.push_back(input.substr(begin, cursor - begin));
  }
  const bool trailing = !input.empty() &&
                        (input.back() == ' ' || input.back() == '\t');
  const auto completed = trailing ? tokens.size()
                                  : tokens.empty() ? 0U : tokens.size() - 1U;
  const auto partial = trailing || tokens.empty() ? std::string_view{}
                                                   : tokens.back();
  const auto engine_mask = terminal->cli.engine == CliEngine::classic ? 2U : 1U;
  const bool configuring = terminal->cli.engine == CliEngine::classic ||
                           session_record->mode != CandidateMode::operational;
  std::vector<std::string> candidates;
  const auto add = [&](std::string_view value) {
    if (!value.starts_with(partial))
      return;
    if (std::find(candidates.begin(), candidates.end(), value) ==
        candidates.end())
      candidates.emplace_back(value);
  };
  const auto configuration_command = [](cli_schema::CommandId id) {
    using enum cli_schema::CommandId;
    switch (id) {
    case configure_card_type:
    case configure_mda_type:
    case configure_system_name:
    case md_card_enable:
    case md_card_disable:
    case md_mda_enable:
    case md_mda_disable:
    case md_port_enable:
    case md_port_disable:
    case md_port_description:
    case md_port_mtu:
    case md_interface_enable:
    case md_interface_disable:
    case md_interface_port:
    case md_interface_ipv4_primary:
    case md_static_route:
    case md_delete_card:
    case md_delete_mda:
    case md_delete_port_description:
    case md_delete_static_route:
    case md_compare:
    case md_commit:
    case md_discard:
      return true;
    default:
      return false;
    }
  };
  for (const auto &spec : cli_schema::commands) {
    if (!(spec.engine_mask & engine_mask) || completed >= spec.token_count ||
        (configuration_command(spec.id) && !configuring))
      continue;
    bool prefix_matches = true;
    for (std::size_t index = 0; index < completed; ++index) {
      const auto &expected = spec.tokens[index];
      if (expected.kind == cli_schema::TokenKind::literal) {
        if (!expected.display.starts_with(tokens[index])) {
          prefix_matches = false;
          break;
        }
      } else if (tokens[index].empty()) {
        prefix_matches = false;
        break;
      }
    }
    if (!prefix_matches)
      continue;
    const auto &next = spec.tokens[completed];
    using enum cli_schema::TokenKind;
    switch (next.kind) {
    case literal:
      add(next.display);
      break;
    case port_id: {
      const auto *inventory = supervisor_.hardware(intent->handle);
      if (inventory) {
        for (std::size_t ordinal = 0;
             ordinal < device_catalog::maximum_ports_per_router; ++ordinal) {
          const auto *port = inventory->at(static_cast<std::uint16_t>(ordinal));
          if (port && port->present)
            add(std::to_string(port->card_slot) + '/' +
                std::to_string(port->mda_slot) + '/' +
                std::to_string(port->port_number));
        }
      }
      break;
    }
    case interface_name:
      for (const auto &item : intent->interfaces)
        add(item.name);
      break;
    case card_slot:
      for (std::uint16_t slot = 1; slot <= device->profile->card_slots; ++slot)
        add(std::to_string(slot));
      break;
    case mda_slot:
      for (std::uint16_t slot = 1;
           slot <= device_catalog::maximum_mda_slots_per_card; ++slot)
        add(std::to_string(slot));
      break;
    case card_type:
      for (std::size_t index = 0; index < device->profile->card_count; ++index)
        add(device_catalog::cards[device->profile->first_card + index].type);
      break;
    case mda_type:
      // The profile-specific card rows reference compatible MDA indices. A
      // union is appropriate before a card key is supplied; execution still
      // rejects combinations invalid for the selected physical card.
      for (std::size_t card = 0; card < device->profile->card_count; ++card) {
        const auto &card_profile =
            device_catalog::cards[device->profile->first_card + card];
        for (std::size_t index = 0; index < card_profile.mda_count; ++index)
          add(device_catalog::mdas[device_catalog::card_mdas[
                  card_profile.first_mda + index]].type);
      }
      break;
    default:
      if (trigger == "question")
        add(next.display);
      break;
    }
  }
  std::sort(candidates.begin(), candidates.end());
  if (candidates.empty())
    return {};
  if (candidates.size() == 1U && trigger != "question" &&
      candidates.front().front() != '<') {
    std::string result;
    for (std::size_t index = 0; index < completed; ++index) {
      if (!result.empty())
        result.push_back(' ');
      result.append(tokens[index]);
    }
    if (!result.empty())
      result.push_back(' ');
    result.append(candidates.front());
    return result;
  }
  std::ostringstream out;
  for (std::size_t index = 0; index < candidates.size(); ++index) {
    if (index)
      out << '\n';
    out << candidates[index];
  }
  return out.str();
}

bool LabRuntime::configure_capture(
    std::span<const std::string_view> fields) {
  // Protocol fields are kind, stable object ID, optional port ID, direction
  // and selected flag. UI never supplies an internal CapturePointId or handle.
  // This keeps stale-generation protection and ID allocation inside C++.
  if (fields.size() != 5U)
    return false;
  CapturePointKind kind{};
  if (fields[0] == "link-direction")
    kind = CapturePointKind::link_direction;
  else if (fields[0] == "router-ingress")
    kind = CapturePointKind::router_ingress;
  else if (fields[0] == "router-egress")
    kind = CapturePointKind::router_egress;
  else if (fields[0] == "cpm-punt")
    kind = CapturePointKind::cpm_punt;
  else
    return false;

  unsigned direction{};
  bool selected{};
  if (!decimal(fields[3], direction) || direction > 1U ||
      !boolean(fields[4], selected))
    return false;
  const auto same_location = [&](const CaptureIntent &item) {
    return item.kind == kind && item.object_id == fields[1] &&
           item.port_id == fields[2] && item.direction == direction;
  };
  auto intent = std::find_if(capture_intents_.begin(), capture_intents_.end(),
                             same_location);
  if (intent == capture_intents_.end()) {
    if (!selected || capture_intents_.size() >=
                         device_catalog::selected_capture_points)
      return false;
    // IDs are never recycled during a runtime lifetime. Old records therefore
    // cannot acquire a different location after a topology object is deleted.
    capture_intents_.push_back(
        {static_cast<CapturePointId>(capture_intents_.size()), kind,
         std::string{fields[1]}, std::string{fields[2]},
         static_cast<std::uint8_t>(direction), false});
    intent = std::prev(capture_intents_.end());
  }

  CapturePointProgram program;
  program.id = intent->id;
  program.kind = kind;
  program.selected = selected;
  program.link_endpoint = static_cast<std::uint8_t>(direction);
  std::string name;
  if (kind == CapturePointKind::link_direction) {
    const auto link = supervisor_.topology().find(fields[1]);
    if (!link)
      return false;
    program.link = *link;
    const auto *record = supervisor_.topology().get(*link);
    if (!record)
      return false;
    const auto node_label = [&](NodeHandle handle) -> std::optional<std::string> {
      // Stable node IDs keep captures comparable across renames, while the
      // current display name makes a standalone PCAP understandable to the
      // operator. Both values are read from their authoritative registries.
      if (handle.kind == NodeKind::router) {
        const auto *device = supervisor_.devices().get(
            {handle.index, handle.generation});
        const auto *intent = device ? router(device->node_id) : nullptr;
        if (!device || !intent)
          return std::nullopt;
        return "router:" + device->node_id + "@" + intent->system_name;
      }
      const auto *endpoint = supervisor_.hosts().get(
          {handle.index, handle.generation});
      if (!endpoint)
        return std::nullopt;
      return "host:" + endpoint->node_id + "@" + endpoint->name;
    };
    const auto source_index = direction == 0U ? 0U : 1U;
    const auto target_index = 1U - source_index;
    const auto source = node_label(record->endpoints[source_index].node);
    const auto target = node_label(record->endpoints[target_index].node);
    if (!source || !target)
      return false;
    name = "link:" + std::string{fields[1]} + "/from:" + *source + "/port:" +
           record->endpoints[source_index].port_id + "/to:" + *target +
           "/port:" + record->endpoints[target_index].port_id +
           "/direction:" + std::to_string(direction);
  } else {
    const auto *device = router(fields[1]);
    if (!device)
      return false;
    program.node = node(device->handle);
    if (kind != CapturePointKind::cpm_punt) {
      const auto *inventory = supervisor_.hardware(device->handle);
      const auto ordinal = inventory
                               ? inventory->coordinate_ordinal(fields[2])
                               : std::nullopt;
      if (!ordinal)
        return false;
      program.port_ordinal = *ordinal;
      name = "router:" + device->node_id + "/system:" +
             device->system_name + "/port:" + std::string{fields[2]} +
             (kind == CapturePointKind::router_ingress ? "/ingress"
                                                       : "/egress");
    } else {
      program.port_ordinal = 0xffffU;
      name = "router:" + device->node_id + "/system:" +
             device->system_name + "/cpm-punt";
    }
  }
  if (name.size() > program.name.size())
    return false;
  program.name_size = static_cast<std::uint16_t>(name.size());
  std::copy(name.begin(), name.end(), program.name.begin());
  if (!supervisor_.configure_capture_point(program))
    return false;
  intent->selected = selected;
  return true;
}

bool LabRuntime::replace_capture_selection(
    std::span<const std::string_view> fields) {
  // A full replacement is encoded as one outer payload containing a count and
  // five netstrings per location. Parsing all records before mutation prevents
  // malformed trailing input from creating a partially selected capture.
  if (fields.size() != 1U)
    return false;
  std::string_view payload = fields[0];
  std::string_view count_text;
  unsigned count{};
  if (!next_netstring(payload, count_text) || !decimal(count_text, count) ||
      count > device_catalog::selected_capture_points)
    return false;
  struct RequestedCapture {
    std::array<std::string_view, 5> fields;
  };
  std::vector<RequestedCapture> requested;
  try {
    requested.reserve(count);
    for (unsigned index = 0; index < count; ++index) {
      RequestedCapture value;
      for (auto &field : value.fields)
        if (!next_netstring(payload, field))
          return false;
      // Replacement records always denote selected points. The public batch
      // contract does not admit contradictory select and deselect duplicates.
      if (value.fields[4] != "1" ||
          std::any_of(requested.begin(), requested.end(), [&](const auto &old) {
            return old.fields[0] == value.fields[0] &&
                   old.fields[1] == value.fields[1] &&
                   old.fields[2] == value.fields[2] &&
                   old.fields[3] == value.fields[3];
          }))
        return false;
      requested.push_back(value);
    }
  } catch (const std::bad_alloc &) {
    return false;
  }
  if (!payload.empty())
    return false;

  auto backup = supervisor_.checkpoint();
  if (!backup)
    return false;
  const auto previous = capture_intents_;
  const auto requested_location = [&](const CaptureIntent &intent) {
    return std::any_of(requested.begin(), requested.end(), [&](const auto &item) {
      const auto kind = intent.kind == CapturePointKind::link_direction
                            ? "link-direction"
                        : intent.kind == CapturePointKind::router_ingress
                            ? "router-ingress"
                        : intent.kind == CapturePointKind::router_egress
                            ? "router-egress"
                            : "cpm-punt";
      return item.fields[0] == kind && item.fields[1] == intent.object_id &&
             item.fields[2] == intent.port_id &&
             item.fields[3] == std::to_string(intent.direction);
    });
  };
  bool accepted = true;
  // Existing locations are disabled before new ones are installed. Both the
  // forwarding capture owner and portable intents are restored on any error.
  for (const auto &intent : previous) {
    if (!intent.selected || requested_location(intent))
      continue;
    const auto kind = intent.kind == CapturePointKind::link_direction
                          ? "link-direction"
                      : intent.kind == CapturePointKind::router_ingress
                          ? "router-ingress"
                      : intent.kind == CapturePointKind::router_egress
                          ? "router-egress"
                          : "cpm-punt";
    const auto direction = std::to_string(intent.direction);
    const std::array<std::string_view, 5> disable{
        kind, intent.object_id, intent.port_id, direction, "0"};
    if (!configure_capture(disable)) {
      accepted = false;
      break;
    }
  }
  for (const auto &item : requested) {
    if (accepted && !configure_capture(item.fields)) {
      accepted = false;
      break;
    }
  }
  if (accepted)
    return true;
  capture_intents_ = previous;
  static_cast<void>(supervisor_.restore(std::move(*backup)));
  return false;
}

std::string LabRuntime::snapshot() {
  const auto devices = supervisor_.devices().checkpoint();
  const auto hosts = supervisor_.hosts().checkpoint();
  const auto links = supervisor_.topology().checkpoint();
  const auto sessions = supervisor_.sessions().checkpoint();
  std::ostringstream out;
  // Capability output is derived from the same constants that guard the
  // shared page and command decoder. A protocol or layout revision therefore
  // cannot leave an apparently compatible literal in the browser handshake.
  out << "{\"abiVersion\":" << telemetry_page_v5_abi
      << ",\"protocolVersion\":" << lab_runtime_protocol::version
      << ",\"status\":\"ready\",\"routers\":[";
  bool comma{};
  for (const auto &entry : devices.entries) {
    if (comma)
      out << ',';
    comma = true;
    const auto *intent = router(entry.node_id);
    const auto *inventory = supervisor_.hardware(entry.handle);
    RouterHardwareCheckpoint hardware;
    if (inventory)
      inventory->checkpoint(hardware);
    out << "{\"id\":";
    json_string(out, entry.node_id);
    out << ",\"profileId\":";
    json_string(out, entry.profile_id);
    out << ",\"chassis\":";
    json_string(out, entry.handle && inventory && inventory->profile()
                         ? inventory->profile()->chassis
                         : std::string_view{});
    out << ",\"systemName\":";
    json_string(out, entry.system_name);
    out << ",\"handle\":{" << "\"index\":" << entry.handle.index
        << ",\"generation\":" << entry.handle.generation
        << "},\"cards\":[";
    const auto card_count = inventory && inventory->profile()
                                ? (inventory->profile()->fixed
                                       ? 1U
                                       : inventory->profile()->card_slots)
                                : 0U;
    for (std::size_t card = 0; card < card_count; ++card) {
      if (card)
        out << ',';
      out << "{\"slot\":" << card + 1U << ",\"admin\":"
          << (hardware.cards[card].admin_enabled ? "true" : "false")
          << ",\"provisionedType\":";
      if (hardware.cards[card].provisioned.empty())
        out << "null";
      else
        json_string(out, hardware.cards[card].provisioned);
      out << ",\"equippedType\":";
      if (hardware.cards[card].equipped.empty())
        out << "null";
      else
        json_string(out, hardware.cards[card].equipped);
      out << ",\"mdas\":[";
      for (std::size_t mda = 0;
           mda < device_catalog::maximum_mda_slots_per_card; ++mda) {
        if (mda)
          out << ',';
        out << "{\"slot\":" << mda + 1U << ",\"admin\":"
            << (hardware.cards[card].mdas[mda].admin_enabled ? "true"
                                                              : "false")
            << ",\"provisionedType\":";
        if (hardware.cards[card].mdas[mda].provisioned.empty())
          out << "null";
        else
          json_string(out, hardware.cards[card].mdas[mda].provisioned);
        out << ",\"equippedType\":";
        if (hardware.cards[card].mdas[mda].equipped.empty())
          out << "null";
        else
          json_string(out, hardware.cards[card].mdas[mda].equipped);
        out << '}';
      }
      out << "]}";
    }
    out << "],\"ports\":[";
    bool port_comma{};
    for (std::size_t ordinal = 0;
         ordinal < device_catalog::maximum_ports_per_router; ++ordinal) {
      const auto *port = inventory
                             ? inventory->at(static_cast<std::uint16_t>(ordinal))
                             : nullptr;
      if (!port || !port->present)
        continue;
      if (port_comma)
        out << ',';
      port_comma = true;
      const auto id = std::to_string(port->card_slot) + '/' +
                      std::to_string(port->mda_slot) + '/' +
                      std::to_string(port->port_number);
      const auto configured = intent
                                  ? std::find_if(intent->ports.begin(),
                                                 intent->ports.end(),
                                                 [&](const auto &item) {
                                                   return item.id == id;
                                                 })
                                  : std::vector<PortIntent>::const_iterator{};
      out << "{\"id\":";
      json_string(out, id);
      out << ",\"admin\":" << (port->admin_enabled ? "true" : "false")
          << ",\"carrier\":" << (port->link_signal ? "true" : "false")
          << ",\"oper\":"
          << (port->hierarchy_enabled && port->admin_enabled &&
                      port->link_signal && port->configuration_compatible
                  ? "true"
                  : "false")
          << ",\"mtu\":" << port->mtu << ",\"speedMbps\":"
          << port->speed_mbps << ",\"description\":";
      if (intent && configured != intent->ports.end())
        json_string(out, configured->description);
      else
        json_string(out, std::string_view{});
      out << '}';
    }
    out << "],\"interfaces\":[";
    if (intent) {
      for (std::size_t index = 0; index < intent->interfaces.size(); ++index) {
        const auto &interface = intent->interfaces[index];
        if (index)
          out << ',';
        out << "{\"name\":";
        json_string(out, interface.name);
        out << ",\"portId\":";
        json_string(out, interface.port_id);
        out << ",\"address\":";
        json_string(out, interface.address_configured
                             ? ipv4_text(interface.address) + '/' +
                                   std::to_string(interface.prefix_length)
                             : std::string{});
        out << ",\"admin\":"
            << (interface.admin_enabled ? "true" : "false") << '}';
      }
    }
    out << "],\"staticRoutes\":[";
    if (intent) {
      for (std::size_t index = 0; index < intent->routes.size(); ++index) {
        const auto &route = intent->routes[index];
        if (index)
          out << ',';
        out << "{\"prefix\":";
        json_string(out, ipv4_text(route.network) + '/' +
                             std::to_string(route.prefix_length));
        out << ",\"nextHop\":";
        json_string(out, ipv4_text(route.next_hop));
        out << '}';
      }
    }
    out << "]}";
  }
  out << "],\"hosts\":[";
  comma = false;
  for (const auto &entry : hosts.entries) {
    if (comma)
      out << ',';
    comma = true;
    out << "{\"id\":";
    json_string(out, entry.node_id);
    out << ",\"name\":";
    json_string(out, entry.name);
    out << ",\"handle\":{" << "\"index\":" << entry.handle.index
        << ",\"generation\":" << entry.handle.generation << '}';
    const auto *intent = host(entry.node_id);
    out << ",\"mac\":";
    if (intent) {
      std::ostringstream mac;
      mac << std::hex << std::setfill('0');
      for (std::size_t index = 0; index < intent->mac.size(); ++index) {
        if (index)
          mac << ':';
        mac << std::setw(2) << static_cast<unsigned>(intent->mac[index]);
      }
      json_string(out, mac.str());
    } else
      json_string(out, "00:00:00:00:00:00");
    out << ",\"address\":";
    json_string(out, intent && intent->configured
                         ? ipv4_text((static_cast<std::uint32_t>(intent->address[0]) << 24U) |
                                     (static_cast<std::uint32_t>(intent->address[1]) << 16U) |
                                     (static_cast<std::uint32_t>(intent->address[2]) << 8U) |
                                     intent->address[3]) + '/' +
                               std::to_string(intent->prefix_length)
                         : std::string{});
    out << ",\"gateway\":";
    json_string(out, intent && intent->configured
                         ? ipv4_text((static_cast<std::uint32_t>(intent->gateway[0]) << 24U) |
                                     (static_cast<std::uint32_t>(intent->gateway[1]) << 16U) |
                                     (static_cast<std::uint32_t>(intent->gateway[2]) << 8U) |
                                     intent->gateway[3])
                         : std::string{});
    out << ",\"mtu\":"
        << (intent ? intent->mtu : device_catalog::default_host_ipv4_mtu)
        << '}';
  }
  out << "],\"links\":[";
  comma = false;
  const auto node_id = [&](NodeHandle node_handle) -> std::string_view {
    if (node_handle.kind == NodeKind::router) {
      const auto *record = supervisor_.devices().get(
          {node_handle.index, node_handle.generation});
      return record ? std::string_view{record->node_id} : std::string_view{};
    }
    const auto *record = supervisor_.hosts().get(
        {node_handle.index, node_handle.generation});
    return record ? std::string_view{record->node_id} : std::string_view{};
  };
  for (const auto &entry : links.entries) {
    if (comma)
      out << ',';
    comma = true;
    out << "{\"id\":";
    json_string(out, entry.record.link_id);
    out << ",\"admin\":"
        << (entry.record.admin_enabled ? "true" : "false")
        << ",\"carrier\":" << (entry.record.carrier ? "true" : "false")
        << ",\"speedMbps\":" << entry.record.speed_mbps
        << ",\"propagationDelayNs\":" << entry.record.propagation_ns
        << ",\"endpoints\":[{" << "\"nodeId\":";
    json_string(out, node_id(entry.record.endpoints[0].node));
    out << ",\"portId\":";
    json_string(out, entry.record.endpoints[0].port_id);
    out << "},{\"nodeId\":";
    json_string(out, node_id(entry.record.endpoints[1].node));
    out << ",\"portId\":";
    json_string(out, entry.record.endpoints[1].port_id);
    out << "}]}";
  }
  out << "],\"sessions\":[";
  comma = false;
  for (const auto &entry : sessions.entries) {
    if (comma)
      out << ',';
    comma = true;
    const auto *device = supervisor_.devices().get(entry.record.device);
    out << "{\"id\":";
    json_string(out, entry.record.session_id);
    out << ",\"routerId\":";
    json_string(out, device ? std::string_view{device->node_id}
                            : std::string_view{});
    out << ",\"mode\":" << static_cast<unsigned>(entry.record.mode)
        << ",\"engine\":";
    const auto *terminal = session(entry.record.session_id);
    json_string(out, terminal && terminal->cli.engine == CliEngine::classic
                         ? "classic"
                         : "md");
    out << '}';
  }
  out << "],\"capturePoints\":[";
  comma = false;
  for (const auto &capture : capture_intents_) {
    // Deselected locations keep their numeric identity for retained PCAPNG
    // records but are not projected as active UI selections.
    if (!capture.selected)
      continue;
    if (comma)
      out << ',';
    comma = true;
    out << "{\"id\":" << capture.id << ",\"kind\":";
    switch (capture.kind) {
    case CapturePointKind::link_direction:
      json_string(out, "link-direction");
      break;
    case CapturePointKind::router_ingress:
      json_string(out, "router-ingress");
      break;
    case CapturePointKind::router_egress:
      json_string(out, "router-egress");
      break;
    case CapturePointKind::cpm_punt:
      json_string(out, "cpm-punt");
      break;
    }
    out << ",\"objectId\":";
    json_string(out, capture.object_id);
    out << ",\"portId\":";
    json_string(out, capture.port_id);
    out << ",\"direction\":" << static_cast<unsigned>(capture.direction)
        << '}';
  }
  out << "],\"activeLinks\":" << supervisor_.active_links()
      << ",\"capturedFrames\":" << supervisor_.captured_frames()
      << ",\"captureDropped\":" << supervisor_.capture_dropped()
      << ",\"droppedPackets\":" << supervisor_.dropped_packets() << '}';
  return out.str();
}

void LabRuntime::publish_telemetry() noexcept {
  std::atomic_ref<std::uint32_t> sequence(telemetry_.sequence);
  auto generation = sequence.load(std::memory_order_relaxed);
  if (generation & 1U)
    ++generation;
  sequence.store(generation + 1U, std::memory_order_release);
  telemetry_.abi_version = telemetry_page_v5_abi;
  telemetry_.status = 1;
  // The browser Worker owns control, NetworkPlaneWorker owns the link domain,
  // and larger hosts add generated forwarding pthreads. Telemetry reports only
  // owners that actually exist, never reserved pool capacity.
  telemetry_.worker_count = static_cast<std::uint32_t>(
      2U + (secondary_control_ ? 1U : 0U) +
      supervisor_.forwarding_owner_count());
  auto control = static_cast<std::uint64_t>(
      std::hash<std::thread::id>{}(std::this_thread::get_id()));
  for (auto &worker : telemetry_.workers)
    worker = {};
  // Directory order is an ABI detail, not a scheduling decision. The primary
  // control owner is always first, followed by the physical-medium owner and
  // then the stable forwarding shard indexes. A zero ID is retained until a
  // pthread has entered its loop, allowing startup to reject partial pools.
  telemetry_.workers[0] = {
      .role = static_cast<std::uint8_t>(WorkerRoleV5::control),
      .shard_index = 0,
      .running = 1,
      .thread_id = control ? control : 1U,
  };
  std::size_t directory = 1U;
  if (secondary_control_) {
    const auto owner_id = secondary_control_->thread_id();
    telemetry_.workers[directory++] = {
        .role = static_cast<std::uint8_t>(WorkerRoleV5::control),
        .shard_index = 1,
        .running = static_cast<std::uint8_t>(owner_id != 0),
        .thread_id = owner_id,
        .turns = secondary_control_->turns(),
    };
  }
  telemetry_.workers[directory++] = {
      .role = static_cast<std::uint8_t>(
          supervisor_.forwarding_owner_count()
              ? WorkerRoleV5::link
              : WorkerRoleV5::forwarding_link),
      .shard_index = 0,
      .running = static_cast<std::uint8_t>(supervisor_.network_thread_id() != 0),
      .thread_id = supervisor_.network_thread_id(),
  };
  for (std::size_t index = 0; index < supervisor_.forwarding_owner_count();
       ++index) {
    const auto owner_id = supervisor_.forwarding_owner_thread_id(index);
    telemetry_.workers[directory++] = {
        .role = static_cast<std::uint8_t>(WorkerRoleV5::forwarding),
        .shard_index = static_cast<std::uint8_t>(index),
        .running = static_cast<std::uint8_t>(owner_id != 0),
        .thread_id = owner_id,
        .turns = supervisor_.forwarding_owner_turns(index),
    };
  }
  telemetry_.device_count = static_cast<std::uint32_t>(routers_.size());
  telemetry_.session_count = static_cast<std::uint32_t>(sessions_.size());
  telemetry_.captured_frames = supervisor_.captured_frames();
  telemetry_.capture_dropped = supervisor_.capture_dropped();
  telemetry_.dropped_packets = supervisor_.dropped_packets();
  for (auto &device : telemetry_.devices) {
    auto device_generation = device.sequence;
    if (device_generation & 1U)
      ++device_generation;
    device = {};
    device.sequence = device_generation;
  }
  for (auto &bits : telemetry_.port_oper_bitsets)
    bits.fill(std::uint8_t{0});
  for (const auto &intent : routers_) {
    if (intent.handle.index >= telemetry_.devices.size())
      continue;
    auto &device = telemetry_.devices[intent.handle.index];
    auto &bits = telemetry_.port_oper_bitsets[intent.handle.index];
    std::atomic_ref<std::uint32_t> device_sequence(device.sequence);
    const auto device_snapshot_generation = device.sequence;
    device_sequence.store(device_snapshot_generation + 1U,
                          std::memory_order_release);
    device.device_index = intent.handle.index;
    device.device_generation = intent.handle.generation;
    const auto *inventory = supervisor_.hardware(intent.handle);
    device.port_bitset_offset = static_cast<std::uint32_t>(
        offsetof(TelemetryPageV5, port_oper_bitsets) +
        intent.handle.index * TelemetryPageV5::port_bitset_bytes);
    device.port_bitset_bytes = TelemetryPageV5::port_bitset_bytes;
    if (!inventory) {
      device_sequence.store(device_snapshot_generation + 2U,
                            std::memory_order_release);
      continue;
    }
    const bool assigned_secondary =
        secondary_control_ && (intent.handle.index % 2U) == 1U;
    if (assigned_secondary) {
      ControlProjectionCommand projection{
          .id = next_projection_id_++,
          .device_index = intent.handle.index,
          .device_generation = intent.handle.generation,
      };
      for (std::size_t ordinal = 0; ordinal < projection.ports.size();
           ++ordinal) {
        const auto *port = inventory->at(static_cast<std::uint16_t>(ordinal));
        if (!port)
          continue;
        auto &flags = projection.ports[ordinal].flags;
        if (port->present)
          flags |= ControlPortProjectionInput::present;
        if (port->admin_enabled)
          flags |= ControlPortProjectionInput::admin_enabled;
        if (port->link_signal)
          flags |= ControlPortProjectionInput::link_signal;
      }
      // Telemetry publication is lossless control work. A full command or
      // result ring applies bounded backpressure to this low-frequency caller;
      // packet and link owners continue running independently while it waits.
      while (!secondary_control_->submit(projection))
        std::this_thread::yield();
      ControlProjectionResult result;
      while (!secondary_control_->read(result))
        std::this_thread::yield();
      if (result.id == projection.id &&
          result.device_index == intent.handle.index &&
          result.device_generation == intent.handle.generation) {
        device.inventory_ports = result.inventory_ports;
        device.operational_ports = result.operational_ports;
        bits = result.operational_bitset;
      }
    } else {
      device.inventory_ports =
          static_cast<std::uint32_t>(inventory->present_ports());
      for (std::size_t ordinal = 0;
           ordinal < device_catalog::maximum_ports_per_router; ++ordinal) {
        const auto *port = inventory->at(static_cast<std::uint16_t>(ordinal));
        if (port && port->present && port->admin_enabled && port->link_signal) {
          bits[ordinal / 8U] |=
              static_cast<std::uint8_t>(1U << (ordinal % 8U));
          ++device.operational_ports;
        }
      }
    }
    device_sequence.store(device_snapshot_generation + 2U,
                          std::memory_order_release);
  }
  for (auto &terminal : telemetry_.sessions)
    terminal = {};
  for (const auto &intent : sessions_) {
    if (intent.handle.index >= telemetry_.sessions.size())
      continue;
    const auto *record = supervisor_.sessions().get(intent.handle);
    auto &terminal = telemetry_.sessions[intent.handle.index];
    terminal.session_index = intent.handle.index;
    terminal.session_generation = intent.handle.generation;
    terminal.device_index = record ? record->device.index : 0xffffU;
    terminal.device_generation = record ? record->device.generation : 0U;
    terminal.candidate_mode =
        record ? static_cast<std::uint8_t>(record->mode) : 0U;
    terminal.engine = intent.cli.engine == CliEngine::classic ? 1U : 0U;
    terminal.active = record ? 1U : 0U;
  }
  sequence.store(generation + 2U, std::memory_order_release);
}

std::string_view LabRuntime::command(std::string_view message) {
  const auto parsed = parse_message(message);
  if (!parsed) {
    fail("invalid protocol 3 netstring message");
    return response_;
  }
  const auto operation = parsed->values[0];
  const auto fields = std::span{parsed->values}.subspan(1U, parsed->count - 1U);
  bool changed{};
  if (operation == lab_runtime_protocol::snapshot && fields.empty()) {
    response_ = snapshot();
    publish_telemetry();
    return response_;
  }
  if (operation == lab_runtime_protocol::router_create)
    changed = create_router(fields);
  else if (operation ==
           lab_runtime_protocol::router_configuration_replace)
    changed = replace_router_configuration(fields);
  else if (operation == lab_runtime_protocol::system_name_set &&
           fields.size() == 2U) {
    auto *device = router(fields[0]);
    if (device && supervisor_.set_system_name(device->handle, fields[1])) {
      device->system_name.assign(fields[1]);
      changed = true;
    }
  }
  else if (operation == lab_runtime_protocol::host_create)
    changed = create_host(fields);
  else if (operation == lab_runtime_protocol::host_create_configured &&
           fields.size() == 6U) {
    const std::array<std::string_view, 2> identity{fields[0], fields[1]};
    const std::array<std::string_view, 5> configuration{
        fields[0], fields[2], fields[3], fields[4], fields[5]};
    // Configuration failure removes the newly isolated endpoint before the
    // command returns, so the next retry sees neither a ghost host nor a used
    // stable identity.
    if (create_host(identity)) {
      auto *endpoint = host(fields[0]);
      if (configure_host(configuration)) {
        changed = true;
      } else if (endpoint) {
        const auto handle = endpoint->handle;
        static_cast<void>(supervisor_.delete_host(handle));
        hosts_.erase(std::find_if(hosts_.begin(), hosts_.end(),
                                  [&](const auto &item) {
                                    return item.handle == handle;
                                  }));
      }
    }
  }
  else if (operation == lab_runtime_protocol::host_update &&
           fields.size() == 6U) {
    auto *endpoint = host(fields[0]);
    auto backup = endpoint ? supervisor_.checkpoint() : nullptr;
    if (endpoint && backup) {
      // Registry name and network identity form one product transaction. The
      // network pthread validates addressing before the portable HostIntent is
      // published. Any rejected field restores the detached supervisor graph,
      // so React never observes a renamed but otherwise stale host.
      const auto before = *endpoint;
      const std::array<std::string_view, 5> configuration{
          fields[0], fields[2], fields[3], fields[4], fields[5]};
      if (supervisor_.set_host_name(endpoint->handle, fields[1]) &&
          configure_host(configuration)) {
        endpoint->name.assign(fields[1]);
        changed = true;
      } else {
        *endpoint = before;
        static_cast<void>(supervisor_.restore(std::move(*backup)));
      }
    }
  }
  else if (operation == lab_runtime_protocol::host_name_set &&
           fields.size() == 2U) {
    auto *endpoint = host(fields[0]);
    if (endpoint && supervisor_.set_host_name(endpoint->handle, fields[1])) {
      endpoint->name.assign(fields[1]);
      changed = true;
    }
  }
  else if (operation == lab_runtime_protocol::hardware_card_set)
    changed = set_card(fields);
  else if (operation == lab_runtime_protocol::hardware_mda_set)
    changed = set_mda(fields);
  else if (operation == lab_runtime_protocol::hardware_card_admin_set &&
           fields.size() == 3U) {
    unsigned slot{};
    bool enabled{};
    auto *device = router(fields[0]);
    changed = device && decimal(fields[1], slot) && slot <= 0xffffU &&
              boolean(fields[2], enabled) &&
              supervisor_.set_card_admin(
                  device->handle, static_cast<std::uint16_t>(slot), enabled) ==
                  HardwareEditResult::applied;
  }
  else if (operation == lab_runtime_protocol::hardware_mda_admin_set &&
           fields.size() == 4U) {
    unsigned card{};
    unsigned mda{};
    bool enabled{};
    auto *device = router(fields[0]);
    changed = device && decimal(fields[1], card) &&
              decimal(fields[2], mda) && card <= 0xffffU && mda <= 0xffffU &&
              boolean(fields[3], enabled) &&
              supervisor_.set_mda_admin(
                  device->handle, static_cast<std::uint16_t>(card),
                  static_cast<std::uint16_t>(mda), enabled) ==
                  HardwareEditResult::applied;
  }
  else if (operation == lab_runtime_protocol::port_configure)
    changed = configure_port(fields);
  else if (operation == lab_runtime_protocol::interface_configure)
    changed = configure_interface(fields);
  else if (operation == lab_runtime_protocol::interface_delete)
    changed = delete_interface(fields);
  else if (operation == lab_runtime_protocol::static_route_add)
    changed = add_static_route(fields);
  else if (operation == lab_runtime_protocol::static_route_delete)
    changed = delete_static_route(fields);
  else if (operation == lab_runtime_protocol::link_create)
    changed = create_link(fields);
  else if (operation == lab_runtime_protocol::host_configure)
    changed = configure_host(fields);
  else if (operation == lab_runtime_protocol::session_create)
    changed = create_session(fields);
  else if (operation == lab_runtime_protocol::capture_point_set)
    changed = configure_capture(fields);
  else if (operation == lab_runtime_protocol::capture_selection_replace)
    changed = replace_capture_selection(fields);
  else if (operation == lab_runtime_protocol::router_delete &&
           fields.size() == 1U) {
    auto *device = router(fields[0]);
    if (device && supervisor_.delete_router(device->handle)) {
      const auto handle = device->handle;
      sessions_.erase(std::remove_if(sessions_.begin(), sessions_.end(),
                                     [&](const auto &item) {
                                       const auto *record =
                                           supervisor_.sessions().get(item.handle);
                                       return !record || record->device == handle;
                                     }),
                      sessions_.end());
      routers_.erase(std::find_if(routers_.begin(), routers_.end(),
                                  [&](const auto &item) {
                                    return item.handle == handle;
                                  }));
      changed = true;
    }
  } else if (operation == lab_runtime_protocol::host_delete &&
             fields.size() == 1U) {
    auto *endpoint = host(fields[0]);
    if (endpoint && supervisor_.delete_host(endpoint->handle)) {
      const auto handle = endpoint->handle;
      hosts_.erase(std::find_if(hosts_.begin(), hosts_.end(),
                                [&](const auto &item) {
                                  return item.handle == handle;
                                }));
      changed = true;
    }
  } else if (operation == lab_runtime_protocol::link_delete &&
             fields.size() == 1U) {
    const auto link = supervisor_.topology().find(fields[0]);
    changed = link && supervisor_.delete_link(*link);
  } else if (operation == lab_runtime_protocol::link_admin_set &&
             fields.size() == 2U) {
    bool enabled{};
    const auto link = supervisor_.topology().find(fields[0]);
    changed = link && boolean(fields[1], enabled) &&
              supervisor_.set_link_admin(*link, enabled);
  } else if (operation == lab_runtime_protocol::link_properties_set &&
             fields.size() == 3U) {
    bool enabled{};
    std::uint64_t propagation{};
    const auto link = supervisor_.topology().find(fields[0]);
    changed = link && boolean(fields[1], enabled) &&
              decimal(fields[2], propagation) &&
              propagation <= static_cast<std::uint64_t>(
                                 std::chrono::nanoseconds::max().count()) &&
              supervisor_.set_link_properties(
                  *link, enabled,
                  std::chrono::nanoseconds{
                      static_cast<std::int64_t>(propagation)});
  } else if (operation == lab_runtime_protocol::session_close &&
             fields.size() == 1U) {
    auto *terminal = session(fields[0]);
    if (terminal && supervisor_.close_session(terminal->handle)) {
      const auto handle = terminal->handle;
      sessions_.erase(std::find_if(sessions_.begin(), sessions_.end(),
                                   [&](const auto &item) {
                                     return item.handle == handle;
                                   }));
      changed = true;
    }
  } else if (operation == lab_runtime_protocol::session_state &&
             fields.size() == 1U) {
    response_ = session_state(fields[0]);
    if (response_.empty())
      fail("terminal session does not exist");
    return response_;
  } else if (operation == lab_runtime_protocol::session_execute &&
             fields.size() == 2U) {
    response_ = execute_session(fields[0], fields[1]);
    if (response_.empty())
      fail("terminal session does not exist");
    publish_telemetry();
    return response_;
  } else if (operation == lab_runtime_protocol::session_poll &&
             fields.size() == 1U) {
    response_ = poll_session(fields[0]);
    if (response_.empty())
      fail("terminal session does not exist");
    publish_telemetry();
    return response_;
  } else if (operation == lab_runtime_protocol::session_cancel &&
             fields.size() == 1U) {
    auto *terminal = session(fields[0]);
    if (!terminal) {
      fail("terminal session does not exist");
      return response_;
    }
    terminal->ping.cancel_requested = terminal->ping.active;
    succeed();
    return response_;
  } else if (operation == lab_runtime_protocol::session_complete &&
             fields.size() == 3U) {
    if (!session(fields[0])) {
      fail("terminal session does not exist");
      return response_;
    }
    response_ = complete_session(fields[0], fields[1], fields[2]);
    return response_;
  } else if (operation == lab_runtime_protocol::router_ping_start &&
             fields.size() == 3U) {
    auto *device = router(fields[0]);
    const auto destination = ipv4(fields[1]);
    unsigned sequence{};
    changed = device && destination && decimal(fields[2], sequence) &&
              sequence <= 0xffffU &&
              supervisor_.start_router_ping(
                  device->handle, *destination,
                  static_cast<std::uint16_t>(sequence));
  } else if (operation == lab_runtime_protocol::router_ping_status &&
             fields.size() == 2U) {
    auto *device = router(fields[0]);
    unsigned sequence{};
    if (!device || !decimal(fields[1], sequence) || sequence > 0xffffU) {
      fail("invalid router ping status query");
      return response_;
    }
    succeed(supervisor_.router_ping_reply(
                device->handle, static_cast<std::uint16_t>(sequence))
                ? "reply"
                : "pending");
    return response_;
  } else if (operation == lab_runtime_protocol::host_ping_start &&
             fields.size() == 3U) {
    auto *endpoint = host(fields[0]);
    const auto destination = ipv4(fields[1]);
    unsigned sequence{};
    changed = endpoint && destination && decimal(fields[2], sequence) &&
              sequence <= 0xffffU &&
              supervisor_.start_host_ping(
                  endpoint->handle, ipv4_bytes(*destination),
                  static_cast<std::uint16_t>(sequence));
  } else if (operation == lab_runtime_protocol::host_ping_status &&
             fields.size() == 2U) {
    auto *endpoint = host(fields[0]);
    unsigned sequence{};
    if (!endpoint || !decimal(fields[1], sequence) || sequence > 0xffffU) {
      fail("invalid host ping status query");
      return response_;
    }
    succeed(supervisor_.host_ping_reply(
                endpoint->handle, static_cast<std::uint16_t>(sequence))
                ? "reply"
                : "pending");
    return response_;
  } else {
    fail("unknown or malformed protocol 3 operation");
    return response_;
  }
  if (!changed) {
    fail("operation was rejected without changing the laboratory");
    return response_;
  }
  publish_telemetry();
  response_ = snapshot();
  return response_;
}

std::span<const std::uint8_t> LabRuntime::prepare_capture() noexcept {
  try {
    // Interface Description Block names are refreshed at export time. A router
    // or host may have been renamed after capture selection, and exporting a
    // stale label would detach the PCAP from the current project vocabulary.
    for (const auto &intent : capture_intents_) {
      if (!intent.selected)
        continue;
      const std::string_view kind = intent.kind == CapturePointKind::link_direction
                                        ? "link-direction"
                                    : intent.kind == CapturePointKind::router_ingress
                                        ? "router-ingress"
                                    : intent.kind == CapturePointKind::router_egress
                                        ? "router-egress"
                                        : "cpm-punt";
      const std::string_view direction = intent.direction ? "1" : "0";
      // configure_capture updates the matched intent's selected flag. Copying
      // its textual key first prevents the parser fields from borrowing the
      // same vector element that the nested operation is permitted to mutate.
      const std::string object_id = intent.object_id;
      const std::string port_id = intent.port_id;
      const std::array<std::string_view, 5> fields{
          kind, object_id, port_id, direction, "1"};
      if (!configure_capture(fields)) {
        capture_bytes_.clear();
        return {};
      }
    }
    const auto prepared = supervisor_.prepare_capture();
    // The C ABI uses separate pointer and size calls. Owning this immutable
    // copy keeps both observations paired even if another control query runs
    // before JavaScript transfers the bytes.
    capture_bytes_.assign(prepared.begin(), prepared.end());
  } catch (...) {
    capture_bytes_.clear();
  }
  return capture_bytes_;
}

std::span<const std::uint8_t> LabRuntime::export_checkpoint() {
  const auto checkpoint = supervisor_.checkpoint();
  if (!checkpoint) {
    checkpoint_bytes_.clear();
    return {};
  }
  try {
    // Forwarding checkpoints intentionally omit display-only configuration.
    // Append the control facade's portable records to the same validated ABI
    // so a bare checkpoint is complete and does not depend on prior manifest
    // replay or matching objects already present in this LabRuntime instance.
    checkpoint->portable_routers.reserve(routers_.size());
    for (const auto &router : routers_) {
      PortableRouterIntentCheckpoint value;
      value.device = router.handle;
      value.ports.reserve(router.ports.size());
      for (const auto &port : router.ports)
        value.ports.push_back({port.id, port.admin_enabled, port.mtu,
                               port.speed_mbps, port.description});
      value.interfaces.reserve(router.interfaces.size());
      for (const auto &interface : router.interfaces)
        value.interfaces.push_back(
            {interface.name, interface.port_id, interface.mac,
             interface.address, interface.prefix_length,
             interface.admin_enabled, interface.port_configured,
             interface.address_configured});
      value.routes.reserve(router.routes.size());
      for (const auto &route : router.routes)
        value.routes.push_back(
            {route.network, route.next_hop, route.prefix_length});
      value.global_candidate_initialized =
          router.global_candidate_initialized;
      if (router.global_candidate_initialized)
        value.global_candidate =
            portable_configuration(router.global_candidate);
      checkpoint->portable_routers.push_back(std::move(value));
    }
    checkpoint->portable_session_candidates.reserve(sessions_.size());
    const auto checkpoint_now = std::chrono::steady_clock::now();
    const auto relative_ns = [&](auto deadline) {
      if (deadline <= checkpoint_now)
        return std::uint64_t{};
      return static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(
              deadline - checkpoint_now)
              .count());
    };
    for (const auto &session : sessions_) {
      PortableSessionCandidateCheckpoint value;
      value.session = session.handle;
      value.initialized = session.private_candidate_initialized;
      if (value.initialized)
        value.candidate = portable_configuration(session.private_candidate);
      value.ping_destination = session.ping.destination;
      value.ping_sequence = session.ping.sequence;
      value.ping_payload_octets = session.ping.payload_octets;
      value.ping_requested = session.ping.requested;
      value.ping_sent = session.ping.sent;
      value.ping_received = session.ping.received;
      value.ping_next_send_ns = relative_ns(session.ping.next_send);
      value.ping_reply_deadline_ns = relative_ns(session.ping.reply_deadline);
      value.ping_dont_fragment = session.ping.dont_fragment;
      value.ping_waiting = session.ping.waiting;
      value.ping_active = session.ping.active;
      value.ping_cancel_requested = session.ping.cancel_requested;
      checkpoint->portable_session_candidates.push_back(std::move(value));
    }
    checkpoint->portable_hosts.reserve(hosts_.size());
    for (const auto &host : hosts_)
      checkpoint->portable_hosts.push_back(
          {host.handle, host.mac, host.address, host.gateway,
           host.prefix_length, host.mtu, host.configured});
    checkpoint->portable_capture_points.reserve(capture_intents_.size());
    for (const auto &capture : capture_intents_)
      checkpoint->portable_capture_points.push_back(
          {capture.id, capture.kind, capture.object_id, capture.port_id,
           capture.direction, capture.selected});
  } catch (...) {
    checkpoint_bytes_.clear();
    return {};
  }
  checkpoint_bytes_ = checkpoint_v5::encode(*checkpoint);
  return checkpoint_bytes_;
}

bool LabRuntime::import_checkpoint(std::span<const std::uint8_t> bytes) {
  auto checkpoint = checkpoint_v5::decode(bytes);
  if (!checkpoint)
    return false;
  try {
    const auto configuration_intent = [](const PortableConfigurationCheckpoint &source) {
      ConfigurationIntent target;
      target.system_name = source.system_name;
      for (std::size_t card = 0; card < source.cards.size(); ++card) {
        target.cards[card].provisioned = source.cards[card].provisioned;
        target.cards[card].admin_enabled = source.cards[card].admin_enabled;
        for (std::size_t mda = 0; mda < source.cards[card].mdas.size(); ++mda) {
          target.cards[card].mdas[mda].provisioned =
              source.cards[card].mdas[mda].provisioned;
          target.cards[card].mdas[mda].admin_enabled =
              source.cards[card].mdas[mda].admin_enabled;
        }
      }
      for (const auto &port : source.ports)
        target.ports.push_back({port.id, port.admin_enabled, port.mtu,
                                port.speed_mbps, port.description});
      for (const auto &interface : source.interfaces)
        target.interfaces.push_back(
            {interface.name, interface.port_id, interface.mac,
             interface.address, interface.prefix_length,
             interface.admin_enabled, interface.port_configured,
             interface.address_configured});
      for (const auto &route : source.routes)
        target.routes.push_back(
            {route.network, route.next_hop, route.prefix_length});
      return target;
    };
    // Stage the entire portable graph before the supervisor commits owner
    // state. Every handle must map one-to-one to a validated registry record;
    // otherwise the import fails without changing the active laboratory.
    std::vector<RouterIntent> routers;
    std::vector<HostIntent> hosts;
    std::vector<SessionIntent> sessions;
    std::vector<CaptureIntent> captures;
    if (checkpoint->portable_routers.size() !=
            checkpoint->devices.entries.size() ||
        checkpoint->portable_hosts.size() != checkpoint->hosts.entries.size() ||
        checkpoint->portable_session_candidates.size() !=
            checkpoint->sessions.entries.size())
      return false;
    routers.reserve(checkpoint->devices.entries.size());
    hosts.reserve(checkpoint->hosts.entries.size());
    sessions.reserve(checkpoint->sessions.entries.size());
    captures.reserve(checkpoint->portable_capture_points.size());
    for (const auto &device : checkpoint->devices.entries) {
      const auto portable = std::find_if(
          checkpoint->portable_routers.begin(),
          checkpoint->portable_routers.end(), [&](const auto &item) {
            return item.device == device.handle;
          });
      if (portable == checkpoint->portable_routers.end())
        return false;
      RouterIntent value{.handle = device.handle,
                         .node_id = device.node_id,
                         .system_name = device.system_name,
                         .profile_id = device.profile_id,
                         .ports = {},
                         .interfaces = {},
                         .routes = {},
                         .global_candidate = {},
                         .global_candidate_initialized = false};
      value.ports.reserve(portable->ports.size());
      for (const auto &port : portable->ports)
        value.ports.push_back({port.id, port.admin_enabled, port.mtu,
                               port.speed_mbps, port.description});
      value.interfaces.reserve(portable->interfaces.size());
      for (const auto &interface : portable->interfaces)
        value.interfaces.push_back(
            {interface.name, interface.port_id, interface.mac,
             interface.address, interface.prefix_length,
             interface.admin_enabled, interface.port_configured,
             interface.address_configured});
      value.routes.reserve(portable->routes.size());
      for (const auto &route : portable->routes)
        value.routes.push_back(
            {route.network, route.next_hop, route.prefix_length});
      value.global_candidate_initialized =
          portable->global_candidate_initialized;
      if (value.global_candidate_initialized)
        value.global_candidate =
            configuration_intent(portable->global_candidate);
      routers.push_back(std::move(value));
    }
    for (const auto &endpoint : checkpoint->hosts.entries) {
      const auto portable = std::find_if(
          checkpoint->portable_hosts.begin(),
          checkpoint->portable_hosts.end(), [&](const auto &item) {
            return item.host == endpoint.handle;
          });
      if (portable == checkpoint->portable_hosts.end())
        return false;
      hosts.push_back({.handle = endpoint.handle,
                       .node_id = endpoint.node_id,
                       .name = endpoint.name,
                       .mac = portable->mac,
                       .address = portable->address,
                       .gateway = portable->gateway,
                       .prefix_length = portable->prefix_length,
                       .mtu = portable->mtu,
                       .configured = portable->configured});
    }
    const auto restore_now = std::chrono::steady_clock::now();
    for (const auto &terminal : checkpoint->sessions.entries) {
      SessionIntent restored{.handle = terminal.handle,
                             .session_id = terminal.record.session_id,
                             .cli = {},
                             .private_candidate = {},
                             .private_candidate_initialized = false,
                             .ping = {}};
      // Import replaces the active laboratory. Session semantics therefore
      // come from the validated checkpoint even when an equal textual session
      // ID happened to exist before the atomic swap.
      restored.cli = terminal.record.cli;
      const auto portable_candidate = std::find_if(
          checkpoint->portable_session_candidates.begin(),
          checkpoint->portable_session_candidates.end(),
          [&](const auto &item) { return item.session == terminal.handle; });
      if (portable_candidate ==
          checkpoint->portable_session_candidates.end())
        return false;
      restored.private_candidate_initialized = portable_candidate->initialized;
      if (restored.private_candidate_initialized)
        restored.private_candidate =
            configuration_intent(portable_candidate->candidate);
      restored.ping.destination = portable_candidate->ping_destination;
      restored.ping.sequence = portable_candidate->ping_sequence;
      restored.ping.payload_octets =
          portable_candidate->ping_payload_octets;
      restored.ping.requested = portable_candidate->ping_requested;
      restored.ping.sent = portable_candidate->ping_sent;
      restored.ping.received = portable_candidate->ping_received;
      restored.ping.dont_fragment =
          portable_candidate->ping_dont_fragment;
      restored.ping.waiting = portable_candidate->ping_waiting;
      restored.ping.active = portable_candidate->ping_active;
      restored.ping.cancel_requested =
          portable_candidate->ping_cancel_requested;
      restored.ping.next_send =
          restore_now + std::chrono::nanoseconds{
                            static_cast<std::int64_t>(
                                portable_candidate->ping_next_send_ns)};
      restored.ping.reply_deadline =
          restore_now + std::chrono::nanoseconds{
                            static_cast<std::int64_t>(
                                portable_candidate->ping_reply_deadline_ns)};
      restored.ping.sent_at = restored.ping.reply_deadline -
                              device_catalog::ping_timeout;
      sessions.push_back(std::move(restored));
    }
    for (const auto &capture : checkpoint->portable_capture_points) {
      if (std::any_of(captures.begin(), captures.end(), [&](const auto &item) {
            return item.id == capture.id ||
                   (item.kind == capture.kind &&
                    item.object_id == capture.object_id &&
                    item.port_id == capture.port_id &&
                    item.direction == capture.direction);
          }))
        return false;
      captures.push_back({capture.id, capture.kind, capture.object_id,
                          capture.port_id, capture.direction,
                          capture.selected});
    }
    if (!supervisor_.restore(std::move(*checkpoint)))
      return false;
    routers_.swap(routers);
    hosts_.swap(hosts);
    sessions_.swap(sessions);
    capture_intents_.swap(captures);
  } catch (...) {
    return false;
  }
  publish_telemetry();
  return true;
}

} // namespace router::lab
