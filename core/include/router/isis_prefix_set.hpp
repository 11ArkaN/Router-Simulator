// Extended prefix advertisements copied from one immutable local LSDB visit.
// The instance shard owns both bounded generations. Eligibility comes from its
// matching link graph; no route, policy, next-hop or foreign runtime is read.

// Source: ietf.isis.lsdb_prefix_collection

#pragma once

#include "router/isis_basic_tlvs.hpp"
#include "router/isis_link_graph.hpp"
#include "router/isis_multi_topology.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace router::isis {
struct PrefixCollectionBudget {
  std::size_t records{}, attributes{};
  bool operator==(const PrefixCollectionBudget &) const = default;
};
struct PrefixAdvertisement {
  packet::isis::LspId origin{};
  ip::IpPrefix prefix{};
  std::uint32_t metric{};
  std::uint8_t level{};
  bool down{}, external{};
  std::uint32_t attributes_offset{};
  std::uint16_t attributes_size{};
  bool operator==(const PrefixAdvertisement &) const = default;
};
enum class PrefixSetStatus : std::uint8_t { applied, invalid_selection, malformed_database, capacity };
struct PrefixSetCheckpoint {
  std::uint32_t version{1U};
  PrefixCollectionBudget budget;
  std::vector<PrefixAdvertisement> entries;
  std::vector<std::uint8_t> attributes;
  std::size_t ignored{};
};
class ExtendedPrefixSet final {
public:
  // Cold allocations only. Explicit emulator budgets count advertisements and
  // retained sub-TLV bytes, not vendor scale. Invalid budgets throw before use.
  ExtendedPrefixSet(std::size_t prefixes, std::size_t attributes)
      : maximum_prefixes_(prefixes), maximum_attributes_(attributes) {
    if (!prefixes || prefixes > std::numeric_limits<std::uint32_t>::max() ||
        attributes > std::numeric_limits<std::uint32_t>::max() ||
        prefixes > published_.entries.max_size() || attributes > published_.attributes.max_size())
      throw std::invalid_argument("Invalid IS-IS prefix collection budget");
    for (auto *generation : {&published_, &working_}) {
      generation->entries.reserve(prefixes);
      generation->attributes.reserve(attributes);
    }
  }
  // Same owner, no concurrent LSDB mutation. graph must have been successfully
  // built from this exact immutable database visit and now value. Its selection
  // must name an IP family and wide metrics. Narrow extraction is not admitted.
  // Live graph roots gate every fragment, and pseudonodes contribute no prefix.
  // No allocation or borrowed packet bytes escape. Any refusal retains the
  // entire old generation. Valid empty input publishes withdrawal.
  [[nodiscard]] PrefixSetStatus rebuild(const LinkStateDatabase &database,
      const LinkGraph &graph, RuntimeClock::time_point now) noexcept {
    const auto result = prepare(database, graph, now);
    if (result == PrefixSetStatus::applied) static_cast<void>(commit());
    return result;
  }
  // Same preconditions as rebuild. Prepare changes scratch only. The owner may
  // run SPF before commit; abort or any later failed prepare invalidates this
  // transaction while preserving all published views. No allocation occurs.
  [[nodiscard]] PrefixSetStatus prepare(const LinkStateDatabase &database,
      const LinkGraph &graph, RuntimeClock::time_point now) noexcept {
    prepared_ = false;
    const auto &selection = graph.selection();
    if (!selection.protocol || selection.metrics != GraphMetricStyle::wide ||
        (*selection.protocol != packet::isis::ipv4_nlpid && *selection.protocol != packet::isis::ipv6_nlpid))
      return PrefixSetStatus::invalid_selection;
    working_.entries.clear();
    working_.attributes.clear();
    working_.ignored = 0U;
    if (graph.root()) for (std::size_t index{}; index < database.size(); ++index) {
      const auto record = database.at(index, now);
      if (!record || !record->header.remaining_seconds || !record->header.sequence ||
          !record->header.checksum || record->header.id[6U]) continue;
      packet::isis::LanId origin{};
      std::copy_n(record->header.id.begin(), origin.size(), origin.begin());
      const auto member = std::lower_bound(graph.nodes().begin(), graph.nodes().end(), origin,
          [](const auto &node, const auto &id) { return node.id < id; });
      if (member == graph.nodes().end() || member->id != origin) continue;
      packet::isis::TlvCursor options(record->pdu.tlvs);
      while (const auto option = options.next()) {
        auto entries = *option;
        const auto ordinary = *selection.protocol == packet::isis::ipv4_nlpid ? 135U : 236U;
        const auto multi = *selection.protocol == packet::isis::ipv4_nlpid ? 235U : 237U;
        if (!selection.topology) {
          if (option->code != ordinary) continue;
        } else {
          if (option->code != multi) continue;
          const auto wrapped = packet::isis::mt_reachability(*option);
          if (!wrapped) { ++working_.ignored; continue; }
          if (!wrapped->topology || wrapped->topology != selection.topology) continue;
          entries = wrapped->entries;
        }
        // Validate the complete option first. A malformed late entry must not
        // publish earlier entries or cause a spurious capacity refusal.
        packet::isis::ExtendedPrefixCursor validation(entries);
        while (validation.next()) {}
        if (!validation.valid()) { ++working_.ignored; continue; }
        packet::isis::ExtendedPrefixCursor prefixes(entries);
        while (const auto prefix = prefixes.next()) {
          if (prefix->metric > packet::isis::maximum_path_metric ||
              (prefix->prefix.network.family == ip::AddressFamily::ipv6 && prefix->prefix.length >= 10U &&
               ip::is_link_local(prefix->prefix.network.bytes))) continue;
          if (working_.entries.size() == maximum_prefixes_ ||
              prefix->sub_tlvs.size() > maximum_attributes_ - working_.attributes.size())
            return PrefixSetStatus::capacity;
          working_.entries.push_back({record->header.id, prefix->prefix, prefix->metric,
              static_cast<std::uint8_t>(record->pdu.type == packet::isis::PduType::lsp_l1 ? 1U : 2U),
              prefix->down, prefix->external, static_cast<std::uint32_t>(working_.attributes.size()),
              static_cast<std::uint16_t>(prefix->sub_tlvs.size())});
          working_.attributes.insert(working_.attributes.end(), prefix->sub_tlvs.begin(), prefix->sub_tlvs.end());
        }
      }
      if (!options.valid()) return PrefixSetStatus::malformed_database;
    }
    prepared_ = true;
    return PrefixSetStatus::applied;
  }
  // Sole owner only, after successful prepare and any dependent calculations.
  // False means no complete prepared generation. A successful commit expires
  // old published views and cannot allocate or fail partway through swapping.
  [[nodiscard]] bool commit() noexcept {
    if (!prepared_) return false;
    std::swap(published_, working_);
    prepared_ = false;
    return true;
  }
  void abort() noexcept { prepared_ = false; }
  // Views expire only at successful rebuild or destruction, on this shard.
  // Raw sub-TLV order/bytes remain intact, including unknown attributes. Their
  // semantic consumers must validate each known attribute independently.
  [[nodiscard]] std::span<const PrefixAdvertisement> entries() const noexcept { return published_.entries; }
  [[nodiscard]] std::span<const std::uint8_t> attributes(std::size_t index) const noexcept {
    if (index >= published_.entries.size()) return {};
    const auto &entry = published_.entries[index];
    return std::span{published_.attributes}.subspan(entry.attributes_offset, entry.attributes_size);
  }
  [[nodiscard]] std::size_t ignored_options() const noexcept { return published_.ignored; }
  // Same instance owner with no prepared transaction. Capture owns the exact
  // published order/attributes and can throw allocation or invalid_argument.
  // Restore validates all bounds and framing before allocation-free replacement;
  // an existing prepared transaction refuses without mutation.
  [[nodiscard]] PrefixSetCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const PrefixSetCheckpoint &saved) noexcept;
private:
  struct Generation {
    std::vector<PrefixAdvertisement> entries;
    std::vector<std::uint8_t> attributes;
    std::size_t ignored{};
  };
  std::size_t maximum_prefixes_{}, maximum_attributes_{};
  Generation published_, working_;
  bool prepared_{};
};
} // namespace router::isis
