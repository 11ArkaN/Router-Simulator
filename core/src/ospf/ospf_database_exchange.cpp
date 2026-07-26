// RFC 2328 sections 10.6 through 10.9 and 13.5 neighbor database-list logic.
// Packet emission and timers belong to the process owner; this module maintains
// the exact bounded values those operations consume.

#include "router/ospf_database_exchange.hpp"

#include <algorithm>
#include <new>

namespace router::ospf {
namespace {

[[nodiscard]] bool same_identity(
    const packet::ospf::LsaHeaderView &header,
    const packet::ospf::LinkStateRequestEntry &request) noexcept {
  return header.type == request.link_state_type &&
         header.link_state_id == request.link_state_id &&
         header.advertising_router == request.advertising_router;
}

[[nodiscard]] bool same_identity(const LsaRecord &record,
                                 const packet::ospf::LsaHeaderView &header) {
  return record.key.type == header.type &&
         record.key.link_state_id == header.link_state_id &&
         record.key.advertising_router == header.advertising_router;
}

} // namespace

NeighborDatabaseExchange::NeighborDatabaseExchange(
    std::size_t maximum_summaries, std::size_t maximum_requests,
    std::size_t maximum_retransmissions,
    std::size_t maximum_acknowledgments)
    : maximum_summaries_(maximum_summaries),
      maximum_requests_(maximum_requests),
      maximum_retransmissions_(maximum_retransmissions),
      maximum_acknowledgments_(maximum_acknowledgments) {
  summaries_.reserve(maximum_summaries_);
  requests_.reserve(maximum_requests_);
  retransmissions_.reserve(maximum_retransmissions_);
  acknowledgments_.reserve(maximum_acknowledgments_);
}

bool NeighborDatabaseExchange::begin(std::span<const LsaRecord> records,
                                     std::uint8_t version,
                                     RuntimeClock::time_point now,
                                     bool permit_autonomous_system_scope)
    noexcept {
  if (version != packet::ospf::version_two &&
      version != packet::ospf::version_three)
    return false;
  try {
    std::vector<packet::ospf::LsaHeaderView> next;
    next.reserve(std::min(maximum_summaries_, records.size()));
    for (const auto &record : records) {
      // A virtual adjacency reaches the same routers through its normal
      // transit area. Re-summarizing AS-scope state would duplicate flooding
      // and is explicitly forbidden by both OSPF specifications.
      if (!permit_autonomous_system_scope &&
          record.key.scope == FloodingScope::autonomous_system)
        continue;
      auto header = packet::ospf::lsa_header(record.bytes, version);
      if (!header)
        return false;
      header->age_seconds = record.age(now);
      if (header->age_seconds == max_age_seconds)
        continue;
      if (next.size() == maximum_summaries_)
        return false;
      next.push_back(*header);
    }
    std::sort(next.begin(), next.end(), [](const auto &left,
                                           const auto &right) {
      if (left.type != right.type)
        return left.type < right.type;
      if (left.link_state_id != right.link_state_id)
        return left.link_state_id < right.link_state_id;
      return left.advertising_router < right.advertising_router;
    });
    summaries_ = std::move(next);
    requests_.clear();
    retransmissions_.clear();
    acknowledgments_.clear();
    version_ = version;
    permit_autonomous_system_scope_ = permit_autonomous_system_scope;
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool NeighborDatabaseExchange::process_database_description(
    const packet::ospf::DatabaseDescriptionView &description,
    const LinkStateDatabase &database,
    RuntimeClock::time_point now) noexcept {
  if (description.version != version_ ||
      description.lsa_headers.size() %
              packet::ospf::lsa_header_octets !=
          0U)
    return false;
  try {
    auto next = requests_;
    for (std::size_t offset{}; offset < description.lsa_headers.size();
         offset += packet::ospf::lsa_header_octets) {
      const auto remote = packet::ospf::lsa_header(
          description.lsa_headers.subspan(
              offset, packet::ospf::lsa_header_octets),
          version_);
      if (!remote)
        return false;
      if (!permit_autonomous_system_scope_ &&
          lsa_key(*remote).scope == FloodingScope::autonomous_system)
        continue;
      const auto local_record =
          std::find_if(database.records().begin(), database.records().end(),
                       [&](const auto &record) {
        return same_identity(record, *remote);
      });
      bool request = local_record == database.records().end();
      if (!request) {
        auto local = packet::ospf::lsa_header(local_record->bytes, version_);
        if (!local)
          return false;
        local->age_seconds = local_record->age(now);
        request = compare_lsa_headers(*remote, *local) == LsaRecency::newer;
      }
      if (!request)
        continue;
      const packet::ospf::LinkStateRequestEntry entry{
          .link_state_type = remote->type,
          .link_state_id = remote->link_state_id,
          .advertising_router = remote->advertising_router};
      if (std::find(next.begin(), next.end(), entry) != next.end())
        continue;
      if (next.size() == maximum_requests_)
        return false;
      next.push_back(entry);
    }
    requests_ = std::move(next);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

void NeighborDatabaseExchange::received_lsa(
    const packet::ospf::LsaHeaderView &header, InstallResult result) noexcept {
  if (result != InstallResult::installed &&
      result != InstallResult::identical &&
      result != InstallResult::fight_back_required)
    return;
  // A requested self-originated LSA is still a valid response even when its
  // newer sequence causes RFC 2328 section 13.4 fight-back instead of normal
  // installation. Keeping that identity on the request list would trap a
  // freshly restarted router in Loading while it repeatedly requests the
  // exact LSA generation that already triggered its authoritative reply.
  requests_.erase(
      std::remove_if(requests_.begin(), requests_.end(),
                     [&](const auto &request) {
        return same_identity(header, request);
      }),
      requests_.end());
}

bool NeighborDatabaseExchange::queue_retransmission(
    const LsaRecord &record, std::uint8_t version,
    RuntimeClock::time_point now) noexcept {
  auto header = packet::ospf::lsa_header(record.bytes, version);
  if (!header)
    return false;
  const RetransmissionEntry entry{
      .key = record.key,
      .sequence_number = header->sequence_number,
      .checksum = header->checksum};
  const auto existing =
      std::find_if(retransmissions_.begin(), retransmissions_.end(),
                   [&](const auto &value) { return value.key == entry.key; });
  if (existing != retransmissions_.end()) {
    *existing = entry;
    return true;
  }
  if (retransmissions_.size() == maximum_retransmissions_)
    return false;
  try {
    // Age is sampled by the packet encoder when retransmission occurs. The
    // list identifies the exact LSA generation and does not store a stale age.
    static_cast<void>(now);
    retransmissions_.push_back(entry);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool NeighborDatabaseExchange::acknowledge(
    const packet::ospf::LsaHeaderView &header) noexcept {
  const auto old_size = retransmissions_.size();
  retransmissions_.erase(
      std::remove_if(retransmissions_.begin(), retransmissions_.end(),
                     [&](const auto &entry) {
        return entry.key.type == header.type &&
               entry.key.link_state_id == header.link_state_id &&
               entry.key.advertising_router ==
                   header.advertising_router &&
               entry.sequence_number == header.sequence_number &&
               entry.checksum == header.checksum;
      }),
      retransmissions_.end());
  return retransmissions_.size() != old_size;
}

bool NeighborDatabaseExchange::retransmits(
    const LsaKey &key) const noexcept {
  return std::any_of(retransmissions_.begin(), retransmissions_.end(),
                     [&](const auto &entry) {
                       return entry.key == key;
                     });
}

bool NeighborDatabaseExchange::queue_delayed_acknowledgment(
    const packet::ospf::LsaHeaderView &header) noexcept {
  const auto present =
      std::find_if(acknowledgments_.begin(), acknowledgments_.end(),
                   [&](const auto &entry) {
    return entry.type == header.type &&
           entry.link_state_id == header.link_state_id &&
           entry.advertising_router == header.advertising_router &&
           entry.sequence_number == header.sequence_number &&
           entry.checksum == header.checksum;
  });
  if (present != acknowledgments_.end())
    return true;
  if (acknowledgments_.size() == maximum_acknowledgments_)
    return false;
  try {
    acknowledgments_.push_back(header);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

void NeighborDatabaseExchange::consume_delayed_acknowledgments(
    std::size_t count) noexcept {
  // The packet owner removes only headers it successfully encoded. Any
  // remainder stays ordered for the next MTU-sized acknowledgment packet.
  count = std::min(count, acknowledgments_.size());
  acknowledgments_.erase(
      acknowledgments_.begin(),
      acknowledgments_.begin() + static_cast<std::ptrdiff_t>(count));
}

void NeighborDatabaseExchange::reset() noexcept {
  summaries_.clear();
  requests_.clear();
  retransmissions_.clear();
  acknowledgments_.clear();
  version_ = 0U;
}

NeighborDatabaseExchangeCheckpoint
NeighborDatabaseExchange::checkpoint() const {
  return {.summaries = summaries_,
          .requests = requests_,
          .retransmissions = retransmissions_,
          .acknowledgments = acknowledgments_,
          .version = version_,
          .permit_autonomous_system_scope =
              permit_autonomous_system_scope_};
}

bool NeighborDatabaseExchange::restore(
    const NeighborDatabaseExchangeCheckpoint &checkpoint) noexcept {
  if (checkpoint.summaries.size() > maximum_summaries_ ||
      checkpoint.requests.size() > maximum_requests_ ||
      checkpoint.retransmissions.size() > maximum_retransmissions_ ||
      checkpoint.acknowledgments.size() > maximum_acknowledgments_ ||
      (checkpoint.version != 0U &&
       checkpoint.version != packet::ospf::version_two &&
       checkpoint.version != packet::ospf::version_three))
    return false;
  try {
    auto summaries = checkpoint.summaries;
    auto requests = checkpoint.requests;
    auto retransmissions = checkpoint.retransmissions;
    auto acknowledgments = checkpoint.acknowledgments;
    summaries_.swap(summaries);
    requests_.swap(requests);
    retransmissions_.swap(retransmissions);
    acknowledgments_.swap(acknowledgments);
    version_ = checkpoint.version;
    permit_autonomous_system_scope_ =
        checkpoint.permit_autonomous_system_scope;
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router::ospf
