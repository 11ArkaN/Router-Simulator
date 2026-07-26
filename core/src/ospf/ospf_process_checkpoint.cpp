// OSPF process checkpoint capture, validation and restoration.
// InstanceProcess owns restored state and accepts it only as a complete value.

#include "ospf_process_internal.hpp"

namespace router::ospf {

InstanceProcessCheckpoint
InstanceProcess::checkpoint(RuntimeClock::time_point now) const {
  const auto remaining = [now](RuntimeClock::time_point deadline) {
    if (deadline == RuntimeClock::time_point{} || deadline <= now)
      return std::chrono::milliseconds{};
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - now);
  };
  const auto elapsed = [now](RuntimeClock::time_point point) {
    if (point == RuntimeClock::time_point{} || point > now)
      return std::chrono::milliseconds{};
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - point);
  };
  const auto age = [now](RuntimeClock::time_point started) {
    if (started == RuntimeClock::time_point{} || started >= now)
      return std::chrono::milliseconds{};
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now - started);
  };

  InstanceProcessCheckpoint result{
      .database = database_.checkpoint(now),
      .interfaces = {},
      .pending_fight_backs = {},
      .pending_sequence_wraps = pending_sequence_wraps_,
      .coordinator_lsas = {},
      .virtual_endpoint_addresses = virtual_endpoint_addresses_,
      .pending_coordinator_advertisements =
          pending_coordinator_advertisements_,
      .last_local_origination_age = age(last_local_origination_),
      .local_origination_remaining =
          remaining(local_origination_deadline_),
      .spf_remaining = remaining(spf_deadline_),
      .last_spf_started_age = age(last_spf_started_),
      .current_lsa_delay = current_lsa_delay_,
      .current_spf_delay = current_spf_delay_,
      .route_generation = route_generation_,
      .next_dd_sequence = next_dd_sequence_,
      .next_coordinator_link_state_id =
          next_coordinator_link_state_id_,
      .router_lsa_sequence = router_lsa_sequence_,
      .prefix_lsa_sequence = prefix_lsa_sequence_,
      .router_information_lsa_sequence =
          router_information_lsa_sequence_,
      .route_recalculation_status = route_recalculation_status_,
      .run_ready_status = run_ready_status_,
      .local_origination_status = local_origination_status_,
      .local_origination_install_result =
          local_origination_install_result_,
      .coordinator_reconcile_pending =
          coordinator_reconcile_pending_,
      .router_sequence_at_max = router_sequence_at_max_,
      .prefix_sequence_at_max = prefix_sequence_at_max_,
      .router_information_sequence_at_max =
          router_information_sequence_at_max_,
      .router_sequence_wrap_pending =
          router_sequence_wrap_pending_,
      .prefix_sequence_wrap_pending =
          prefix_sequence_wrap_pending_,
      .router_information_sequence_wrap_pending =
          router_information_sequence_wrap_pending_,
      .area_border_router = area_border_router_,
      .autonomous_system_boundary_router =
          autonomous_system_boundary_router_,
      .virtual_link_endpoint = virtual_link_endpoint_,
      .overload = overload_,
      .graceful_restart_helper = graceful_restart_helper_,
      .loop_free_alternates = loop_free_alternates_};
  result.interfaces.reserve(interfaces_.size());
  for (const auto &owner : interfaces_) {
    ProcessInterfaceCheckpoint saved{
        .configuration = owner.configuration,
        .runtime = owner.runtime.checkpoint(now),
        .exchanges = {},
        .nbma_peers = {},
        .send_authentication = owner.send_authentication,
        .receive_authentications = owner.receive_authentications,
        .authentication_sequence = owner.authentication_sequence,
        .authentication_send_key_id =
            owner.authentication_send_key_id,
        .ipsec_replay_sequence = owner.ipsec_replay_sequence,
        .network_lsa_sequence = owner.network_lsa_sequence,
        .network_prefix_lsa_sequence =
            owner.network_prefix_lsa_sequence,
        .link_lsa_sequence = owner.link_lsa_sequence,
        .authentication_required = owner.authentication_required,
        .ipsec_replay_sequence_seen =
            owner.ipsec_replay_sequence_seen,
        .network_lsa_originated = owner.network_lsa_originated,
        .network_sequence_at_max = owner.network_sequence_at_max,
        .network_prefix_sequence_at_max =
            owner.network_prefix_sequence_at_max,
        .link_sequence_at_max = owner.link_sequence_at_max,
        .network_sequence_wrap_pending =
            owner.network_sequence_wrap_pending,
        .network_prefix_sequence_wrap_pending =
            owner.network_prefix_sequence_wrap_pending,
        .link_sequence_wrap_pending =
            owner.link_sequence_wrap_pending};
    if (saved.send_authentication)
      saved.send_authentication->key.fill(0U);
    for (auto &authentication : saved.receive_authentications)
      authentication.key.fill(0U);
    saved.nbma_peers.reserve(owner.nbma_peers.size());
    for (const auto &peer : owner.nbma_peers)
      saved.nbma_peers.push_back(
          {.configuration = peer.configuration,
           .hello_remaining = remaining(peer.hello_deadline),
           .router_id = peer.router_id});
    saved.exchanges.reserve(owner.exchanges.size());
    for (const auto &neighbor : owner.exchanges)
      saved.exchanges.push_back(
          {.database = neighbor.database.checkpoint(),
           .router_id = neighbor.router_id,
           .dd_sequence = neighbor.dd_sequence,
           .summary_cursor = neighbor.summary_cursor,
           .request_cursor = neighbor.request_cursor,
           .update_cursor = neighbor.update_cursor,
           .dd_retransmit_remaining =
               remaining(neighbor.dd_retransmit_deadline),
           .request_retransmit_remaining =
               remaining(neighbor.request_retransmit_deadline),
           .update_retransmit_remaining =
               remaining(neighbor.update_retransmit_deadline),
           .ipv4_address = neighbor.ipv4_address,
           .ipv6_address = neighbor.ipv6_address,
           .authentication_sequences =
               neighbor.authentication_sequences,
           .authentication_sequence_seen =
               neighbor.authentication_sequence_seen,
           .helper_remaining = remaining(neighbor.helper_deadline),
           .helper_elapsed = elapsed(neighbor.helper_started_at),
           .local_master = neighbor.local_master,
           .negotiation_complete = neighbor.negotiation_complete,
           .pending_database_description =
               neighbor.pending_database_description,
           .pending_request = neighbor.pending_request,
           .pending_update = neighbor.pending_update,
           .pending_acknowledgment =
               neighbor.pending_acknowledgment,
           .peer_more = neighbor.peer_more,
           .sent_more = neighbor.sent_more,
           .complete_after_reply = neighbor.complete_after_reply,
           .helper_active = neighbor.helper_active,
           .helper_was_designated_router =
               neighbor.helper_was_designated_router});
    result.interfaces.push_back(std::move(saved));
  }
  result.pending_fight_backs.reserve(pending_fight_backs_.size());
  for (const auto &entry : pending_fight_backs_)
    result.pending_fight_backs.push_back(
        {.key = entry.key, .bytes = entry.bytes});
  result.coordinator_lsas.reserve(coordinator_lsas_.size());
  for (const auto &entry : coordinator_lsas_)
    result.coordinator_lsas.push_back(
        {.advertisement = entry.advertisement,
         .key = entry.key,
         .sequence = entry.sequence,
         .withdrawing = entry.withdrawing,
         .sequence_at_max = entry.sequence_at_max,
         .sequence_wrap_pending = entry.sequence_wrap_pending});
  return result;
}

bool InstanceProcess::restore(
    const InstanceProcessCheckpoint &checkpoint,
    RuntimeClock::time_point now) noexcept {
  if (checkpoint.interfaces.size() > maximum_interfaces_ ||
      checkpoint.database.records.size() > maximum_lsas_ ||
      checkpoint.current_lsa_delay < std::chrono::milliseconds{} ||
      checkpoint.current_spf_delay < std::chrono::milliseconds{})
    return false;
  const auto deadline = [now](std::chrono::milliseconds remaining) {
    return remaining == std::chrono::milliseconds{}
               ? RuntimeClock::time_point{}
               : now + remaining;
  };
  try {
    if (!database_.restore(checkpoint.database, version_, now))
      return false;
    interfaces_.clear();
    for (const auto &saved : checkpoint.interfaces) {
      if (saved.configuration.protocol.version != version_ ||
          saved.configuration.protocol.area_id != area_id_ ||
          saved.runtime.configuration != saved.configuration.protocol ||
          saved.exchanges.size() > maximum_neighbors_per_interface_ ||
          saved.nbma_peers.size() > maximum_neighbors_per_interface_ ||
          saved.receive_authentications.size() > 64U)
        return false;
      InterfaceOwner owner{saved.configuration,
                           maximum_neighbors_per_interface_, now};
      if (!owner.runtime.restore(saved.runtime, now))
        return false;
      owner.send_authentication = saved.send_authentication;
      owner.receive_authentications = saved.receive_authentications;
      owner.authentication_sequence = saved.authentication_sequence;
      owner.authentication_send_key_id =
          saved.authentication_send_key_id;
      owner.authentication_required = saved.authentication_required;
      owner.ipsec_replay_sequence = saved.ipsec_replay_sequence;
      owner.ipsec_replay_sequence_seen =
          saved.ipsec_replay_sequence_seen;
      owner.network_lsa_sequence = saved.network_lsa_sequence;
      owner.network_prefix_lsa_sequence =
          saved.network_prefix_lsa_sequence;
      owner.link_lsa_sequence = saved.link_lsa_sequence;
      owner.network_lsa_originated = saved.network_lsa_originated;
      owner.network_sequence_at_max = saved.network_sequence_at_max;
      owner.network_prefix_sequence_at_max =
          saved.network_prefix_sequence_at_max;
      owner.link_sequence_at_max = saved.link_sequence_at_max;
      owner.network_sequence_wrap_pending =
          saved.network_sequence_wrap_pending;
      owner.network_prefix_sequence_wrap_pending =
          saved.network_prefix_sequence_wrap_pending;
      owner.link_sequence_wrap_pending =
          saved.link_sequence_wrap_pending;
      for (const auto &peer : saved.nbma_peers)
        owner.nbma_peers.push_back(
            {.configuration = peer.configuration,
             .hello_deadline = deadline(peer.hello_remaining),
             .router_id = peer.router_id});
      for (const auto &saved_neighbor : saved.exchanges) {
        if (saved_neighbor.router_id == 0U ||
            saved_neighbor.summary_cursor >
                saved_neighbor.database.summaries.size() ||
            saved_neighbor.request_cursor >
                saved_neighbor.database.requests.size() ||
            saved_neighbor.update_cursor >
                saved_neighbor.database.retransmissions.size())
          return false;
        NeighborExchange neighbor{saved_neighbor.router_id,
                                  maximum_lsas_};
        if (!neighbor.database.restore(saved_neighbor.database))
          return false;
        neighbor.dd_sequence = saved_neighbor.dd_sequence;
        neighbor.summary_cursor = saved_neighbor.summary_cursor;
        neighbor.request_cursor = saved_neighbor.request_cursor;
        neighbor.update_cursor = saved_neighbor.update_cursor;
        neighbor.dd_retransmit_deadline =
            deadline(saved_neighbor.dd_retransmit_remaining);
        neighbor.request_retransmit_deadline =
            deadline(saved_neighbor.request_retransmit_remaining);
        neighbor.update_retransmit_deadline =
            deadline(saved_neighbor.update_retransmit_remaining);
        neighbor.ipv4_address = saved_neighbor.ipv4_address;
        neighbor.ipv6_address = saved_neighbor.ipv6_address;
        neighbor.authentication_sequences =
            saved_neighbor.authentication_sequences;
        neighbor.authentication_sequence_seen =
            saved_neighbor.authentication_sequence_seen;
        neighbor.local_master = saved_neighbor.local_master;
        neighbor.negotiation_complete =
            saved_neighbor.negotiation_complete;
        neighbor.pending_database_description =
            saved_neighbor.pending_database_description;
        neighbor.pending_request = saved_neighbor.pending_request;
        neighbor.pending_update = saved_neighbor.pending_update;
        neighbor.pending_acknowledgment =
            saved_neighbor.pending_acknowledgment;
        neighbor.peer_more = saved_neighbor.peer_more;
        neighbor.sent_more = saved_neighbor.sent_more;
        neighbor.complete_after_reply =
            saved_neighbor.complete_after_reply;
        neighbor.helper_deadline =
            deadline(saved_neighbor.helper_remaining);
        neighbor.helper_started_at =
            saved_neighbor.helper_elapsed == std::chrono::milliseconds{}
                ? RuntimeClock::time_point{}
                : now - saved_neighbor.helper_elapsed;
        neighbor.helper_active = saved_neighbor.helper_active;
        neighbor.helper_was_designated_router =
            saved_neighbor.helper_was_designated_router;
        owner.exchanges.push_back(std::move(neighbor));
      }
      interfaces_.push_back(std::move(owner));
    }
    pending_fight_backs_.clear();
    for (const auto &entry : checkpoint.pending_fight_backs)
      pending_fight_backs_.push_back(
          {.key = entry.key, .bytes = entry.bytes});
    pending_sequence_wraps_ = checkpoint.pending_sequence_wraps;
    coordinator_lsas_.clear();
    for (const auto &entry : checkpoint.coordinator_lsas)
      coordinator_lsas_.push_back(
          {.advertisement = entry.advertisement,
           .key = entry.key,
           .sequence = entry.sequence,
           .withdrawing = entry.withdrawing,
           .sequence_at_max = entry.sequence_at_max,
           .sequence_wrap_pending = entry.sequence_wrap_pending});
    virtual_endpoint_addresses_ =
        checkpoint.virtual_endpoint_addresses;
    pending_coordinator_advertisements_ =
        checkpoint.pending_coordinator_advertisements;
    coordinator_reconcile_pending_ =
        checkpoint.coordinator_reconcile_pending;
    next_dd_sequence_ = checkpoint.next_dd_sequence;
    next_coordinator_link_state_id_ =
        checkpoint.next_coordinator_link_state_id;
    router_lsa_sequence_ = checkpoint.router_lsa_sequence;
    prefix_lsa_sequence_ = checkpoint.prefix_lsa_sequence;
    router_information_lsa_sequence_ =
        checkpoint.router_information_lsa_sequence;
    router_sequence_at_max_ = checkpoint.router_sequence_at_max;
    prefix_sequence_at_max_ = checkpoint.prefix_sequence_at_max;
    router_information_sequence_at_max_ =
        checkpoint.router_information_sequence_at_max;
    router_sequence_wrap_pending_ =
        checkpoint.router_sequence_wrap_pending;
    prefix_sequence_wrap_pending_ =
        checkpoint.prefix_sequence_wrap_pending;
    router_information_sequence_wrap_pending_ =
        checkpoint.router_information_sequence_wrap_pending;
    area_border_router_ = checkpoint.area_border_router;
    autonomous_system_boundary_router_ =
        checkpoint.autonomous_system_boundary_router;
    virtual_link_endpoint_ = checkpoint.virtual_link_endpoint;
    overload_ = checkpoint.overload;
    graceful_restart_helper_ = checkpoint.graceful_restart_helper;
    loop_free_alternates_ = checkpoint.loop_free_alternates;
    last_local_origination_ =
        checkpoint.last_local_origination_age ==
                std::chrono::milliseconds{}
            ? RuntimeClock::time_point{}
            : now - checkpoint.last_local_origination_age;
    local_origination_deadline_ =
        deadline(checkpoint.local_origination_remaining);
    spf_deadline_ = deadline(checkpoint.spf_remaining);
    last_spf_started_ =
        checkpoint.last_spf_started_age == std::chrono::milliseconds{}
            ? RuntimeClock::time_point{}
            : now - checkpoint.last_spf_started_age;
    current_lsa_delay_ = checkpoint.current_lsa_delay;
    current_spf_delay_ = checkpoint.current_spf_delay;
    route_generation_ = checkpoint.route_generation;
    route_recalculation_status_ =
        checkpoint.route_recalculation_status;
    run_ready_status_ = checkpoint.run_ready_status;
    local_origination_status_ =
        checkpoint.local_origination_status;
    local_origination_install_result_ =
        checkpoint.local_origination_install_result;
    // Derived SPF, route inputs and FIB candidates are never trusted from a
    // checkpoint. Rebuild them solely from the restored LSDB and configured
    // local egress identities before ControlWorker can publish this process.
    return recalculate_routes(now);
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router::ospf
