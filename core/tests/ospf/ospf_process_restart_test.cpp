// OSPF graceful-restart, checkpoint and generation-replacement cases.
// Each process owns restored state and exchanges only encoded packets.

#include "ospf_process_test_support.hpp"

void ospf_process_restart_tests() {
  using namespace router;
  using namespace router::ospf;
  const auto now = RuntimeClock::time_point{std::chrono::seconds{100U}};
  std::size_t written{};
  // Graceful-restart assistance is exercised through an actual Grace-LSA in
  // an LSU, never by editing the neighbor repository. The helper keeps an
  // already Full adjacency beyond DeadInterval and releases it precisely at
  // the remaining grace deadline.
  InstanceProcess helper{
      0x07070707U, 0U, router::packet::ospf::version_two, 0U,
      0x70707070U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess restarting{
      0x08080808U, 0U, router::packet::ospf::version_two, 0U,
      0x80808080U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  helper.set_graceful_restart_helper(true);
  require(helper.add_interface(
              interface_configuration(0x07070707U, 0xc0000207U, 0U),
              now) &&
              restarting.add_interface(
                  interface_configuration(0x08080808U, 0xc0000208U, 0U),
                  now),
          "graceful-restart peers rejected valid interfaces");
  deliver_ready(helper, restarting, {{192U, 0U, 2U, 7U}}, now);
  deliver_ready(restarting, helper, {{192U, 0U, 2U, 8U}}, now);
  const auto helper_convergence =
      now + router::device_catalog::ospf_hello_interval;
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets &&
       (helper.neighbor_state(1U, 0x08080808U) !=
            NeighborState::full ||
        restarting.neighbor_state(1U, 0x07070707U) !=
            NeighborState::full);
       ++turn) {
    deliver_ready(helper, restarting, {{192U, 0U, 2U, 7U}},
                  helper_convergence);
    deliver_ready(restarting, helper, {{192U, 0U, 2U, 8U}},
                  helper_convergence);
  }
  require(helper.neighbor_state(1U, 0x08080808U) ==
              NeighborState::full,
          "graceful-restart fixture did not establish Full adjacency");

  std::array<std::uint8_t, 44U> grace_lsa{};
  const auto put16 = [](std::span<std::uint8_t> bytes,
                        std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value);
  };
  const auto put32 = [](std::span<std::uint8_t> bytes,
                        std::size_t offset, std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value);
  };
  put16(grace_lsa, 0U, 0U);
  grace_lsa[2U] = static_cast<std::uint8_t>(
      router::packet::ospf::option_opaque_capability);
  grace_lsa[3U] = static_cast<std::uint8_t>(
      router::packet::ospf::lsa::version_two_link_opaque_type);
  put32(grace_lsa, 4U,
        static_cast<std::uint32_t>(
            router::packet::ospf::lsa::
                version_two_grace_opaque_type)
            << 24U);
  put32(grace_lsa, 8U, 0x08080808U);
  put32(grace_lsa, 12U,
        static_cast<std::uint32_t>(initial_sequence_number));
  put16(grace_lsa, 18U,
        static_cast<std::uint16_t>(grace_lsa.size()));
  put16(grace_lsa, 20U, 1U);
  put16(grace_lsa, 22U, 4U);
  put32(grace_lsa, 24U, 120U);
  put16(grace_lsa, 28U, 2U);
  put16(grace_lsa, 30U, 1U);
  grace_lsa[32U] = static_cast<std::uint8_t>(
      router::packet::ospf::lsa::GraceRestartReason::software_restart);
  put16(grace_lsa, 36U, 3U);
  put16(grace_lsa, 38U, 4U);
  put32(grace_lsa, 40U, 0xc0000208U);
  require(update_lsa_checksum(grace_lsa),
          "Grace-LSA fixture checksum failed");
  const std::array grace_advertisements{
      router::packet::ospf::EncodedLsa{
          .bytes = grace_lsa}};
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      grace_payload_storage{};
  const auto grace_payload =
      router::packet::ospf::encode_link_state_update_payload(
          grace_payload_storage, router::packet::ospf::version_two,
          grace_advertisements);
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      grace_packet_storage{};
  constexpr std::array<std::uint8_t, 8U> grace_null_authentication{};
  const auto grace_packet =
      grace_payload
          ? router::packet::ospf::encode_version_two(
                grace_packet_storage,
                router::packet::ospf::PacketType::link_state_update,
                0x08080808U, 0U,
                router::packet::ospf::AuthenticationType::none,
                grace_null_authentication, *grace_payload)
          : std::nullopt;
  require(grace_packet &&
              helper.receive_ipv4_packet(
                  1U, *grace_packet, {{192U, 0U, 2U, 8U}},
                  router::packet::ospf::all_spf_routers_v4,
                  helper_convergence) == ReceiveStatus::accepted,
          "valid Grace-LSA did not enter helper processing");
  // Continuity restore must retain the live Full adjacency, Grace-LSA,
  // exchange repositories and remaining helper deadline. Derived routes are
  // rebuilt from the restored LSDB rather than trusted as serialized output.
  const auto helper_checkpoint = helper.checkpoint(helper_convergence);
  InstanceProcess restored_helper{
      0x07070707U, 0U, router::packet::ospf::version_two, 0U,
      0x70707070U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  require(restored_helper.restore(helper_checkpoint, helper_convergence) &&
              restored_helper.neighbor_state(1U, 0x08080808U) ==
                  NeighborState::full &&
              restored_helper.database().records().size() ==
                  helper.database().records().size(),
          "OSPF continuity restore lost live adjacency or LSDB state");
  std::array<ProcessOutput,
             router::device_catalog::ospf_work_budget_packets>
      helper_output{};
  const auto after_dead =
      helper_convergence + std::chrono::seconds{41U};
  require(helper.run_ready(after_dead, helper_output, written) &&
              helper.neighbor_state(1U, 0x08080808U) ==
                  NeighborState::full,
          "helper released Full adjacency at ordinary DeadInterval");
  const auto after_grace =
      helper_convergence + std::chrono::seconds{121U};
  require(helper.run_ready(after_grace, helper_output, written) &&
              helper.neighbor_state(1U, 0x08080808U) !=
                  NeighborState::full,
          "helper retained adjacency after Grace-LSA expiry");
  require(restored_helper.run_ready(after_grace, helper_output, written) &&
              restored_helper.neighbor_state(1U, 0x08080808U) !=
                  NeighborState::full,
          "restored helper did not preserve the remaining grace deadline");

  // A committed configuration generation constructs a fresh process while
  // the remote router can still retain its prior Full adjacency. Exercise
  // that asymmetric restart using encoded Hellos and DD packets. The peer
  // must follow OneWayReceived or SeqNumberMismatch back through ExStart and
  // reconverge without a management-plane neighbor reset.
  InstanceProcess generation_a{
      0x0a0a0a0aU, 0U, router::packet::ospf::version_two, 0U,
      0xa0a0a0a0U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess generation_b{
      0x0b0b0b0bU, 0U, router::packet::ospf::version_two, 0U,
      0xb0b0b0b0U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  const auto generation_a_interface =
      interface_configuration(0x0a0a0a0aU, 0xc000020aU, 0U);
  const auto generation_b_interface =
      interface_configuration(0x0b0b0b0bU, 0xc000020bU, 0U);
  require(generation_a.add_interface(generation_a_interface, now) &&
              generation_b.add_interface(generation_b_interface, now),
          "generation-replacement fixture rejected valid interfaces");
  // The first Hello creates Init state on each side. The next periodic Hello
  // carries the learned Router ID and is what makes the relationship 2-Way.
  deliver_ready(generation_a, generation_b, {{192U, 0U, 2U, 10U}}, now);
  deliver_ready(generation_b, generation_a, {{192U, 0U, 2U, 11U}}, now);
  const auto initial_generation_convergence =
      now + router::device_catalog::ospf_hello_interval;
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets &&
       (generation_a.neighbor_state(1U, 0x0b0b0b0bU) !=
            NeighborState::full ||
        generation_b.neighbor_state(1U, 0x0a0a0a0aU) !=
            NeighborState::full);
       ++turn) {
    deliver_ready(generation_a, generation_b, {{192U, 0U, 2U, 10U}},
                  initial_generation_convergence);
    deliver_ready(generation_b, generation_a, {{192U, 0U, 2U, 11U}},
                  initial_generation_convergence);
  }
  require(generation_a.neighbor_state(1U, 0x0b0b0b0bU) ==
                  NeighborState::full &&
              generation_b.neighbor_state(1U, 0x0a0a0a0aU) ==
                  NeighborState::full,
          "generation-replacement fixture did not establish Full");

  InstanceProcess replacement_a{
      0x0a0a0a0aU, 0U, router::packet::ospf::version_two, 0U,
      0xc0c0c0c0U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  require(replacement_a.add_interface(generation_a_interface,
                                      initial_generation_convergence),
          "fresh committed generation rejected the unchanged interface");
  // Deliver the replacement's neighbor-less first Hello while the peer still
  // owns its old Full row. This is the exact asymmetric state transition that
  // a live configuration commit creates.
  deliver_ready(replacement_a, generation_b,
                {{192U, 0U, 2U, 10U}}, initial_generation_convergence);
  const auto replacement_convergence =
      initial_generation_convergence +
      router::device_catalog::ospf_hello_interval;
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets * 2U &&
       (replacement_a.neighbor_state(1U, 0x0b0b0b0bU) !=
            NeighborState::full ||
       generation_b.neighbor_state(1U, 0x0a0a0a0aU) !=
            NeighborState::full);
       ++turn) {
    deliver_ready(generation_b, replacement_a,
                  {{192U, 0U, 2U, 11U}}, replacement_convergence);
    deliver_ready(replacement_a, generation_b,
                  {{192U, 0U, 2U, 10U}}, replacement_convergence);
  }
  const auto replacement_a_state =
      replacement_a.neighbor_state(1U, 0x0b0b0b0bU);
  const auto generation_b_state =
      generation_b.neighbor_state(1U, 0x0a0a0a0aU);
  if (replacement_a_state != NeighborState::full ||
      generation_b_state != NeighborState::full) {
    const auto replacement_checkpoint =
        replacement_a.checkpoint(replacement_convergence);
    const auto retained_checkpoint =
        generation_b.checkpoint(replacement_convergence);
    const auto &replacement_exchange =
        replacement_checkpoint.interfaces.front().exchanges.front();
    const auto &retained_exchange =
        retained_checkpoint.interfaces.front().exchanges.front();
    throw std::runtime_error(
        "fresh OSPF generation required a manual neighbor reset; fresh=" +
        std::to_string(replacement_a_state
                           ? static_cast<unsigned>(*replacement_a_state)
                           : 255U) +
        " retained=" +
        std::to_string(generation_b_state
                           ? static_cast<unsigned>(*generation_b_state)
                           : 255U) +
        " fresh-requests=" +
        std::to_string(replacement_exchange.database.requests.size()) +
        " fresh-pending-request=" +
        std::to_string(replacement_exchange.pending_request) +
        " fresh-request-cursor=" +
        std::to_string(replacement_exchange.request_cursor) +
        " retained-retransmissions=" +
        std::to_string(retained_exchange.database.retransmissions.size()) +
        " retained-pending-update=" +
        std::to_string(retained_exchange.pending_update));
  }
}
