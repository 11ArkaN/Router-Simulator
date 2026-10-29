// The IS-IS pthread schedules encoded update PDUs and consumes actual physical
// admission receipts. Circuit-local pacing covers both levels. All retry storage
// is reserved before publication; dependencies stay within the protocol owner.

// Source: iso.10589.2002.runtime_update

#include "router/isis_control_worker.hpp"

#include <algorithm>

namespace router::isis {
namespace {
std::optional<std::size_t> update_level(packet::isis::PduType type) noexcept {
  using packet::isis::PduType;
  switch (type) {
  case PduType::lsp_l1: case PduType::csnp_l1: case PduType::psnp_l1: return 0U;
  case PduType::lsp_l2: case PduType::csnp_l2: case PduType::psnp_l2: return 1U;
  default: return std::nullopt;
  }
}
bool is_lsp(packet::isis::PduType type) noexcept {
  return type == packet::isis::PduType::lsp_l1 || type == packet::isis::PduType::lsp_l2;
}
bool is_complete(packet::isis::PduType type) noexcept {
  return type == packet::isis::PduType::csnp_l1 || type == packet::isis::PduType::csnp_l2;
}
}

bool ControlWorker::complete_update(OwnedCircuit &owned,
    const protocol::PacketChannel<device_catalog::isis_packet_ring_frames, true>::Completion &receipt,
    const packet::isis::PduView &pdu, RuntimeClock::time_point now) noexcept {
  const auto level = update_level(pdu.type);
  if (!level || !owned.update || !owned.update_egress || owned.update->status != UpdateStatus::applied) return false;
  auto output = owned.update->process.outputs(owned.update_slot, *level);
  if (!output || output->synchronization_epoch != receipt.metadata.protocol_epoch) return false;
  auto &egress = *owned.update_egress;
  if (is_lsp(pdu.type)) {
    const auto header = packet::isis::lsp(pdu);
    if (!header) return false;
    const auto completed = output->reservations.lsp.complete(receipt.metadata.protocol_epoch,
        receipt.metadata.transmission_id, receipt.enqueued, now);
    if (!completed.accepted) return false;
    if (receipt.enqueued) ++owned.counters.lsp_enqueued;
    else ++owned.counters.lsp_refused;
    if (receipt.enqueued && completed.current_version) {
      std::erase_if(egress.retries, [&](const auto &entry) {
        const auto *owner = owned.update->process.level(entry.level);
        return !owner || !owner->database().database().find(entry.header.id, now);
      });
      auto retry = std::find_if(egress.retries.begin(), egress.retries.end(), [&](const auto &entry) {
        return entry.level == *level && entry.header.id == header->id;
      });
      if (retry == egress.retries.end()) {
        if (egress.retries.size() == egress.retries.capacity()) {
          owned.update->status = UpdateStatus::capacity;
          return true;
        }
        egress.retries.push_back({});
        retry = egress.retries.end() - 1;
      }
      *retry = {*header, *level, now + std::chrono::seconds{owned.update->configuration.transmission.retransmit_seconds}};
    }
    egress.lsp[*level] = now;
  } else {
    const auto completed = output->reservations.snp.complete(receipt.metadata.protocol_epoch,
        receipt.metadata.transmission_id, receipt.enqueued, now);
    if (!completed.accepted) return false;
    if (receipt.enqueued) ++owned.counters.snp_enqueued;
    else ++owned.counters.snp_refused;
    if (is_complete(pdu.type)) egress.complete[*level] = receipt.enqueued ? now : now +
        *jittered_interval(std::chrono::seconds{owned.update->configuration.transmission.partial_seconds}, egress.random);
  }
  return true;
}

RuntimeClock::time_point ControlWorker::emit_updates(OwnedCircuit &owned,
    RuntimeClock::time_point now, std::size_t &budget) noexcept {
  auto deadline = RuntimeClock::time_point::max();
  if (!owned.update || !owned.update_egress || owned.update->status != UpdateStatus::applied) return deadline;
  auto &instance = *owned.update;
  auto &egress = *owned.update_egress;
  const auto &program = instance.configuration.transmission;
  const auto &configuration = owned.circuit.configuration();
  const auto maximum_pdu = std::min<std::size_t>(program.maximum_pdu_octets,
      std::min(configuration.maximum_pdu_octets, packet::maximum_frame_octets -
          packet::ethernet_header_octets - packet::llc_ui_header_octets));
  if (now >= egress.pacing) {
    egress.pacing = now + program.pacing_period;
    egress.credits = program.pacing_burst;
  }
  const auto shard = owned.identity.device.index % forwarding_shards_;
  auto &channel = channels_.egress[shard];
  const auto available = [&] { return budget && channel.producer_available(); };
  for (std::size_t level{}; level < 2U; ++level) {
    auto output = instance.process.outputs(owned.update_slot, level);
    if (!output) continue;
    if (egress.epochs[level] != output->synchronization_epoch || egress.synchronize) {
      egress.epochs[level] = output->synchronization_epoch;
      egress.complete[level] = egress.partial[level] = egress.lsp[level] = now;
      egress.complete_started[level] = true;
      egress.remaining[level] = 0U;
    }
    if (egress.revision[level] != instance.revision[level]) {
      egress.revision[level] = instance.revision[level];
      egress.lsp[level] = now;
      egress.remaining[level] = 0U;
    }
    const auto publish = [&](std::uint64_t ticket, packet::isis::PduType type) {
      --budget;
      const bool published = channel.try_send({owned.identity.device, owned.identity.interface_id,
          owned.identity.physical_port_ordinal, owned.identity.configuration_generation, ticket,
          static_cast<std::uint8_t>(type), owned.identity.instance, output->synchronization_epoch}, output_);
      if (published) {
        if (channels_.egress_wakeup) channels_.egress_wakeup(channels_.egress_context, shard);
      } else if (is_lsp(type)) {
        static_cast<void>(output->reservations.lsp.complete(output->synchronization_epoch, ticket, false, now));
        ++owned.counters.lsp_refused;
        egress.lsp[level] = egress.pacing;
      } else {
        static_cast<void>(output->reservations.snp.complete(output->synchronization_epoch, ticket, false, now));
        ++owned.counters.snp_refused;
        if (is_complete(type)) egress.complete[level] = now +
            *jittered_interval(std::chrono::seconds{program.partial_seconds}, egress.random);
      }
    };
    SnpContents contents;
    contents.header.source = instance.configuration.local;
    contents.header.maximum_area_addresses = instance.configuration.maximum_areas;
    contents.source = configuration.mac;
    contents.destination = owned.destination;
    contents.maximum_pdu_octets = maximum_pdu;
    const std::array<std::uint16_t, 1U> topology{0U};
    if (owned.wire_instance || (owned.format == packet::isis::InstanceFormat::legacy_2009 && configuration.emit_instance))
      contents.instance = PduInstanceOption{owned.format, owned.wire_instance,
          owned.format == packet::isis::InstanceFormat::standard ? std::span<const std::uint16_t>(topology) :
              std::span<const std::uint16_t>{}};
    if (available() && !output->reservations.snp.pending() && now >= egress.complete[level]) {
      if (!egress.complete_started[level]) {
        output->reservations.snp.request_complete();
        egress.complete_started[level] = true;
      }
      contents.header.type = level ? packet::isis::PduType::csnp_l2 : packet::isis::PduType::csnp_l1;
      const auto prepared = output->reservations.snp.prepare(SnpEmission::complete,
          contents, false, output_, scratch_, now);
      if (prepared.status == SnpExchangeStatus::encoded) publish(prepared.ticket, contents.header.type);
      else if (prepared.status == SnpExchangeStatus::idle) {
        egress.complete_started[level] = false;
        egress.complete[level] = program.complete_seconds ? now +
            *jittered_interval(std::chrono::seconds{program.complete_seconds}, egress.random) : RuntimeClock::time_point::max();
      } else instance.status = UpdateStatus::invalid_configuration;
    }
    if (instance.status != UpdateStatus::applied) return RuntimeClock::time_point::max();
    if (available() && !output->reservations.snp.pending() && now >= egress.partial[level]) {
      contents.header.type = level ? packet::isis::PduType::psnp_l2 : packet::isis::PduType::psnp_l1;
      egress.partial[level] = now + *jittered_interval(std::chrono::seconds{program.partial_seconds}, egress.random);
      for (unsigned choice{}; choice < 2U; ++choice) {
        const bool transient = egress.transient_first[level] != (choice != 0U);
        const auto prepared = output->reservations.snp.prepare(transient ? SnpEmission::transient_acknowledgement :
            SnpEmission::partial, contents, false, output_, scratch_, now);
        if (prepared.status == SnpExchangeStatus::encoded) {
          publish(prepared.ticket, contents.header.type);
          egress.transient_first[level] = !transient;
          break;
        }
        if (prepared.status != SnpExchangeStatus::idle) { instance.status = UpdateStatus::invalid_configuration; break; }
      }
    }
    if (instance.status != UpdateStatus::applied) return RuntimeClock::time_point::max();
    if (available() && !output->reservations.lsp.pending() && now >= egress.lsp[level] && program.pacing_burst) {
      if (!egress.credits) egress.lsp[level] = egress.pacing;
      else {
        const auto &database = instance.process.level(level)->database();
        const auto count = database.database().size();
        if (!egress.remaining[level]) {
          egress.remaining[level] = count;
          egress.earliest[level] = RuntimeClock::time_point::max();
        }
        auto scans = std::min(egress.remaining[level], device_catalog::isis_work_budget_packets);
        while (count && scans--) {
          const auto stored = database.database().at(egress.scan[level] % count, now);
          egress.scan[level] = (egress.scan[level] % count + 1U) % count;
          --egress.remaining[level];
          if (!stored) continue;
          const auto flags = database.flags(stored->header.id, owned.update_slot);
          if (!flags || !flags->srm) continue;
          const auto retry = std::find_if(egress.retries.begin(), egress.retries.end(), [&](const auto &entry) {
            return entry.level == level && entry.header.id == stored->header.id &&
                entry.header.sequence == stored->header.sequence && entry.header.checksum == stored->header.checksum &&
                (entry.header.remaining_seconds == 0U) == (stored->header.remaining_seconds == 0U);
          });
          if (retry != egress.retries.end() && now < retry->at) {
            egress.earliest[level] = std::min(egress.earliest[level], retry->at);
            continue;
          }
          const auto prepared = output->reservations.lsp.prepare(stored->header.id, configuration.mac,
              owned.destination, maximum_pdu, program.transit_seconds, output_, scratch_, now);
          if (prepared.status == LspEmissionStatus::encoded) {
            --egress.credits;
            publish(prepared.ticket, level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1);
            break;
          }
          if (prepared.status == LspEmissionStatus::too_large) ++owned.counters.lsp_too_large;
          else if (prepared.status == LspEmissionStatus::purge_required) {
            ++owned.counters.purge_pending;
            owned.counters.last_update = UpdateStatus::level_refused;
          } else { instance.status = UpdateStatus::capacity; break; }
        }
        egress.lsp[level] = egress.remaining[level] ? now : egress.earliest[level];
      }
    }
    if (available()) {
      if (!output->reservations.snp.pending()) deadline = std::min({deadline, egress.complete[level], egress.partial[level]});
      if (!output->reservations.lsp.pending() && program.pacing_burst) deadline = std::min(deadline, egress.lsp[level]);
    }
  }
  egress.synchronize = false;
  return deadline;
}
} // namespace router::isis
