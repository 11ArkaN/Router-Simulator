// IID fixtures distinguish legacy two-octet values from the RFC 8202 ITID format.
// Test-owned PDU buffers exercise cross-option consistency and placement rules.

#include "router/isis_instance_tlv.hpp"

#include <algorithm>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_instance_tlv_tests() {
  using namespace router::packet::isis;
  constexpr auto legacy = InstanceFormat::legacy_2009;
  constexpr auto standard = InstanceFormat::standard;
  const std::array<std::uint8_t, 4U> fixture{0x12U, 0x34U, 0U, 0U};
  const auto decoded = decode_instance_tlv({7U, fixture}, standard);
  require(decoded && decoded->instance == 0x1234U && decoded->topology_count() == 1U &&
            decoded->topology(0U) == 0U && !decoded->topology(1U) &&
            !decode_instance_tlv({7U, fixture}, legacy), "IS-IS instance format distinction failed");
  const auto old = decode_instance_tlv({7U, std::span(fixture).first(2U)}, legacy);
  require(old && old->instance == 0x1234U && old->topology_count() == 0U &&
            !decode_instance_tlv({7U, std::span(fixture).first(2U)}, standard),
          "IS-IS legacy instance fixture failed");
  std::array<std::uint8_t, 512U> options{};
  TlvWriter writer(options);
  const std::array<std::uint16_t, 1U> topology_zero{0U};
  require(encode_instance_tlv(writer, standard, 0x1234U, topology_zero) && writer.bytes()[0U] == 7U &&
            writer.bytes()[1U] == 4U && std::equal(fixture.begin(), fixture.end(), writer.bytes().begin() + 2U),
          "IS-IS instance wire encoding mismatch");
  const SystemId source{1U, 2U, 3U, 4U, 5U, 6U};
  std::array<std::uint8_t, 1024U> output{};
  auto wire = encode_hello(output, {PduType::point_to_point_hello, source, 30U, 3U}, writer.bytes());
  DecodeError envelope{};
  auto pdu = wire ? parse(*wire, envelope) : std::nullopt;
  InstanceError error{};
  auto selected = pdu ? select_instance(*pdu, standard, false, error) : std::nullopt;
  require(selected && selected->present && selected->instance == 0x1234U && selected->topology_zero,
          "IS-IS standard instance selection failed");
  require(encode_instance_tlv(writer, standard, 0x4321U, topology_zero), "IS-IS conflicting IID fixture failed");
  wire = encode_hello(output, {PduType::point_to_point_hello, source, 30U, 3U}, writer.bytes());
  pdu = parse(*wire, envelope);
  require(!select_instance(*pdu, standard, false, error) && error == InstanceError::conflicting_instance,
          "IS-IS accepted conflicting instance identifiers");
  TlvWriter mixed(options);
  const std::array<std::uint16_t, 1U> topology_two{2U};
  require(encode_instance_tlv(mixed, standard, 1U, topology_zero) &&
            encode_instance_tlv(mixed, standard, 1U, topology_two), "IS-IS mixed ITID fixture failed");
  wire = encode_hello(output, {PduType::point_to_point_hello, source, 30U, 3U}, mixed.bytes());
  pdu = parse(*wire, envelope);
  require(!select_instance(*pdu, standard, false, error) && error == InstanceError::mixed_zero_topology,
          "IS-IS accepted zero and nonzero ITIDs across options");
  TlvWriter zero(options);
  require(encode_instance_tlv(zero, standard, 0U, {}), "IS-IS zero IID fixture failed");
  wire = encode_hello(output, {PduType::point_to_point_hello, source, 30U, 3U}, zero.bytes());
  pdu = parse(*wire, envelope);
  require(select_instance(*pdu, standard, true, error).has_value() &&
            !select_instance(*pdu, standard, false, error) && error == InstanceError::zero_instance_placement,
          "IS-IS zero IID physical circuit rule failed");
  wire = encode_snp(output, {PduType::psnp_l1, source}, zero.bytes());
  pdu = parse(*wire, envelope);
  require(!select_instance(*pdu, standard, true, error) &&
            select_instance(*pdu, legacy, false, error).has_value(), "IS-IS zero IID SNP rule failed");
  TlvWriter old_duplicate(options);
  require(encode_instance_tlv(old_duplicate, legacy, 1U, {}) &&
            encode_instance_tlv(old_duplicate, legacy, 1U, {}), "IS-IS legacy duplicate fixture failed");
  wire = encode_hello(output, {PduType::point_to_point_hello, source, 30U, 3U}, old_duplicate.bytes());
  pdu = parse(*wire, envelope);
  require(!select_instance(*pdu, legacy, true, error) && error == InstanceError::duplicate,
          "IS-IS legacy duplicate IID was accepted");
  const std::array<std::uint16_t, 2U> topologies{1U, 2U};
  TlvWriter multiple(options);
  require(encode_instance_tlv(multiple, standard, 1U, topologies), "IS-IS multiple ITID fixture failed");
  wire = encode_snp(output, {PduType::psnp_l1, source}, multiple.bytes());
  pdu = parse(*wire, envelope);
  require(!select_instance(*pdu, standard, true, error) && error == InstanceError::topology_count,
          "IS-IS SNP selected several topology databases");
  wire = encode_snp(output, {PduType::psnp_l1, source}, {});
  pdu = parse(*wire, envelope);
  selected = select_instance(*pdu, standard, false, error);
  require(selected && !selected->present && selected->instance == 0U,
          "IS-IS absent IID did not select standard instance");
  const auto unchanged = options;
  TlvWriter invalid(options);
  require(!encode_instance_tlv(invalid, legacy, 1U, topology_zero) &&
            !encode_instance_tlv(invalid, standard, 0U, topology_zero) &&
            !encode_instance_tlv(invalid, standard, 1U, {}) && options == unchanged,
          "IS-IS invalid IID write mutated output");
}
