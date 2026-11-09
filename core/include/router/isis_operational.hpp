// The IS-IS pthread prepares immutable operational values for cold queries.
// Each row owns accepted non-secret neighbor attributes. No protocol pointer,
// borrowed frame, authentication material or host clock epoch escapes.
#pragma once
#include "router/isis_control_worker.hpp"
namespace router::isis {
enum class OperationalAdjacencyState : std::uint8_t {
  initializing = 1U, up = 2U, failed = 3U, down = 4U
};
struct AdjacencyOperational {
  CircuitIdentity circuit;
  packet::isis::SystemId system{};
  packet::Mac snpa{};
  Levels usage{Levels::none};
  OperationalAdjacencyState state{OperationalAdjacencyState::initializing};
  std::chrono::nanoseconds expires_in{};
  std::vector<std::uint8_t> attributes;
};
struct AdjacencyQuery {
  std::uint32_t version{1U};
  lab::DeviceHandle device;
  std::uint8_t instance{};
  std::size_t maximum_rows{}, maximum_attribute_octets{};
  std::vector<AdjacencyOperational> rows;
};
}
