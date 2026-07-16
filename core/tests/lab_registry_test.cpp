// Registry tests exercise capacity, stale handle rejection, point-to-point
// port ownership and confirmed device deletion cleanup.

#include "router/lab_registry.hpp"

#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char *message) {
  // This repository uses one compact native test executable. Throwing keeps
  // failures visible to its shared runner without introducing a test library.
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void lab_registry_tests() {
  using namespace router::lab;
  DeviceRegistry devices;
  HostRegistry hosts;
  TopologyRegistry topology;
  SessionRegistry sessions;

  const auto r1 = devices.create("r1", "7750-sr-1", "R1");
  const auto r2 = devices.create("r2", "7750-sr-12", "R2");
  const auto h1 = hosts.create("h1", "Host 1");
  require(r1 && r2 && h1, "registry rejected valid nodes");
  // Stable project identity and display/system name have different lifetimes.
  // Reusing r1 is invalid even when the proposed system name differs.
  require(!devices.create("r1", "7750-sr-7", "duplicate"),
          "registry accepted duplicate node identity");
  require(!devices.create("bad", "unsupported", "Bad"),
          "registry accepted unknown profile");

  for (std::size_t index = 0;
       index < router::device_catalog::maximum_sessions_per_router; ++index) {
    require(sessions.create(*r1, "s" + std::to_string(index)).has_value(),
            "session registry rejected capacity member");
  }
  // Per-device capacity is enforced before global capacity. Other routers keep
  // their reserved session allowance after this rejection.
  require(!sessions.create(*r1, "overflow"),
          "session registry accepted a fifth router session");

  const LinkEndpoint r1p1{node(*r1), "1/1/1"};
  const LinkEndpoint r2p1{node(*r2), "1/1/1"};
  const LinkEndpoint r1p2{node(*r1), "1/1/2"};
  const LinkEndpoint h1p{node(*h1), "eth0"};
  require(topology.create("r1-r2", r1p1, r2p1, 100).has_value(),
          "topology rejected router link");
  require(topology.create("r1-h1", r1p2, h1p, 100).has_value(),
          "topology rejected host link");
  require(!topology.create("duplicate-port", r1p1, h1p, 100),
          "topology accepted an already bound physical port");

  const auto stale = *r1;
  // Deletion order mirrors supervisor ownership: detach network references,
  // close terminal state, then invalidate the device identity itself.
  require(topology.detach(node(*r1)) == 2,
          "device detach did not remove every incident link");
  require(sessions.close_device(*r1) ==
              router::device_catalog::maximum_sessions_per_router,
          "device close did not remove every terminal session");
  require(devices.erase(*r1), "device registry rejected live handle");
  require(!devices.get(stale) && !devices.erase(stale),
          "stale device handle remained valid after deletion");
  const auto replacement = devices.create("r3", "7750-sr-7", "R3");
  // First-free allocation should reuse the compact slot, but generation must
  // prevent delayed commands addressed to r1 from reaching r3.
  require(replacement && replacement->index == stale.index &&
              replacement->generation != stale.generation,
          "reused slot did not advance its generation");

  const auto restored_link = topology.create(
      "r3-r2", {node(*replacement), "1/1/3"}, {node(*r2), "1/1/2"}, 250);
  const auto restored_session = sessions.create(*replacement, "console-1");
  require(restored_link && restored_session,
          "registry checkpoint fixture could not be created");
  const auto device_image = devices.checkpoint();
  const auto host_image = hosts.checkpoint();
  const auto topology_image = topology.checkpoint();
  const auto session_image = sessions.checkpoint();
  DeviceRegistry device_copy;
  HostRegistry host_copy;
  TopologyRegistry topology_copy;
  SessionRegistry session_copy;
  require(device_copy.restore(device_image) && host_copy.restore(host_image) &&
              topology_copy.restore(topology_image) &&
              session_copy.restore(session_image) &&
              device_copy.get(*replacement) && host_copy.get(*h1) &&
              topology_copy.get(*restored_link) &&
              session_copy.get(*restored_session),
          "registry checkpoint did not preserve stable handles and records");
  auto invalid_devices = device_image;
  invalid_devices.generations[replacement->index] = 0;
  require(!device_copy.restore(invalid_devices) &&
              device_copy.get(*replacement),
          "invalid registry checkpoint partially replaced live identities");
}
