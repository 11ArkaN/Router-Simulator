// Real route payloads and keyed installation results exercise the local
// protocol-to-RIB ownership contract. The test owns both serialized roles;
// the shared primitive separately tests two-thread memory publication.

#include "router/route_publication.hpp"

#include <memory>
#include <stdexcept>

void route_publication_tests() {
  using namespace router;
  using namespace router::routing;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("Route publication receipt invariant failed");
  };
  auto channel = std::make_unique<RoutePublicationChannel<1U>>();
  const auto edit = channel->try_acquire();
  require(edit.has_value());
  edit->generation->device = {3U, 7U};
  edit->generation->generation = 11U;
  edit->generation->ipv4_count = 1U;
  auto &route = edit->generation->ipv4[0U];
  route.configured = route.operational = true;
  route.network = 0xc0000200U;
  route.prefix_length = 24U;
  route.next_hop = 0xc6336402U;
  route.port_ordinal = 4U;
  route.metric = 20U;
  require(channel->publish(edit->handle) && !channel->publish(edit->handle));
  const auto input = channel->try_receive();
  require(input && input->generation->ipv4_count == 1U && input->generation->ipv4[0U].metric == 20U);
  const auto device = input->generation->device;
  require(!channel->complete(input->handle, {3U, 8U}, 11U, RouteInstallStatus::installed) &&
      !channel->complete(input->handle, device, 10U, RouteInstallStatus::installed) &&
      !channel->complete(input->handle, device, 11U, RouteInstallStatus::pending) &&
      !channel->try_completion() && !channel->try_acquire());
  require(channel->complete(input->handle, device, 11U, RouteInstallStatus::forwarding_failed) &&
      !channel->complete(input->handle, device, 11U, RouteInstallStatus::installed));
  require(!channel->try_acquire());
  const auto failed = channel->try_completion();
  require(failed && failed->device == device && failed->generation == 11U &&
      failed->status == RouteInstallStatus::forwarding_failed && !channel->try_completion());
  const auto replacement = channel->try_acquire();
  require(replacement && !replacement->generation->ipv4_count && !replacement->generation->generation);
  replacement->generation->device = device;
  replacement->generation->generation = 12U;
  require(channel->publish(replacement->handle));
  const auto withdrawal = channel->try_receive();
  require(withdrawal && !withdrawal->generation->ipv4_count &&
      !channel->complete(withdrawal->handle, device, 11U, RouteInstallStatus::installed) &&
      channel->complete(withdrawal->handle, device, 12U, RouteInstallStatus::installed));
  const auto installed = channel->try_completion();
  require(installed && installed->generation == 12U && installed->status == RouteInstallStatus::installed);
  const auto cancelled = channel->try_acquire();
  require(cancelled && channel->cancel(cancelled->handle) && !channel->cancel(cancelled->handle));
}
