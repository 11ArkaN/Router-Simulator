// Dynamic inventory tests cover every chassis class, compatibility rejection,
// physical mismatch and generation changes after hardware replacement.

#include "router/router_hardware_inventory.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char *message) {
  // The shared native runner reports the first failed inventory invariant.
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void router_hardware_inventory_tests() {
  using namespace router::lab;
  const auto *sr1 = router::device_catalog::find_profile("7750-sr-1");
  const auto *sr7 = router::device_catalog::find_profile("7750-sr-7");
  const auto *sr12 = router::device_catalog::find_profile("7750-sr-12");
  require(sr1 && sr7 && sr12, "generated chassis profiles are missing");

  RouterHardwareInventory fixed{{0, 1}, *sr1};
  // SR-1 default integrated MDAs expose 6 plus 12 Ethernet ports. Users cannot
  // remove the fixed card through modular inventory operations.
  require(fixed.present_ports() == 18 && fixed.handle("1/1/1") &&
              fixed.handle("1/2/12"),
          "fixed SR-1 inventory did not derive catalog ports");
  require(fixed.set_card(1, {}, {}) == HardwareEditResult::fixed_hardware,
          "fixed SR-1 accepted card removal");

  RouterHardwareInventory modular{{1, 1}, *sr7};
  require(modular.present_ports() == 0,
          "modular SR-7 created ports without hardware");

  RouterHardwareInventory retained{{3, 1}, *sr7};
  require(retained.configure_port("1/1/1", true, 1600, 100'000) ==
              HardwareEditResult::applied &&
              !retained.handle("1/1/1") &&
              retained.set_card(1, "iom4-e", "iom4-e") ==
                  HardwareEditResult::applied &&
              retained.set_mda(1, 1, "me10-10gb-sfp+", "me10-10gb-sfp+") ==
                  HardwareEditResult::applied &&
              retained.find("1/1/1")->present &&
              !retained.find("1/1/1")->configuration_compatible &&
              !retained.handle("1/1/1"),
          "absent port intent was lost or raised carrier on incompatible MDA");
  require(retained.set_mda(1, 1, "me1-100gb-cfp2", "me1-100gb-cfp2") ==
              HardwareEditResult::applied &&
              retained.handle("1/1/1") &&
              retained.find("1/1/1")->mtu == 1600,
          "compatible replacement MDA did not reactivate retained port intent");
  require(modular.set_card(1, "iom4-e", "iom4-e") ==
              HardwareEditResult::applied,
          "SR-7 rejected compatible card inventory");
  require(modular.set_mda(1, 1, "me10-10gb-sfp+", "me1-100gb-cfp2") ==
              HardwareEditResult::applied &&
              modular.present_ports() == 0,
          "MDA mismatch exposed operational ports");
  require(modular.set_mda(1, 1, "me10-10gb-sfp+", "me10-10gb-sfp+") ==
              HardwareEditResult::applied &&
              modular.present_ports() == 10,
          "matching MDA did not expose its ten ports");
  {
    // Runtime messages are temporary strings. Destroy both of them before a
    // later inventory rebuild to prove MDA slots retain catalog identities,
    // not borrowed parser bytes that merely happened to survive one call.
    std::string provisioned{"me10-10gb-sfp+"};
    std::string equipped{"me10-10gb-sfp+"};
    require(modular.set_mda(1, 1, provisioned, equipped) ==
                HardwareEditResult::applied,
            "temporary MDA identity was rejected");
    provisioned.assign(256, 'x');
    equipped.assign(256, 'y');
  }
  require(modular.set_card_admin(1, false) == HardwareEditResult::applied &&
              modular.present_ports() == 10 && modular.find("1/1/10") &&
              modular.configure_port("1/1/10", true, 9212, 10'000) ==
                  HardwareEditResult::applied,
          "inventory retained caller-owned MDA text after command return");
  const auto old_port = modular.handle("1/1/1");
  require(old_port.has_value(), "live modular port has no handle");
  require(modular.set_mda(1, 1, {}, {}) == HardwareEditResult::applied &&
              !modular.handle("1/1/1"),
          "MDA removal retained a live port");
  require(modular.set_mda(1, 1, "me10-10gb-sfp+", "me10-10gb-sfp+") ==
              HardwareEditResult::applied,
          "MDA reinsertion was rejected");
  require(!modular.find("1/1/1")->hierarchy_enabled &&
              modular.set_mda_admin(1, 1, true) ==
                  HardwareEditResult::applied &&
              !modular.find("1/1/1")->hierarchy_enabled &&
              modular.set_card_admin(1, true) ==
                  HardwareEditResult::applied &&
              modular.find("1/1/1")->hierarchy_enabled,
          "card and MDA administrative hierarchy did not gate the port");
  require(modular.handle("1/1/1")->generation != old_port->generation,
          "MDA reinsertion reused a stale port generation");
  require(modular.configure_port("1/1/1", true, 1600, 10'000) ==
              HardwareEditResult::applied &&
              modular.set_link_signal(*modular.handle("1/1/1"), true),
          "hardware checkpoint fixture rejected port state");
  auto hardware_image = std::make_unique<RouterHardwareCheckpoint>();
  modular.checkpoint(*hardware_image);
  auto hardware_copy = std::make_unique<RouterHardwareInventory>();
  require(hardware_copy->restore(*hardware_image) &&
              hardware_copy->handle("1/1/1") == modular.handle("1/1/1") &&
              hardware_copy->find("1/1/1")->link_signal &&
              hardware_copy->find("1/1/1")->hierarchy_enabled &&
              hardware_copy->find("1/1/1")->mtu == 1600,
          "hardware checkpoint lost inventory, generation or port state");
  auto invalid_hardware =
      std::make_unique<RouterHardwareCheckpoint>(*hardware_image);
  invalid_hardware->ports[0].generation = 0;
  require(!hardware_copy->restore(*invalid_hardware) &&
              hardware_copy->find("1/1/1")->link_signal,
          "invalid hardware checkpoint partially replaced live inventory");

  RouterHardwareInventory large{{2, 1}, *sr12};
  require(large.set_card(10, "iom5-e", "iom5-e") ==
              HardwareEditResult::applied &&
              large.set_mda(10, 2, "me16-25gb-sfp28+2-100gb-qsfp28",
                            "me16-25gb-sfp28+2-100gb-qsfp28") ==
                  HardwareEditResult::applied &&
              large.handle("10/2/18"),
          "SR-12 upper slot inventory did not map stable port coordinates");
  require(large.set_card(10, "imm48-1gb-sfp-c", "imm48-1gb-sfp-c") ==
              HardwareEditResult::incompatible_children,
          "parent card change silently discarded incompatible MDA intent");

  // Generated ranges are executable compatibility data, not documentation.
  // Exercise every profile-card-MDA relation so a generator indexing mistake
  // cannot leave an entry visible in the UI but unusable by the runtime.
  std::array<bool, router::device_catalog::mdas.size()> observed_mdas{};
  for (const auto &profile : router::device_catalog::profiles) {
    for (std::size_t card_offset = 0; card_offset < profile.card_count;
         ++card_offset) {
      const auto &card = router::device_catalog::cards[
          profile.first_card + card_offset];
      require(card.device_profile == profile.id &&
                  router::device_catalog::find_card(profile, card.type) == &card,
              "generated card range escaped its chassis profile");
      for (std::size_t mda_offset = 0; mda_offset < card.mda_count;
           ++mda_offset) {
        const auto mda_index = router::device_catalog::card_mdas[
            card.first_mda + mda_offset];
        require(mda_index < router::device_catalog::mdas.size(),
                "generated card references an invalid MDA index");
        observed_mdas[mda_index] = true;
        const auto &mda = router::device_catalog::mdas[mda_index];
        require(router::device_catalog::card_supports_mda(card, mda.type),
                "generated card rejected its own MDA relation");

        if (profile.fixed)
          continue;
        RouterHardwareInventory catalog_entry{{4, 1}, profile};
        require(catalog_entry.set_card(1, card.type, card.type) ==
                    HardwareEditResult::applied &&
                    catalog_entry.set_mda(1, 1, mda.type, mda.type) ==
                        HardwareEditResult::applied &&
                    catalog_entry.present_ports() ==
                        (mda.ethernet ? mda.port_count : 0U),
                "compatible generated hardware entry was not instantiable");
      }

      if (!profile.fixed) {
        const auto incompatible = std::find_if(
            router::device_catalog::mdas.begin(),
            router::device_catalog::mdas.end(), [&](const auto &mda) {
              return !router::device_catalog::card_supports_mda(card, mda.type);
            });
        if (incompatible != router::device_catalog::mdas.end()) {
          RouterHardwareInventory rejected{{5, 1}, profile};
          require(rejected.set_card(1, card.type, card.type) ==
                      HardwareEditResult::applied &&
                      rejected.set_mda(1, 1, incompatible->type,
                                       incompatible->type) ==
                          HardwareEditResult::unsupported_type,
                  "card accepted an MDA outside its generated compatibility set");
        }
      }
    }
  }
  require(std::all_of(observed_mdas.begin(), observed_mdas.end(),
                      [](bool value) { return value; }),
          "generated MDA catalog contains an unreachable entry");
}
