// Catalog-driven router inventory implementation. No chassis or MDA name is
// embedded in control flow. All compatibility comes from generated records.

#include "router/router_hardware_inventory.hpp"

#include <algorithm>
#include <charconv>
#include <memory>
#include <new>

namespace router::lab {
namespace {

std::optional<std::array<std::uint16_t, 3>>
parse_port_id(std::string_view text) noexcept {
  // from_chars is locale-independent and rejects signs and whitespace. Exact
  // slash placement keeps malformed identifiers out of ordinal arithmetic.
  std::array<std::uint16_t, 3> values{};
  for (std::size_t field = 0; field < values.size(); ++field) {
    const auto slash = text.find('/');
    const auto token = slash == std::string_view::npos ? text : text.substr(0, slash);
    unsigned value{};
    const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value);
    if (token.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != token.data() + token.size() || !value || value > 0xffffU)
      return std::nullopt;
    values[field] = static_cast<std::uint16_t>(value);
    if (field + 1U == values.size()) {
      if (slash != std::string_view::npos)
        return std::nullopt;
    } else {
      if (slash == std::string_view::npos)
        return std::nullopt;
      text.remove_prefix(slash + 1U);
    }
  }
  return values;
}

bool supports_speed(const device_catalog::MdaProfile &mda,
                    std::uint16_t port_number,
                    std::uint32_t speed_mbps) noexcept {
  std::uint16_t first_port = 1;
  for (std::size_t group_index = 0; group_index < mda.group_count;
       ++group_index) {
    const auto &group = mda.groups[group_index];
    if (port_number >= first_port &&
        port_number < first_port + group.count)
      return std::find(group.speeds_mbps.begin(), group.speeds_mbps.end(),
                       speed_mbps) != group.speeds_mbps.end();
    first_port = static_cast<std::uint16_t>(first_port + group.count);
  }
  return false;
}

} // namespace

RouterHardwareInventory::RouterHardwareInventory(
    DeviceHandle device,
    const device_catalog::DeviceProfile &profile) noexcept
    : device_(device), profile_(&profile) {
  // Fixed systems publish their integrated card and catalog default MDAs at
  // construction. Modular chassis remain empty until explicit physical edits.
  if (profile.fixed) {
    auto &card = cards_[0];
    card.provisioned = profile.default_card;
    card.equipped = profile.default_card;
    card.admin_enabled = true;
    for (std::size_t index = 0; index < profile.default_mdas.size(); ++index) {
      if (profile.default_mdas[index].empty())
        continue;
      card.mdas[index].provisioned = profile.default_mdas[index];
      card.mdas[index].equipped = profile.default_mdas[index];
      card.mdas[index].admin_enabled = true;
    }
  }
  rebuild_ports();
}

const device_catalog::CardProfile *RouterHardwareInventory::supported_card(
    std::string_view type) const noexcept {
  // An empty value is absence, not a catalog lookup. The profile pointer is
  // installed by the non-default constructor before any public edit is valid.
  return profile_ && !type.empty() ? device_catalog::find_card(*profile_, type)
                                   : nullptr;
}

HardwareEditResult RouterHardwareInventory::set_card(
    std::uint16_t slot, std::string_view provisioned,
    std::string_view equipped) noexcept {
  const auto slot_count = profile_ ? (profile_->fixed ? 1U : profile_->card_slots) : 0U;
  if (!slot || slot > slot_count)
    return HardwareEditResult::invalid_slot;
  if (profile_->fixed)
    return HardwareEditResult::fixed_hardware;
  const auto *provisioned_card = provisioned.empty() ? nullptr : supported_card(provisioned);
  const auto *equipped_card = equipped.empty() ? nullptr : supported_card(equipped);
  if ((!provisioned.empty() && !provisioned_card) ||
      (!equipped.empty() && !equipped_card))
    return HardwareEditResult::unsupported_type;

  auto &target = cards_[slot - 1U];
  // SR OS rejects a parent type change that would leave incompatible child MDA
  // provisioning. It does not silently delete configuration to make it fit.
  if (provisioned_card) {
    for (const auto &mda : target.mdas) {
      if (!mda.provisioned.empty() &&
          !device_catalog::card_supports_mda(*provisioned_card,
                                             mda.provisioned))
        return HardwareEditResult::incompatible_children;
    }
  } else if (std::any_of(target.mdas.begin(), target.mdas.end(),
                         [](const auto &mda) {
                           return !mda.provisioned.empty();
                         })) {
    return HardwareEditResult::incompatible_children;
  }

  if (target.equipped != equipped) {
    // Replacing a parent removes every child port even when the next card uses
    // the same MDA and physical port text. Live handles must cross a generation.
    for (std::uint16_t mda = 1;
         mda <= device_catalog::maximum_mda_slots_per_card; ++mda)
      invalidate_mda_ports(slot, mda);
  }
  target.provisioned = provisioned_card ? provisioned_card->type : std::string_view{};
  target.equipped = equipped_card ? equipped_card->type : std::string_view{};
  if (!provisioned_card)
    target.admin_enabled = false;
  rebuild_ports();
  return HardwareEditResult::applied;
}

HardwareEditResult RouterHardwareInventory::set_mda(
    std::uint16_t card_slot, std::uint16_t mda_slot,
    std::string_view provisioned, std::string_view equipped) noexcept {
  const auto card_count = profile_ ? (profile_->fixed ? 1U : profile_->card_slots) : 0U;
  if (!card_slot || card_slot > card_count || !mda_slot ||
      mda_slot > device_catalog::maximum_mda_slots_per_card)
    return HardwareEditResult::invalid_slot;
  if (profile_->fixed)
    return HardwareEditResult::fixed_hardware;

  auto &card = cards_[card_slot - 1U];
  const auto *card_profile = supported_card(card.provisioned);
  if (!card_profile || mda_slot > card_profile->mda_slots)
    return HardwareEditResult::invalid_slot;
  const auto *provisioned_mda =
      provisioned.empty() ? nullptr : device_catalog::find_mda(provisioned);
  const auto *equipped_mda =
      equipped.empty() ? nullptr : device_catalog::find_mda(equipped);
  if ((!provisioned.empty() &&
       (!provisioned_mda ||
        !device_catalog::card_supports_mda(*card_profile, provisioned))) ||
      (!equipped.empty() &&
       (!equipped_mda ||
        !device_catalog::card_supports_mda(*card_profile, equipped))))
    return HardwareEditResult::unsupported_type;

  auto &target = card.mdas[mda_slot - 1U];
  if (target.equipped != equipped)
    invalidate_mda_ports(card_slot, mda_slot);
  // MdaSlot deliberately uses string_view because release catalog identities
  // are process-lifetime immutable. Never retain the caller's command buffer:
  // the netstring decoder reuses it immediately and would turn hardware type
  // state into unrelated bytes from the next CLI or runtime operation.
  target.provisioned = provisioned_mda ? provisioned_mda->type
                                       : std::string_view{};
  target.equipped = equipped_mda ? equipped_mda->type : std::string_view{};
  if (provisioned.empty())
    target.admin_enabled = false;
  rebuild_ports();
  return HardwareEditResult::applied;
}

HardwareEditResult RouterHardwareInventory::set_card_admin(
    std::uint16_t slot, bool enabled) noexcept {
  const auto slots = profile_ ? (profile_->fixed ? 1U : profile_->card_slots) : 0U;
  if (!slot || slot > slots)
    return HardwareEditResult::invalid_slot;
  auto &card = cards_[slot - 1U];
  if (profile_->fixed)
    return enabled ? HardwareEditResult::applied
                   : HardwareEditResult::fixed_hardware;
  if (enabled && card.provisioned.empty())
    return HardwareEditResult::invalid_slot;
  card.admin_enabled = enabled;
  rebuild_ports();
  return HardwareEditResult::applied;
}

HardwareEditResult RouterHardwareInventory::set_mda_admin(
    std::uint16_t card_slot, std::uint16_t mda_slot, bool enabled) noexcept {
  const auto cards = profile_ ? (profile_->fixed ? 1U : profile_->card_slots) : 0U;
  if (!card_slot || card_slot > cards || !mda_slot ||
      mda_slot > device_catalog::maximum_mda_slots_per_card)
    return HardwareEditResult::invalid_slot;
  auto &mda = cards_[card_slot - 1U].mdas[mda_slot - 1U];
  if (profile_->fixed)
    return enabled ? HardwareEditResult::applied
                   : HardwareEditResult::fixed_hardware;
  if (enabled && mda.provisioned.empty())
    return HardwareEditResult::invalid_slot;
  mda.admin_enabled = enabled;
  rebuild_ports();
  return HardwareEditResult::applied;
}

std::optional<std::size_t> RouterHardwareInventory::ordinal(
    std::uint16_t card, std::uint16_t mda, std::uint16_t port) noexcept {
  if (!card || card > device_catalog::maximum_card_slots || !mda ||
      mda > device_catalog::maximum_mda_slots_per_card || !port ||
      port > device_catalog::maximum_ports_per_mda)
    return std::nullopt;
  // The fixed coordinate grid gives a physical identity the same ordinal even
  // after an MDA is removed or replaced by a type exposing fewer ports.
  return (card - 1U) * device_catalog::maximum_mda_slots_per_card *
             device_catalog::maximum_ports_per_mda +
         (mda - 1U) * device_catalog::maximum_ports_per_mda + (port - 1U);
}

RouterPortState *RouterHardwareInventory::find(std::string_view port_id) noexcept {
  // The out-of-band management connector is catalog-owned hardware, but it is
  // not located below an IOM or MDA and therefore has no numeric card path.
  // Its stable ordinal sits outside the physical coordinate grid.
  if (profile_ && profile_->management_port && port_id == "management")
    return &ports_[device_catalog::management_port_ordinal];
  const auto parsed = parse_port_id(port_id);
  if (!parsed)
    return nullptr;
  const auto index = ordinal((*parsed)[0], (*parsed)[1], (*parsed)[2]);
  return index && *index < ports_.size() ? &ports_[*index] : nullptr;
}

const RouterPortState *
RouterHardwareInventory::find(std::string_view port_id) const noexcept {
  // Parsing is identical for const projections and mutable control edits. A
  // textual port never gains a second interpretation in the UI read path.
  if (profile_ && profile_->management_port && port_id == "management")
    return &ports_[device_catalog::management_port_ordinal];
  const auto parsed = parse_port_id(port_id);
  if (!parsed)
    return nullptr;
  const auto index = ordinal((*parsed)[0], (*parsed)[1], (*parsed)[2]);
  return index && *index < ports_.size() ? &ports_[*index] : nullptr;
}

std::optional<PortHandle>
RouterHardwareInventory::handle(std::string_view port_id) const noexcept {
  const auto *port = find(port_id);
  if (!port || !port->present || !port->configuration_compatible)
    return std::nullopt;
  if (port_id == "management")
    return PortHandle{node(device_), device_catalog::management_port_ordinal,
                      port->generation};
  const auto index = ordinal(port->card_slot, port->mda_slot, port->port_number);
  if (!index)
    return std::nullopt;
  return PortHandle{node(device_), static_cast<std::uint16_t>(*index),
                    port->generation};
}

std::optional<std::uint16_t> RouterHardwareInventory::coordinate_ordinal(
    std::string_view port_id) const noexcept {
  if (profile_ && profile_->management_port && port_id == "management")
    return device_catalog::management_port_ordinal;
  const auto parsed = parse_port_id(port_id);
  const auto card_limit = profile_ ? (profile_->fixed ? 1U : profile_->card_slots) : 0U;
  if (!parsed || (*parsed)[0] > card_limit ||
      (*parsed)[1] > device_catalog::maximum_mda_slots_per_card)
    return std::nullopt;
  bool possible{};
  for (std::size_t card_offset = 0;
       profile_ && card_offset < profile_->card_count && !possible;
       ++card_offset) {
    const auto &card = device_catalog::cards[profile_->first_card + card_offset];
    if ((*parsed)[1] > card.mda_slots)
      continue;
    for (std::size_t mda_offset = 0;
         mda_offset < card.mda_count && !possible; ++mda_offset) {
      const auto &mda = device_catalog::mdas[
          device_catalog::card_mdas[card.first_mda + mda_offset]];
      possible = mda.ethernet && (*parsed)[2] <= mda.port_count;
    }
  }
  const auto index = possible ? ordinal((*parsed)[0], (*parsed)[1], (*parsed)[2])
                              : std::nullopt;
  return index && *index <= 0xffffU
             ? std::optional<std::uint16_t>{
                   static_cast<std::uint16_t>(*index)}
             : std::nullopt;
}

std::optional<packet::Mac>
RouterHardwareInventory::physical_mac(std::string_view port_id) const noexcept {
  const auto value = coordinate_ordinal(port_id);
  if (!value || !device_)
    return std::nullopt;
  // The emulator has no EEPROM OUI allocation. A locally administered unicast
  // address derived from the generation-bearing device and physical coordinate
  // is collision-free inside a live lab without using a vendor-owned prefix.
  return packet::Mac{0x02U,
                     static_cast<std::uint8_t>(device_.index),
                     static_cast<std::uint8_t>(device_.generation >> 8U),
                     static_cast<std::uint8_t>(device_.generation),
                     static_cast<std::uint8_t>(*value >> 8U),
                     static_cast<std::uint8_t>(*value)};
}

packet::Mac RouterHardwareInventory::chassis_base_mac() const noexcept {
  // The generation-bearing registry identity prevents reuse after deletion.
  // Final coordinate bytes are zero because this is chassis identity rather
  // than a physical port. U/L remains set so no vendor OUI is claimed.
  return packet::Mac{0x02U,
                     static_cast<std::uint8_t>(device_.index),
                     static_cast<std::uint8_t>(device_.generation >> 8U),
                     static_cast<std::uint8_t>(device_.generation), 0U, 0U};
}

bool RouterHardwareInventory::set_link_signal(PortHandle handle,
                                              bool present) noexcept {
  // Validate device identity, coordinate and hardware generation. A delayed
  // topology update cannot raise carrier on replacement equipment.
  if (handle.node != node(device_) || handle.ordinal >= ports_.size())
    return false;
  auto &port = ports_[handle.ordinal];
  if (!port.present || port.generation != handle.generation)
    return false;
  port.link_signal = present;
  return true;
}

RouterPortState *RouterHardwareInventory::at(std::uint16_t ordinal) noexcept {
  return ordinal < ports_.size() ? &ports_[ordinal] : nullptr;
}

const RouterPortState *
RouterHardwareInventory::at(std::uint16_t ordinal) const noexcept {
  // Ordinal access is reserved for compact runtime projections. UI and project
  // boundaries continue to validate canonical textual port IDs.
  return ordinal < ports_.size() ? &ports_[ordinal] : nullptr;
}

HardwareEditResult RouterHardwareInventory::configure_port(
    std::string_view port_id, bool admin_enabled, std::uint16_t mtu,
    std::uint32_t speed_mbps) noexcept {
  auto *port = find(port_id);
  if (port_id == "management") {
    if (!port)
      return HardwareEditResult::invalid_slot;
    // BOF limits this connector to these three Ethernet rates. Unlike an MDA
    // port, its capabilities do not depend on provisioned card equipment.
    const bool speed_supported =
        speed_mbps == 10U || speed_mbps == 100U || speed_mbps == 1000U;
    if (mtu < device_catalog::minimum_network_mtu ||
        mtu > device_catalog::maximum_network_mtu || !speed_supported)
      return HardwareEditResult::unsupported_type;
    port->admin_enabled = admin_enabled;
    port->mtu = mtu;
    port->speed_mbps = speed_mbps;
    port->configuration_compatible = true;
    return HardwareEditResult::applied;
  }
  const auto parsed = parse_port_id(port_id);
  if (!port || !parsed || !coordinate_ordinal(port_id))
    return HardwareEditResult::invalid_slot;
  if (mtu < device_catalog::minimum_network_mtu ||
      mtu > device_catalog::maximum_network_mtu || !speed_mbps)
    return HardwareEditResult::unsupported_type;

  bool speed_supported{};
  if (port->present) {
    const auto *mda = device_catalog::find_mda(
        cards_[(*parsed)[0] - 1U].mdas[(*parsed)[1] - 1U].equipped);
    speed_supported = mda && supports_speed(*mda, (*parsed)[2], speed_mbps);
  } else if (profile_) {
    // An absent coordinate is configurable only if at least one card and MDA
    // combination legal for this chassis could expose that numbered port at
    // the requested rate. This retains intent without accepting fantasy ports.
    for (std::size_t card_offset = 0;
         card_offset < profile_->card_count && !speed_supported; ++card_offset) {
      const auto &card = device_catalog::cards[profile_->first_card + card_offset];
      if ((*parsed)[1] > card.mda_slots)
        continue;
      for (std::size_t mda_offset = 0;
           mda_offset < card.mda_count && !speed_supported; ++mda_offset) {
        const auto &mda = device_catalog::mdas[
            device_catalog::card_mdas[card.first_mda + mda_offset]];
        speed_supported = supports_speed(mda, (*parsed)[2], speed_mbps);
      }
    }
  }
  if (!speed_supported)
    return HardwareEditResult::unsupported_type;
  port->admin_enabled = admin_enabled;
  port->mtu = mtu;
  port->speed_mbps = speed_mbps;
  port->card_slot = (*parsed)[0];
  port->mda_slot = (*parsed)[1];
  port->port_number = (*parsed)[2];
  port->configuration_compatible = true;
  return HardwareEditResult::applied;
}

void RouterHardwareInventory::set_presence(
    std::array<bool, device_catalog::maximum_ports_per_router> &next_presence,
    std::uint16_t card, std::uint16_t mda,
    const device_catalog::MdaProfile &profile) noexcept {
  std::uint16_t port_number = 1;
  for (std::size_t group_index = 0; group_index < profile.group_count;
       ++group_index) {
    const auto &group = profile.groups[group_index];
    // The highest supported rate is the initial selected rate. It is a
    // configuration value and can later be changed only to another group rate.
    const auto default_speed = *std::max_element(group.speeds_mbps.begin(),
                                                 group.speeds_mbps.end());
    for (std::uint16_t offset = 0; offset < group.count;
         ++offset, ++port_number) {
      const auto index = *ordinal(card, mda, port_number);
      next_presence[index] = true;
      auto &port = ports_[index];
      port.card_slot = card;
      port.mda_slot = mda;
      port.port_number = port_number;
      // A zero speed means no running intent has ever selected a rate. Mere
      // equipment absence is not permission to overwrite retained config.
      if (!port.speed_mbps)
        port.speed_mbps = default_speed;
      // A retained speed is evaluated against the exact equipment now
      // present. Incompatibility suppresses the live handle instead of
      // rewriting running configuration to the MDA default.
      port.configuration_compatible =
          supports_speed(profile, port_number, port.speed_mbps);
      port.hierarchy_enabled = cards_[card - 1U].admin_enabled &&
                               cards_[card - 1U].mdas[mda - 1U].admin_enabled;
    }
  }
}

void RouterHardwareInventory::invalidate_mda_ports(std::uint16_t card,
                                                   std::uint16_t mda) noexcept {
  for (std::uint16_t port_number = 1;
       port_number <= device_catalog::maximum_ports_per_mda; ++port_number) {
    const auto index = *ordinal(card, mda, port_number);
    auto &port = ports_[index];
    if (!port.present)
      continue;
    port.present = false;
    port.link_signal = false;
    ++port.generation;
    if (!port.generation)
      port.generation = 1;
  }
}

void RouterHardwareInventory::rebuild_ports() noexcept {
  std::array<bool, device_catalog::maximum_ports_per_router> next_presence{};
  if (profile_ && profile_->management_port) {
    // OOB management is integrated chassis hardware. Card removal cannot make
    // it disappear, so its presence and hierarchy are independent of IOMs.
    const auto index = device_catalog::management_port_ordinal;
    next_presence[index] = true;
    auto &management = ports_[index];
    management.hierarchy_enabled = true;
    management.configuration_compatible = true;
    if (!management.speed_mbps)
      management.speed_mbps = 100U;
  }
  const auto card_count = profile_ ? (profile_->fixed ? 1U : profile_->card_slots) : 0U;
  for (std::uint16_t card_index = 0; card_index < card_count; ++card_index) {
    const auto &card = cards_[card_index];
    const auto *card_profile = supported_card(card.provisioned);
    if (!card_profile || card.provisioned != card.equipped)
      continue;
    for (std::uint16_t mda_index = 0; mda_index < card_profile->mda_slots;
         ++mda_index) {
      const auto &mda = card.mdas[mda_index];
      if (mda.provisioned.empty() || mda.provisioned != mda.equipped ||
          !device_catalog::card_supports_mda(*card_profile, mda.provisioned))
        continue;
      const auto *mda_profile = device_catalog::find_mda(mda.provisioned);
      if (mda_profile && mda_profile->ethernet)
        set_presence(next_presence, card_index + 1U, mda_index + 1U,
                     *mda_profile);
    }
  }

  present_ports_ = 0;
  for (std::size_t index = 0; index < ports_.size(); ++index) {
    auto &port = ports_[index];
    if (port.present && !next_presence[index]) {
      // Hardware removal invalidates live PortHandle values but keeps running
      // configuration in the coordinate slot for a later compatible insert.
      ++port.generation;
      if (!port.generation)
        port.generation = 1;
      port.link_signal = false;
    }
    port.present = next_presence[index];
    if (!port.present)
      port.configuration_compatible = true;
    if (!port.present)
      port.hierarchy_enabled = false;
    if (port.present)
      ++present_ports_;
  }
}

void RouterHardwareInventory::checkpoint(RouterHardwareCheckpoint &state) const {
  // Caller owns the large fixed port image, normally in a supervisor heap
  // arena. Writing into it avoids a hidden return buffer on the 64 KiB Wasm
  // control stack.
  state.device = device_;
  state.profile_id = profile_ ? std::string{profile_->id} : std::string{};
  for (std::size_t card = 0; card < cards_.size(); ++card) {
    state.cards[card].provisioned = cards_[card].provisioned;
    state.cards[card].equipped = cards_[card].equipped;
    state.cards[card].admin_enabled = cards_[card].admin_enabled;
    for (std::size_t mda = 0; mda < cards_[card].mdas.size(); ++mda) {
      state.cards[card].mdas[mda].provisioned =
          cards_[card].mdas[mda].provisioned;
      state.cards[card].mdas[mda].equipped =
          cards_[card].mdas[mda].equipped;
      state.cards[card].mdas[mda].admin_enabled =
          cards_[card].mdas[mda].admin_enabled;
    }
  }
  state.ports = ports_;
}

bool RouterHardwareInventory::restore(const RouterHardwareCheckpoint &state) {
  const auto *profile = device_catalog::find_profile(state.profile_id);
  if (!state.device || !profile)
    return false;
  try {
    auto replacement =
        std::make_unique<RouterHardwareInventory>(state.device, *profile);
    const auto card_count = profile->fixed ? 1U : profile->card_slots;
    for (std::size_t card = 0; card < state.cards.size(); ++card) {
      const auto &source = state.cards[card];
      if (card >= card_count) {
        if (!source.provisioned.empty() || !source.equipped.empty() ||
            std::any_of(source.mdas.begin(), source.mdas.end(),
                        [](const auto &mda) {
                          return !mda.provisioned.empty() ||
                                 !mda.equipped.empty();
                        }))
          return false;
        continue;
      }
      if (profile->fixed) {
        const auto &expected = replacement->cards_[card];
        if (source.provisioned != expected.provisioned ||
            source.equipped != expected.equipped ||
            source.admin_enabled != expected.admin_enabled)
          return false;
        for (std::size_t mda = 0; mda < source.mdas.size(); ++mda)
          if (source.mdas[mda].provisioned != expected.mdas[mda].provisioned ||
              source.mdas[mda].equipped != expected.mdas[mda].equipped ||
              source.mdas[mda].admin_enabled !=
                  expected.mdas[mda].admin_enabled)
            return false;
        continue;
      }
      if (replacement->set_card(static_cast<std::uint16_t>(card + 1U),
                                source.provisioned, source.equipped) !=
          HardwareEditResult::applied)
        return false;
      if (replacement->set_card_admin(static_cast<std::uint16_t>(card + 1U),
                                      source.admin_enabled) !=
          HardwareEditResult::applied)
        return false;
      for (std::size_t mda = 0; mda < source.mdas.size(); ++mda) {
        const auto &mda_source = source.mdas[mda];
        if (mda_source.provisioned.empty() && mda_source.equipped.empty())
          continue;
        if (replacement->set_mda(static_cast<std::uint16_t>(card + 1U),
                                 static_cast<std::uint16_t>(mda + 1U),
                                 mda_source.provisioned,
                                 mda_source.equipped) !=
            HardwareEditResult::applied)
          return false;
        if (replacement->set_mda_admin(
                static_cast<std::uint16_t>(card + 1U),
                static_cast<std::uint16_t>(mda + 1U),
                mda_source.admin_enabled) != HardwareEditResult::applied)
          return false;
      }
    }

    std::size_t present{};
    for (std::size_t index = 0; index < state.ports.size(); ++index) {
      const auto &source = state.ports[index];
      const bool management =
          index == device_catalog::management_port_ordinal &&
          profile->management_port;
      if (management) {
        // The OOB connector has no card, MDA or port coordinate. Validate it
        // through the same public configuration contract used by live BOF
        // edits, then preserve carrier and generation from the checkpoint.
        if (!source.generation || !source.present ||
            source.card_slot != 0U || source.mda_slot != 0U ||
            source.port_number != 0U ||
            source.mtu < device_catalog::minimum_network_mtu ||
            source.mtu > device_catalog::maximum_network_mtu ||
            replacement->configure_port(
                "management", source.admin_enabled, source.mtu,
                source.speed_mbps) != HardwareEditResult::applied ||
            source.configuration_compatible !=
                replacement->ports_[index].configuration_compatible ||
            source.hierarchy_enabled !=
                replacement->ports_[index].hierarchy_enabled)
          return false;
        ++present;
        continue;
      }
      const auto expected_card = static_cast<std::uint16_t>(
          index / (device_catalog::maximum_mda_slots_per_card *
                   device_catalog::maximum_ports_per_mda) +
          1U);
      const auto expected_mda = static_cast<std::uint16_t>(
          index / device_catalog::maximum_ports_per_mda %
              device_catalog::maximum_mda_slots_per_card +
          1U);
      const auto expected_port = static_cast<std::uint16_t>(
          index % device_catalog::maximum_ports_per_mda + 1U);
      if (!source.generation || source.present != replacement->ports_[index].present ||
          (source.present &&
           (source.card_slot != expected_card || source.mda_slot != expected_mda ||
            source.port_number != expected_port)) ||
          (!source.present && source.link_signal) ||
          source.mtu < device_catalog::minimum_network_mtu ||
          source.mtu > device_catalog::maximum_network_mtu)
        return false;
      if (source.present) {
        const auto port_id = std::to_string(expected_card) + "/" +
                             std::to_string(expected_mda) + "/" +
                             std::to_string(expected_port);
        if (replacement->configure_port(port_id, source.admin_enabled,
                                        source.mtu, source.speed_mbps) !=
                HardwareEditResult::applied ||
            source.configuration_compatible !=
                replacement->ports_[index].configuration_compatible ||
            source.hierarchy_enabled !=
                replacement->ports_[index].hierarchy_enabled)
          return false;
        ++present;
      } else if (source.speed_mbps) {
        bool known_speed{};
        for (const auto &mda : device_catalog::mdas)
          for (std::size_t group = 0; group < mda.group_count; ++group)
            known_speed = known_speed ||
                          std::find(mda.groups[group].speeds_mbps.begin(),
                                    mda.groups[group].speeds_mbps.end(),
                                    source.speed_mbps) !=
                              mda.groups[group].speeds_mbps.end();
        if (!known_speed)
          return false;
      }
    }
    replacement->ports_ = state.ports;
    replacement->present_ports_ = present;
    *this = std::move(*replacement);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router::lab
