// RFC 7383 fragment-set validation and bounded reassembly. Authenticated
// fragment bytes are retained in arrival order inside one reserved arena, then
// copied to protocol order only after every fragment is present.

#include "router/ikev2_fragmentation.hpp"

#include <algorithm>

namespace router::ikev2 {

FragmentAssembler::FragmentAssembler(
    std::size_t maximum_fragments, std::size_t maximum_message_octets,
    std::chrono::milliseconds timeout)
    : slots_(maximum_fragments), storage_(maximum_message_octets),
      timeout_(timeout) {}

void FragmentAssembler::clear() noexcept {
  // Erasing authenticated plaintext prevents a later exchange from observing
  // bytes belonging to an expired or rejected fragment set.
  std::fill(storage_.begin(), storage_.begin() +
                                   static_cast<std::ptrdiff_t>(stored_octets_),
            std::uint8_t{0});
  for (auto &slot : slots_)
    slot = {};
  key_ = {};
  deadline_ = {};
  stored_octets_ = 0U;
  received_ = 0U;
  total_ = 0U;
  first_payload_ = 0U;
  active_ = false;
}

FragmentAcceptResult FragmentAssembler::accept(
    const FragmentSetKey &key, std::uint16_t number, std::uint16_t total,
    std::uint8_t next_payload,
    std::span<const std::uint8_t> encrypted_plaintext, Clock::time_point now,
    std::span<std::uint8_t> assembled_output) noexcept {
  if (number == 0U || total == 0U || number > total ||
      total > slots_.size() || encrypted_plaintext.empty() ||
      timeout_ <= std::chrono::milliseconds::zero() ||
      (number == 1U ? next_payload == 0U : next_payload != 0U))
    return {.status = FragmentAcceptStatus::invalid};

  if (active_ && now >= deadline_) {
    clear();
    return {.status = FragmentAcceptStatus::expired};
  }
  if (!active_) {
    if (now > Clock::time_point::max() - timeout_)
      return {.status = FragmentAcceptStatus::invalid};
    active_ = true;
    key_ = key;
    total_ = total;
    deadline_ = now + timeout_;
  } else if (!(key == key_) || total != total_) {
    return {.status = FragmentAcceptStatus::conflicting_set};
  }

  const auto slot_index = static_cast<std::size_t>(number - 1U);
  auto &slot = slots_[slot_index];
  bool already_present{};
  if (slot.present) {
    const auto stored =
        std::span<const std::uint8_t>{storage_}.subspan(slot.offset, slot.length);
    if (stored.size() != encrypted_plaintext.size() ||
        !std::equal(stored.begin(), stored.end(), encrypted_plaintext.begin()) ||
        (number == 1U && first_payload_ != next_payload)) {
      clear();
      return {.status = FragmentAcceptStatus::conflicting_duplicate};
    }
    already_present = true;
    if (received_ != total_)
      return {.status = FragmentAcceptStatus::duplicate};
  }
  if (!already_present) {
    if (encrypted_plaintext.size() > storage_.size() - stored_octets_) {
      clear();
      return {.status = FragmentAcceptStatus::resource_exhausted};
    }
    slot = {.offset = stored_octets_,
            .length = encrypted_plaintext.size(),
            .present = true};
    std::copy(encrypted_plaintext.begin(), encrypted_plaintext.end(),
              storage_.begin() + static_cast<std::ptrdiff_t>(stored_octets_));
    stored_octets_ += encrypted_plaintext.size();
    ++received_;
    if (number == 1U)
      first_payload_ = next_payload;
  }
  if (received_ != total_)
    return {.status = FragmentAcceptStatus::stored};
  if (assembled_output.size() < stored_octets_)
    return {.status = FragmentAcceptStatus::output_too_small,
            .assembled_octets = stored_octets_,
            .first_payload = first_payload_};

  std::size_t output_offset{};
  for (std::size_t index = 0U; index < total_; ++index) {
    const auto &ordered = slots_[index];
    if (!ordered.present) {
      clear();
      return {.status = FragmentAcceptStatus::invalid};
    }
    std::copy_n(storage_.begin() + static_cast<std::ptrdiff_t>(ordered.offset),
                ordered.length,
                assembled_output.begin() +
                    static_cast<std::ptrdiff_t>(output_offset));
    output_offset += ordered.length;
  }
  const auto completed_payload = first_payload_;
  const auto completed_octets = stored_octets_;
  clear();
  return {.status = FragmentAcceptStatus::complete,
          .assembled_octets = completed_octets,
          .first_payload = completed_payload};
}

} // namespace router::ikev2
