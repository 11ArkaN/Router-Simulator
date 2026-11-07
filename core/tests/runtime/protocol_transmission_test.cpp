// Delayed and duplicate receipts cannot finish a replacement reservation,
// including operational cancellation inside an unchanged circuit epoch.

#include "router/protocol_transmission.hpp"

#include <stdexcept>

void protocol_transmission_tests() {
  using router::protocol::TransmissionWindow;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("Protocol transmission receipt identity invariant failed");
  };
  TransmissionWindow window(7U);
  const auto first = window.begin();
  require(first && !window.begin() && window.pending());
  window.cancel();
  const auto replacement = window.begin();
  require(replacement && *replacement > *first && !window.complete(7U, *first) && window.pending());
  require(!window.complete(6U, *replacement) && !window.complete(7U, 0U) &&
      window.complete(7U, *replacement) && !window.complete(7U, *replacement));
  const auto previous_epoch = window.begin();
  require(previous_epoch && !window.replace(7U) && !window.replace(0U) && window.replace(8U));
  const auto current = window.begin();
  require(current && !window.complete(7U, *previous_epoch) && window.complete(8U, *current));
  TransmissionWindow exhausted(8U, std::numeric_limits<std::uint64_t>::max());
  require(!exhausted.begin() && !exhausted.pending());
  bool rejected{};
  try { TransmissionWindow invalid(0U); }
  catch (const std::invalid_argument &) { rejected = true; }
  require(rejected);
  TransmissionWindow original(19U);
  const auto outstanding = original.begin();
  const auto saved = original.checkpoint();
  TransmissionWindow resumed(19U);
  require(outstanding && resumed.restore(saved) && resumed.pending());
  require(!resumed.complete(18U, *outstanding) && resumed.complete(19U, *outstanding) &&
      !resumed.complete(19U, *outstanding));
  require(resumed.begin() == saved.next_ticket);
  const auto unchanged = resumed.checkpoint();
  const auto refused = [&](auto invalid) {
    require(!resumed.restore(invalid) && resumed.checkpoint().pending == unchanged.pending &&
        resumed.checkpoint().next_ticket == unchanged.next_ticket);
  };
  auto invalid = saved;
  invalid.version = 2U; refused(invalid);
  invalid = saved; invalid.epoch = 18U; refused(invalid);
  invalid = saved; invalid.next_ticket = 0U; refused(invalid);
  invalid = saved; invalid.pending = invalid.next_ticket; refused(invalid);
  auto exhausted_saved = exhausted.checkpoint();
  TransmissionWindow exhausted_copy(8U);
  require(exhausted_copy.restore(exhausted_saved) && !exhausted_copy.begin());
  exhausted_saved.pending = exhausted_saved.next_ticket - 1U;
  require(exhausted_copy.restore(exhausted_saved) &&
      exhausted_copy.complete(8U, exhausted_saved.pending) && !exhausted_copy.begin());
}
