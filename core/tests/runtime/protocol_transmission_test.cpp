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
}
