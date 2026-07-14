#pragma once

#include "router/bounded_queue.hpp"
#include "router/packet.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>

namespace router {

class LinkDirection final {
public:
  using Clock = std::chrono::steady_clock;
  struct Admission {
    // started is the first preamble bit on the medium. delivered is the end of
    // FCS plus propagation at the receiver. IFG affects only the next started.
    Clock::time_point started{};
    Clock::time_point delivered{};
  };

  struct Transmission {
    // A value object makes the pool handle and on-wire length impossible to
    // swap accidentally. It also leaves room for future per-frame link
    // metadata without growing the argument list.
    std::uint32_t packet_handle{};
    std::size_t captured_octets{};
  };

  // A direction owns its transmitter deadline. Full-duplex links use two
  // instances so traffic in one direction cannot serialize the other.
  LinkDirection(std::uint64_t bits_per_second,
                std::chrono::nanoseconds propagation) noexcept
      : bits_per_second_(bits_per_second), propagation_(propagation) {}

  void set_propagation(std::chrono::nanoseconds propagation) noexcept {
    // A configuration change affects frames admitted after this call. Existing
    // in-flight entries retain the delivery deadlines calculated at admission,
    // just as changing a circuit profile cannot move bits already in transit.
    propagation_ = propagation;
  }

  [[nodiscard]] std::optional<Admission>
  try_transmit(Transmission transmission,
               Clock::time_point now = Clock::now()) noexcept {
    if (in_flight_.full() || !bits_per_second_)
      return std::nullopt;
    const auto start = std::max(now, transmitter_available_);
    // Source: ieee.802_3.ethernet_frame_timing. captured_octets excludes FCS.
    // The medium serializes 8 octets of preamble/SFD, at least 64 octets from
    // destination MAC through FCS, and reserves a 12 octet inter-frame gap.
    const auto mac_octets =
        std::max<std::uint64_t>(transmission.captured_octets + 4U, 64U);
    const auto delivery_bits = (8U + mac_octets) * 8U;
    const auto spacing_bits = (8U + mac_octets + 12U) * 8U;
    const auto duration = nanoseconds_for(delivery_bits);
    transmitter_available_ = start + nanoseconds_for(spacing_bits);
    const Admission admission{.started = start,
                              .delivered = start + duration + propagation_};
    if (!in_flight_.try_push({transmission.packet_handle, admission.delivered}))
      return std::nullopt;
    return admission;
  }

  [[nodiscard]] bool
  pop_delivered(std::uint32_t &packet_handle,
                Clock::time_point now = Clock::now()) noexcept {
    // Only the front can be delivered because fixed propagation preserves FIFO
    // order within one direction. The opposite full-duplex direction has a
    // separate instance and can progress independently.
    InFlight front;
    if (!in_flight_.try_peek(front) || front.delivered > now)
      return false;
    static_cast<void>(in_flight_.try_pop(front));
    packet_handle = front.packet_handle;
    return true;
  }

  [[nodiscard]] std::optional<Clock::time_point>
  next_delivery() const noexcept {
    InFlight front;
    if (!in_flight_.try_peek(front))
      return std::nullopt;
    return front.delivered;
  }

  [[nodiscard]] std::size_t in_flight() const noexcept {
    return in_flight_.size();
  }

private:
  struct InFlight {
    // This is modeled medium state, not a global future-event record. The link
    // owner may inspect only its own ordered transmissions.
    std::uint32_t packet_handle{};
    Clock::time_point delivered{};
  };

  [[nodiscard]] std::chrono::nanoseconds
  nanoseconds_for(std::uint64_t bits) const noexcept {
    // Integer ceiling is conservative because steady_clock exposes whole
    // nanoseconds. At 10 Gb/s a 67.2 ns minimum interval becomes 68 ns.
    return std::chrono::nanoseconds(
        (bits * 1000000000ULL + bits_per_second_ - 1U) / bits_per_second_);
  }

  // steady_clock is monotonic and unaffected by wall clock correction. Wall
  // time is used only for capture metadata, never for runtime deadlines.
  std::uint64_t bits_per_second_;
  // propagation_ never contributes to transmitter_available_. Conflating them
  // would limit a 10 Gb/s link to roughly one frame per millisecond.
  std::chrono::nanoseconds propagation_;
  std::chrono::steady_clock::time_point transmitter_available_{};
  BoundedQueue<InFlight, 2048> in_flight_;
};

} // namespace router
