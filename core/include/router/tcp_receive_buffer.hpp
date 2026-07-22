// Allocation-free TCP receive and out-of-order repository for one TCB. The
// endpoint owner supplies byte and bitmap arenas, so capacity is a resource
// profile decision rather than a hidden protocol limit in this module.

#pragma once

#include "router/tcp_options.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace router::transport::tcp {

enum class ReceiveInsertStatus : std::uint8_t {
  accepted,
  duplicate,
  outside_window,
  invalid
};

struct ReceiveInsertResult {
  ReceiveInsertStatus status{ReceiveInsertStatus::invalid};
  std::uint32_t receive_next{};
  std::size_t newly_stored{};
};

struct ReceiveBufferCheckpoint {
  std::vector<std::uint8_t> storage;
  std::vector<std::uint8_t> received;
  std::uint32_t read_sequence{};
  std::uint32_t receive_next{};
  std::uint32_t head{};
  std::uint32_t recent_sequence{};
  bool recent_sequence_present{};
};

class ReceiveBuffer final {
public:
  // received_bitmap must provide ceil(storage.size()/8) bytes. Capacity must
  // be nonzero and at most 2^30, retaining unambiguous RFC serial arithmetic
  // under the maximum window-scale domain.
  ReceiveBuffer(std::span<std::uint8_t> storage,
                std::span<std::uint8_t> received_bitmap,
                std::uint32_t initial_receive_sequence) noexcept;

  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] ReceiveInsertResult
  accept(std::uint32_t sequence,
         std::span<const std::uint8_t> payload) noexcept;

  // read returns only the contiguous prefix already acknowledged through
  // receive_next. It never exposes bytes beyond a gap. Consumed capacity
  // immediately advances the advertised right edge without changing RCV.NXT.
  [[nodiscard]] std::size_t read(std::span<std::uint8_t> output) noexcept;

  [[nodiscard]] std::uint32_t receive_next() const noexcept {
    return receive_next_;
  }
  [[nodiscard]] std::uint32_t read_sequence() const noexcept {
    return read_sequence_;
  }
  [[nodiscard]] std::uint32_t advertised_window() const noexcept;
  [[nodiscard]] std::size_t readable_octets() const noexcept;

  // Writes SACK blocks for currently buffered data above RCV.NXT. The block
  // containing the most recently accepted segment is first as RFC 2018
  // requires; remaining blocks are ordered from highest sequence downward.
  // Output capacity selects how many blocks fit beside other TCP options.
  [[nodiscard]] std::size_t
  sack_blocks(std::span<SackBlock> output) const noexcept;

  [[nodiscard]] ReceiveBufferCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const ReceiveBufferCheckpoint &state) noexcept;

private:
  [[nodiscard]] bool received(std::size_t physical_index) const noexcept;
  void set_received(std::size_t physical_index, bool value) noexcept;
  [[nodiscard]] std::size_t physical(std::uint32_t offset) const noexcept;
  void advance_contiguous() noexcept;

  std::span<std::uint8_t> storage_;
  std::span<std::uint8_t> received_bitmap_;
  std::uint32_t read_sequence_{};
  std::uint32_t receive_next_{};
  std::uint32_t head_{};
  bool valid_{};
  std::uint32_t recent_sequence_{};
  bool recent_sequence_present_{};
};

} // namespace router::transport::tcp
