// RFC 7383 encrypted-fragment reassembly owned by one IKE SA control component.
// Constructor allocation reserves the complete configured budget; accepting a
// datagram performs no allocation. Deadlines use the host monotonic clock and
// are local to this assembler, never a global simulated event queue.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace router::ikev2 {

struct FragmentSetKey {
  std::uint64_t initiator_spi{};
  std::uint64_t responder_spi{};
  std::uint32_t message_id{};
  bool response{};

  [[nodiscard]] friend constexpr bool
  operator==(const FragmentSetKey &, const FragmentSetKey &) noexcept = default;
};

enum class FragmentAcceptStatus : std::uint8_t {
  stored,
  duplicate,
  complete,
  invalid,
  conflicting_set,
  conflicting_duplicate,
  resource_exhausted,
  expired,
  output_too_small
};

struct FragmentAcceptResult {
  FragmentAcceptStatus status{FragmentAcceptStatus::invalid};
  std::size_t assembled_octets{};
  std::uint8_t first_payload{};
};

class FragmentAssembler final {
public:
  using Clock = std::chrono::steady_clock;

  FragmentAssembler(std::size_t maximum_fragments,
                    std::size_t maximum_message_octets,
                    std::chrono::milliseconds timeout);

  // encrypted_plaintext is the authenticated plaintext of one Encrypted
  // Fragment payload after IKE SK decryption. Fragment 1 carries the inner
  // Next Payload value; later fragments must carry zero in that field.
  [[nodiscard]] FragmentAcceptResult accept(
      const FragmentSetKey &key, std::uint16_t number, std::uint16_t total,
      std::uint8_t next_payload,
      std::span<const std::uint8_t> encrypted_plaintext,
      Clock::time_point now, std::span<std::uint8_t> assembled_output) noexcept;

  void clear() noexcept;
  [[nodiscard]] bool active() const noexcept { return active_; }

private:
  struct Slot {
    std::size_t offset{};
    std::size_t length{};
    bool present{};
  };

  std::vector<Slot> slots_;
  std::vector<std::uint8_t> storage_;
  std::chrono::milliseconds timeout_{};
  FragmentSetKey key_{};
  Clock::time_point deadline_{};
  std::size_t stored_octets_{};
  std::size_t received_{};
  std::uint16_t total_{};
  std::uint8_t first_payload_{};
  bool active_{};
};

} // namespace router::ikev2
