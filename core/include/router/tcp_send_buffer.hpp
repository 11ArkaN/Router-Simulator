// Caller-sized TCP send repository for one connection. The endpoint shard is
// the sole mutable owner. The repository retains both unsent and unacknowledged
// bytes, but it does not own packet buffers, clocks, congestion policy or IP.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace router::transport::tcp {

enum class SendAcknowledgeStatus : std::uint8_t {
  advanced,
  duplicate,
  beyond_sent,
  invalid
};

struct SendAcknowledgeResult {
  SendAcknowledgeStatus status{SendAcknowledgeStatus::invalid};
  std::uint32_t newly_acknowledged{};
};

// A prepared range is an immutable intent, not proof that a segment entered
// the packet path. The generation binds it to the exact repository state that
// produced it. Any write, ACK or successful commit invalidates stale intents.
struct PreparedSendRange {
  std::uint32_t sequence{};
  std::uint32_t length{};
  std::uint64_t generation{};
  bool retransmission{};

  [[nodiscard]] explicit operator bool() const noexcept { return length != 0U; }
};

struct SendBufferCheckpoint {
  std::vector<std::uint8_t> storage;
  std::uint32_t send_unacknowledged{};
  std::uint32_t send_next{};
  std::uint32_t write_next{};
  std::uint32_t head{};
  std::uint64_t generation{};
};

class SendBuffer final {
public:
  // storage is owned by the calling endpoint and must outlive this object.
  // Its size is a resource-profile choice. The 2^30 ceiling is not a product
  // limit: it preserves unambiguous RFC serial-number comparisons for every
  // live byte while still covering the complete scaled TCP window domain.
  SendBuffer(std::span<std::uint8_t> storage,
             std::uint32_t initial_data_sequence) noexcept;

  [[nodiscard]] bool valid() const noexcept { return valid_; }

  // Writes accept as much application data as the owner-provided repository
  // can retain. A short result is backpressure, not silent data loss.
  [[nodiscard]] std::size_t
  write(std::span<const std::uint8_t> input) noexcept;

  // maximum_payload is computed by the connection owner from SMSS, cwnd and
  // rwnd. Zero therefore means that transmission is presently forbidden.
  [[nodiscard]] PreparedSendRange
  prepare_new(std::uint32_t maximum_payload) const noexcept;
  [[nodiscard]] PreparedSendRange
  prepare_retransmission(std::uint32_t maximum_payload) const noexcept;
  [[nodiscard]] PreparedSendRange prepare_retransmission_at(
      std::uint32_t sequence, std::uint32_t maximum_payload) const noexcept;

  // Copies a prepared range into packet-pool storage without changing SND.NXT.
  // The caller must commit only after the encoded IP packet is admitted to the
  // next bounded queue. This two-phase rule prevents phantom transmissions.
  [[nodiscard]] bool copy(const PreparedSendRange &range,
                          std::span<std::uint8_t> output) const noexcept;
  [[nodiscard]] bool commit(const PreparedSendRange &range) noexcept;

  // Only ACKs within (SND.UNA,SND.NXT] release storage. ACKs beyond SND.NXT
  // are reported distinctly so RFC 9293 processing can send a corrective ACK.
  [[nodiscard]] SendAcknowledgeResult
  acknowledge(std::uint32_t acknowledgment) noexcept;

  [[nodiscard]] std::uint32_t send_unacknowledged() const noexcept {
    return send_unacknowledged_;
  }
  [[nodiscard]] std::uint32_t send_next() const noexcept { return send_next_; }
  [[nodiscard]] std::uint32_t write_next() const noexcept { return write_next_; }
  [[nodiscard]] std::uint32_t flight_size() const noexcept;
  [[nodiscard]] std::uint32_t unsent_octets() const noexcept;
  [[nodiscard]] std::uint32_t queued_octets() const noexcept;
  [[nodiscard]] std::uint32_t writable_octets() const noexcept;
  [[nodiscard]] std::uint32_t capacity() const noexcept {
    return valid_ ? static_cast<std::uint32_t>(storage_.size()) : 0U;
  }

  [[nodiscard]] SendBufferCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const SendBufferCheckpoint &state) noexcept;

private:
  [[nodiscard]] std::size_t physical(std::uint32_t offset) const noexcept;
  [[nodiscard]] bool range_is_current(const PreparedSendRange &range) const noexcept;

  std::span<std::uint8_t> storage_;
  std::uint32_t send_unacknowledged_{};
  std::uint32_t send_next_{};
  std::uint32_t write_next_{};
  std::uint32_t head_{};
  std::uint64_t generation_{1U};
  bool valid_{};
};

} // namespace router::transport::tcp
