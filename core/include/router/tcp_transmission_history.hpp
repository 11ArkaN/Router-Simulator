// Caller-sized history of admitted original TCP segments. One connection
// owner mutates the records after lower-queue admission and cumulative ACKs.
// The history retains timing needed by R1, R2, RTT and later SACK recovery.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::transport::tcp {

struct TransmissionRecord {
  std::chrono::steady_clock::time_point first_transmitted_at{};
  std::chrono::steady_clock::time_point last_transmitted_at{};
  std::uint32_t first{};
  std::uint32_t end{};
  std::uint32_t retransmissions{};
};

struct TransmissionRecordCheckpoint {
  std::uint32_t first{};
  std::uint32_t end{};
  std::uint32_t retransmissions{};
  std::int64_t first_age_nanoseconds{};
  std::int64_t last_age_nanoseconds{};
};

struct TransmissionHistoryCheckpoint {
  std::vector<TransmissionRecordCheckpoint> records;
};

class TransmissionHistory final {
public:
  using Clock = std::chrono::steady_clock;

  // records is connection-owned storage and must outlive this object. Its
  // capacity comes from the endpoint resource profile, not a protocol-wide
  // segment-count constant hidden in the transport implementation.
  explicit TransmissionHistory(
      std::span<TransmissionRecord> records) noexcept;

  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] bool can_record_original(std::uint32_t first,
                                         std::uint32_t end,
                                         Clock::time_point now) const noexcept;

  // Original segments must append contiguous sequence space. This is called
  // only after the matching packet is admitted, so its timestamp is evidence
  // of a real transmission rather than a prepared packet intent.
  [[nodiscard]] bool record_original(std::uint32_t first,
                                     std::uint32_t end,
                                     Clock::time_point now) noexcept;

  // A repair may cover one record, a partial record, or several records after
  // PMTU resegmentation. Every overlapping original record retains one repair
  // count and the latest successful transmission time.
  [[nodiscard]] std::size_t record_retransmission(
      std::uint32_t first, std::uint32_t end,
      Clock::time_point now) noexcept;
  [[nodiscard]] bool can_record_retransmission(
      std::uint32_t first, std::uint32_t end,
      Clock::time_point now) const noexcept;

  // Cumulative ACK removal preserves the age of a partially acknowledged
  // oldest record while moving its first outstanding byte to acknowledgment.
  void acknowledge(std::uint32_t acknowledgment) noexcept;

  [[nodiscard]] std::optional<TransmissionRecord> oldest() const noexcept;
  // ICMP quotations contain the first TCP sequence number but may contain no
  // payload. This query recognizes only bytes from a segment admitted to IP
  // and not yet cumulatively acknowledged.
  [[nodiscard]] bool contains(std::uint32_t sequence) const noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return count_; }
  [[nodiscard]] std::size_t capacity() const noexcept {
    return valid_ ? records_.size() : 0U;
  }

  [[nodiscard]] TransmissionHistoryCheckpoint
  checkpoint(Clock::time_point now) const;
  [[nodiscard]] static bool validate_checkpoint(
      const TransmissionHistoryCheckpoint &state, std::size_t capacity,
      Clock::time_point now) noexcept;
  [[nodiscard]] bool restore(const TransmissionHistoryCheckpoint &state,
                             Clock::time_point now) noexcept;

private:
  [[nodiscard]] std::size_t physical(std::size_t logical) const noexcept;

  std::span<TransmissionRecord> records_;
  std::size_t head_{};
  std::size_t count_{};
  bool valid_{};
};

} // namespace router::transport::tcp
