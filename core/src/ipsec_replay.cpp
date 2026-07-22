// RFC 4302 section 3.3.2 and RFC 4303 section 3.4.3 replay processing, including
// the ESN high-order reconstruction from RFC 4303 Appendix A. The caller owns
// authentication and invokes commit only when the ICV or AEAD tag is valid.

#include "router/ipsec_replay.hpp"

#include <limits>

namespace router::ipsec {

ReplayWindow::ReplayWindow(std::uint8_t width,
                           bool extended_sequence_numbers) noexcept
    : width_(width <= 64U ? width : 0U),
      extended_(extended_sequence_numbers) {}

std::uint64_t ReplayWindow::active_mask() const noexcept {
  if (width_ == 0U)
    return 0U;
  return width_ == 64U ? std::numeric_limits<std::uint64_t>::max()
                       : (std::uint64_t{1U} << width_) - 1U;
}

std::optional<std::uint64_t>
ReplayWindow::reconstruct(std::uint32_t received_low) const noexcept {
  if (width_ == 0U ||
      (received_low == 0U && (!extended_ || highest_ == 0U)))
    return std::nullopt;
  if (!extended_)
    return static_cast<std::uint64_t>(received_low);
  if (highest_ == 0U)
    return static_cast<std::uint64_t>(received_low);

  const auto highest_low = static_cast<std::uint32_t>(highest_);
  auto highest_high = static_cast<std::uint32_t>(highest_ >> 32U);
  const auto behind = static_cast<std::uint32_t>(width_ - 1U);

  // Appendix A divides the sequence space around zero. Near the beginning of
  // a subspace, very large low words belong to the previous subspace. Away from
  // zero, a low word below the left edge belongs to the next subspace. These
  // rules are unambiguous while the window is far smaller than 2^31.
  if (highest_low < behind) {
    const auto previous_floor =
        std::numeric_limits<std::uint32_t>::max() - (behind - highest_low) + 1U;
    if (received_low >= previous_floor) {
      if (highest_high == 0U)
        return std::nullopt;
      --highest_high;
    }
  } else if (received_low < highest_low - behind) {
    if (highest_high == std::numeric_limits<std::uint32_t>::max())
      return std::nullopt;
    ++highest_high;
  }
  return (static_cast<std::uint64_t>(highest_high) << 32U) | received_low;
}

ReplayCandidate ReplayWindow::check(std::uint32_t received_low) const noexcept {
  if (width_ == 0U)
    return {.status = ReplayStatus::invalid_window};
  const auto reconstructed = reconstruct(received_low);
  if (!reconstructed)
    return {.status = received_low == 0U ? ReplayStatus::zero_sequence
                                         : ReplayStatus::sequence_space_exhausted};
  if (highest_ == 0U || *reconstructed > highest_)
    return {.status = ReplayStatus::admissible, .sequence = *reconstructed};

  const auto distance = highest_ - *reconstructed;
  if (distance >= width_)
    return {.status = ReplayStatus::too_old, .sequence = *reconstructed};
  if ((bitmap_ & (std::uint64_t{1U} << distance)) != 0U)
    return {.status = ReplayStatus::duplicate, .sequence = *reconstructed};
  return {.status = ReplayStatus::admissible, .sequence = *reconstructed};
}

bool ReplayWindow::commit(std::uint64_t authenticated_sequence) noexcept {
  if (width_ == 0U || authenticated_sequence == 0U ||
      (!extended_ && authenticated_sequence >
                         std::numeric_limits<std::uint32_t>::max()))
    return false;
  if (highest_ == 0U) {
    highest_ = authenticated_sequence;
    bitmap_ = 1U;
    return true;
  }
  if (authenticated_sequence > highest_) {
    const auto advance = authenticated_sequence - highest_;
    bitmap_ = advance >= width_ ? 1U : ((bitmap_ << advance) | 1U);
    bitmap_ &= active_mask();
    highest_ = authenticated_sequence;
    return true;
  }
  const auto distance = highest_ - authenticated_sequence;
  if (distance >= width_ ||
      (bitmap_ & (std::uint64_t{1U} << distance)) != 0U)
    return false;
  bitmap_ |= std::uint64_t{1U} << distance;
  return true;
}

bool ReplayWindow::restore(std::uint64_t highest,
                           std::uint64_t bitmap) noexcept {
  if (width_ == 0U || (!extended_ && highest >
                                      std::numeric_limits<std::uint32_t>::max()) ||
      (bitmap & ~active_mask()) != 0U ||
      ((highest == 0U) != (bitmap == 0U)) ||
      (highest != 0U && (bitmap & 1U) == 0U))
    return false;
  highest_ = highest;
  bitmap_ = bitmap;
  return true;
}

std::optional<std::uint64_t> OutboundSequence::next() noexcept {
  const auto maximum = extended_ ? std::numeric_limits<std::uint64_t>::max()
                                 : std::numeric_limits<std::uint32_t>::max();
  if (current_ == maximum)
    return std::nullopt;
  ++current_;
  return current_;
}

bool OutboundSequence::restore(std::uint64_t current) noexcept {
  if (!extended_ && current > std::numeric_limits<std::uint32_t>::max())
    return false;
  current_ = current;
  return true;
}

} // namespace router::ipsec
