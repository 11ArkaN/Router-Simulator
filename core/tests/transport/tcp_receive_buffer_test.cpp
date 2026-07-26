// TCP receive-buffer tests cover gaps, overlap, wrap, zero-window pressure,
// application reads and exact checkpoint restore using caller-owned arenas.

#include "router/tcp_receive_buffer.hpp"

#include <array>
#include <stdexcept>

void tcp_receive_buffer_tests() {
  using namespace router::transport::tcp;

  std::array<std::uint8_t, 16> storage{};
  std::array<std::uint8_t, 2> bitmap{};
  ReceiveBuffer buffer{storage, bitmap, 0xfffffff8U};
  if (!buffer.valid() || buffer.advertised_window() != 16U)
    throw std::runtime_error("TCP receive arena rejected a valid capacity");

  constexpr std::array<std::uint8_t, 8> later{9U, 10U, 11U, 12U,
                                              13U, 14U, 15U, 16U};
  const auto out_of_order = buffer.accept(0U, later);
  if (out_of_order.status != ReceiveInsertStatus::accepted ||
      out_of_order.newly_stored != later.size() ||
      buffer.receive_next() != 0xfffffff8U || buffer.readable_octets() != 0U)
    throw std::runtime_error("TCP exposed bytes beyond a receive gap");

  constexpr std::array<std::uint8_t, 8> first{1U, 2U, 3U, 4U,
                                              5U, 6U, 7U, 8U};
  if (buffer.accept(0xfffffff8U, first).receive_next != 8U ||
      buffer.readable_octets() != 16U || buffer.advertised_window() != 0U)
    throw std::runtime_error("TCP did not join a gap across sequence wrap");
  std::array<std::uint8_t, 10> read{};
  if (buffer.read(read) != read.size() || read[0] != 1U || read[7] != 8U ||
      read[8] != 9U || read[9] != 10U || buffer.advertised_window() != 10U)
    throw std::runtime_error("TCP circular read changed stream order");

  constexpr std::array<std::uint8_t, 10> tail{
      17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U, 26U};
  if (buffer.accept(8U, tail).newly_stored != tail.size() ||
      buffer.receive_next() != 18U || buffer.advertised_window() != 0U ||
      buffer.accept(18U, first).status != ReceiveInsertStatus::outside_window)
    throw std::runtime_error("TCP receive window exceeded owner capacity");
  if (buffer.accept(0U, later).status != ReceiveInsertStatus::duplicate)
    throw std::runtime_error("TCP receive buffer stored acknowledged duplicates");

  // Later overlaps cannot replace bytes already accepted into sequence space.
  // This differs from IPv4 fragment reassembly and is why the repositories are
  // separate even though both track holes.
  std::array<std::uint8_t, 16> overlap_storage{};
  std::array<std::uint8_t, 2> overlap_bitmap{};
  ReceiveBuffer overlap{overlap_storage, overlap_bitmap, 100U};
  constexpr std::array<std::uint8_t, 5> original{50U, 51U, 52U, 53U, 54U};
  constexpr std::array<std::uint8_t, 10> overlapping{
      1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U};
  static_cast<void>(overlap.accept(105U, original));
  const auto joined = overlap.accept(100U, overlapping);
  std::array<std::uint8_t, 10> joined_bytes{};
  if (joined.newly_stored != 5U || overlap.read(joined_bytes) != 10U ||
      joined_bytes[4] != 5U || joined_bytes[5] != 50U ||
      joined_bytes[9] != 54U)
    throw std::runtime_error("TCP overlap overwrote previously accepted bytes");

  // Persist a live hole and restore it into a different physical arena. The
  // missing prefix must still block reads until it arrives after restore.
  std::array<std::uint8_t, 12> checkpoint_storage{};
  std::array<std::uint8_t, 2> checkpoint_bitmap{};
  ReceiveBuffer checkpointed{checkpoint_storage, checkpoint_bitmap, 1000U};
  static_cast<void>(checkpointed.accept(1004U, original));
  const auto saved = checkpointed.checkpoint();
  std::array<std::uint8_t, 12> restored_storage{};
  std::array<std::uint8_t, 2> restored_bitmap{};
  ReceiveBuffer restored{restored_storage, restored_bitmap, 0U};
  if (!restored.restore(saved) || restored.readable_octets() != 0U ||
      restored.receive_next() != 1000U)
    throw std::runtime_error("TCP receive checkpoint collapsed a live gap");
  constexpr std::array<std::uint8_t, 4> prefix{1U, 2U, 3U, 4U};
  if (restored.accept(1000U, prefix).receive_next != 1009U)
    throw std::runtime_error("TCP restored receive gap did not continue");

  auto invalid = saved;
  invalid.received.back() |= 0xf0U;
  if (restored.restore(invalid))
    throw std::runtime_error("TCP receive checkpoint accepted bitmap padding");

  // SACK reports the block containing the latest accepted segment first, then
  // older high-sequence blocks. Bridging data merges blocks without a fixed
  // scoreboard limit, because the receipt bitmap remains the source of truth.
  std::array<std::uint8_t, 32> sack_storage{};
  std::array<std::uint8_t, 4> sack_bitmap{};
  ReceiveBuffer sack_buffer{sack_storage, sack_bitmap, 100U};
  constexpr std::array<std::uint8_t, 4> four{1U, 2U, 3U, 4U};
  static_cast<void>(sack_buffer.accept(108U, four));
  static_cast<void>(sack_buffer.accept(120U, four));
  std::array<SackBlock, 4> blocks{};
  if (sack_buffer.sack_blocks(blocks) != 2U ||
      blocks[0].left_edge != 120U || blocks[0].right_edge != 124U ||
      blocks[1].left_edge != 108U || blocks[1].right_edge != 112U)
    throw std::runtime_error("TCP SACK did not prioritize the recent block");
  constexpr std::array<std::uint8_t, 8> bridge{
      1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
  static_cast<void>(sack_buffer.accept(112U, bridge));
  if (sack_buffer.sack_blocks(blocks) != 1U ||
      blocks[0].left_edge != 108U || blocks[0].right_edge != 124U)
    throw std::runtime_error("TCP SACK did not merge a bridging segment");
  static_cast<void>(sack_buffer.accept(100U, later));
  if (sack_buffer.receive_next() != 124U ||
      sack_buffer.sack_blocks(blocks) != 0U)
    throw std::runtime_error("TCP SACK reported cumulatively acknowledged data");
}
