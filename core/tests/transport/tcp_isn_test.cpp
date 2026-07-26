// ISN tests use fixed secrets and externally calculated HMAC vectors. Explicit
// time points verify the four-microsecond M component without exposing a test
// clock through the production runtime or permitting time travel in the UI.

#include "router/tcp_isn.hpp"

#include <chrono>
#include <stdexcept>

void tcp_isn_tests() {
  using namespace std::chrono_literals;
  using router::transport::tcp::InitialSequenceGenerator;
  using router::transport::tcp::IsnCheckpoint;

  router::crypto::Sha256Digest secret{};
  for (std::size_t index = 0U; index < secret.size(); ++index)
    secret[index] = static_cast<std::uint8_t>(index + 1U);
  const auto origin = InitialSequenceGenerator::Clock::time_point{123s};
  InitialSequenceGenerator generator{secret, origin};
  if (!generator.valid())
    throw std::runtime_error("TCP ISN rejected a nonzero endpoint secret");

  constexpr router::packet::Ipv4 local4{192U, 0U, 2U, 1U};
  constexpr router::packet::Ipv4 remote4{198U, 51U, 100U, 2U};
  // 0xdeef7319 is the first HMAC-SHA-256 word for the family-tagged tuple,
  // independently calculated outside the implementation. M is zero at origin.
  const auto first = generator.generate(local4, 12345U, remote4, 443U, origin);
  if (first != 0xdeef7319U ||
      generator.generate(local4, 12345U, remote4, 443U, origin + 3us) != first ||
      generator.generate(local4, 12345U, remote4, 443U, origin + 4us) !=
          first + 1U)
    throw std::runtime_error("TCP ISN clock or IPv4 PRF vector drifted");

  const auto local6 = router::ip::parse_ipv6("2001:db8::1");
  const auto remote6 = router::ip::parse_ipv6("2001:db8::2");
  InitialSequenceGenerator ipv6_generator{secret, origin};
  if (!local6 || !remote6 ||
      ipv6_generator.generate(*local6, 12345U, *remote6, 443U, origin) !=
          0x4be3b7e4U)
    throw std::runtime_error("TCP ISN IPv6 tuple vector drifted");
  if (generator.generate(local4, 12346U, remote4, 443U, origin) == first)
    throw std::runtime_error("TCP ISN PRF omitted a connection tuple field");

  const auto saved = generator.checkpoint(origin + 40us);
  InitialSequenceGenerator restored{{}, origin + 10s};
  if (!restored.restore(saved, origin + 10s) ||
      restored.generate(local4, 12345U, remote4, 443U, origin + 10s + 12us) !=
          0xdeef7319U + 13U)
    throw std::runtime_error("TCP ISN checkpoint lost four-microsecond continuity");

  auto invalid = IsnCheckpoint{};
  if (InitialSequenceGenerator::validate_checkpoint(invalid) ||
      restored.restore(invalid, origin))
    throw std::runtime_error("TCP ISN accepted a missing all-zero secret");
}
