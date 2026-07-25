// Keychain tests cover SR OS youngest-key send selection, receive overlap,
// exact replacement boundaries, preactivation overlap, disabled entries and
// malformed persisted state.

#include "router/ospf_keychain.hpp"

#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_keychain_tests() {
  using namespace router::ospf;
  KeychainConfiguration keychain{
      .name = "ospf-rollover",
      .bidirectional = {
          {.secret = 101U,
           .begin_utc_seconds = 1000,
           .end_utc_seconds = 2000,
           .tolerance_seconds = 300U,
           .id = 1U,
           .algorithm = KeychainAlgorithm::hmac_sha256,
           .algorithm_configured = true,
           .secret_configured = true},
          {.secret = 102U,
           .begin_utc_seconds = 1900,
           .end_utc_seconds = 3000,
           .tolerance_seconds = 300U,
           .id = 2U,
           .algorithm = KeychainAlgorithm::hmac_sha256,
           .algorithm_configured = true,
           .secret_configured = true}}};
  require(validate(keychain) == KeychainStatus::valid,
          "valid OSPF keychain failed canonical validation");
  require(select_send_key(keychain, 1800)->id == 1U &&
              select_send_key(keychain, 1950)->id == 2U,
          "keychain did not select the youngest active send key");
  require(select_receive_key(keychain, 1U, 2199) &&
              !select_receive_key(keychain, 1U, 2200),
          "keychain did not apply the exact receive tolerance boundary");
  require(!select_send_key(keychain, 999) &&
              !select_receive_key(keychain, 2U, 1599) &&
              select_receive_key(keychain, 2U, 1600),
          "keychain did not apply preactivation receive tolerance");
  require(select_send_key(keychain, 4000)->id == 2U &&
              select_receive_key(keychain, 2U, 4000),
          "OSPF did not retain the last valid key after expiry");

  keychain.bidirectional[1U].id = 1U;
  require(validate(keychain) == KeychainStatus::duplicate_entry &&
              !select_send_key(keychain, 1950),
          "duplicate Key IDs leaked into operational key selection");
  keychain.bidirectional[1U].id = 2U;
  keychain.bidirectional[1U].end_utc_seconds = 1900;
  require(validate(keychain) == KeychainStatus::invalid_window,
          "empty key lifetime passed canonical validation");
}
