// Project-secret tests exercise authenticated encryption, purpose binding,
// tamper rejection, rewrapping, capacity, pruning and checkpoint restore. No
// test asks the vault to export plaintext through a persistent representation.

#include "router/secret_vault.hpp"

#include <array>
#include <cstdint>
#include <ranges>
#include <stdexcept>

void secret_vault_tests() {
  using namespace router::vault;

  const std::array<std::uint8_t, 32U> first_key{
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
  const std::array<std::uint8_t, 32U> second_key{
      0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
      0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
      0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
      0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf};
  const std::array<std::uint8_t, 16U> first_context{
      'p', 'r', 'o', 'j', 'e', 'c', 't', ':', 'a', '/', 'v', 'a', 'u', 'l', 't', '1'};
  const std::array<std::uint8_t, 16U> second_context{
      'p', 'r', 'o', 'j', 'e', 'c', 't', ':', 'b', '/', 'v', 'a', 'u', 'l', 't', '1'};
  const std::array<std::uint8_t, 9U> psk{
      's', '3', 'c', 'r', '3', 't', '-', 'p', 's'};
  const std::array<std::uint8_t, 6U> ppk{0x00, 0x01, 0x02,
                                                0xfd, 0xfe, 0xff};

  auto vault = SecretVault::create(first_key, first_context, 2U);
  if (!vault)
    throw std::runtime_error("valid project vault material was rejected");
  const auto [psk_result, psk_handle] =
      vault->seal(SecretKind::ike_pre_shared_key, psk);
  const auto [ppk_result, ppk_handle] =
      vault->seal(SecretKind::ipsec_ppk_hexadecimal, ppk);
  if (psk_result != Result::applied || ppk_result != Result::applied ||
      !psk_handle || ppk_handle <= psk_handle)
    throw std::runtime_error("project secrets were not sealed");

  // Repeating a command is a semantic no-op. It must reuse the stable handle
  // and must not consume another bounded credential record.
  const auto [duplicate_result, duplicate_handle] =
      vault->seal(SecretKind::ike_pre_shared_key, psk);
  if (duplicate_result != Result::applied || duplicate_handle != psk_handle ||
      vault->checkpoint().records.size() != 2U)
    throw std::runtime_error("equal project secret was duplicated");
  if (vault->seal(SecretKind::ipsec_ppk_ascii,
                  std::array<std::uint8_t, 1U>{'x'})
          .first != Result::resource_exhausted)
    throw std::runtime_error("vault capacity was not enforced");

  auto [open_result, opened] =
      vault->open(psk_handle, SecretKind::ike_pre_shared_key);
  if (open_result != Result::applied || !opened ||
      !std::ranges::equal(opened->bytes(), psk))
    throw std::runtime_error("authenticated project secret did not open");
  if (vault->open(psk_handle, SecretKind::ipsec_ppk_ascii).first !=
      Result::wrong_kind)
    throw std::runtime_error("secret purpose binding was not enforced");

  const auto first_checkpoint = vault->checkpoint();
  auto restored =
      SecretVault::restore(first_checkpoint, first_key, first_context, 2U);
  if (!restored ||
      restored->open(ppk_handle, SecretKind::ipsec_ppk_hexadecimal).first !=
          Result::applied)
    throw std::runtime_error("authenticated vault checkpoint did not restore");
  if (SecretVault::restore(first_checkpoint, second_key, first_context, 2U) ||
      SecretVault::restore(first_checkpoint, first_key, second_context, 2U))
    throw std::runtime_error("wrong vault key or context was accepted");

  auto tampered = first_checkpoint;
  tampered.records.front().sealed.back() ^= 0x80U;
  if (SecretVault::restore(tampered, first_key, first_context, 2U))
    throw std::runtime_error("tampered vault ciphertext was accepted");
  tampered = first_checkpoint;
  tampered.records.front().kind = SecretKind::dnssec_private_key;
  if (SecretVault::restore(tampered, first_key, first_context, 2U))
    throw std::runtime_error("tampered vault purpose was accepted");

  if (vault->rewrap(second_key, second_context) != Result::applied)
    throw std::runtime_error("project vault rotation failed");
  const auto rotated = vault->checkpoint();
  if (SecretVault::restore(rotated, first_key, first_context, 2U) ||
      !SecretVault::restore(rotated, second_key, second_context, 2U))
    throw std::runtime_error("project vault rotation retained the old key");

  // Pruning receives the complete live-handle set from the configuration and
  // protocol owners. Removing one record must not renumber the surviving one.
  const std::array<SecretHandle, 1U> live{ppk_handle};
  vault->prune(live);
  if (vault->contains(psk_handle, SecretKind::ike_pre_shared_key) ||
      !vault->contains(ppk_handle, SecretKind::ipsec_ppk_hexadecimal) ||
      vault->erase(ppk_handle) != Result::applied ||
      vault->erase(ppk_handle) != Result::not_found)
    throw std::runtime_error("vault pruning or erasure violated handle ownership");

  // OSPF keychain configuration uses a distinct authenticated purpose, so a
  // valid encrypted routing key cannot be reopened as an IPsec credential.
  auto ospf_vault = SecretVault::create(first_key, first_context, 1U);
  const std::array<std::uint8_t, 16U> ospf_key{
      0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
      0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU};
  if (!ospf_vault)
    throw std::runtime_error("OSPF vault fixture was rejected");
  const auto [ospf_result, ospf_handle] = ospf_vault->seal(
      SecretKind::ospf_authentication_key, ospf_key);
  auto [ospf_open_result, opened_ospf] = ospf_vault->open(
      ospf_handle, SecretKind::ospf_authentication_key);
  if (ospf_result != Result::applied ||
      ospf_open_result != Result::applied || !opened_ospf ||
      !std::ranges::equal(opened_ospf->bytes(), ospf_key) ||
      ospf_vault->open(ospf_handle,
                       SecretKind::ipsec_static_authentication_key)
              .first != Result::wrong_kind)
    throw std::runtime_error("OSPF secret purpose binding was not enforced");
}
