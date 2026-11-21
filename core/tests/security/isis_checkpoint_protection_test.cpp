// The project vault protects detached protocol checkpoint wire without adding
// credential records or consuming handles. Authentication precedes any decoded
// state; project, structural-prefix binding and ciphertext changes must refuse.

#include "router/secret_vault.hpp"

#include <algorithm>
#include <source_location>
#include <stdexcept>
#include <string>

void isis_checkpoint_protection_tests() {
  using namespace router::vault;
  const auto require = [](bool value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS checkpoint protection invariant at " + std::to_string(where.line()));
  };
  std::array<std::uint8_t, 32U> key{}, binding{};
  key.fill(0x31U); binding.fill(0x73U);
  const std::array<std::uint8_t, 4U> context{'l', 'a', 'b', '1'};
  auto vault = SecretVault::create(key, context, 1U);
  require(vault.has_value());
  const auto before = vault->checkpoint();
  // A checkpoint is larger than a credential and never uses the record limit.
  // Keep both payload and ciphertext off the default 1 MiB native stack.
  std::vector<std::uint8_t> wire(1024U * 1024U, 0xa5U);
  const std::string password{"checkpoint-wire-password-47"};
  std::copy(password.begin(), password.end(), wire.begin() + 17U);
  auto [status, sealed] = vault->seal_isis_checkpoint(wire, binding);
  require(status == Result::applied && sealed.size() > wire.size() && vault->checkpoint() == before);
  require(std::search(sealed.begin(), sealed.end(), password.begin(), password.end()) == sealed.end());
  const auto [again_status, again] = vault->seal_isis_checkpoint(wire, binding);
  require(again_status == Result::applied && again != sealed && vault->checkpoint() == before);
  const auto [opened_status, opened] = vault->open_isis_checkpoint(sealed, binding);
  require(opened_status == Result::applied && opened && std::ranges::equal(opened->bytes(), wire));
  const auto refuses = [&](const SecretVault &owner, std::span<const std::uint8_t> input,
      std::span<const std::uint8_t> associated) {
    const auto [result, plaintext] = owner.open_isis_checkpoint(input, associated);
    require(result != Result::applied && !plaintext);
  };
  auto wrong_binding = binding;
  wrong_binding[0U] ^= 1U;
  refuses(*vault, sealed, wrong_binding);
  refuses(*vault, sealed, std::span(binding).first(31U));
  refuses(*vault, std::span(sealed).first(sealed.size() - 1U), binding);
  for (const auto index : {std::size_t{}, std::size_t{6U}, sealed.size() / 2U, sealed.size() - 1U}) {
    auto damaged = sealed;
    damaged[index] ^= 1U;
    refuses(*vault, damaged, binding);
  }
  key[0U] ^= 1U;
  auto other_key = SecretVault::create(key, context, 1U);
  require(other_key.has_value());
  refuses(*other_key, sealed, binding);
  key[0U] ^= 1U;
  auto other_project = SecretVault::create(key, std::array<std::uint8_t, 4U>{'l', 'a', 'b', '2'}, 1U);
  require(other_project.has_value());
  refuses(*other_project, sealed, binding);
  require(vault->seal_isis_checkpoint({}, binding).first == Result::invalid_argument &&
      vault->seal_isis_checkpoint(wire, std::span(binding).first(31U)).first == Result::invalid_argument &&
      vault->seal(SecretKind::isis_checkpoint_state, std::span(wire).first(8U)).first == Result::invalid_argument &&
      vault->seal(SecretKind::ike_pre_shared_key, wire).first == Result::invalid_argument &&
      vault->checkpoint() == before);
  const std::array<std::uint8_t, 3U> credential{1U, 2U, 3U};
  require(vault->seal(SecretKind::ike_pre_shared_key, credential).first == Result::applied);
  // A full credential catalog still permits detached checkpoint protection.
  require(vault->seal_isis_checkpoint(wire, binding).first == Result::applied && vault->checkpoint().records.size() == 1U);
}
