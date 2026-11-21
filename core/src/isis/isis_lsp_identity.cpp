// Pure operational identity conversion. Callers own input and output values;
// no LSDB, CLI session or runtime owner is retained by this module.
#include "router/isis_lsp_identity.hpp"
namespace router::isis {
std::string format_lsp_id(const packet::isis::LspId &id) {
  constexpr std::string_view digits="0123456789abcdef";
  std::string output; output.reserve(20U);
  for (std::size_t index{}; index<id.size(); ++index) {
    if (index==2U || index==4U || index==6U) output+='.';
    if (index==7U) output+='-';
    output+=digits[id[index]>>4U]; output+=digits[id[index]&15U];
  }
  return output;
}
std::optional<packet::isis::LspId> parse_lsp_id(std::string_view text) noexcept {
  if (text.size()!=20U || text[4U]!='.' || text[9U]!='.' || text[14U]!='.' || text[17U]!='-') return std::nullopt;
  const auto nibble=[](unsigned char value)->std::optional<std::uint8_t> {
    if (value>='0' && value<='9') return static_cast<std::uint8_t>(value-'0');
    if (value>='a' && value<='f') return static_cast<std::uint8_t>(value-'a'+10U);
    if (value>='A' && value<='F') return static_cast<std::uint8_t>(value-'A'+10U);
    return std::nullopt;
  };
  packet::isis::LspId result{};
  for (std::size_t index{},position{}; index<result.size(); ++index) {
    if (position==4U || position==9U || position==14U || position==17U) ++position;
    const auto high=nibble(text[position++]), low=nibble(text[position++]);
    if (!high || !low) return std::nullopt;
    result[index]=static_cast<std::uint8_t>((*high<<4U)|*low);
  }
  return result;
}
}
