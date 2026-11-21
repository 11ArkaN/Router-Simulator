// Lexical fixtures use the selected YANG lsp-id pattern and round-trip all
// octet positions. The test owns every value and requires no runtime owner.
#include "router/isis_lsp_identity.hpp"
#include <array>
#include <stdexcept>
void isis_lsp_identity_tests() {
  using namespace router::isis;
  const auto require=[](bool value) { if (!value) throw std::runtime_error("LSP identity invariant"); };
  require(format_lsp_id({})=="0000.0000.0000.00-00");
  const auto upper=parse_lsp_id("ABCD.EF01.2345.67-89");
  require(upper && *upper==router::packet::isis::LspId{0xabU,0xcdU,0xefU,1U,0x23U,0x45U,0x67U,0x89U});
  for (const std::string_view value : {"", "0000.0000.0000.00.00", "0000.0000.0000.0-00", "0000.0000.0000.000-00",
      "0000.0000.0000.00-0g", "0000.0000.0000.00-00 ", " 0000.0000.0000.00-00", "0000-0000.0000.00-00"})
    require(!parse_lsp_id(value));
  for (std::size_t position{}; position<8U; ++position) for (unsigned value{}; value<256U; ++value) {
    router::packet::isis::LspId id{}; id[position]=static_cast<std::uint8_t>(value);
    const auto text=format_lsp_id(id); require(text.size()==20U && parse_lsp_id(text)==id);
  }
}
