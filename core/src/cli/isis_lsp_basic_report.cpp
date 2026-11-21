// Pure cold rendering of source-bound basic LSP options. Input belongs to the
// caller and must already exclude authentication values. Unsupported options
// refuse the complete report rather than silently omitting protocol content.
#include "cli/isis_lsp_basic_report.hpp"
#include "router/isis_basic_tlvs.hpp"
#include "router/isis_configuration.hpp"
#include "router/isis_reachability.hpp"
#include "router/isis_lsp_identity.hpp"
#include "router/isis_operational.hpp"
#include "router/isis_prefix_attributes.hpp"
#include <sstream>
#include <optional>
namespace router::lab::isis_cli {
std::optional<std::string> basic_lsp_options(std::span<const std::uint8_t> bytes,std::span<const isis::HostnameOperational> names) {
  using namespace packet::isis;
  std::ostringstream out;
  TlvCursor options(bytes);
  while (const auto option=options.next()) {
    switch (option->code) {
    case 1U: {
      out << "  Area Addresses:\n";
      AreaAddressCursor areas(*option);
      while (const auto area=areas.next()) {
        isis::NeighborArea value; value.length=static_cast<std::uint8_t>(area->size());
        std::copy(area->begin(),area->end(),value.bytes.begin());
        out << "    Area Address : (" << area->size() << ") " << isis::format_configured_area(value) << '\n';
      }
      if (!areas.valid()) return std::nullopt;
      break;
    }
    case 8U: break;
    case 22U: {
      ExtendedNeighborCursor neighbors(*option);
      while (const auto neighbor=neighbors.next()) {
        if (!neighbor->sub_tlvs.empty()) return std::nullopt;
        LspId id{}; std::copy(neighbor->id.begin(),neighbor->id.end(),id.begin());
        auto label=isis::format_lsp_id(id).substr(0U,17U);
        SystemId system{}; std::copy_n(id.begin(),system.size(),system.begin());
        const auto name=std::lower_bound(names.begin(),names.end(),system,
            [](const auto &candidate,const auto &key) { return candidate.system<key; });
        if (name!=names.end() && name->system==system) {
          std::ostringstream escaped;
          for (const unsigned char value : name->hostname) {
            if (value>0x7fU) return std::nullopt;
            if (value>=0x20U && value<=0x7eU) escaped << static_cast<char>(value);
            else { constexpr std::string_view hex="0123456789abcdef"; escaped << "\\x" << hex[value>>4U] << hex[value&15U]; }
          }
          label=escaped.str()+label.substr(14U);
        }
        out << "  TE IS Nbrs   :\n    Nbr   : " << label
            << "\n    Default Metric  : " << neighbor->metric << "\n    Sub TLV Len     : 0\n";
      }
      if (!neighbors.valid()) return std::nullopt;
      break;
    }
    case 135U: case 236U: {
      const bool ipv6=option->code==236U;
      out << (ipv6 ? "  IPv6 Reach:\n" : "  TE IP Reach   :\n");
      ExtendedPrefixCursor prefixes(*option);
      while (const auto prefix=prefixes.next()) {
        if (ipv6 && prefix->down) return std::nullopt;
        if (ipv6) out << "    Metric: ( " << (prefix->external ? "E" : "I") << " ) " << prefix->metric
            << "\n    Prefix  : " << ip::format_ip_prefix(prefix->prefix) << '\n';
        else out << "    Default Metric  : " << prefix->metric << "\n    Control Info: "
            << (prefix->down ? "D" : "") << (prefix->sub_tlvs_present ? "S" : "") << ", prefLen "
            << unsigned(prefix->prefix.length) << "\n    Prefix   : " << ip::format_ip_address(prefix->prefix.network) << '\n';
        if (prefix->sub_tlvs_present) out << "    Sub TLV   :\n";
        TlvCursor attributes(prefix->sub_tlvs);
        while (const auto attribute=attributes.next()) {
          if (attribute->code!=4U) return std::nullopt;
          const auto flags=prefix_attribute_flags(*attribute,prefix->prefix);
          if (!flags) return std::nullopt;
          out << "      Attribute Flags : ";
          if (flags->node) out << 'N';
          if (flags->readvertised) out << 'R';
          if (flags->external) out << 'X';
          out << '\n';
        }
        if (!attributes.valid()) return std::nullopt;
      }
      if (!prefixes.valid()) return std::nullopt;
      break;
    }
    case 129U:
      out << "  Supp Protocols:\n    Protocols     :";
      for (const auto value : option->value) {
        if (value==ipv4_nlpid) out << " IPv4";
        else if (value==ipv6_nlpid) out << " IPv6";
        else return std::nullopt;
      }
      out << '\n'; break;
    case 132U: case 134U: case 232U: {
      const bool ipv6=option->code==232U;
      const std::size_t width=ipv6 ? 16U : 4U;
      if (option->value.size()%width || (option->code==134U && option->value.size()!=4U)) return std::nullopt;
      out << (option->code==134U ? "  Router ID   :\n" : ipv6 ? "  I/F Addresses IPv6 :\n" : "  I/F Addresses :\n");
      for (std::size_t offset{}; offset<option->value.size(); offset+=width) {
        ip::IpAddress address; address.family=ipv6 ? ip::AddressFamily::ipv6 : ip::AddressFamily::ipv4;
        std::copy_n(option->value.begin()+offset,width,address.bytes.begin());
        out << (option->code==134U ? "    Router ID   : " : ipv6 ? "    IPv6 Address   : " : "    I/F Address   : ")
            << ip::format_ip_address(address) << '\n';
      }
      break;
    }
    case 137U:
      if (option->value.empty()) return std::nullopt;
      out << "  IS-Hostname   : ";
      for (const auto value : option->value) {
        if (value>0x7fU) return std::nullopt;
        if (value>=0x20U && value<=0x7eU) out << static_cast<char>(value);
        else { constexpr std::string_view hex="0123456789abcdef"; out << "\\x" << hex[value>>4U] << hex[value&15U]; }
      }
      out << '\n'; break;
    default: return std::nullopt;
    }
  }
  return options.valid() ? std::optional{out.str()} : std::nullopt;
}
}
