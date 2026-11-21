// Basic LSP diagnostics preserve sourced values and refuse unsupported content.
// The test owns all input bytes and output strings; no runtime is involved.
#include <optional>
#include <span>
#include <string>
#include <vector>
#include <stdexcept>
#include "cli/isis_lsp_basic_report.hpp"
#include "router/isis_reachability.hpp"
#include "router/isis_operational.hpp"
#include "router/isis_prefix_attributes.hpp"
#include <array>
void isis_lsp_basic_report_tests() {
  using router::lab::isis_cli::basic_lsp_options;
  const auto require=[](bool value) { if (!value) throw std::runtime_error("Basic LSP report invariant"); };
  const std::vector<unsigned char> bytes{1U,4U,3U,0x49U,0U,1U,129U,2U,0xccU,0x8eU,137U,2U,'R','1',134U,4U,10U,0U,0U,1U};
  const auto report=basic_lsp_options(bytes);
  require(report && report->find("49.0001")!=std::string::npos && report->find("IPv4 IPv6")!=std::string::npos &&
      report->find("IS-Hostname   : R1")!=std::string::npos && report->find("10.0.0.1")!=std::string::npos);
  require(!basic_lsp_options(std::vector<unsigned char>{10U,2U,1U,'x'}));
  require(!basic_lsp_options(std::vector<unsigned char>{137U,1U,0x80U}));
  require(!basic_lsp_options(std::vector<unsigned char>{132U,3U,1U,2U,3U}));
  require(!basic_lsp_options(std::vector<unsigned char>{250U,0U}));
  const auto escaped=basic_lsp_options(std::vector<unsigned char>{137U,1U,0x1bU});
  require(escaped && escaped->find("\\x1b")!=std::string::npos && escaped->find(char(0x1bU))==std::string::npos);
  std::array<unsigned char,128U> buffer{};
  router::packet::isis::TlvWriter writer(buffer);
  require(router::packet::isis::encode_extended_neighbor(writer,{{1U,2U,3U,4U,5U,6U,7U},17U,{}}));
  router::packet::isis::ExtendedPrefix v4{{{router::ip::AddressFamily::ipv4,{192U,0U,2U,0U}},24U},23U,true,false,false,{}};
  require(router::packet::isis::encode_extended_prefix(writer,v4));
  router::packet::isis::ExtendedPrefix v6; v6.prefix.network.family=router::ip::AddressFamily::ipv6;
  v6.prefix.network.bytes[15U]=1U; v6.prefix.length=128U; v6.metric=31U;
  require(router::packet::isis::encode_extended_prefix(writer,v6));
  const auto reachability=basic_lsp_options(writer.bytes());
  require(reachability && reachability->find("0102.0304.0506.07")!=std::string::npos &&
      reachability->find("Default Metric  : 17")!=std::string::npos &&
      reachability->find("192.0.2.0")!=std::string::npos && reachability->find("Control Info: D, prefLen 24")!=std::string::npos &&
      reachability->find("::1/128")!=std::string::npos && reachability->find("Metric: ( I ) 31")!=std::string::npos);
  const std::array catalog{router::isis::HostnameOperational{{1U,2U,3U,4U,5U,6U},"peer"}};
  const auto named=basic_lsp_options(writer.bytes(),catalog);
  require(named && named->find("Nbr   : peer.07")!=std::string::npos);
  std::array<unsigned char,8U> attribute_bytes{};
  router::packet::isis::TlvWriter attributes(attribute_bytes);
  require(router::packet::isis::encode_prefix_attribute_flags(attributes,v4.prefix,{false,true,false}));
  std::array<unsigned char,64U> leaked_bytes{};
  router::packet::isis::TlvWriter leaked_writer(leaked_bytes);
  v4.down=false; v4.sub_tlvs_present=true; v4.sub_tlvs=attributes.bytes();
  require(router::packet::isis::encode_extended_prefix(leaked_writer,v4));
  const auto leaked=basic_lsp_options(leaked_writer.bytes());
  require(leaked && leaked->find("Attribute Flags : R")!=std::string::npos);
}
