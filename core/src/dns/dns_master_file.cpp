// Master-file lexical and record conversion. Escapes are decoded only after
// token boundaries are known, so escaped dots, semicolons and whitespace never
// acquire control meaning accidentally.

#include "router/dns_master_file.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <limits>
#include <new>

namespace router::dns {
namespace {

struct Token {
  std::string text;
  bool quoted{};
};

struct Entry {
  std::vector<Token> tokens;
  std::size_t line{};
  bool owner_omitted{};
};

struct ImportFrame {
  // Frames model textual $INCLUDE insertion without recursive C++ calls. This
  // allows arbitrarily deep acyclic include graphs until ordinary memory
  // exhaustion, rather than imposing an unrelated protocol depth limit or
  // risking native stack overflow.
  std::vector<Entry> entries;
  std::optional<packet::dns::Name> origin;
  std::string identity;
  std::size_t next_entry{};
};

MasterFileError error(MasterFileErrorCode code, const Entry &entry,
                      std::size_t token = 0U) noexcept {
  return {.code = code, .source = {}, .line = entry.line, .token = token};
}

std::optional<std::vector<Entry>> tokenize(std::string_view text,
                                           MasterFileError &failure) {
  std::vector<Entry> entries;
  Entry entry{.tokens = {}, .line = 1U, .owner_omitted = false};
  Token token;
  std::size_t line{1U};
  std::size_t parentheses{};
  bool quote{};
  bool comment{};
  bool escape{};
  bool token_active{};
  bool entry_started{};

  const auto finish_token = [&]() {
    if (!token_active)
      return;
    entry.tokens.push_back(std::move(token));
    token = {};
    token_active = false;
  };
  const auto finish_entry = [&]() {
    finish_token();
    if (!entry.tokens.empty())
      entries.push_back(std::move(entry));
    entry = {.tokens = {}, .line = line + 1U, .owner_omitted = false};
    entry_started = false;
  };

  for (const auto character : text) {
    if (comment) {
      if (character == '\n') {
        comment = false;
        if (parentheses == 0U)
          finish_entry();
        ++line;
      }
      continue;
    }
    if (escape) {
      token.text.push_back('\\');
      token.text.push_back(character);
      token_active = true;
      escape = false;
      continue;
    }
    if (character == '\\') {
      escape = true;
      token_active = true;
      continue;
    }
    if (quote) {
      if (character == '"') {
        quote = false;
        token.quoted = true;
      } else {
        token.text.push_back(character);
      }
      token_active = true;
      if (character == '\n')
        ++line;
      continue;
    }
    if (character == '"') {
      quote = true;
      token.quoted = true;
      token_active = true;
      entry_started = true;
      continue;
    }
    if (character == ';') {
      finish_token();
      comment = true;
      continue;
    }
    if (character == '(') {
      finish_token();
      ++parentheses;
      entry_started = true;
      continue;
    }
    if (character == ')') {
      finish_token();
      if (parentheses == 0U) {
        failure = {.code = MasterFileErrorCode::unmatched_parenthesis,
                   .source = {},
                   .line = line,
                   .token = entry.tokens.size()};
        return std::nullopt;
      }
      --parentheses;
      continue;
    }
    if (character == '\n') {
      if (parentheses == 0U)
        finish_entry();
      else
        finish_token();
      ++line;
      continue;
    }
    if (std::isspace(static_cast<unsigned char>(character))) {
      if (!entry_started && entry.tokens.empty() && !token_active)
        entry.owner_omitted = true;
      finish_token();
      continue;
    }
    token.text.push_back(character);
    token_active = true;
    entry_started = true;
  }
  if (escape || quote) {
    failure = {.code = quote ? MasterFileErrorCode::unterminated_quote
                             : MasterFileErrorCode::malformed_token,
               .source = {},
               .line = line,
               .token = entry.tokens.size()};
    return std::nullopt;
  }
  if (parentheses != 0U) {
    failure = {.code = MasterFileErrorCode::unmatched_parenthesis,
               .source = {},
               .line = line,
               .token = entry.tokens.size()};
    return std::nullopt;
  }
  finish_entry();
  return entries;
}

std::optional<std::vector<std::uint8_t>> decode_escapes(std::string_view text) {
  std::vector<std::uint8_t> result;
  result.reserve(text.size());
  for (std::size_t index = 0U; index < text.size(); ++index) {
    if (text[index] != '\\') {
      result.push_back(static_cast<std::uint8_t>(text[index]));
      continue;
    }
    if (++index >= text.size())
      return std::nullopt;
    if (std::isdigit(static_cast<unsigned char>(text[index]))) {
      if (index + 2U >= text.size() ||
          !std::isdigit(static_cast<unsigned char>(text[index + 1U])) ||
          !std::isdigit(static_cast<unsigned char>(text[index + 2U])))
        return std::nullopt;
      const auto value = static_cast<unsigned>(text[index] - '0') * 100U +
                         static_cast<unsigned>(text[index + 1U] - '0') * 10U +
                         static_cast<unsigned>(text[index + 2U] - '0');
      if (value > 255U)
        return std::nullopt;
      result.push_back(static_cast<std::uint8_t>(value));
      index += 2U;
    } else {
      result.push_back(static_cast<std::uint8_t>(text[index]));
    }
  }
  return result;
}

std::optional<packet::dns::Name> master_name(std::string_view text,
                                             const packet::dns::Name &origin) {
  if (text == "@")
    return origin;
  // An empty token cannot denote the root. The root has the explicit text
  // form "."; accepting an empty token would hide lexer or caller mistakes.
  if (text.empty())
    return std::nullopt;
  const bool absolute = !text.empty() && text.back() == '.';
  packet::dns::Name result;
  result.octets = 0U;
  std::size_t begin{};
  const auto end = absolute ? text.size() - 1U : text.size();
  while (begin < end) {
    std::size_t delimiter = begin;
    bool escaped{};
    for (; delimiter < end; ++delimiter) {
      if (!escaped && text[delimiter] == '.')
        break;
      if (!escaped && text[delimiter] == '\\')
        escaped = true;
      else
        escaped = false;
    }
    const auto label = decode_escapes(text.substr(begin, delimiter - begin));
    if (!label || label->empty() ||
        label->size() > packet::dns::maximum_label_octets ||
        result.octets + 1U + label->size() >= result.wire.size())
      return std::nullopt;
    result.wire[result.octets++] = static_cast<std::uint8_t>(label->size());
    std::copy(label->begin(), label->end(),
              result.wire.begin() + result.octets);
    result.octets = static_cast<std::uint16_t>(result.octets + label->size());
    begin = delimiter + 1U;
  }
  if (!absolute) {
    if (result.octets + origin.octets > result.wire.size())
      return std::nullopt;
    std::copy_n(origin.wire.begin(), origin.octets,
                result.wire.begin() + result.octets);
    result.octets = static_cast<std::uint16_t>(result.octets + origin.octets);
  } else {
    result.wire[result.octets++] = 0U;
  }
  return result.octets <= packet::dns::maximum_name_octets
             ? std::optional<packet::dns::Name>{result}
             : std::nullopt;
}

template <typename Integer>
std::optional<Integer> decimal(std::string_view text) noexcept {
  Integer result{};
  const auto parsed =
      std::from_chars(text.data(), text.data() + text.size(), result, 10);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size()
             ? std::optional<Integer>{result}
             : std::nullopt;
}

std::string upper(std::string_view text) {
  std::string result{text};
  std::transform(result.begin(), result.end(), result.begin(), [](char value) {
    return static_cast<char>(std::toupper(static_cast<unsigned char>(value)));
  });
  return result;
}

std::optional<std::uint16_t> record_type(std::string_view text) {
  const auto value = upper(text);
  const std::array known{std::pair{"A", packet::dns::type_a},
                         std::pair{"NS", packet::dns::type_ns},
                         std::pair{"MD", packet::dns::type_md},
                         std::pair{"MF", packet::dns::type_mf},
                         std::pair{"CNAME", packet::dns::type_cname},
                         std::pair{"SOA", packet::dns::type_soa},
                         std::pair{"MB", packet::dns::type_mb},
                         std::pair{"MG", packet::dns::type_mg},
                         std::pair{"MR", packet::dns::type_mr},
                         std::pair{"NULL", packet::dns::type_null},
                         std::pair{"WKS", packet::dns::type_wks},
                         std::pair{"PTR", packet::dns::type_ptr},
                         std::pair{"HINFO", packet::dns::type_hinfo},
                         std::pair{"MINFO", packet::dns::type_minfo},
                         std::pair{"MX", packet::dns::type_mx},
                         std::pair{"TXT", packet::dns::type_txt},
                         std::pair{"AAAA", packet::dns::type_aaaa},
                         std::pair{"SRV", packet::dns::type_srv},
                         std::pair{"DNAME", packet::dns::type_dname}};
  for (const auto &[name, type] : known)
    if (value == name)
      return type;
  if (value.starts_with("TYPE"))
    return decimal<std::uint16_t>(std::string_view{value}.substr(4U));
  return std::nullopt;
}

std::optional<std::uint8_t> protocol_number(std::string_view text) {
  if (const auto numeric = decimal<std::uint16_t>(text);
      numeric && *numeric <= std::numeric_limits<std::uint8_t>::max())
    return static_cast<std::uint8_t>(*numeric);

  // RFC 1035 points WKS presentation to the contemporary Assigned Numbers
  // registry. These are every keyword present in RFC 1010's protocol table;
  // entries without a keyword remain expressible by their decimal number.
  static constexpr std::array protocols{
      std::pair{"ICMP", 1U},         std::pair{"IGMP", 2U},
      std::pair{"GGP", 3U},          std::pair{"ST", 5U},
      std::pair{"TCP", 6U},          std::pair{"UCL", 7U},
      std::pair{"EGP", 8U},          std::pair{"IGP", 9U},
      std::pair{"BBN-RCC-MON", 10U}, std::pair{"NVP-II", 11U},
      std::pair{"PUP", 12U},         std::pair{"ARGUS", 13U},
      std::pair{"EMCON", 14U},       std::pair{"XNET", 15U},
      std::pair{"CHAOS", 16U},       std::pair{"UDP", 17U},
      std::pair{"MUX", 18U},         std::pair{"DCN-MEAS", 19U},
      std::pair{"HMP", 20U},         std::pair{"PRM", 21U},
      std::pair{"XNS-IDP", 22U},     std::pair{"TRUNK-1", 23U},
      std::pair{"TRUNK-2", 24U},     std::pair{"LEAF-1", 25U},
      std::pair{"LEAF-2", 26U},      std::pair{"RDP", 27U},
      std::pair{"IRTP", 28U},        std::pair{"ISO-TP4", 29U},
      std::pair{"NETBLT", 30U},      std::pair{"MFE-NSP", 31U},
      std::pair{"MERIT-INP", 32U},   std::pair{"SEP", 33U},
      std::pair{"CFTP", 62U},        std::pair{"SAT-EXPAK", 64U},
      std::pair{"MIT-SUBNET", 65U},  std::pair{"RVD", 66U},
      std::pair{"IPPC", 67U},        std::pair{"SAT-MON", 69U},
      std::pair{"IPCV", 71U},        std::pair{"BR-SAT-MON", 76U},
      std::pair{"WB-MON", 78U},      std::pair{"WB-EXPAK", 79U}};
  const auto name = upper(text);
  const auto found =
      std::find_if(protocols.begin(), protocols.end(),
                   [&](const auto &entry) { return entry.first == name; });
  return found == protocols.end()
             ? std::nullopt
             : std::optional<std::uint8_t>{
                   static_cast<std::uint8_t>(found->second)};
}

std::optional<std::uint16_t> service_port(std::string_view text) {
  if (const auto numeric = decimal<std::uint16_t>(text))
    return numeric;

  // WKS predates today's service-name registry. RFC 1035 normatively points
  // at RFC 1010, so accepting later aliases would change the grammar of the
  // pinned master-file format. Every RFC 1010 keyword is represented here.
  static constexpr std::array services{
      std::pair{"RJE", 5U},           std::pair{"ECHO", 7U},
      std::pair{"DISCARD", 9U},       std::pair{"USERS", 11U},
      std::pair{"DAYTIME", 13U},      std::pair{"QUOTE", 17U},
      std::pair{"CHARGEN", 19U},      std::pair{"FTP-DATA", 20U},
      std::pair{"FTP", 21U},          std::pair{"TELNET", 23U},
      std::pair{"SMTP", 25U},         std::pair{"NSW-FE", 27U},
      std::pair{"MSG-ICP", 29U},      std::pair{"MSG-AUTH", 31U},
      std::pair{"DSP", 33U},          std::pair{"TIME", 37U},
      std::pair{"RLP", 39U},          std::pair{"GRAPHICS", 41U},
      std::pair{"NAMESERVER", 42U},   std::pair{"NICNAME", 43U},
      std::pair{"MPM-FLAGS", 44U},    std::pair{"MPM", 45U},
      std::pair{"MPM-SND", 46U},      std::pair{"NI-FTP", 47U},
      std::pair{"LOGIN", 49U},        std::pair{"LA-MAINT", 51U},
      std::pair{"DOMAIN", 53U},       std::pair{"ISI-GL", 55U},
      std::pair{"NI-MAIL", 61U},      std::pair{"VIA-FTP", 63U},
      std::pair{"TACACS-DS", 65U},    std::pair{"BOOTPS", 67U},
      std::pair{"BOOTPC", 68U},       std::pair{"TFTP", 69U},
      std::pair{"NETRJS-1", 71U},     std::pair{"NETRJS-2", 72U},
      std::pair{"NETRJS-3", 73U},     std::pair{"NETRJS-4", 74U},
      std::pair{"FINGER", 79U},       std::pair{"HOSTS2-NS", 81U},
      std::pair{"MIT-ML-DEV", 83U},   std::pair{"SU-MIT-TG", 89U},
      std::pair{"MIT-DOV", 91U},      std::pair{"DCP", 93U},
      std::pair{"SUPDUP", 95U},       std::pair{"SWIFT-RVF", 97U},
      std::pair{"TACNEWS", 98U},      std::pair{"METAGRAM", 99U},
      std::pair{"HOSTNAME", 101U},    std::pair{"ISO-TSAP", 102U},
      std::pair{"X400", 103U},        std::pair{"X400-SND", 104U},
      std::pair{"CSNET-NS", 105U},    std::pair{"RTELNET", 107U},
      std::pair{"POP-2", 109U},       std::pair{"SUNRPC", 111U},
      std::pair{"AUTH", 113U},        std::pair{"SFTP", 115U},
      std::pair{"UUCP-PATH", 117U},   std::pair{"NNTP", 119U},
      std::pair{"ERPC", 121U},        std::pair{"NTP", 123U},
      std::pair{"LOCUS-MAP", 125U},   std::pair{"LOCUS-CON", 127U},
      std::pair{"PWDGEN", 129U},      std::pair{"CISCO-FNA", 130U},
      std::pair{"CISCO-TNA", 131U},   std::pair{"CISCO-SYS", 132U},
      std::pair{"STATSRV", 133U},     std::pair{"INGRES-NET", 134U},
      std::pair{"LOC-SRV", 135U},     std::pair{"PROFILE", 136U},
      std::pair{"NETBIOS-NS", 137U},  std::pair{"NETBIOS-DGM", 138U},
      std::pair{"NETBIOS-SSN", 139U}, std::pair{"EMFIS-DATA", 140U},
      std::pair{"EMFIS-CNTL", 141U},  std::pair{"BL-IDM", 142U},
      std::pair{"SUR-MEAS", 243U},    std::pair{"LINK", 245U}};
  const auto name = upper(text);
  const auto found =
      std::find_if(services.begin(), services.end(),
                   [&](const auto &entry) { return entry.first == name; });
  return found == services.end()
             ? std::nullopt
             : std::optional<std::uint16_t>{
                   static_cast<std::uint16_t>(found->second)};
}

bool append_character_string(std::vector<std::uint8_t> &output,
                             const Token &token) {
  const auto bytes = decode_escapes(token.text);
  if (!bytes || bytes->size() > 255U)
    return false;
  output.push_back(static_cast<std::uint8_t>(bytes->size()));
  output.insert(output.end(), bytes->begin(), bytes->end());
  return true;
}

void append_u16(std::vector<std::uint8_t> &output, std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
  output.push_back(static_cast<std::uint8_t>(value));
}

void append_u32(std::vector<std::uint8_t> &output, std::uint32_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 24U));
  output.push_back(static_cast<std::uint8_t>(value >> 16U));
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
  output.push_back(static_cast<std::uint8_t>(value));
}

bool append_name(std::vector<std::uint8_t> &output, const Token &token,
                 const packet::dns::Name &origin) {
  const auto value = master_name(token.text, origin);
  if (!value)
    return false;
  output.insert(output.end(), value->wire.begin(),
                value->wire.begin() + value->octets);
  return true;
}

std::optional<std::vector<std::uint8_t>>
generic_rdata(std::span<const Token> tokens) {
  if (tokens.size() < 2U || tokens[0].text != "\\#")
    return std::nullopt;
  const auto expected = decimal<std::size_t>(tokens[1].text);
  if (!expected || *expected > std::numeric_limits<std::uint16_t>::max())
    return std::nullopt;
  std::string hex;
  for (std::size_t index = 2U; index < tokens.size(); ++index)
    hex += tokens[index].text;
  if (hex.size() != *expected * 2U)
    return std::nullopt;
  std::vector<std::uint8_t> output;
  output.reserve(*expected);
  for (std::size_t index = 0U; index < hex.size(); index += 2U) {
    unsigned value{};
    const auto parsed =
        std::from_chars(hex.data() + index, hex.data() + index + 2U, value, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != hex.data() + index + 2U)
      return std::nullopt;
    output.push_back(static_cast<std::uint8_t>(value));
  }
  return output;
}

std::optional<std::vector<std::uint8_t>>
typed_rdata(std::uint16_t type, std::span<const Token> tokens,
            const packet::dns::Name &origin) {
  if (!tokens.empty() && tokens[0].text == "\\#")
    return generic_rdata(tokens);
  std::vector<std::uint8_t> output;
  if (type == packet::dns::type_a) {
    if (tokens.size() != 1U)
      return std::nullopt;
    std::size_t begin{};
    for (std::size_t octet = 0U; octet < 4U; ++octet) {
      const auto end = tokens[0].text.find('.', begin);
      const auto part = tokens[0].text.substr(
          begin, end == std::string::npos ? end : end - begin);
      const auto value = decimal<std::uint16_t>(part);
      if (!value || *value > 255U || (octet < 3U) == (end == std::string::npos))
        return std::nullopt;
      output.push_back(static_cast<std::uint8_t>(*value));
      // Avoid relying on unsigned wrap after the fourth field. That wrap was
      // harmless because the loop ended immediately, but keeping indices valid
      // makes future changes to this parser safe.
      if (end != std::string::npos)
        begin = end + 1U;
    }
    return output;
  }
  if (type == packet::dns::type_aaaa) {
    if (tokens.size() != 1U)
      return std::nullopt;
    const auto address = ip::parse_ipv6(tokens[0].text);
    return address ? std::optional<std::vector<std::uint8_t>>{std::vector<
                         std::uint8_t>{address->begin(), address->end()}}
                   : std::nullopt;
  }
  if (type == packet::dns::type_ns || type == packet::dns::type_cname ||
      type == packet::dns::type_ptr || type == packet::dns::type_dname ||
      type == packet::dns::type_md || type == packet::dns::type_mf ||
      type == packet::dns::type_mb || type == packet::dns::type_mg ||
      type == packet::dns::type_mr) {
    if (tokens.size() != 1U || !append_name(output, tokens[0], origin))
      return std::nullopt;
    return output;
  }
  if (type == packet::dns::type_mx || type == packet::dns::type_srv) {
    const auto numeric_fields = type == packet::dns::type_mx ? 1U : 3U;
    if (tokens.size() != numeric_fields + 1U)
      return std::nullopt;
    for (std::size_t index = 0U; index < numeric_fields; ++index) {
      const auto value = decimal<std::uint16_t>(tokens[index].text);
      if (!value)
        return std::nullopt;
      append_u16(output, *value);
    }
    if (!append_name(output, tokens[numeric_fields], origin))
      return std::nullopt;
    return output;
  }
  if (type == packet::dns::type_soa) {
    if (tokens.size() != 7U || !append_name(output, tokens[0], origin) ||
        !append_name(output, tokens[1], origin))
      return std::nullopt;
    for (std::size_t index = 2U; index < tokens.size(); ++index) {
      const auto value = decimal<std::uint32_t>(tokens[index].text);
      if (!value)
        return std::nullopt;
      append_u32(output, *value);
    }
    return output;
  }
  if (type == packet::dns::type_txt || type == packet::dns::type_hinfo) {
    // HINFO has exactly CPU and OS. TXT has one or more strings. Both use the
    // same RFC 1035 length-prefixed character-string wire representation.
    if ((type == packet::dns::type_hinfo && tokens.size() != 2U) ||
        (type == packet::dns::type_txt && tokens.empty()))
      return std::nullopt;
    for (const auto &token : tokens)
      if (!append_character_string(output, token))
        return std::nullopt;
    return output;
  }
  if (type == packet::dns::type_minfo) {
    if (tokens.size() != 2U || !append_name(output, tokens[0], origin) ||
        !append_name(output, tokens[1], origin))
      return std::nullopt;
    return output;
  }
  if (type == packet::dns::type_wks) {
    // WKS consists of the IPv4 address, one protocol octet and a dense bit
    // map whose most significant bit is the lowest port in each octet.
    if (tokens.size() < 2U)
      return std::nullopt;
    std::size_t begin{};
    for (std::size_t octet = 0U; octet < 4U; ++octet) {
      const auto end = tokens[0].text.find('.', begin);
      const auto part = tokens[0].text.substr(
          begin, end == std::string::npos ? end : end - begin);
      const auto value = decimal<std::uint16_t>(part);
      if (!value || *value > 255U || (octet < 3U) == (end == std::string::npos))
        return std::nullopt;
      output.push_back(static_cast<std::uint8_t>(*value));
      if (end != std::string::npos)
        begin = end + 1U;
    }
    const auto protocol = protocol_number(tokens[1].text);
    if (!protocol)
      return std::nullopt;
    output.push_back(*protocol);

    std::vector<std::uint16_t> ports;
    ports.reserve(tokens.size() - 2U);
    for (std::size_t index = 2U; index < tokens.size(); ++index) {
      const auto port = service_port(tokens[index].text);
      if (!port)
        return std::nullopt;
      ports.push_back(*port);
    }
    if (!ports.empty()) {
      const auto highest = *std::max_element(ports.begin(), ports.end());
      output.resize(output.size() + highest / 8U + 1U, 0U);
      const auto bitmap = output.size() - (highest / 8U + 1U);
      for (const auto port : ports)
        output[bitmap + port / 8U] |=
            static_cast<std::uint8_t>(0x80U >> (port % 8U));
    }
    return output;
  }
  if (type == packet::dns::type_null) {
    // RFC 1035 explicitly prohibits NULL's mnemonic form in master files.
    // RFC 3597 generic TYPE10 syntax remains accepted by generic_rdata above.
    return std::nullopt;
  }
  return std::nullopt;
}

std::string master_name_text(const packet::dns::Name &name) {
  std::string output;
  std::size_t offset{};
  while (offset < name.octets && name.wire[offset] != 0U) {
    const auto length = name.wire[offset++];
    if (!output.empty())
      output.push_back('.');
    for (std::size_t index = 0U; index < length; ++index) {
      const auto value = name.wire[offset++];
      const bool ordinary = std::isalnum(value) || value == '-' || value == '_';
      if (ordinary)
        output.push_back(static_cast<char>(value));
      else {
        output.push_back('\\');
        output.push_back(static_cast<char>('0' + value / 100U));
        output.push_back(static_cast<char>('0' + (value / 10U) % 10U));
        output.push_back(static_cast<char>('0' + value % 10U));
      }
    }
  }
  output.push_back('.');
  return output;
}

} // namespace

MasterFileResult
import_master_file(std::string_view text,
                   std::optional<packet::dns::Name> initial_origin,
                   std::optional<std::uint32_t> initial_ttl,
                   const MasterFileIncludeResolver *include_resolver,
                   std::string_view source_identity) noexcept {
  try {
    MasterFileError lexical_error;
    auto root_entries = tokenize(text, lexical_error);
    if (!root_entries) {
      lexical_error.source = source_identity;
      return {.records = {}, .error = lexical_error};
    }

    std::vector<ImportFrame> frames;
    frames.push_back({.entries = std::move(*root_entries),
                      .origin = initial_origin,
                      .identity = std::string{source_identity},
                      .next_entry = 0U});
    auto default_ttl = initial_ttl;
    std::optional<std::uint32_t> last_ttl;
    std::optional<packet::dns::Name> last_owner;
    std::vector<ZoneRecord> records;
    records.reserve(frames.front().entries.size());

    while (!frames.empty()) {
      auto &frame = frames.back();
      if (frame.next_entry == frame.entries.size()) {
        frames.pop_back();
        continue;
      }
      const auto &entry = frame.entries[frame.next_entry++];
      const auto fail = [&](MasterFileErrorCode code,
                            std::size_t token = 0U) -> MasterFileResult {
        auto detail = error(code, entry, token);
        detail.source = frame.identity;
        return {.records = {}, .error = std::move(detail)};
      };

      if (entry.tokens.front().text.starts_with('$')) {
        const auto directive = upper(entry.tokens.front().text);
        if (directive == "$INCLUDE") {
          if (entry.tokens.size() < 2U || entry.tokens.size() > 3U)
            return fail(MasterFileErrorCode::malformed_token);
          if (!include_resolver || !*include_resolver)
            return fail(MasterFileErrorCode::include_unavailable, 1U);

          const auto requested_bytes = decode_escapes(entry.tokens[1].text);
          if (!requested_bytes || requested_bytes->empty())
            return fail(MasterFileErrorCode::malformed_token, 1U);
          const std::string requested{
              reinterpret_cast<const char *>(requested_bytes->data()),
              requested_bytes->size()};
          std::optional<MasterFileInclude> included;
          try {
            included = (*include_resolver)(frame.identity, requested);
          } catch (const std::bad_alloc &) {
            throw;
          } catch (...) {
            // A storage adapter failure is an unavailable include, not an
            // exception crossing the noexcept protocol boundary.
            return fail(MasterFileErrorCode::include_unavailable, 1U);
          }
          if (!included || included->canonical_name.empty())
            return fail(MasterFileErrorCode::include_unavailable, 1U);
          if (std::any_of(frames.begin(), frames.end(),
                          [&](const auto &active) {
                            return !active.identity.empty() &&
                                   active.identity == included->canonical_name;
                          }))
            return fail(MasterFileErrorCode::include_cycle, 1U);

          auto child_origin = frame.origin;
          if (entry.tokens.size() == 3U) {
            const auto absolute = !entry.tokens[2].text.empty() &&
                                  entry.tokens[2].text.back() == '.';
            if (!absolute && !frame.origin)
              return fail(MasterFileErrorCode::missing_origin, 2U);
            const packet::dns::Name root{};
            child_origin =
                master_name(entry.tokens[2].text, frame.origin.value_or(root));
            if (!child_origin)
              return fail(MasterFileErrorCode::invalid_owner, 2U);
          }

          MasterFileError included_error;
          auto included_entries = tokenize(included->contents, included_error);
          if (!included_entries) {
            included_error.source = included->canonical_name;
            return {.records = {}, .error = std::move(included_error)};
          }
          // Parent origin is stored in its frame and therefore restored when
          // this child is popped. Owner, TTL and class defaults intentionally
          // remain shared because RFC 1035 defines insertion semantics and
          // scopes only the included origin.
          frames.push_back({.entries = std::move(*included_entries),
                            .origin = child_origin,
                            .identity = std::move(included->canonical_name),
                            .next_entry = 0U});
          continue;
        }
        if (directive == "$ORIGIN") {
          if (entry.tokens.size() != 2U)
            return fail(MasterFileErrorCode::malformed_token);
          const packet::dns::Name root{};
          const auto parsed =
              master_name(entry.tokens[1].text, frame.origin.value_or(root));
          if (!parsed)
            return fail(MasterFileErrorCode::invalid_owner, 1U);
          frame.origin = *parsed;
          continue;
        }
        if (directive == "$TTL") {
          if (entry.tokens.size() != 2U)
            return fail(MasterFileErrorCode::invalid_ttl);
          const auto parsed = decimal<std::uint32_t>(entry.tokens[1].text);
          if (!parsed || *parsed > 0x7fffffffU)
            return fail(MasterFileErrorCode::invalid_ttl, 1U);
          default_ttl = *parsed;
          continue;
        }
        return fail(MasterFileErrorCode::unsupported_directive);
      }
      if (!frame.origin)
        return fail(MasterFileErrorCode::missing_origin);
      std::size_t index{};
      packet::dns::Name owner;
      if (entry.owner_omitted) {
        if (!last_owner)
          return fail(MasterFileErrorCode::missing_owner);
        owner = *last_owner;
      } else {
        const auto parsed =
            master_name(entry.tokens[index++].text, *frame.origin);
        if (!parsed)
          return fail(MasterFileErrorCode::invalid_owner);
        owner = *parsed;
        last_owner = owner;
      }

      std::optional<std::uint32_t> ttl;
      bool internet_class{};
      std::optional<std::uint16_t> type;
      for (; index < entry.tokens.size(); ++index) {
        const auto value = upper(entry.tokens[index].text);
        if (value == "IN" || value == "CLASS1") {
          internet_class = true;
          continue;
        }
        if (!ttl) {
          const auto parsed_ttl = decimal<std::uint32_t>(value);
          if (parsed_ttl) {
            if (*parsed_ttl > 0x7fffffffU)
              return fail(MasterFileErrorCode::invalid_ttl, index);
            ttl = *parsed_ttl;
            last_ttl = ttl;
            continue;
          }
        }
        type = record_type(value);
        if (type) {
          ++index;
          break;
        }
        return fail(MasterFileErrorCode::invalid_type, index);
      }
      if (!type)
        return fail(MasterFileErrorCode::invalid_type);
      if (!internet_class)
        internet_class = true;
      // RFC 2308 gives $TTL the default-TTL role. The older RFC 1035 form used
      // the last explicit TTL, which remains the final compatibility fallback.
      const auto effective_ttl =
          ttl ? ttl : (default_ttl ? default_ttl : last_ttl);
      if (!effective_ttl)
        return fail(MasterFileErrorCode::missing_ttl);
      const auto rdata = typed_rdata(
          *type, std::span<const Token>{entry.tokens}.subspan(index),
          *frame.origin);
      if (!rdata)
        return fail(MasterFileErrorCode::invalid_rdata, index);
      records.push_back({.owner = owner,
                         .type = *type,
                         .record_class = packet::dns::internet_class,
                         .ttl = *effective_ttl,
                         .rdata = std::move(*rdata)});
    }
    return {.records = std::move(records), .error = {}};
  } catch (const std::bad_alloc &) {
    return {.records = {},
            .error = {.code = MasterFileErrorCode::resource_exhausted,
                      .source = {},
                      .line = 0U,
                      .token = 0U}};
  }
}

std::optional<std::string>
export_master_file(const packet::dns::Name &origin,
                   std::span<const ZoneRecord> records) noexcept {
  try {
    packet::dns::Name validated;
    const auto consumed = packet::dns::parse_name(origin.view(), 0U, validated);
    if (!consumed || *consumed != origin.octets)
      return std::nullopt;
    std::string output = "$ORIGIN " + master_name_text(origin) + "\n";
    for (const auto &record : records) {
      packet::dns::Name validated_owner;
      const auto owner_consumed =
          packet::dns::parse_name(record.owner.view(), 0U, validated_owner);
      if (!owner_consumed || *owner_consumed != record.owner.octets ||
          record.rdata.size() > std::numeric_limits<std::uint16_t>::max())
        return std::nullopt;
      output += master_name_text(record.owner) + " " +
                std::to_string(record.ttl) + " IN TYPE" +
                std::to_string(record.type) + " \\# " +
                std::to_string(record.rdata.size());
      static constexpr char hex[] = "0123456789ABCDEF";
      if (!record.rdata.empty())
        output.push_back(' ');
      for (const auto byte : record.rdata) {
        output.push_back(hex[byte >> 4U]);
        output.push_back(hex[byte & 0x0fU]);
      }
      output.push_back('\n');
    }
    return output;
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

} // namespace router::dns
