// OpenSSL 3.5 TLS 1.3 adapter over bounded BIO pairs. SSL owns the internal BIO
// endpoint. Engine owns the network endpoint that exchanges ciphertext with
// modeled TCP. No BIO is connected to a host file descriptor.
// Source: ietf.tls13.rfc8446
// Source: openssl.tls.memory_bio.3_5

#include "router/tls_engine.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <string>

namespace router::pki::tls_access {

class EngineAccess final {
public:
  [[nodiscard]] static EVP_PKEY *private_key(OpenIdentity &identity) noexcept {
    return static_cast<EVP_PKEY *>(identity.native_private_key());
  }
};

} // namespace router::pki::tls_access

namespace router::tls {
namespace {

template <typename T, void (*Free)(T *)> struct OpenSslDeleter {
  void operator()(T *value) const noexcept {
    if (value)
      Free(value);
  }
};

struct BioDeleter {
  void operator()(BIO *value) const noexcept {
    if (value)
      static_cast<void>(BIO_free(value));
  }
};

using ContextOwner =
    std::unique_ptr<SSL_CTX, OpenSslDeleter<SSL_CTX, SSL_CTX_free>>;
using SslOwner = std::unique_ptr<SSL, OpenSslDeleter<SSL, SSL_free>>;
using BioOwner = std::unique_ptr<BIO, BioDeleter>;
using X509Owner = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;
using PkeyOwner =
    std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;

X509Owner decode_certificate(std::span<const std::uint8_t> der) noexcept {
  if (der.empty() ||
      der.size() > static_cast<std::size_t>(std::numeric_limits<long>::max()))
    return {};
  const auto *cursor = der.data();
  X509Owner certificate{
      d2i_X509(nullptr, &cursor, static_cast<long>(der.size()))};
  return certificate && cursor == der.data() + der.size()
             ? std::move(certificate)
             : X509Owner{};
}

bool self_signed(X509 *certificate) noexcept {
  if (!certificate ||
      X509_NAME_cmp(X509_get_subject_name(certificate),
                    X509_get_issuer_name(certificate)) != 0)
    return false;
  PkeyOwner public_key{X509_get_pubkey(certificate)};
  return public_key && X509_verify(certificate, public_key.get()) == 1;
}

bool install_identity(SSL_CTX *context, pki::OpenIdentity &identity) {
  const auto chain = identity.certificate_chain_der();
  auto *private_key = pki::tls_access::EngineAccess::private_key(identity);
  if (!context || !private_key || chain.empty())
    return false;
  auto leaf = decode_certificate(chain.front());
  if (!leaf || SSL_CTX_use_certificate(context, leaf.get()) != 1 ||
      SSL_CTX_use_PrivateKey(context, private_key) != 1 ||
      SSL_CTX_check_private_key(context) != 1 ||
      SSL_CTX_clear_chain_certs(context) != 1)
    return false;
  for (std::size_t index = 1U; index < chain.size(); ++index) {
    auto certificate = decode_certificate(chain[index]);
    if (!certificate)
      return false;
    // RFC 8446 permits omission of the self-signed trust anchor and deployed
    // TLS servers normally omit it. Intermediates remain in leaf-to-root order.
    if (index + 1U == chain.size() && self_signed(certificate.get()))
      continue;
    if (SSL_CTX_add1_chain_cert(context, certificate.get()) != 1)
      return false;
  }
  return true;
}

bool install_trust_anchors(
    SSL_CTX *context,
    std::span<const std::vector<std::uint8_t>> anchors) {
  auto *store = context ? SSL_CTX_get_cert_store(context) : nullptr;
  if (!store)
    return false;
  for (const auto &der : anchors) {
    auto certificate = decode_certificate(der);
    if (!certificate || X509_STORE_add_cert(store, certificate.get()) != 1)
      return false;
  }
  return true;
}

bool valid_clock(std::uint64_t seconds) noexcept {
  return seconds != 0U &&
         seconds <= static_cast<std::uint64_t>(
                        std::numeric_limits<std::time_t>::max());
}

std::optional<std::string>
openssl_list(std::span<const std::string_view> names) {
  if (names.empty())
    return std::nullopt;
  std::size_t bytes = names.size() - 1U;
  for (const auto name : names) {
    // A colon is OpenSSL's list separator. Rejecting it here keeps one SR OS
    // list entry from smuggling multiple provider algorithms past the release
    // resolver and preserves exact operator order.
    if (name.empty() || name.find(':') != std::string_view::npos ||
        name.size() > std::numeric_limits<std::size_t>::max() - bytes)
      return std::nullopt;
    bytes += name.size();
  }
  std::string joined;
  joined.reserve(bytes);
  for (const auto name : names) {
    if (!joined.empty())
      joined.push_back(':');
    joined.append(name);
  }
  return joined;
}

std::optional<std::vector<std::uint8_t>>
alpn_wire(std::span<const std::string_view> protocols) {
  if (protocols.empty())
    return std::vector<std::uint8_t>{};
  std::size_t octets{};
  for (const auto protocol : protocols) {
    if (protocol.empty() || protocol.size() > 255U ||
        octets > std::numeric_limits<std::uint16_t>::max() -
                     (protocol.size() + 1U))
      return std::nullopt;
    octets += protocol.size() + 1U;
  }
  try {
    std::vector<std::uint8_t> wire;
    wire.reserve(octets);
    for (const auto protocol : protocols) {
      wire.push_back(static_cast<std::uint8_t>(protocol.size()));
      wire.insert(wire.end(), protocol.begin(), protocol.end());
    }
    return wire;
  } catch (...) {
    return std::nullopt;
  }
}

bool install_policy(SSL_CTX *context, const Tls13PolicyView *policy,
                    bool server) {
  if (!policy)
    return true;
  const auto ciphers = openssl_list(policy->cipher_suites);
  const auto groups = openssl_list(policy->groups);
  const auto signatures = openssl_list(policy->signatures);
  if (!context || !ciphers || !groups || !signatures ||
      SSL_CTX_set_ciphersuites(context, ciphers->c_str()) != 1 ||
      SSL_CTX_set1_groups_list(context, groups->c_str()) != 1 ||
      SSL_CTX_set1_sigalgs_list(context, signatures->c_str()) != 1)
    return false;
  if (server)
    // The SR OS server list is explicitly ordered by its numeric keys. Asking
    // OpenSSL to prefer that order keeps the configured server policy from
    // being silently replaced by the client's preference.
    static_cast<void>(SSL_CTX_set_options(
        context, static_cast<std::uint64_t>(SSL_OP_CIPHER_SERVER_PREFERENCE)));
  return true;
}

bool configure_tls13(SSL_CTX *context, std::uint64_t wall_clock_seconds,
                     const Tls13PolicyView *policy, bool server) {
  if (!context || !valid_clock(wall_clock_seconds) ||
      SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1 ||
      !install_policy(context, policy, server))
    return false;
  auto *parameters = SSL_CTX_get0_param(context);
  if (!parameters)
    return false;
  X509_VERIFY_PARAM_set_time(
      parameters, static_cast<std::time_t>(wall_clock_seconds));
  return true;
}

bool valid_peer_identity(const PeerIdentity &identity) noexcept {
  const auto selectors = static_cast<unsigned>(!identity.hostname.empty()) +
                         static_cast<unsigned>(identity.ipv4_address.has_value()) +
                         static_cast<unsigned>(identity.ipv6_address.has_value());
  return selectors <= 1U &&
         identity.hostname.find('\0') == std::string::npos;
}

} // namespace

struct Engine::Impl {
  ContextOwner context;
  SslOwner ssl;
  BioOwner network_bio;
  State state{State::handshaking};
  Failure failure{Failure::none};
  long provider_error{};
  std::vector<std::uint8_t> server_alpn_wire;

  static int select_alpn(SSL *, const unsigned char **selected,
                         unsigned char *selected_length,
                         const unsigned char *client_protocols,
                         unsigned int client_protocols_length,
                         void *context) noexcept {
    const auto *self = static_cast<const Impl *>(context);
    if (!self || self->server_alpn_wire.empty())
      return SSL_TLSEXT_ERR_NOACK;
    unsigned char *choice{};
    unsigned char choice_length{};
    const auto result = SSL_select_next_proto(
        &choice, &choice_length, self->server_alpn_wire.data(),
        static_cast<unsigned int>(self->server_alpn_wire.size()),
        client_protocols, client_protocols_length);
    if (result != OPENSSL_NPN_NEGOTIATED)
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    *selected = choice;
    *selected_length = choice_length;
    return SSL_TLSEXT_ERR_OK;
  }

  void fail(Failure reason) noexcept {
    state = State::failed;
    failure = reason;
    provider_error = static_cast<long>(ERR_peek_last_error());
  }

  void consume_ssl_result(int result) noexcept {
    if (result > 0)
      return;
    const auto error = SSL_get_error(ssl.get(), result);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
      return;
    if (error == SSL_ERROR_ZERO_RETURN) {
      state = State::closed;
      failure = Failure::peer_closed;
      return;
    }
    fail(SSL_get_verify_result(ssl.get()) == X509_V_OK
             ? Failure::protocol_error
             : Failure::certificate_rejected);
  }
};

Engine::Engine(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Engine::Engine(Engine &&) noexcept = default;
Engine &Engine::operator=(Engine &&) noexcept = default;
Engine::~Engine() = default;

std::optional<Engine>
Engine::client(const ClientConfiguration &configuration) noexcept {
  const bool authenticate = configuration.peer_authentication ==
                            PeerAuthentication::required;
  // A disabled policy is explicit and must not carry anchors that would be
  // ignored. A required policy uses only project anchors and never inherits a
  // host trust store. Client certificates remain independently optional.
  const auto encoded_alpn = alpn_wire(configuration.alpn_protocols);
  if (!encoded_alpn ||
      (authenticate && configuration.trust_anchors_der.empty()) ||
      (!authenticate && !configuration.trust_anchors_der.empty()) ||
      configuration.transport_buffer_octets <
          minimum_transport_buffer_octets ||
      !valid_peer_identity(configuration.peer))
    return std::nullopt;
  try {
    auto impl = std::make_unique<Impl>();
    impl->context.reset(SSL_CTX_new(TLS_method()));
    if (!impl->context ||
        !configure_tls13(impl->context.get(),
                         configuration.wall_clock_seconds,
                         configuration.policy, false) ||
        (authenticate &&
         !install_trust_anchors(impl->context.get(),
                                configuration.trust_anchors_der)) ||
        (configuration.identity &&
         !install_identity(impl->context.get(), *configuration.identity)))
      return std::nullopt;
    if (!encoded_alpn->empty() &&
        SSL_CTX_set_alpn_protos(
            impl->context.get(), encoded_alpn->data(),
            static_cast<unsigned int>(encoded_alpn->size())) != 0)
      return std::nullopt;
    SSL_CTX_set_verify(impl->context.get(),
                       authenticate ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                       nullptr);
    impl->ssl.reset(SSL_new(impl->context.get()));
    BIO *internal{};
    BIO *network{};
    if (!impl->ssl ||
        BIO_new_bio_pair(&internal, configuration.transport_buffer_octets,
                         &network, configuration.transport_buffer_octets) != 1) {
      BIO_free(internal);
      BIO_free(network);
      return std::nullopt;
    }
    impl->network_bio.reset(network);
    SSL_set_bio(impl->ssl.get(), internal, internal);
    SSL_set_connect_state(impl->ssl.get());
    SSL_set_mode(impl->ssl.get(), SSL_MODE_ENABLE_PARTIAL_WRITE |
                                      SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    auto *parameters = SSL_get0_param(impl->ssl.get());
    if (!parameters)
      return std::nullopt;
    if (!configuration.peer.hostname.empty()) {
      if (SSL_set_tlsext_host_name(impl->ssl.get(),
                                   configuration.peer.hostname.c_str()) != 1 ||
          (authenticate &&
           SSL_set1_host(impl->ssl.get(),
                         configuration.peer.hostname.c_str()) != 1))
        return std::nullopt;
    } else if (authenticate && configuration.peer.ipv4_address) {
      if (X509_VERIFY_PARAM_set1_ip(
              parameters, configuration.peer.ipv4_address->data(),
              configuration.peer.ipv4_address->size()) != 1)
        return std::nullopt;
    } else if (authenticate && configuration.peer.ipv6_address &&
               X509_VERIFY_PARAM_set1_ip(
                   parameters, configuration.peer.ipv6_address->data(),
                   configuration.peer.ipv6_address->size()) != 1) {
      return std::nullopt;
    }
    return Engine{std::move(impl)};
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<Engine>
Engine::server(const ServerConfiguration &configuration) noexcept {
  auto encoded_alpn = alpn_wire(configuration.alpn_protocols);
  if (!encoded_alpn || !configuration.identity ||
      configuration.transport_buffer_octets <
          minimum_transport_buffer_octets ||
      (configuration.require_client_certificate &&
       configuration.trust_anchors_der.empty()))
    return std::nullopt;
  try {
    auto impl = std::make_unique<Impl>();
    impl->server_alpn_wire = std::move(*encoded_alpn);
    impl->context.reset(SSL_CTX_new(TLS_method()));
    if (!impl->context ||
        !configure_tls13(impl->context.get(),
                         configuration.wall_clock_seconds,
                         configuration.policy, true) ||
        !install_identity(impl->context.get(), *configuration.identity) ||
        (!configuration.trust_anchors_der.empty() &&
         !install_trust_anchors(impl->context.get(),
                                configuration.trust_anchors_der)))
      return std::nullopt;
    if (!impl->server_alpn_wire.empty())
      SSL_CTX_set_alpn_select_cb(impl->context.get(), &Impl::select_alpn,
                                 impl.get());
    SSL_CTX_set_verify(
        impl->context.get(),
        configuration.require_client_certificate
            ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            : SSL_VERIFY_NONE,
        nullptr);
    impl->ssl.reset(SSL_new(impl->context.get()));
    BIO *internal{};
    BIO *network{};
    if (!impl->ssl ||
        BIO_new_bio_pair(&internal, configuration.transport_buffer_octets,
                         &network, configuration.transport_buffer_octets) != 1) {
      BIO_free(internal);
      BIO_free(network);
      return std::nullopt;
    }
    impl->network_bio.reset(network);
    SSL_set_bio(impl->ssl.get(), internal, internal);
    SSL_set_accept_state(impl->ssl.get());
    SSL_set_mode(impl->ssl.get(), SSL_MODE_ENABLE_PARTIAL_WRITE |
                                      SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return Engine{std::move(impl)};
  } catch (...) {
    return std::nullopt;
  }
}

std::size_t
Engine::ingest_ciphertext(std::span<const std::uint8_t> bytes) noexcept {
  if (!impl_ || !impl_->network_bio || bytes.empty() ||
      impl_->state == State::failed || impl_->state == State::closed)
    return 0U;
  std::size_t written{};
  return BIO_write_ex(impl_->network_bio.get(), bytes.data(), bytes.size(),
                      &written) == 1
             ? written
             : 0U;
}

std::size_t Engine::take_ciphertext(std::span<std::uint8_t> output) noexcept {
  if (!impl_ || !impl_->network_bio || output.empty())
    return 0U;
  std::size_t read{};
  return BIO_read_ex(impl_->network_bio.get(), output.data(), output.size(),
                     &read) == 1
             ? read
             : 0U;
}

std::size_t Engine::pending_ciphertext() const noexcept {
  return impl_ && impl_->network_bio
             ? static_cast<std::size_t>(BIO_ctrl_pending(
                   impl_->network_bio.get()))
             : 0U;
}

State Engine::progress() noexcept {
  if (!impl_)
    return State::failed;
  if (impl_->state != State::handshaking)
    return impl_->state;
  ERR_clear_error();
  const auto result = SSL_do_handshake(impl_->ssl.get());
  if (result == 1)
    impl_->state = State::established;
  else
    impl_->consume_ssl_result(result);
  return impl_->state;
}

std::size_t
Engine::write_plaintext(std::span<const std::uint8_t> bytes) noexcept {
  if (!impl_ || impl_->state != State::established || bytes.empty())
    return 0U;
  ERR_clear_error();
  std::size_t written{};
  const auto result = SSL_write_ex(impl_->ssl.get(), bytes.data(), bytes.size(),
                                   &written);
  if (result != 1)
    impl_->consume_ssl_result(result);
  return written;
}

std::size_t Engine::read_plaintext(std::span<std::uint8_t> output) noexcept {
  if (!impl_ || impl_->state != State::established || output.empty())
    return 0U;
  ERR_clear_error();
  std::size_t read{};
  const auto result =
      SSL_read_ex(impl_->ssl.get(), output.data(), output.size(), &read);
  if (result != 1)
    impl_->consume_ssl_result(result);
  return read;
}

State Engine::shutdown() noexcept {
  if (!impl_)
    return State::failed;
  if (impl_->state == State::closed || impl_->state == State::failed)
    return impl_->state;
  ERR_clear_error();
  const auto result = SSL_shutdown(impl_->ssl.get());
  if (result == 1) {
    impl_->state = State::closed;
  } else if (result == 0) {
    impl_->state = State::closing;
  } else {
    impl_->consume_ssl_result(result);
    if (impl_->state != State::failed && impl_->state != State::closed)
      impl_->state = State::closing;
  }
  return impl_->state;
}

State Engine::state() const noexcept {
  return impl_ ? impl_->state : State::failed;
}

Failure Engine::failure() const noexcept {
  return impl_ ? impl_->failure : Failure::invalid_configuration;
}

long Engine::provider_error() const noexcept {
  return impl_ ? impl_->provider_error : 0L;
}

std::string Engine::negotiated_cipher() const {
  if (!impl_ || impl_->state != State::established)
    return {};
  const auto *cipher = SSL_get_current_cipher(impl_->ssl.get());
  const auto *name = cipher ? SSL_CIPHER_get_name(cipher) : nullptr;
  return name ? std::string{name} : std::string{};
}

std::string Engine::negotiated_alpn() const {
  if (!impl_ || impl_->state != State::established)
    return {};
  const unsigned char *protocol{};
  unsigned int length{};
  SSL_get0_alpn_selected(impl_->ssl.get(), &protocol, &length);
  return protocol && length != 0U
             ? std::string{reinterpret_cast<const char *>(protocol), length}
             : std::string{};
}

std::optional<std::vector<std::uint8_t>>
Engine::peer_certificate_der() const noexcept {
  if (!impl_ || impl_->state != State::established)
    return std::nullopt;
  X509Owner certificate{SSL_get1_peer_certificate(impl_->ssl.get())};
  if (!certificate)
    return std::nullopt;
  const auto length = i2d_X509(certificate.get(), nullptr);
  if (length <= 0)
    return std::nullopt;
  try {
    std::vector<std::uint8_t> output(static_cast<std::size_t>(length));
    auto *cursor = output.data();
    return i2d_X509(certificate.get(), &cursor) == length
               ? std::optional<std::vector<std::uint8_t>>{std::move(output)}
               : std::nullopt;
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace router::tls
