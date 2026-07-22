// ngtcp2 1.24.0 plus OpenSSL 3.5.7 implementation of the socket-free QUIC
// owner. sockaddr values below are protocol-address containers required by
// ngtcp2. No socket API is called and every emitted datagram returns to the
// emulator-owned UDP transport.
// Source: ietf.quic.transport.rfc9000
// Source: ietf.quic.tls.rfc9001
// Source: ietf.quic.recovery.rfc9002
// Source: ngtcp2.quic.1_24_0

#include "router/quic_connection.hpp"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <utility>

namespace router::pki::quic_access {

class EngineAccess final {
public:
  [[nodiscard]] static EVP_PKEY *private_key(OpenIdentity &identity) noexcept {
    return static_cast<EVP_PKEY *>(identity.native_private_key());
  }
};

} // namespace router::pki::quic_access

namespace router::quic {
namespace {

template <typename T, void (*Free)(T *)> struct OpenSslDeleter {
  void operator()(T *value) const noexcept {
    if (value)
      Free(value);
  }
};

using ContextOwner =
    std::unique_ptr<SSL_CTX, OpenSslDeleter<SSL_CTX, SSL_CTX_free>>;
using SslOwner = std::unique_ptr<SSL, OpenSslDeleter<SSL, SSL_free>>;
using X509Owner = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;
using PkeyOwner =
    std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;

struct NativeAddress {
  sockaddr_storage storage{};
  socklen_t length{};
};

[[nodiscard]] NativeAddress native_address(const EndpointAddress &value) {
  NativeAddress result;
  if (value.family == AddressFamily::ipv4) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(value.port);
    std::memcpy(&address.sin_addr, value.bytes.data(), 4U);
    std::memcpy(&result.storage, &address, sizeof(address));
    result.length = sizeof(address);
    return result;
  }
  sockaddr_in6 address{};
  address.sin6_family = AF_INET6;
  address.sin6_port = htons(value.port);
  std::memcpy(&address.sin6_addr, value.bytes.data(), 16U);
  std::memcpy(&result.storage, &address, sizeof(address));
  result.length = sizeof(address);
  return result;
}

[[nodiscard]] std::optional<EndpointAddress>
endpoint_address(const ngtcp2_addr &value) noexcept {
  if (!value.addr)
    return std::nullopt;
  if (value.addr->sa_family == AF_INET &&
      value.addrlen >= sizeof(sockaddr_in)) {
    const auto *address = reinterpret_cast<const sockaddr_in *>(value.addr);
    ip::Ipv4 bytes{};
    std::memcpy(bytes.data(), &address->sin_addr, bytes.size());
    return EndpointAddress::ipv4(bytes, ntohs(address->sin_port));
  }
  if (value.addr->sa_family == AF_INET6 &&
      value.addrlen >= sizeof(sockaddr_in6)) {
    const auto *address = reinterpret_cast<const sockaddr_in6 *>(value.addr);
    ip::Ipv6 bytes{};
    std::memcpy(bytes.data(), &address->sin6_addr, bytes.size());
    return EndpointAddress::ipv6(bytes, ntohs(address->sin6_port));
  }
  return std::nullopt;
}

struct NativePath {
  NativeAddress local;
  NativeAddress remote;
  ngtcp2_path value{};

  explicit NativePath(const Path &path)
      : local(native_address(path.local)), remote(native_address(path.remote)) {
    // ngtcp2 borrows the address storage only for the surrounding API call.
    // Keeping both sockaddr_storage values as members makes those pointers
    // stable even when the library rewrites path metadata during packet output.
    value.local.addr = reinterpret_cast<sockaddr *>(&local.storage);
    value.local.addrlen = local.length;
    value.remote.addr = reinterpret_cast<sockaddr *>(&remote.storage);
    value.remote.addrlen = remote.length;
  }
};

[[nodiscard]] ngtcp2_tstamp timestamp(RuntimeClock::time_point value) noexcept {
  const auto duration =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          value.time_since_epoch());
  return duration.count() <= 0 ? 0U
                               : static_cast<ngtcp2_tstamp>(duration.count());
}

[[nodiscard]] RuntimeClock::time_point time_point(ngtcp2_tstamp value) noexcept {
  using Rep = RuntimeClock::duration::rep;
  const auto maximum = static_cast<ngtcp2_tstamp>(
      std::numeric_limits<Rep>::max());
  const auto clamped = std::min(value, maximum);
  return RuntimeClock::time_point{std::chrono::duration_cast<RuntimeClock::duration>(
      std::chrono::nanoseconds{static_cast<Rep>(clamped)})};
}

[[nodiscard]] X509Owner
decode_certificate(std::span<const std::uint8_t> der) noexcept {
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

[[nodiscard]] bool self_signed(X509 *certificate) noexcept {
  if (!certificate ||
      X509_NAME_cmp(X509_get_subject_name(certificate),
                    X509_get_issuer_name(certificate)) != 0)
    return false;
  PkeyOwner public_key{X509_get_pubkey(certificate)};
  return public_key && X509_verify(certificate, public_key.get()) == 1;
}

[[nodiscard]] bool install_identity(SSL_CTX *context,
                                    pki::OpenIdentity &identity) {
  const auto chain = identity.certificate_chain_der();
  auto *private_key =
      pki::quic_access::EngineAccess::private_key(identity);
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
    // TLS Certificate normally omits a self-signed root but retains every
    // intermediate. The project store already provides leaf-to-root order.
    if (index + 1U == chain.size() && self_signed(certificate.get()))
      continue;
    if (SSL_CTX_add1_chain_cert(context, certificate.get()) != 1)
      return false;
  }
  return true;
}

[[nodiscard]] bool install_trust_anchors(
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

[[nodiscard]] std::optional<std::string>
openssl_list(std::span<const std::string_view> values) {
  if (values.empty())
    return std::nullopt;
  std::string result;
  for (const auto value : values) {
    if (value.empty() || value.find(':') != std::string_view::npos)
      return std::nullopt;
    if (!result.empty())
      result.push_back(':');
    result.append(value);
  }
  return result;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>>
alpn_wire(std::span<const std::string_view> protocols) {
  if (protocols.empty())
    return std::nullopt;
  std::vector<std::uint8_t> result;
  for (const auto protocol : protocols) {
    if (protocol.empty() || protocol.size() > 255U ||
        result.size() > std::numeric_limits<std::uint16_t>::max() -
                            protocol.size() - 1U)
      return std::nullopt;
    result.push_back(static_cast<std::uint8_t>(protocol.size()));
    result.insert(result.end(), protocol.begin(), protocol.end());
  }
  return result;
}

[[nodiscard]] bool install_tls_policy(SSL_CTX *context,
                                      const tls::Tls13PolicyView *policy,
                                      bool server) {
  if (!policy)
    return true;
  const auto ciphers = openssl_list(policy->cipher_suites);
  const auto groups = openssl_list(policy->groups);
  const auto signatures = openssl_list(policy->signatures);
  if (!ciphers || !groups || !signatures ||
      SSL_CTX_set_ciphersuites(context, ciphers->c_str()) != 1 ||
      SSL_CTX_set1_groups_list(context, groups->c_str()) != 1 ||
      SSL_CTX_set1_sigalgs_list(context, signatures->c_str()) != 1)
    return false;
  if (server)
    static_cast<void>(SSL_CTX_set_options(
        context, static_cast<std::uint64_t>(SSL_OP_CIPHER_SERVER_PREFERENCE)));
  return true;
}

[[nodiscard]] bool valid_clock(std::uint64_t seconds) noexcept {
  return seconds != 0U &&
         seconds <= static_cast<std::uint64_t>(
                        std::numeric_limits<std::time_t>::max());
}

[[nodiscard]] bool valid_path(const Path &path) noexcept {
  return path.local.family == path.remote.family && path.local.port != 0U &&
         path.remote.port != 0U;
}

[[nodiscard]] bool
valid_transport(const TransportConfiguration &configuration) noexcept {
  const auto maximum_udp = static_cast<std::size_t>(NGTCP2_MAX_TX_UDP_PAYLOAD_SIZE);
  return configuration.connection_receive_window != 0U &&
         configuration.stream_receive_window != 0U &&
         configuration.stream_receive_window <=
             configuration.connection_receive_window &&
         configuration.max_udp_payload_octets >=
             minimum_initial_datagram_octets &&
         configuration.max_udp_payload_octets <= maximum_udp &&
         configuration.max_buffered_receive_octets >=
             configuration.connection_receive_window &&
         configuration.max_buffered_send_octets != 0U &&
         configuration.max_pending_transport_events != 0U &&
         configuration.max_bidirectional_streams <= NGTCP2_MAX_VARINT &&
         configuration.max_unidirectional_streams <= NGTCP2_MAX_VARINT;
}

[[nodiscard]] ngtcp2_cc_algo
congestion_control(CongestionControl value) noexcept {
  switch (value) {
  case CongestionControl::reno:
    return NGTCP2_CC_ALGO_RENO;
  case CongestionControl::bbr2:
    return NGTCP2_CC_ALGO_BBR;
  case CongestionControl::cubic:
  default:
    return NGTCP2_CC_ALGO_CUBIC;
  }
}

[[nodiscard]] ngtcp2_duration milliseconds(std::uint64_t value) noexcept {
  if (value > std::numeric_limits<ngtcp2_duration>::max() /
                  NGTCP2_MILLISECONDS)
    return std::numeric_limits<ngtcp2_duration>::max();
  return value * NGTCP2_MILLISECONDS;
}

} // namespace

EndpointAddress EndpointAddress::ipv4(const ip::Ipv4 &address,
                                      std::uint16_t port) noexcept {
  EndpointAddress result{.family = AddressFamily::ipv4, .port = port};
  std::copy(address.begin(), address.end(), result.bytes.begin());
  return result;
}

EndpointAddress EndpointAddress::ipv6(const ip::Ipv6 &address,
                                      std::uint16_t port) noexcept {
  return EndpointAddress{.family = AddressFamily::ipv6,
                         .bytes = address,
                         .port = port};
}

struct Connection::Impl {
  struct SendChunk {
    std::uint64_t stream_offset{};
    std::vector<std::uint8_t> bytes;
    std::size_t submitted{};
    bool fin{};
    bool fin_submitted{};
  };

  struct SendStream {
    std::deque<SendChunk> chunks;
    std::uint64_t next_offset{};
    std::uint64_t acknowledged_offset{};
  };

  bool server{};
  TransportConfiguration transport;
  Path current_path;
  std::vector<std::uint8_t> server_alpn;
  std::vector<std::uint8_t> stateless_reset_secret;
  ContextOwner context;
  SslOwner ssl;
  ngtcp2_crypto_ossl_ctx *crypto_context{};
  ngtcp2_conn *connection{};
  ngtcp2_crypto_conn_ref connection_ref{};
  std::map<std::int64_t, SendStream> send_streams;
  std::deque<std::int64_t> writable_streams;
  std::deque<ReceivedStreamChunk> received_streams;
  std::deque<AcknowledgedStreamRange> acknowledged_streams;
  std::size_t buffered_send_octets{};
  std::size_t buffered_receive_octets{};
  State state{State::handshaking};
  Failure failure{Failure::none};
  bool entropy_failed{};
  std::optional<std::uint64_t> pending_application_close;

  Impl(bool is_server, const TransportConfiguration &limits,
       const Path &path)
      : server(is_server), transport(limits), current_path(path),
        connection_ref{get_connection, this} {}

  ~Impl() {
    // OpenSSL callbacks can consult connection_ref while SSL is freed. Clear
    // app_data first and keep ngtcp2 alive until after SSL teardown.
    if (ssl)
      SSL_set_app_data(ssl.get(), nullptr);
    ssl.reset();
    if (crypto_context)
      ngtcp2_crypto_ossl_ctx_del(crypto_context);
    crypto_context = nullptr;
    ngtcp2_conn_del(connection);
    connection = nullptr;
  }

  [[nodiscard]] static ngtcp2_conn *
  get_connection(ngtcp2_crypto_conn_ref *reference) noexcept {
    const auto *self = static_cast<const Impl *>(reference->user_data);
    return self ? self->connection : nullptr;
  }

  static void random_bytes(std::uint8_t *output, std::size_t size,
                           const ngtcp2_rand_ctx *context) noexcept {
    auto *self = context
                     ? static_cast<Impl *>(context->native_handle)
                     : nullptr;
    if (!self || size > static_cast<std::size_t>(
                            std::numeric_limits<int>::max()) ||
        RAND_bytes(output, static_cast<int>(size)) != 1) {
      // The callback has no error return. Marking the owner failed prevents
      // any packet created with fallback bytes from leaving the module.
      if (self)
        self->entropy_failed = true;
      std::fill_n(output, size, std::uint8_t{0});
    }
  }

  static int get_new_connection_id(
      ngtcp2_conn *, ngtcp2_cid *cid,
      ngtcp2_stateless_reset_token *token, std::size_t cid_length,
      void *user_data) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    if (!self || cid_length > NGTCP2_MAX_CIDLEN ||
        cid_length > static_cast<std::size_t>(
                         std::numeric_limits<int>::max()) ||
        RAND_bytes(cid->data, static_cast<int>(cid_length)) != 1)
      return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cid_length;
    if (self->stateless_reset_secret.empty()) {
      // Clients do not advertise stateless reset tokens. ngtcp2 still uses
      // this shared callback table for local CIDs, so fill an unpredictable
      // unused token without introducing a project-global secret.
      return RAND_bytes(token->data, sizeof(token->data)) == 1
                 ? 0
                 : NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return ngtcp2_crypto_generate_stateless_reset_token(
               token->data, self->stateless_reset_secret.data(),
               self->stateless_reset_secret.size(), cid) == 0
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
  }

  static int receive_stream(ngtcp2_conn *connection, std::uint32_t flags,
                            std::int64_t stream_id, std::uint64_t offset,
                            const std::uint8_t *data, std::size_t data_length,
                            void *user_data, void *) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    if (!self || data_length > self->transport.max_buffered_receive_octets -
                                    self->buffered_receive_octets)
      return NGTCP2_ERR_CALLBACK_FAILURE;
    try {
      ReceivedStreamChunk chunk{.stream_id = stream_id,
                                .offset = offset,
                                .bytes = {data, data + data_length},
                                .fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) !=
                                       0U};
      self->received_streams.push_back(std::move(chunk));
      self->buffered_receive_octets += data_length;
      // Receive credit is deliberately not extended here. It is extended only
      // when the application consumes the chunk, making advertised flow
      // control correspond to actual bounded owner memory.
      static_cast<void>(connection);
      return 0;
    } catch (...) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }

  static int acknowledge_stream(ngtcp2_conn *, std::int64_t stream_id,
                                std::uint64_t offset,
                                std::uint64_t data_length, void *user_data,
                                void *) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    if (!self)
      return NGTCP2_ERR_CALLBACK_FAILURE;
    auto iterator = self->send_streams.find(stream_id);
    if (iterator == self->send_streams.end() ||
        offset != iterator->second.acknowledged_offset)
      return NGTCP2_ERR_CALLBACK_FAILURE;
    auto &stream = iterator->second;
    if (self->acknowledged_streams.size() >=
        self->transport.max_pending_transport_events)
      return NGTCP2_ERR_CALLBACK_FAILURE;
    try {
      self->acknowledged_streams.push_back(
          {.stream_id = stream_id,
           .offset = offset,
           .octets = data_length});
    } catch (...) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    stream.acknowledged_offset += data_length;
    while (!stream.chunks.empty()) {
      const auto &chunk = stream.chunks.front();
      const auto end = chunk.stream_offset + chunk.bytes.size();
      if (end > stream.acknowledged_offset ||
          (chunk.fin && !chunk.fin_submitted))
        break;
      self->buffered_send_octets -= chunk.bytes.size();
      stream.chunks.pop_front();
    }
    return 0;
  }

  [[nodiscard]] static ngtcp2_callbacks callbacks(bool server) noexcept {
    ngtcp2_callbacks result{};
    if (server)
      result.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    else {
      result.client_initial = ngtcp2_crypto_client_initial_cb;
      result.recv_retry = ngtcp2_crypto_recv_retry_cb;
    }
    result.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    result.encrypt = ngtcp2_crypto_encrypt_cb;
    result.decrypt = ngtcp2_crypto_decrypt_cb;
    result.hp_mask = ngtcp2_crypto_hp_mask_cb;
    result.recv_stream_data = receive_stream;
    result.acked_stream_data_offset = acknowledge_stream;
    result.rand = random_bytes;
    result.update_key = ngtcp2_crypto_update_key_cb;
    result.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    result.delete_crypto_cipher_ctx =
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    result.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    result.get_new_connection_id2 = get_new_connection_id;
    result.get_path_challenge_data2 =
        ngtcp2_crypto_get_path_challenge_data2_cb;
    return result;
  }

  [[nodiscard]] bool configure_common_tls(
      std::uint64_t wall_clock_seconds,
      const tls::Tls13PolicyView *policy) noexcept {
    if (!context || !valid_clock(wall_clock_seconds) ||
        SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
        !install_tls_policy(context.get(), policy, server))
      return false;
    auto *parameters = SSL_CTX_get0_param(context.get());
    if (!parameters)
      return false;
    X509_VERIFY_PARAM_set_time(
        parameters, static_cast<std::time_t>(wall_clock_seconds));
    return true;
  }

  static int select_alpn(SSL *, const unsigned char **selected,
                         unsigned char *selected_length,
                         const unsigned char *client_protocols,
                         unsigned int client_protocols_length,
                         void *context) noexcept {
    const auto *self = static_cast<const Impl *>(context);
    if (!self || self->server_alpn.empty())
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    unsigned char *choice{};
    unsigned char choice_length{};
    if (SSL_select_next_proto(&choice, &choice_length,
                              self->server_alpn.data(),
                              static_cast<unsigned int>(self->server_alpn.size()),
                              client_protocols, client_protocols_length) !=
        OPENSSL_NPN_NEGOTIATED)
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    *selected = choice;
    *selected_length = choice_length;
    return SSL_TLSEXT_ERR_OK;
  }

  [[nodiscard]] bool make_tls_client(
      const ClientConfiguration &configuration,
      std::span<const std::uint8_t> encoded_alpn) noexcept {
    const bool authenticate = configuration.peer_authentication ==
                              tls::PeerAuthentication::required;
    context.reset(SSL_CTX_new(TLS_method()));
    if (!configure_common_tls(configuration.wall_clock_seconds,
                              configuration.tls_policy) ||
        (authenticate &&
         !install_trust_anchors(context.get(),
                                configuration.trust_anchors_der)) ||
        (configuration.identity &&
         !install_identity(context.get(), *configuration.identity)))
      return false;
    SSL_CTX_set_verify(context.get(),
                       authenticate ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                       nullptr);
    ssl.reset(SSL_new(context.get()));
    if (!ssl ||
        ngtcp2_crypto_ossl_ctx_new(&crypto_context, ssl.get()) != 0 ||
        ngtcp2_crypto_ossl_configure_client_session(ssl.get()) != 0 ||
        SSL_set_alpn_protos(ssl.get(), encoded_alpn.data(),
                            static_cast<unsigned int>(encoded_alpn.size())) !=
            0)
      return false;
    SSL_set_app_data(ssl.get(), &connection_ref);
    SSL_set_connect_state(ssl.get());
    auto *parameters = SSL_get0_param(ssl.get());
    if (!parameters)
      return false;
    if (!configuration.peer.hostname.empty()) {
      if (SSL_set_tlsext_host_name(ssl.get(),
                                   configuration.peer.hostname.c_str()) != 1 ||
          (authenticate &&
           SSL_set1_host(ssl.get(), configuration.peer.hostname.c_str()) != 1))
        return false;
    } else if (authenticate && configuration.peer.ipv4_address) {
      if (X509_VERIFY_PARAM_set1_ip(parameters,
                                    configuration.peer.ipv4_address->data(),
                                    configuration.peer.ipv4_address->size()) !=
          1)
        return false;
    } else if (authenticate && configuration.peer.ipv6_address &&
               X509_VERIFY_PARAM_set1_ip(
                   parameters, configuration.peer.ipv6_address->data(),
                   configuration.peer.ipv6_address->size()) != 1) {
      return false;
    }
    ngtcp2_conn_set_tls_native_handle(connection, crypto_context);
    return true;
  }

  [[nodiscard]] bool make_tls_server(
      const ServerConfiguration &configuration,
      std::vector<std::uint8_t> encoded_alpn) noexcept {
    server_alpn = std::move(encoded_alpn);
    context.reset(SSL_CTX_new(TLS_method()));
    if (!configure_common_tls(configuration.wall_clock_seconds,
                              configuration.tls_policy) ||
        !install_identity(context.get(), *configuration.identity) ||
        (configuration.require_client_certificate &&
         !install_trust_anchors(context.get(),
                                configuration.trust_anchors_der)))
      return false;
    SSL_CTX_set_verify(
        context.get(),
        configuration.require_client_certificate
            ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            : SSL_VERIFY_NONE,
        nullptr);
    SSL_CTX_set_alpn_select_cb(context.get(), select_alpn, this);
    ssl.reset(SSL_new(context.get()));
    if (!ssl ||
        ngtcp2_crypto_ossl_ctx_new(&crypto_context, ssl.get()) != 0 ||
        ngtcp2_crypto_ossl_configure_server_session(ssl.get()) != 0)
      return false;
    SSL_set_app_data(ssl.get(), &connection_ref);
    SSL_set_accept_state(ssl.get());
    ngtcp2_conn_set_tls_native_handle(connection, crypto_context);
    return true;
  }

  [[nodiscard]] Failure fail(Failure reason) noexcept {
    failure = reason;
    state = State::failed;
    return reason;
  }

  void update_state() noexcept {
    if (state == State::failed || state == State::closed)
      return;
    if (ngtcp2_conn_in_closing_period2(connection)) {
      state = State::closing;
      return;
    }
    if (ngtcp2_conn_in_draining_period2(connection)) {
      state = State::draining;
      return;
    }
    if (ngtcp2_conn_get_handshake_completed2(connection))
      state = State::established;
  }
};

namespace {

void configure_ngtcp2(const TransportConfiguration &configuration,
                      RuntimeClock::time_point now, void *owner,
                      ngtcp2_settings &settings,
                      ngtcp2_transport_params &parameters) noexcept {
  ngtcp2_settings_default(&settings);
  settings.initial_ts = timestamp(now);
  settings.cc_algo = congestion_control(configuration.congestion_control);
  settings.max_tx_udp_payload_size = configuration.max_udp_payload_octets;
  settings.rand_ctx.native_handle = owner;
  ngtcp2_transport_params_default(&parameters);
  parameters.initial_max_data = configuration.connection_receive_window;
  parameters.initial_max_stream_data_bidi_local =
      configuration.stream_receive_window;
  parameters.initial_max_stream_data_bidi_remote =
      configuration.stream_receive_window;
  parameters.initial_max_stream_data_uni =
      configuration.stream_receive_window;
  parameters.initial_max_streams_bidi =
      configuration.max_bidirectional_streams;
  parameters.initial_max_streams_uni =
      configuration.max_unidirectional_streams;
  parameters.max_idle_timeout =
      milliseconds(configuration.max_idle_timeout_milliseconds);
  parameters.max_udp_payload_size = configuration.max_udp_payload_octets;
  parameters.disable_active_migration =
      configuration.allow_active_migration ? 0U : 1U;
}

[[nodiscard]] bool random_cid(ngtcp2_cid &cid,
                              std::size_t length) noexcept {
  if (length > NGTCP2_MAX_CIDLEN ||
      RAND_bytes(cid.data, static_cast<int>(length)) != 1)
    return false;
  cid.datalen = length;
  return true;
}

} // namespace

Connection::Connection(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
Connection::Connection(Connection &&) noexcept = default;
Connection &Connection::operator=(Connection &&) noexcept = default;
Connection::~Connection() = default;

std::optional<Connection>
Connection::client(const ClientConfiguration &configuration,
                   RuntimeClock::time_point now) noexcept {
  const bool authenticate = configuration.peer_authentication ==
                            tls::PeerAuthentication::required;
  auto encoded_alpn = alpn_wire(configuration.alpn_protocols);
  if (!valid_path(configuration.initial_path) ||
      !valid_transport(configuration.transport) || !valid_clock(configuration.wall_clock_seconds) ||
      !encoded_alpn ||
      (authenticate && configuration.trust_anchors_der.empty()) ||
      (!authenticate && !configuration.trust_anchors_der.empty()))
    return std::nullopt;
  try {
    auto impl = std::make_unique<Impl>(false, configuration.transport,
                                      configuration.initial_path);
    ngtcp2_cid destination_id{};
    ngtcp2_cid source_id{};
    if (!random_cid(destination_id, NGTCP2_MIN_INITIAL_DCIDLEN) ||
        !random_cid(source_id, 8U))
      return std::nullopt;
    NativePath path{configuration.initial_path};
    ngtcp2_settings settings{};
    ngtcp2_transport_params parameters{};
    configure_ngtcp2(configuration.transport, now, impl.get(), settings,
                     parameters);
    const auto callbacks = Impl::callbacks(false);
    if (ngtcp2_conn_client_new(
            &impl->connection, &destination_id, &source_id, &path.value,
            NGTCP2_PROTO_VER_V1, &callbacks, &settings, &parameters, nullptr,
            impl.get()) != 0 ||
        !impl->make_tls_client(configuration, *encoded_alpn))
      return std::nullopt;
    return Connection{std::move(impl)};
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<Connection>
Connection::server(const ServerConfiguration &configuration,
                   std::span<const std::uint8_t> first_initial_datagram,
                   RuntimeClock::time_point received_at) noexcept {
  auto encoded_alpn = alpn_wire(configuration.alpn_protocols);
  if (!valid_path(configuration.initial_path) ||
      !valid_transport(configuration.transport) || !valid_clock(configuration.wall_clock_seconds) ||
      !configuration.identity || !encoded_alpn ||
      configuration.stateless_reset_secret.size() < 32U ||
      first_initial_datagram.size() < minimum_initial_datagram_octets)
    return std::nullopt;
  try {
    ngtcp2_version_cid version_cid{};
    if (ngtcp2_pkt_decode_version_cid(&version_cid,
                                      first_initial_datagram.data(),
                                      first_initial_datagram.size(), 0U) != 0 ||
        version_cid.version != NGTCP2_PROTO_VER_V1 ||
        version_cid.dcidlen < NGTCP2_MIN_INITIAL_DCIDLEN ||
        version_cid.scidlen > NGTCP2_MAX_CIDLEN)
      return std::nullopt;
    auto impl = std::make_unique<Impl>(true, configuration.transport,
                                      configuration.initial_path);
    impl->stateless_reset_secret.assign(
        configuration.stateless_reset_secret.begin(),
        configuration.stateless_reset_secret.end());
    ngtcp2_cid destination_id{};
    ngtcp2_cid source_id{};
    ngtcp2_cid original_destination_id{};
    ngtcp2_cid_init(&destination_id, version_cid.scid, version_cid.scidlen);
    ngtcp2_cid_init(&original_destination_id, version_cid.dcid,
                    version_cid.dcidlen);
    if (!random_cid(source_id, 8U))
      return std::nullopt;
    NativePath path{configuration.initial_path};
    ngtcp2_settings settings{};
    ngtcp2_transport_params parameters{};
    configure_ngtcp2(configuration.transport, received_at, impl.get(),
                     settings, parameters);
    parameters.original_dcid = original_destination_id;
    parameters.original_dcid_present = 1U;
    if (ngtcp2_crypto_generate_stateless_reset_token(
            parameters.stateless_reset_token,
            impl->stateless_reset_secret.data(),
            impl->stateless_reset_secret.size(), &source_id) != 0)
      return std::nullopt;
    parameters.stateless_reset_token_present = 1U;
    const auto callbacks = Impl::callbacks(true);
    if (ngtcp2_conn_server_new(
            &impl->connection, &destination_id, &source_id, &path.value,
            version_cid.version, &callbacks, &settings, &parameters, nullptr,
            impl.get()) != 0 ||
        !impl->make_tls_server(configuration, std::move(*encoded_alpn)))
      return std::nullopt;
    Connection result{std::move(impl)};
    if (result.ingest_datagram(configuration.initial_path,
                               first_initial_datagram, received_at) !=
        Failure::none)
      return std::nullopt;
    return result;
  } catch (...) {
    return std::nullopt;
  }
}

Failure Connection::ingest_datagram(
    const Path &path, std::span<const std::uint8_t> datagram,
    RuntimeClock::time_point received_at) noexcept {
  if (!impl_ || impl_->state == State::failed)
    return impl_ ? impl_->failure : Failure::invalid_configuration;
  if (!valid_path(path) || datagram.empty())
    return impl_->fail(Failure::protocol_error);
  if (datagram.size() > impl_->transport.max_udp_payload_octets) {
    // max_udp_payload_size is a receive willingness advertised to the peer.
    // RFC 9000 treats an oversized UDP datagram as undeliverable input, not a
    // connection-wide protocol violation, so discard it without poisoning
    // otherwise valid connection state.
    return Failure::none;
  }
  NativePath native{path};
  ngtcp2_pkt_info packet_info{};
  const auto result = ngtcp2_conn_read_pkt(
      impl_->connection, &native.value, &packet_info, datagram.data(),
      datagram.size(), timestamp(received_at));
  if (result != 0 || impl_->entropy_failed)
    return impl_->fail(SSL_get_verify_result(impl_->ssl.get()) == X509_V_OK
                           ? Failure::protocol_error
                           : Failure::certificate_rejected);
  impl_->current_path = path;
  impl_->update_state();
  return Failure::none;
}

std::size_t Connection::take_datagram(std::span<std::uint8_t> output,
                                      Path &path,
                                      RuntimeClock::time_point now) noexcept {
  if (!impl_ || impl_->state == State::failed ||
      output.size() < impl_->transport.max_udp_payload_octets)
    return 0U;
  if (impl_->pending_application_close) {
    NativePath native{impl_->current_path};
    ngtcp2_pkt_info packet_info{};
    ngtcp2_ccerr close_error{};
    ngtcp2_ccerr_default(&close_error);
    ngtcp2_ccerr_set_application_error(
        &close_error, *impl_->pending_application_close, nullptr, 0U);
    const auto written = ngtcp2_conn_write_connection_close(
        impl_->connection, &native.value, &packet_info, output.data(),
        output.size(), &close_error, timestamp(now));
    if (written <= 0) {
      if (written < 0)
        static_cast<void>(impl_->fail(Failure::protocol_error));
      return 0U;
    }
    const auto local = endpoint_address(native.value.local);
    const auto remote = endpoint_address(native.value.remote);
    if (!local || !remote) {
      static_cast<void>(impl_->fail(Failure::protocol_error));
      return 0U;
    }
    path = Path{.local = *local, .remote = *remote};
    impl_->pending_application_close.reset();
    impl_->state = State::closing;
    return static_cast<std::size_t>(written);
  }
  std::int64_t stream_id = -1;
  ngtcp2_vec vector{};
  std::uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
  Impl::SendChunk *chunk{};
  while (!impl_->writable_streams.empty()) {
    const auto candidate_id = impl_->writable_streams.front();
    impl_->writable_streams.pop_front();
    auto stream_iterator = impl_->send_streams.find(candidate_id);
    if (stream_iterator == impl_->send_streams.end())
      continue;
    auto &stream = stream_iterator->second;
    auto iterator = std::find_if(
        stream.chunks.begin(), stream.chunks.end(),
        [](const Impl::SendChunk &candidate) {
          return candidate.submitted < candidate.bytes.size() ||
                 (candidate.fin && !candidate.fin_submitted);
        });
    if (iterator == stream.chunks.end())
      continue;
    stream_id = candidate_id;
    chunk = &*iterator;
    vector.base = chunk->bytes.data() + chunk->submitted;
    vector.len = chunk->bytes.size() - chunk->submitted;
    if (chunk->fin)
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    // RFC 9250 requires traffic-analysis padding. Padding each packet that
    // carries application stream data to the current path payload size gives
    // DoQ and other privacy-sensitive applications a concrete fixed-size
    // policy without altering application bytes or fabricating EDNS options.
    if (impl_->transport.pad_stream_datagrams)
      flags |= NGTCP2_WRITE_STREAM_FLAG_PADDING;
    break;
  }
  NativePath native{impl_->current_path};
  ngtcp2_pkt_info packet_info{};
  ngtcp2_ssize submitted = -1;
  const auto written = ngtcp2_conn_writev_stream(
      impl_->connection, &native.value, &packet_info, output.data(),
      output.size(), &submitted, flags, stream_id,
      stream_id == -1 ? nullptr : &vector, stream_id == -1 ? 0U : 1U,
      timestamp(now));
  if (written < 0) {
    if (stream_id != -1)
      impl_->writable_streams.push_back(stream_id);
    if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED)
      return 0U;
    static_cast<void>(impl_->fail(Failure::protocol_error));
    return 0U;
  }
  if (impl_->entropy_failed) {
    static_cast<void>(impl_->fail(Failure::protocol_error));
    return 0U;
  }
  if (chunk && submitted >= 0) {
    chunk->submitted += static_cast<std::size_t>(submitted);
    if (chunk->submitted == chunk->bytes.size() && chunk->fin)
      chunk->fin_submitted = true;
  }
  if (stream_id != -1) {
    const auto stream_iterator = impl_->send_streams.find(stream_id);
    if (stream_iterator != impl_->send_streams.end() &&
        std::any_of(stream_iterator->second.chunks.begin(),
                    stream_iterator->second.chunks.end(),
                    [](const Impl::SendChunk &candidate) {
                      return candidate.submitted < candidate.bytes.size() ||
                             (candidate.fin && !candidate.fin_submitted);
                    }))
      // Rotation is across streams only. ngtcp2 still owns byte ordering and
      // retransmission within each stream, while a large transfer cannot
      // starve a later DNS or HTTP transaction on another stream.
      impl_->writable_streams.push_back(stream_id);
  }
  if (written == 0)
    return 0U;
  const auto local = endpoint_address(native.value.local);
  const auto remote = endpoint_address(native.value.remote);
  if (!local || !remote) {
    static_cast<void>(impl_->fail(Failure::protocol_error));
    return 0U;
  }
  path = Path{.local = *local, .remote = *remote};
  ngtcp2_conn_update_pkt_tx_time(impl_->connection, timestamp(now));
  impl_->update_state();
  return static_cast<std::size_t>(written);
}

std::optional<RuntimeClock::time_point> Connection::next_expiry() const
    noexcept {
  if (!impl_ || impl_->state == State::failed ||
      impl_->state == State::closed)
    return std::nullopt;
  const auto expiry = ngtcp2_conn_get_expiry2(impl_->connection);
  return expiry == std::numeric_limits<ngtcp2_tstamp>::max()
             ? std::nullopt
             : std::optional{time_point(expiry)};
}

Failure Connection::handle_expiry(RuntimeClock::time_point now) noexcept {
  if (!impl_ || impl_->state == State::failed)
    return impl_ ? impl_->failure : Failure::invalid_configuration;
  const auto result =
      ngtcp2_conn_handle_expiry(impl_->connection, timestamp(now));
  if (result != 0)
    return impl_->fail(Failure::protocol_error);
  impl_->update_state();
  return Failure::none;
}

std::optional<std::int64_t>
Connection::open_bidirectional_stream() noexcept {
  if (!impl_ || impl_->state != State::established)
    return std::nullopt;
  std::int64_t stream_id{};
  const auto result = ngtcp2_conn_open_bidi_stream(
      impl_->connection, &stream_id, nullptr);
  if (result == NGTCP2_ERR_STREAM_ID_BLOCKED) {
    impl_->failure = Failure::stream_limit_blocked;
    return std::nullopt;
  }
  if (result != 0) {
    static_cast<void>(impl_->fail(Failure::protocol_error));
    return std::nullopt;
  }
  impl_->send_streams.try_emplace(stream_id);
  impl_->failure = Failure::none;
  return stream_id;
}

std::optional<std::int64_t>
Connection::open_unidirectional_stream() noexcept {
  if (!impl_ || impl_->state != State::established)
    return std::nullopt;
  std::int64_t stream_id{};
  const auto result =
      ngtcp2_conn_open_uni_stream(impl_->connection, &stream_id, nullptr);
  if (result == NGTCP2_ERR_STREAM_ID_BLOCKED) {
    impl_->failure = Failure::stream_limit_blocked;
    return std::nullopt;
  }
  if (result != 0) {
    static_cast<void>(impl_->fail(Failure::protocol_error));
    return std::nullopt;
  }
  impl_->send_streams.try_emplace(stream_id);
  impl_->failure = Failure::none;
  return stream_id;
}

Failure Connection::send_stream(std::int64_t stream_id,
                                std::span<const std::uint8_t> bytes,
                                bool fin) noexcept {
  if (!impl_ || impl_->state != State::established)
    return Failure::protocol_error;
  if (bytes.empty() && !fin)
    return Failure::invalid_configuration;
  if (bytes.size() > impl_->transport.max_buffered_send_octets -
                         impl_->buffered_send_octets)
    return Failure::resource_exhausted;
  try {
    auto &stream = impl_->send_streams[stream_id];
    // A FIN is terminal. Rejecting bytes after a queued FIN preserves stream
    // final-size invariants before data reaches ngtcp2.
    if (!stream.chunks.empty() && stream.chunks.back().fin)
      return Failure::protocol_error;
    const auto already_writable = std::any_of(
        stream.chunks.begin(), stream.chunks.end(),
        [](const Impl::SendChunk &candidate) {
          return candidate.submitted < candidate.bytes.size() ||
                 (candidate.fin && !candidate.fin_submitted);
        });
    Impl::SendChunk chunk{.stream_offset = stream.next_offset,
                          .bytes = {bytes.begin(), bytes.end()},
                          .fin = fin};
    stream.next_offset += bytes.size();
    stream.chunks.push_back(std::move(chunk));
    if (!already_writable)
      impl_->writable_streams.push_back(stream_id);
    impl_->buffered_send_octets += bytes.size();
    return Failure::none;
  } catch (...) {
    return Failure::resource_exhausted;
  }
}

Failure Connection::reset_stream(std::int64_t stream_id,
                                 std::uint64_t application_error) noexcept {
  if (!impl_ || impl_->state == State::failed)
    return impl_ ? impl_->failure : Failure::invalid_configuration;
  if (ngtcp2_conn_shutdown_stream(impl_->connection, 0U, stream_id,
                                  application_error) != 0)
    return impl_->fail(Failure::protocol_error);
  impl_->send_streams.erase(stream_id);
  std::erase(impl_->writable_streams, stream_id);
  return Failure::none;
}

Failure Connection::stop_sending(std::int64_t stream_id,
                                 std::uint64_t application_error) noexcept {
  if (!impl_ || impl_->state == State::failed)
    return impl_ ? impl_->failure : Failure::invalid_configuration;
  return ngtcp2_conn_shutdown_stream_read(impl_->connection, 0U, stream_id,
                                          application_error) == 0
             ? Failure::none
             : impl_->fail(Failure::protocol_error);
}

Failure
Connection::close_application(std::uint64_t application_error) noexcept {
  if (!impl_ || impl_->state == State::failed)
    return impl_ ? impl_->failure : Failure::invalid_configuration;
  // Staging the code preserves the transport rule that CONNECTION_CLOSE is a
  // real encoded QUIC packet returned by take_datagram, never a direct state
  // notification to the remote endpoint.
  impl_->pending_application_close = application_error;
  return Failure::none;
}

std::optional<ReceivedStreamChunk>
Connection::take_received_stream() noexcept {
  if (!impl_ || impl_->received_streams.empty())
    return std::nullopt;
  auto result = std::move(impl_->received_streams.front());
  impl_->received_streams.pop_front();
  impl_->buffered_receive_octets -= result.bytes.size();
  return result;
}

Failure Connection::consume_received_stream(std::int64_t stream_id,
                                            std::size_t octets) noexcept {
  if (!impl_ || impl_->state == State::failed)
    return impl_ ? impl_->failure : Failure::invalid_configuration;
  if (octets == 0U)
    return Failure::none;
  // Only the application knows how many bytes its parser retained. Separating
  // delivery from credit release lets QPACK defer consumption safely instead
  // of advertising memory that has not actually been freed.
  if (ngtcp2_conn_extend_max_stream_offset(impl_->connection, stream_id,
                                           octets) != 0)
    return impl_->fail(Failure::protocol_error);
  ngtcp2_conn_extend_max_offset(impl_->connection, octets);
  return Failure::none;
}

std::optional<AcknowledgedStreamRange>
Connection::take_acknowledged_stream() noexcept {
  if (!impl_ || impl_->acknowledged_streams.empty())
    return std::nullopt;
  auto result = impl_->acknowledged_streams.front();
  impl_->acknowledged_streams.pop_front();
  return result;
}

State Connection::state() const noexcept {
  return impl_ ? impl_->state : State::failed;
}

Failure Connection::failure() const noexcept {
  return impl_ ? impl_->failure : Failure::invalid_configuration;
}

std::string Connection::negotiated_alpn() const {
  if (!impl_ || !impl_->ssl)
    return {};
  const unsigned char *selected{};
  unsigned int length{};
  SSL_get0_alpn_selected(impl_->ssl.get(), &selected, &length);
  return std::string{selected, selected + length};
}

Path Connection::current_path() const noexcept {
  return impl_ ? impl_->current_path : Path{};
}

Statistics Connection::statistics() const noexcept {
  if (!impl_)
    return {};
  ngtcp2_conn_info info{};
  ngtcp2_conn_get_conn_info(impl_->connection, &info);
  return Statistics{
      .packets_sent = info.pkt_sent,
      .packets_received = info.pkt_recv,
      .packets_lost = info.pkt_lost,
      .bytes_in_flight = info.bytes_in_flight,
      .congestion_window = info.cwnd,
      .smoothed_rtt = std::chrono::nanoseconds{info.smoothed_rtt}};
}

} // namespace router::quic
