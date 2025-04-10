
#include "config.h"
#include "dolog.hh"
#include "iputils.hh"
#include "lock.hh"
#include "tcpiohandler.hh"

const bool TCPIOHandler::s_disableConnectForUnitTests = false;

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif /* HAVE_LIBSODIUM */

TLSCtx::tickets_key_added_hook TLSCtx::s_ticketsKeyAddedHook{nullptr};

#if defined(HAVE_DNS_OVER_TLS) || defined(HAVE_DNS_OVER_HTTPS)
static std::vector<std::vector<uint8_t>> getALPNVector(TLSFrontend::ALPN alpn, bool client)
{
  if (alpn == TLSFrontend::ALPN::DoT) {
    /* we want to set the ALPN to dot (RFC7858), if only to mitigate the ALPACA attack */
    return std::vector<std::vector<uint8_t>>{{'d', 'o', 't'}};
  }
  if (alpn == TLSFrontend::ALPN::DoH) {
    if (client) {
      /* we want to set the ALPN to h2, if only to mitigate the ALPACA attack */
      return std::vector<std::vector<uint8_t>>{{'h', '2'}};
    }
    /* For server contexts, we want to set the ALPN for DoH (note that h2o sets it own ALPN values):
       - HTTP/1.1 so that the OpenSSL callback ALPN accepts it, letting us later return a static response
       - HTTP/2
    */
    return std::vector<std::vector<uint8_t>>{{'h', '2'},{'h', 't', 't', 'p', '/', '1', '.', '1'}};
  }
  return {};
}

#ifdef HAVE_LIBSSL

namespace {
bool shouldDoVerboseLogging()
{
#ifdef DNSDIST
  return dnsdist::configuration::getCurrentRuntimeConfiguration().d_verbose;
#elif defined(RECURSOR)
  return false;
#else
  return true;
#endif
}
}

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "libssl.hh"

static int sni_server_name_callback(SSL* ssl, int* /* alert */, void* arg);

class OpenSSLFrontendContext
{
public:
  OpenSSLFrontendContext(const ComboAddress& addr, const TLSConfig& tlsConfig): d_ticketKeys(tlsConfig.d_numberOfTicketsKeys)
  {
    registerOpenSSLUser();

    auto [ctx, warnings] = libssl_init_server_context(tlsConfig);
    for (const auto& warning : warnings) {
      warnlog("%s", warning);
    }
    // NOLINTNEXTLINE(cppcoreguidelines-prefer-member-initializer): it cannot be initialized before calling libssl_init_server_context()
    d_ocspResponses = std::move(ctx.d_ocspResponses);
    // NOLINTNEXTLINE(cppcoreguidelines-prefer-member-initializer): it cannot be initialized before calling libssl_init_server_context()
    d_tlsCtx = std::move(ctx.d_defaultContext);
    // NOLINTNEXTLINE(cppcoreguidelines-prefer-member-initializer): it cannot be initialized before calling libssl_init_server_context()
    d_sniMap = std::move(ctx.d_sniMap);
    for (auto& entry : d_sniMap) {
      SSL_CTX_set_tlsext_servername_callback(entry.second.get(), &sni_server_name_callback);
    }

    if (!d_tlsCtx) {
      ERR_print_errors_fp(stderr);
      throw std::runtime_error("Error creating TLS context on " + addr.toStringWithPort());
    }
  }

  void cleanup()
  {
    d_tlsCtx.reset();

    unregisterOpenSSLUser();
  }

  OpenSSLTLSTicketKeysRing d_ticketKeys;
  std::map<int, std::string> d_ocspResponses;
  pdns::libssl::ServerContext::SNIToContextMap d_sniMap;
  std::shared_ptr<SSL_CTX> d_tlsCtx{nullptr};
  pdns::UniqueFilePtr d_keyLogFile{nullptr};
};


static int sni_server_name_callback(SSL* ssl, int* /* alert */, void* /* arg */)
{
  const auto* serverName = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (serverName == nullptr) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL's API
  auto* frontendCtx = reinterpret_cast<OpenSSLFrontendContext*>(libssl_get_ticket_key_callback_data(ssl));
  if (frontendCtx == nullptr) {
    return SSL_TLSEXT_ERR_OK;
  }

  auto serverNameView = std::string_view(serverName);

  auto mapIt = frontendCtx->d_sniMap.find(serverNameView);
  if (mapIt == frontendCtx->d_sniMap.end()) {
    /* keep the default certificate */
    return SSL_TLSEXT_ERR_OK;
  }

  /* if it fails there is nothing we can do,
     let's hope OpenSSL will fallback to the existing,
     default certificate*/
  SSL_set_SSL_CTX(ssl, mapIt->second.get());
  return SSL_TLSEXT_ERR_OK;
}

class OpenSSLSession : public TLSSession
{
public:
  OpenSSLSession(std::unique_ptr<SSL_SESSION, void(*)(SSL_SESSION*)>&& sess): d_sess(std::move(sess))
  {
  }

  std::unique_ptr<SSL_SESSION, void(*)(SSL_SESSION*)> getNative()
  {
    return std::move(d_sess);
  }

private:
  std::unique_ptr<SSL_SESSION, void(*)(SSL_SESSION*)> d_sess;
};

class OpenSSLTLSIOCtx;

class OpenSSLTLSConnection: public TLSConnection
{
public:
  /* server side connection */
  OpenSSLTLSConnection(int socket, const struct timeval& timeout, std::shared_ptr<const OpenSSLTLSIOCtx> tlsCtx, std::unique_ptr<SSL, void(*)(SSL*)>&& conn): d_tlsCtx(std::move(tlsCtx)), d_conn(std::move(conn)), d_timeout(timeout)
  {
    d_socket = socket;

    if (!d_conn) {
      vinfolog("Error creating TLS object");
      if (shouldDoVerboseLogging()) {
        ERR_print_errors_fp(stderr);
      }
      throw std::runtime_error("Error creating TLS object");
    }

    if (!SSL_set_fd(d_conn.get(), d_socket)) {
      throw std::runtime_error("Error assigning socket");
    }

    SSL_set_ex_data(d_conn.get(), getConnectionIndex(), this);
  }

  /* client-side connection */
  OpenSSLTLSConnection(std::string hostname, bool hostIsAddr, int socket, const struct timeval& timeout, std::shared_ptr<const OpenSSLTLSIOCtx> tlsCtx, std::unique_ptr<SSL, void(*)(SSL*)>&& conn): d_tlsCtx(std::move(tlsCtx)), d_conn(std::move(conn)), d_hostname(std::move(hostname)), d_timeout(timeout), d_isClient(true)
  {
    d_socket = socket;

    if (!d_conn) {
      vinfolog("Error creating TLS object");
      if (shouldDoVerboseLogging()) {
        ERR_print_errors_fp(stderr);
      }
      throw std::runtime_error("Error creating TLS object");
    }

    if (!SSL_set_fd(d_conn.get(), d_socket)) {
      throw std::runtime_error("Error assigning socket");
    }

    /* set outgoing Server Name Indication */
    if (!d_hostname.empty() && SSL_set_tlsext_host_name(d_conn.get(), d_hostname.c_str()) != 1) {
      throw std::runtime_error("Error setting TLS SNI to " + d_hostname);
    }

    if (hostIsAddr) {
#if (OPENSSL_VERSION_NUMBER >= 0x10002000L)
      X509_VERIFY_PARAM *param = SSL_get0_param(d_conn.get());
      /* Enable automatic IP checks */
      X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
      if (X509_VERIFY_PARAM_set1_ip_asc(param, d_hostname.c_str()) != 1) {
        throw std::runtime_error("Error setting TLS IP for certificate validation");
      }
#else
      /* no validation for you, see https://wiki.openssl.org/index.php/Hostname_validation */
#endif
    }
    else {
#if (OPENSSL_VERSION_NUMBER >= 0x1010000fL) && defined(HAVE_SSL_SET_HOSTFLAGS) // grrr libressl
      SSL_set_hostflags(d_conn.get(), X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
      if (SSL_set1_host(d_conn.get(), d_hostname.c_str()) != 1) {
        throw std::runtime_error("Error setting TLS hostname for certificate validation");
      }
#elif (OPENSSL_VERSION_NUMBER >= 0x10002000L)
      X509_VERIFY_PARAM *param = SSL_get0_param(d_conn.get());
      /* Enable automatic hostname checks */
      X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
      if (X509_VERIFY_PARAM_set1_host(param, d_hostname.c_str(), d_hostname.size()) != 1) {
        throw std::runtime_error("Error setting TLS hostname for certificate validation");
      }
#else
      /* no hostname validation for you, see https://wiki.openssl.org/index.php/Hostname_validation */
#endif
    }

    SSL_set_ex_data(d_conn.get(), getConnectionIndex(), this);
  }

  std::vector<int> getAsyncFDs() override
  {
    std::vector<int> results;
#ifdef SSL_MODE_ASYNC
    if (SSL_waiting_for_async(d_conn.get()) != 1) {
      return results;
    }

    OSSL_ASYNC_FD fds[32];
    size_t numfds = sizeof(fds)/sizeof(*fds);
    SSL_get_all_async_fds(d_conn.get(), nullptr, &numfds);
    if (numfds == 0) {
      return results;
    }

    SSL_get_all_async_fds(d_conn.get(), fds, &numfds);
    results.reserve(numfds);
    for (size_t idx = 0; idx < numfds; idx++) {
      results.push_back(fds[idx]);
    }
#endif
    return results;
  }

  IOState convertIORequestToIOState(int res) const
  {
    int error = SSL_get_error(d_conn.get(), res);
    if (error == SSL_ERROR_WANT_READ) {
      return IOState::NeedRead;
    }
    else if (error == SSL_ERROR_WANT_WRITE) {
      return IOState::NeedWrite;
    }
    else if (error == SSL_ERROR_SYSCALL) {
      if (errno == 0) {
        throw std::runtime_error("TLS connection closed by remote end");
      }
      else {
        throw std::runtime_error("Syscall error while processing TLS connection: " + std::string(strerror(errno)));
      }
    }
    else if (error == SSL_ERROR_ZERO_RETURN) {
      throw std::runtime_error("TLS connection closed by remote end");
    }
#ifdef SSL_MODE_ASYNC
    else if (error == SSL_ERROR_WANT_ASYNC) {
      return IOState::Async;
    }
#endif
    else {
      if (shouldDoVerboseLogging()) {
        throw std::runtime_error("Error while processing TLS connection: (" + std::to_string(error) + ") " + libssl_get_error_string());
      } else {
        throw std::runtime_error("Error while processing TLS connection: " + std::to_string(error));
      }
    }
  }

  void handleIORequest(int res, const struct timeval& timeout)
  {
    auto state = convertIORequestToIOState(res);
    if (state == IOState::NeedRead) {
      res = waitForData(d_socket, timeout.tv_sec, timeout.tv_usec);
      if (res == 0) {
        throw std::runtime_error("Timeout while reading from TLS connection");
      }
      else if (res < 0) {
        throw std::runtime_error("Error waiting to read from TLS connection");
      }
    }
    else if (state == IOState::NeedWrite) {
      res = waitForRWData(d_socket, false, timeout.tv_sec, timeout.tv_usec);
      if (res == 0) {
        throw std::runtime_error("Timeout while writing to TLS connection");
      }
      else if (res < 0) {
        throw std::runtime_error("Error waiting to write to TLS connection");
      }
    }
  }

  IOState tryConnect(bool fastOpen, const ComboAddress& remote) override
  {
    /* sorry */
    (void) fastOpen;
    (void) remote;

    int res = SSL_connect(d_conn.get());
    if (res == 1) {
      return IOState::Done;
    }
    else if (res < 0) {
      return convertIORequestToIOState(res);
    }

    throw std::runtime_error("Error establishing a TLS connection");
  }

  void connect(bool fastOpen, const ComboAddress& remote, const struct timeval &timeout) override
  {
    /* sorry */
    (void) fastOpen;
    (void) remote;

    struct timeval start{0,0};
    struct timeval remainingTime = timeout;
    if (timeout.tv_sec != 0 || timeout.tv_usec != 0) {
      gettimeofday(&start, nullptr);
    }

    int res = 0;
    do {
      res = SSL_connect(d_conn.get());
      if (res < 0) {
        handleIORequest(res, remainingTime);
      }

      if (timeout.tv_sec != 0 || timeout.tv_usec != 0) {
        struct timeval now;
        gettimeofday(&now, nullptr);
        struct timeval elapsed = now - start;
        if (now < start || remainingTime < elapsed) {
          throw runtime_error("Timeout while establishing TLS connection");
        }
        start = now;
        remainingTime = remainingTime - elapsed;
      }
    }
    while (res != 1);
  }

  IOState tryHandshake() override
  {
    if (isClient()) {
      /* In client mode, the handshake is initiated by the call to SSL_connect()
         done from connect()/tryConnect().
         In blocking mode it does not return before the handshake has been finished,
         and in non-blocking mode calling SSL_connect() once is enough for SSL_write()
         and SSL_read() to transparently continue to negotiate the connection after that
         (equivalent to doing SSL_set_connect_state() plus trying to write).
      */
      return IOState::Done;
    }

    /* As explained above in the client-mode block, we only need to call SSL_accept() once
       for SSL_write() and SSL_read() to transparently continue to negotiate the connection after that.
       It is equivalent to calling SSL_set_accept_state() plus trying to read.
    */
    int res = SSL_accept(d_conn.get());
    if (res == 1) {
      return IOState::Done;
    }
    else if (res < 0) {
      return convertIORequestToIOState(res);
    }

    throw std::runtime_error("Error accepting TLS connection");
  }

  void doHandshake() override
  {
    if (isClient()) {
      /* we are a client, nothing to do, see the non-blocking version */
      return;
    }

    int res = 0;
    do {
      res = SSL_accept(d_conn.get());
      if (res < 0) {
        handleIORequest(res, d_timeout);
      }
    }
    while (res < 0);

    if (res != 1) {
      throw std::runtime_error("Error accepting TLS connection");
    }
  }

  IOState tryWrite(const PacketBuffer& buffer, size_t& pos, size_t toWrite) override
  {
    if (isClient() && !d_connected) {
      if (d_ktls) {
        /* work-around to get kTLS to be started, as we cannot do that until after the socket has been connected */
        SSL_set_fd(d_conn.get(), SSL_get_fd(d_conn.get()));
      }
    }

    do {
      int res = SSL_write(d_conn.get(), reinterpret_cast<const char *>(&buffer.at(pos)), static_cast<int>(toWrite - pos));
      if (res <= 0) {
        return convertIORequestToIOState(res);
      }
      else {
        pos += static_cast<size_t>(res);
      }
    }
    while (pos < toWrite);

    if (!d_connected) {
      d_connected = true;
    }

    return IOState::Done;
  }

  IOState tryRead(PacketBuffer& buffer, size_t& pos, size_t toRead, bool allowIncomplete) override
  {
    do {
      int res = SSL_read(d_conn.get(), reinterpret_cast<char *>(&buffer.at(pos)), static_cast<int>(toRead - pos));
      if (res <= 0) {
        return convertIORequestToIOState(res);
      }
      else {
        pos += static_cast<size_t>(res);
        if (allowIncomplete) {
          break;
        }
      }
    }
    while (pos < toRead);
    return IOState::Done;
  }

  size_t read(void* buffer, size_t bufferSize, const struct timeval& readTimeout, const struct timeval& totalTimeout, bool allowIncomplete) override
  {
    size_t got = 0;
    struct timeval start = {0, 0};
    struct timeval remainingTime = totalTimeout;
    if (totalTimeout.tv_sec != 0 || totalTimeout.tv_usec != 0) {
      gettimeofday(&start, nullptr);
    }

    do {
      int res = SSL_read(d_conn.get(), (reinterpret_cast<char *>(buffer) + got), static_cast<int>(bufferSize - got));
      if (res <= 0) {
        handleIORequest(res, readTimeout);
      }
      else {
        got += static_cast<size_t>(res);
        if (allowIncomplete) {
          break;
        }
      }

      if (totalTimeout.tv_sec != 0 || totalTimeout.tv_usec != 0) {
        struct timeval now;
        gettimeofday(&now, nullptr);
        struct timeval elapsed = now - start;
        if (now < start || remainingTime < elapsed) {
          throw runtime_error("Timeout while reading data");
        }
        start = now;
        remainingTime = remainingTime - elapsed;
      }
    }
    while (got < bufferSize);

    return got;
  }

  size_t write(const void* buffer, size_t bufferSize, const struct timeval& writeTimeout) override
  {
    size_t got = 0;
    do {
      int res = SSL_write(d_conn.get(), (reinterpret_cast<const char *>(buffer) + got), static_cast<int>(bufferSize - got));
      if (res <= 0) {
        handleIORequest(res, writeTimeout);
      }
      else {
        got += static_cast<size_t>(res);
      }
    }
    while (got < bufferSize);

    return got;
  }

  bool isUsable() const override
  {
    if (!d_conn) {
      return false;
    }

    char buf;
    int res = SSL_peek(d_conn.get(), &buf, sizeof(buf));
    if (res > 0) {
      return true;
    }
    try {
      convertIORequestToIOState(res);
      return true;
    }
    catch (...) {
      return false;
    }

    return false;
  }

  void close() override
  {
    if (d_conn) {
      SSL_shutdown(d_conn.get());
    }
  }

  std::string getServerNameIndication() const override
  {
    if (d_conn) {
      const char* value = SSL_get_servername(d_conn.get(), TLSEXT_NAMETYPE_host_name);
      if (value) {
        return std::string(value);
      }
    }
    return std::string();
  }

  std::vector<uint8_t> getNextProtocol() const override
  {
    std::vector<uint8_t> result;
    if (!d_conn) {
      return result;
    }

    const unsigned char* alpn = nullptr;
    unsigned int alpnLen  = 0;
#ifdef HAVE_SSL_GET0_ALPN_SELECTED
    if (alpn == nullptr) {
      SSL_get0_alpn_selected(d_conn.get(), &alpn, &alpnLen);
    }
#endif /* HAVE_SSL_GET0_ALPN_SELECTED */
    if (alpn != nullptr && alpnLen > 0) {
      result.insert(result.end(), alpn, alpn + alpnLen);
    }
    return result;
  }

  LibsslTLSVersion getTLSVersion() const override
  {
    auto proto = SSL_version(d_conn.get());
    switch (proto) {
    case TLS1_VERSION:
      return LibsslTLSVersion::TLS10;
    case TLS1_1_VERSION:
      return LibsslTLSVersion::TLS11;
    case TLS1_2_VERSION:
      return LibsslTLSVersion::TLS12;
#ifdef TLS1_3_VERSION
    case TLS1_3_VERSION:
      return LibsslTLSVersion::TLS13;
#endif /* TLS1_3_VERSION */
    default:
      return LibsslTLSVersion::Unknown;
    }
  }

  bool hasSessionBeenResumed() const override
  {
    if (d_conn) {
      return SSL_session_reused(d_conn.get()) != 0;
    }
    return false;
  }

  std::vector<std::unique_ptr<TLSSession>> getSessions() override
  {
    return std::move(d_tlsSessions);
  }

  void setSession(std::unique_ptr<TLSSession>& session) override
  {
    auto sess = dynamic_cast<OpenSSLSession*>(session.get());
    if (!sess) {
      throw std::runtime_error("Unable to convert OpenSSL session");
    }

    auto native = sess->getNative();
    auto ret = SSL_set_session(d_conn.get(), native.get());
    if (ret != 1) {
      throw std::runtime_error("Error setting up session: " + libssl_get_error_string());
    }
    session.reset();
  }

  void addNewTicket(SSL_SESSION* session)
  {
    d_tlsSessions.push_back(std::make_unique<OpenSSLSession>(std::unique_ptr<SSL_SESSION, void (*)(SSL_SESSION*)>(session, SSL_SESSION_free)));
  }

  void enableKTLS()
  {
    d_ktls = true;
  }

  [[nodiscard]] bool isClient() const
  {
    return d_isClient;
  }

  static void generateConnectionIndexIfNeeded()
  {
    auto init = s_initTLSConnIndex.lock();
    if (*init == true) {
      return;
    }

    /* not initialized yet */
    s_tlsConnIndex = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    if (s_tlsConnIndex == -1) {
      throw std::runtime_error("Error getting an index for TLS connection data");
    }

    *init = true;
  }

  static int getConnectionIndex()
  {
    return s_tlsConnIndex;
  }

private:
  static LockGuarded<bool> s_initTLSConnIndex;
  static int s_tlsConnIndex;
  std::vector<std::unique_ptr<TLSSession>> d_tlsSessions;
  const std::shared_ptr<const OpenSSLTLSIOCtx> d_tlsCtx; // we need to hold a reference to this to make sure that the context exists for as long as the connection, even if a reload happens in the meantime
  std::unique_ptr<SSL, void(*)(SSL*)> d_conn;
  const std::string d_hostname;
  const timeval d_timeout;
  bool d_connected{false};
  bool d_ktls{false};
  const bool d_isClient{false};
};

LockGuarded<bool> OpenSSLTLSConnection::s_initTLSConnIndex{false};
int OpenSSLTLSConnection::s_tlsConnIndex{-1};

class OpenSSLTLSIOCtx: public TLSCtx, public std::enable_shared_from_this<OpenSSLTLSIOCtx>
{
  struct Private
  {
    explicit Private() = default;
  };

public:
  static std::shared_ptr<OpenSSLTLSIOCtx> createServerSideContext(TLSFrontend& frontend)
  {
    return std::make_shared<OpenSSLTLSIOCtx>(frontend, Private());
  }

  static std::shared_ptr<OpenSSLTLSIOCtx> createClientSideContext(const TLSContextParameters& params)
  {
    return std::make_shared<OpenSSLTLSIOCtx>(params, Private());
  }

  /* server side context */
  OpenSSLTLSIOCtx(TLSFrontend& frontend, [[maybe_unused]] Private priv): d_alpnProtos(getALPNVector(frontend.d_alpn, false)), d_feContext(std::make_unique<OpenSSLFrontendContext>(frontend.d_addr, frontend.d_tlsConfig))
  {
    OpenSSLTLSConnection::generateConnectionIndexIfNeeded();

    d_ticketsKeyRotationDelay = frontend.d_tlsConfig.d_ticketsKeyRotationDelay;

    for (auto& entry : d_feContext->d_sniMap) {
      auto* ctx = entry.second.get();
      if (frontend.d_tlsConfig.d_enableTickets && frontend.d_tlsConfig.d_numberOfTicketsKeys > 0) {
        /* use our own ticket keys handler so we can rotate them */
#if OPENSSL_VERSION_MAJOR >= 3
        SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, &OpenSSLTLSIOCtx::ticketKeyCb);
#else
        SSL_CTX_set_tlsext_ticket_key_cb(ctx, &OpenSSLTLSIOCtx::ticketKeyCb);
#endif
        libssl_set_ticket_key_callback_data(ctx, d_feContext.get());
      }

#ifndef DISABLE_OCSP_STAPLING
      if (!d_feContext->d_ocspResponses.empty()) {
        SSL_CTX_set_tlsext_status_cb(ctx, &OpenSSLTLSIOCtx::ocspStaplingCb);
        SSL_CTX_set_tlsext_status_arg(ctx, &d_feContext->d_ocspResponses);
      }
#endif /* DISABLE_OCSP_STAPLING */

      if (frontend.d_tlsConfig.d_readAhead) {
        SSL_CTX_set_read_ahead(ctx, 1);
      }

      libssl_set_error_counters_callback(*ctx, &frontend.d_tlsCounters);

      libssl_set_alpn_select_callback(ctx, alpnServerSelectCallback, this);

      if (!frontend.d_tlsConfig.d_keyLogFile.empty()) {
        d_feContext->d_keyLogFile = libssl_set_key_log_file(ctx, frontend.d_tlsConfig.d_keyLogFile);
      }
    }

    try {
      if (frontend.d_tlsConfig.d_ticketKeyFile.empty()) {
        handleTicketsKeyRotation(time(nullptr));
      }
      else {
        OpenSSLTLSIOCtx::loadTicketsKeys(frontend.d_tlsConfig.d_ticketKeyFile);
      }
    }
    catch (const std::exception& e) {
      throw;
    }
  }

  /* client side context */
  OpenSSLTLSIOCtx(const TLSContextParameters& params, [[maybe_unused]] Private priv)
  {
    int sslOptions =
      SSL_OP_NO_SSLv2 |
      SSL_OP_NO_SSLv3 |
      SSL_OP_NO_COMPRESSION |
      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
      SSL_OP_SINGLE_DH_USE |
      SSL_OP_SINGLE_ECDH_USE |
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
      SSL_OP_IGNORE_UNEXPECTED_EOF |
#endif
      SSL_OP_CIPHER_SERVER_PREFERENCE;
    if (!params.d_enableRenegotiation) {
#ifdef SSL_OP_NO_RENEGOTIATION
      sslOptions |= SSL_OP_NO_RENEGOTIATION;
#elif defined(SSL_OP_NO_CLIENT_RENEGOTIATION)
      sslOptions |= SSL_OP_NO_CLIENT_RENEGOTIATION;
#endif
    }

    if (params.d_ktls) {
#ifdef SSL_OP_ENABLE_KTLS
      sslOptions |= SSL_OP_ENABLE_KTLS;
      d_ktls = true;
#endif /* SSL_OP_ENABLE_KTLS */
    }

    registerOpenSSLUser();

    OpenSSLTLSConnection::generateConnectionIndexIfNeeded();

#ifdef HAVE_TLS_CLIENT_METHOD
    d_tlsCtx = std::shared_ptr<SSL_CTX>(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
#else
    d_tlsCtx = std::shared_ptr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free);
#endif
    if (!d_tlsCtx) {
      ERR_print_errors_fp(stderr);
      throw std::runtime_error("Error creating TLS context");
    }

    SSL_CTX_set_options(d_tlsCtx.get(), sslOptions);
#if defined(SSL_CTX_set_ecdh_auto)
    SSL_CTX_set_ecdh_auto(d_tlsCtx.get(), 1);
#endif

    if (!params.d_ciphers.empty()) {
      if (SSL_CTX_set_cipher_list(d_tlsCtx.get(), params.d_ciphers.c_str()) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error setting the cipher list to '" + params.d_ciphers + "' for the TLS context");
      }
    }
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
    if (!params.d_ciphers13.empty()) {
      if (SSL_CTX_set_ciphersuites(d_tlsCtx.get(), params.d_ciphers13.c_str()) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error setting the TLS 1.3 cipher list to '" + params.d_ciphers13 + "' for the TLS context");
      }
    }
#endif /* HAVE_SSL_CTX_SET_CIPHERSUITES */

    if (params.d_validateCertificates) {
      if (params.d_caStore.empty())  {
        if (SSL_CTX_set_default_verify_paths(d_tlsCtx.get()) != 1) {
          throw std::runtime_error("Error adding the system's default trusted CAs");
        }
      } else {
        if (SSL_CTX_load_verify_locations(d_tlsCtx.get(), params.d_caStore.c_str(), nullptr) != 1) {
          throw std::runtime_error("Error adding the trusted CAs file " + params.d_caStore);
        }
      }

      SSL_CTX_set_verify(d_tlsCtx.get(), SSL_VERIFY_PEER, nullptr);
#if (OPENSSL_VERSION_NUMBER < 0x10002000L)
      warnlog("TLS hostname validation requested but not supported for OpenSSL < 1.0.2");
#endif
    }

    /* we need to set SSL_SESS_CACHE_CLIENT for the "new ticket" callback (below) to be called,
       but we don't want OpenSSL to cache the session itself so we set SSL_SESS_CACHE_NO_INTERNAL_STORE as well */
    SSL_CTX_set_session_cache_mode(d_tlsCtx.get(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(d_tlsCtx.get(), &OpenSSLTLSIOCtx::newTicketFromServerCb);

    if (!params.d_keyLogFile.empty()) {
      d_keyLogFile = libssl_set_key_log_file(d_tlsCtx.get(), params.d_keyLogFile);
    }

    libssl_set_alpn_protos(d_tlsCtx.get(), getALPNVector(params.d_alpn, true));

#ifdef SSL_MODE_RELEASE_BUFFERS
    if (params.d_releaseBuffers) {
      SSL_CTX_set_mode(d_tlsCtx.get(), SSL_MODE_RELEASE_BUFFERS);
    }
#endif
  }

  OpenSSLTLSIOCtx(const OpenSSLTLSIOCtx&) = delete;
  OpenSSLTLSIOCtx(OpenSSLTLSIOCtx&&) = delete;
  OpenSSLTLSIOCtx& operator=(const OpenSSLTLSIOCtx&) = delete;
  OpenSSLTLSIOCtx& operator=(OpenSSLTLSIOCtx&&) = delete;

  ~OpenSSLTLSIOCtx() override
  {
    d_tlsCtx.reset();
    unregisterOpenSSLUser();
  }

#if OPENSSL_VERSION_MAJOR >= 3
  static int ticketKeyCb(SSL* s, unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char* iv, EVP_CIPHER_CTX* ectx, EVP_MAC_CTX* hctx, int enc)
#else
  static int ticketKeyCb(SSL* s, unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char* iv, EVP_CIPHER_CTX* ectx, HMAC_CTX* hctx, int enc)
#endif
  {
    auto* ctx = reinterpret_cast<OpenSSLFrontendContext*>(libssl_get_ticket_key_callback_data(s));
    if (ctx == nullptr) {
      return -1;
    }

    int ret = libssl_ticket_key_callback(s, ctx->d_ticketKeys, keyName, iv, ectx, hctx, enc);
    if (enc == 0) {
      if (ret == 0 || ret == 2) {
        auto* conn = reinterpret_cast<OpenSSLTLSConnection*>(SSL_get_ex_data(s, OpenSSLTLSConnection::getConnectionIndex()));
        if (conn != nullptr) {
          if (ret == 0) {
            conn->setUnknownTicketKey();
          }
          else if (ret == 2) {
            conn->setResumedFromInactiveTicketKey();
          }
        }
      }
    }

    return ret;
  }

#ifndef DISABLE_OCSP_STAPLING
  static int ocspStaplingCb(SSL* ssl, void* arg)
  {
    if (ssl == nullptr || arg == nullptr) {
      return SSL_TLSEXT_ERR_NOACK;
    }
    const auto ocspMap = reinterpret_cast<std::map<int, std::string>*>(arg);
    return libssl_ocsp_stapling_callback(ssl, *ocspMap);
  }
#endif /* DISABLE_OCSP_STAPLING */

  static int newTicketFromServerCb(SSL* ssl, SSL_SESSION* session)
  {
    OpenSSLTLSConnection* conn = reinterpret_cast<OpenSSLTLSConnection*>(SSL_get_ex_data(ssl, OpenSSLTLSConnection::getConnectionIndex()));
    if (session == nullptr || conn == nullptr) {
      return 0;
    }

    conn->addNewTicket(session);
    return 1;
  }

  SSL_CTX* getOpenSSLContext() const
  {
    if (d_feContext) {
      return d_feContext->d_tlsCtx.get();
    }
    return d_tlsCtx.get();
  }

  std::unique_ptr<TLSConnection> getConnection(int socket, const struct timeval& timeout, time_t now) override
  {
    handleTicketsKeyRotation(now);

    return std::make_unique<OpenSSLTLSConnection>(socket, timeout, shared_from_this(), std::unique_ptr<SSL, void(*)(SSL*)>(SSL_new(getOpenSSLContext()), SSL_free));
  }

  std::unique_ptr<TLSConnection> getClientConnection(const std::string& host, bool hostIsAddr, int socket, const struct timeval& timeout) override
  {
    auto conn = std::make_unique<OpenSSLTLSConnection>(host, hostIsAddr, socket, timeout, shared_from_this(), std::unique_ptr<SSL, void(*)(SSL*)>(SSL_new(getOpenSSLContext()), SSL_free));
    if (d_ktls) {
      conn->enableKTLS();
    }
    return conn;
  }

  void rotateTicketsKey(time_t now) override
  {
    d_feContext->d_ticketKeys.rotateTicketsKey(now);

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = now + d_ticketsKeyRotationDelay;
    }
  }

  void loadTicketsKeys(const std::string& keyFile) final
  {
    d_feContext->d_ticketKeys.loadTicketsKeys(keyFile);

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = time(nullptr) + d_ticketsKeyRotationDelay;
    }
  }

  void loadTicketsKey(const std::string& key) final
  {
    d_feContext->d_ticketKeys.loadTicketsKey(key);

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = time(nullptr) + d_ticketsKeyRotationDelay;
    }
  }

  size_t getTicketsKeysCount() override
  {
    return d_feContext->d_ticketKeys.getKeysCount();
  }

  std::string getName() const override
  {
    return "openssl";
  }

  bool isServerContext() const
  {
    return d_feContext != nullptr;
  }

private:
  /* called in a client context, if the client advertised more than one ALPN value and the server returned more than one as well, to select the one to use. */
  static int alpnServerSelectCallback(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg)
  {
    if (!arg) {
      return SSL_TLSEXT_ERR_ALERT_WARNING;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL's API
    OpenSSLTLSIOCtx* obj = reinterpret_cast<OpenSSLTLSIOCtx*>(arg);

    const pdns::views::UnsignedCharView inView(in, inlen);
    // Server preference algorithm as per RFC 7301 section 3.2
    for (const auto& tentative : obj->d_alpnProtos) {
      size_t pos = 0;
      while (pos < inView.size()) {
        size_t protoLen = inView.at(pos);
        pos++;
        if (protoLen > (inlen - pos)) {
          /* something is very wrong */
          return SSL_TLSEXT_ERR_ALERT_WARNING;
        }

        if (tentative.size() == protoLen && memcmp(&inView.at(pos), tentative.data(), tentative.size()) == 0) {
          *out = &inView.at(pos);
          *outlen = protoLen;
          return SSL_TLSEXT_ERR_OK;
        }
        pos += protoLen;
      }
    }

    return SSL_TLSEXT_ERR_NOACK;
  }

  const std::vector<std::vector<uint8_t>> d_alpnProtos; // store the supported ALPN protocols, so that the server can select based on what the client sent
  std::shared_ptr<SSL_CTX> d_tlsCtx{nullptr}; // client context, on a server-side the context is stored in d_feContext->d_tlsCtx
  std::unique_ptr<OpenSSLFrontendContext> d_feContext{nullptr};
  pdns::UniqueFilePtr d_keyLogFile{nullptr};
  bool d_ktls{false};
};

#endif /* HAVE_LIBSSL */

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

static void safe_memory_lock(void* data, size_t size)
{
#ifdef HAVE_LIBSODIUM
  sodium_mlock(data, size);
#endif
}

static void safe_memory_release(void* data, size_t size)
{
#ifdef HAVE_LIBSODIUM
  sodium_munlock(data, size);
#elif defined(HAVE_EXPLICIT_BZERO)
  explicit_bzero(data, size);
#elif defined(HAVE_EXPLICIT_MEMSET)
  explicit_memset(data, 0, size);
#elif defined(HAVE_GNUTLS_MEMSET)
  gnutls_memset(data, 0, size);
#else
  /* shamelessly taken from Dovecot's src/lib/safe-memset.c */
  volatile unsigned int volatile_zero_idx = 0;
  volatile unsigned char *p = reinterpret_cast<volatile unsigned char *>(data);

  if (size == 0)
    return;

  do {
    memset(data, 0, size);
  } while (p[volatile_zero_idx] != 0);
#endif
}

class GnuTLSTicketsKey
{
public:
  GnuTLSTicketsKey()
  {
    if (gnutls_session_ticket_key_generate(&d_key) != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error generating tickets key for TLS context");
    }

    safe_memory_lock(d_key.data, d_key.size);
  }

  GnuTLSTicketsKey(const std::string& key)
  {
    /* to be sure we are loading the correct amount of data, which
       may change between versions, let's generate a correct key first */
    if (gnutls_session_ticket_key_generate(&d_key) != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error generating tickets key (before parsing key file) for TLS context");
    }

    safe_memory_lock(d_key.data, d_key.size);
    if (key.size() != d_key.size) {
      safe_memory_release(d_key.data, d_key.size);
      gnutls_free(d_key.data);
      d_key.data = nullptr;
      throw std::runtime_error("Invalid GnuTLS ticket key size");
    }
    memcpy(d_key.data, key.data(), key.size());
  }
  GnuTLSTicketsKey(std::ifstream& file)
  {
    /* to be sure we are loading the correct amount of data, which
       may change between versions, let's generate a correct key first */
    if (gnutls_session_ticket_key_generate(&d_key) != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error generating tickets key (before parsing key file) for TLS context");
    }

    safe_memory_lock(d_key.data, d_key.size);

    try {
      file.read(reinterpret_cast<char*>(d_key.data), d_key.size);

      if (file.fail()) {
        throw std::runtime_error("Invalid GnuTLS tickets key file");
      }

    }
    catch (const std::exception& e) {
      safe_memory_release(d_key.data, d_key.size);
      gnutls_free(d_key.data);
      d_key.data = nullptr;
      throw;
    }
  }
  [[nodiscard]] std::string content() const
  {
    std::string result{};
    if (d_key.data != nullptr && d_key.size > 0) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      result.append(reinterpret_cast<const char*>(d_key.data), d_key.size);
      safe_memory_lock(result.data(), result.size());
    }
    return result;
  }

  ~GnuTLSTicketsKey()
  {
    if (d_key.data != nullptr && d_key.size > 0) {
      safe_memory_release(d_key.data, d_key.size);
    }
    gnutls_free(d_key.data);
    d_key.data = nullptr;
  }
  const gnutls_datum_t& getKey() const
  {
    return d_key;
  }

private:
  gnutls_datum_t d_key{nullptr, 0};
};

class GnuTLSSession : public TLSSession
{
public:
  GnuTLSSession(gnutls_datum_t& sess): d_sess(sess)
  {
    sess.data = nullptr;
    sess.size = 0;
  }

  ~GnuTLSSession() override
  {
    if (d_sess.data != nullptr && d_sess.size > 0) {
      safe_memory_release(d_sess.data, d_sess.size);
    }
    gnutls_free(d_sess.data);
    d_sess.data = nullptr;
  }

  const gnutls_datum_t& getNative()
  {
    return d_sess;
  }

private:
  gnutls_datum_t d_sess{nullptr, 0};
};

class GnuTLSConnection: public TLSConnection
{
public:
  /* server side connection */
  GnuTLSConnection(int socket, const struct timeval& timeout, std::shared_ptr<gnutls_certificate_credentials_st>& creds, const gnutls_priority_t priorityCache, std::shared_ptr<GnuTLSTicketsKey>& ticketsKey, bool enableTickets): d_creds(creds), d_ticketsKey(ticketsKey), d_conn(std::unique_ptr<gnutls_session_int, void(*)(gnutls_session_t)>(nullptr, gnutls_deinit))
  {
    unsigned int sslOptions = GNUTLS_SERVER | GNUTLS_NONBLOCK;
#ifdef GNUTLS_NO_SIGNAL
    sslOptions |= GNUTLS_NO_SIGNAL;
#endif

    d_socket = socket;

    gnutls_session_t conn;
    if (gnutls_init(&conn, sslOptions) != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error creating TLS connection");
    }

    d_conn = std::unique_ptr<gnutls_session_int, void(*)(gnutls_session_t)>(conn, gnutls_deinit);
    conn = nullptr;

    if (gnutls_credentials_set(d_conn.get(), GNUTLS_CRD_CERTIFICATE, d_creds.get()) != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting certificate and key to TLS connection");
    }

    if (gnutls_priority_set(d_conn.get(), priorityCache) != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting ciphers to TLS connection");
    }

    if (enableTickets && d_ticketsKey) {
      const gnutls_datum_t& key = d_ticketsKey->getKey();
      if (gnutls_session_ticket_enable_server(d_conn.get(), &key) != GNUTLS_E_SUCCESS) {
        throw std::runtime_error("Error setting the tickets key to TLS connection");
      }
    }

    gnutls_transport_set_int(d_conn.get(), d_socket);

    /* timeouts are in milliseconds */
    gnutls_handshake_set_timeout(d_conn.get(), timeout.tv_sec * 1000 + timeout.tv_usec / 1000);
    gnutls_record_set_timeout(d_conn.get(), timeout.tv_sec * 1000 + timeout.tv_usec / 1000);
  }

  /* client-side connection */
  GnuTLSConnection(const std::string& host, int socket, const struct timeval& timeout, std::shared_ptr<gnutls_certificate_credentials_st>& creds, const gnutls_priority_t priorityCache, bool validateCerts): d_creds(creds), d_conn(std::unique_ptr<gnutls_session_int, void(*)(gnutls_session_t)>(nullptr, gnutls_deinit)), d_host(host), d_client(true)
  {
    unsigned int sslOptions = GNUTLS_CLIENT | GNUTLS_NONBLOCK;
#ifdef GNUTLS_NO_SIGNAL
    sslOptions |= GNUTLS_NO_SIGNAL;
#endif

    d_socket = socket;

    gnutls_session_t conn;
    if (gnutls_init(&conn, sslOptions) != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error creating TLS connection");
    }

    d_conn = std::unique_ptr<gnutls_session_int, void(*)(gnutls_session_t)>(conn, gnutls_deinit);
    conn = nullptr;

    int rc = gnutls_credentials_set(d_conn.get(), GNUTLS_CRD_CERTIFICATE, d_creds.get());
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting certificate and key to TLS connection: " + std::string(gnutls_strerror(rc)));
    }

    rc = gnutls_priority_set(d_conn.get(), priorityCache);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting ciphers to TLS connection: " + std::string(gnutls_strerror(rc)));
    }

    gnutls_transport_set_int(d_conn.get(), d_socket);

    /* timeouts are in milliseconds */
    gnutls_handshake_set_timeout(d_conn.get(),  timeout.tv_sec * 1000 + timeout.tv_usec / 1000);
    gnutls_record_set_timeout(d_conn.get(),  timeout.tv_sec * 1000 + timeout.tv_usec / 1000);

#ifdef HAVE_GNUTLS_SESSION_SET_VERIFY_CERT
    if (validateCerts && !d_host.empty()) {
      gnutls_session_set_verify_cert(d_conn.get(), d_host.c_str(), GNUTLS_VERIFY_ALLOW_UNSORTED_CHAIN);
      rc = gnutls_server_name_set(d_conn.get(), GNUTLS_NAME_DNS, d_host.c_str(), d_host.size());
      if (rc != GNUTLS_E_SUCCESS) {
        throw std::runtime_error("Error setting the SNI value to '" + d_host + "' on TLS connection: " + std::string(gnutls_strerror(rc)));
      }
    }
#else
    /* no hostname validation for you */
#endif

    /* allow access to our data in the callbacks */
    gnutls_session_set_ptr(d_conn.get(), this);
    gnutls_handshake_set_hook_function(d_conn.get(), GNUTLS_HANDSHAKE_NEW_SESSION_TICKET, GNUTLS_HOOK_POST, newTicketFromServerCb);
  }

  /* The callback prototype changed in 3.4.0. */
#if GNUTLS_VERSION_NUMBER >= 0x030400
  static int newTicketFromServerCb(gnutls_session_t session, unsigned int htype, unsigned post, unsigned int /* incoming */, const gnutls_datum_t* /* msg */)
#else
  static int newTicketFromServerCb(gnutls_session_t session, unsigned int htype, unsigned post, unsigned int /* incoming */)
#endif /* GNUTLS_VERSION_NUMBER >= 0x030400 */
  {
    if (htype != GNUTLS_HANDSHAKE_NEW_SESSION_TICKET || post != GNUTLS_HOOK_POST || session == nullptr) {
      return 0;
    }

    GnuTLSConnection* conn = reinterpret_cast<GnuTLSConnection*>(gnutls_session_get_ptr(session));
    if (conn == nullptr) {
      return 0;
    }

    gnutls_datum_t sess{nullptr, 0};
    auto ret = gnutls_session_get_data2(session, &sess);
    /* GnuTLS returns a 'fake' ticket of 4 bytes set to zero when there is no ticket available */
    if (ret != GNUTLS_E_SUCCESS || sess.size <= 4) {
      throw std::runtime_error("Error getting GnuTLSSession: " + std::string(gnutls_strerror(ret)));
    }
    conn->d_tlsSessions.push_back(std::make_unique<GnuTLSSession>(sess));
    return 0;
  }

  IOState tryConnect(bool fastOpen, [[maybe_unused]] const ComboAddress& remote) override
  {
    int ret = 0;

    if (fastOpen) {
#ifdef HAVE_GNUTLS_TRANSPORT_SET_FASTOPEN
      gnutls_transport_set_fastopen(d_conn.get(), d_socket, const_cast<struct sockaddr*>(reinterpret_cast<const struct sockaddr*>(&remote)), remote.getSocklen(), 0);
#endif
    }

    do {
      ret = gnutls_handshake(d_conn.get());
      if (ret == GNUTLS_E_SUCCESS) {
        d_handshakeDone = true;
        return IOState::Done;
      }
      else if (ret == GNUTLS_E_AGAIN) {
        int direction = gnutls_record_get_direction(d_conn.get());
        return direction == 0 ? IOState::NeedRead : IOState::NeedWrite;
      }
      else if (gnutls_error_is_fatal(ret) || ret == GNUTLS_E_WARNING_ALERT_RECEIVED) {
        throw std::runtime_error("Error establishing a new connection: " + std::string(gnutls_strerror(ret)));
      }
    } while (ret == GNUTLS_E_INTERRUPTED);

    throw std::runtime_error("Error establishing a new connection: " + std::string(gnutls_strerror(ret)));
  }

  void connect(bool fastOpen, const ComboAddress& remote, const struct timeval& timeout) override
  {
    struct timeval start = {0, 0};
    struct timeval remainingTime = timeout;
    if (timeout.tv_sec != 0 || timeout.tv_usec != 0) {
      gettimeofday(&start, nullptr);
    }

    IOState state;
    do {
      state = tryConnect(fastOpen, remote);
      if (state == IOState::Done) {
        return;
      }
      else if (state == IOState::NeedRead) {
        int result = waitForData(d_socket, remainingTime.tv_sec, remainingTime.tv_usec);
        if (result <= 0) {
          throw std::runtime_error("Error reading from TLS connection: " + std::to_string(result));
        }
      }
      else if (state == IOState::NeedWrite) {
        int result = waitForRWData(d_socket, false, remainingTime.tv_sec, remainingTime.tv_usec);
        if (result <= 0) {
          throw std::runtime_error("Error reading from TLS connection: " + std::to_string(result));
        }
      }

      if (timeout.tv_sec != 0 || timeout.tv_usec != 0) {
        struct timeval now;
        gettimeofday(&now, nullptr);
        struct timeval elapsed = now - start;
        if (now < start || remainingTime < elapsed) {
          throw runtime_error("Timeout while establishing TLS connection");
        }
        start = now;
        remainingTime = remainingTime - elapsed;
      }
    }
    while (state != IOState::Done);
  }

  void doHandshake() override
  {
    int ret = 0;
    do {
      ret = gnutls_handshake(d_conn.get());
      if (gnutls_error_is_fatal(ret) || ret == GNUTLS_E_WARNING_ALERT_RECEIVED) {
        if (d_client) {
          throw std::runtime_error("Error establishing a new connection: " + std::string(gnutls_strerror(ret)));
        }
        else {
          throw std::runtime_error("Error accepting a new connection: " + std::string(gnutls_strerror(ret)));
        }
      }
    }
    while (ret != GNUTLS_E_SUCCESS && ret == GNUTLS_E_INTERRUPTED);

    d_handshakeDone = true;
  }

  IOState tryHandshake() override
  {
    int ret = 0;

    do {
      ret = gnutls_handshake(d_conn.get());
      if (ret == GNUTLS_E_SUCCESS) {
        d_handshakeDone = true;
        return IOState::Done;
      }
      else if (ret == GNUTLS_E_AGAIN) {
        int direction = gnutls_record_get_direction(d_conn.get());
        return direction == 0 ? IOState::NeedRead : IOState::NeedWrite;
      }
      else if (gnutls_error_is_fatal(ret) || ret == GNUTLS_E_WARNING_ALERT_RECEIVED) {
        if (d_client) {
          std::string error;
#ifdef HAVE_GNUTLS_SESSION_GET_VERIFY_CERT_STATUS
          if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
            gnutls_datum_t out;
            if (gnutls_certificate_verification_status_print(gnutls_session_get_verify_cert_status(d_conn.get()), gnutls_certificate_type_get(d_conn.get()), &out, 0) == 0) {
              error = " (" + std::string(reinterpret_cast<const char*>(out.data)) + ")";
              gnutls_free(out.data);
            }
          }
#endif /* HAVE_GNUTLS_SESSION_GET_VERIFY_CERT_STATUS */
          throw std::runtime_error("Error accepting a new connection: " + std::string(gnutls_strerror(ret)) + error);
        }
        else {
          throw std::runtime_error("Error establishing a new connection: " + std::string(gnutls_strerror(ret)));
        }
      }
    } while (ret == GNUTLS_E_INTERRUPTED);

    if (d_client) {
      throw std::runtime_error("Error establishinging a new connection: " + std::string(gnutls_strerror(ret)));
    }
    else {
      throw std::runtime_error("Error accepting a new connection: " + std::string(gnutls_strerror(ret)));
    }
  }

  IOState tryWrite(const PacketBuffer& buffer, size_t& pos, size_t toWrite) override
  {
    if (!d_handshakeDone) {
      /* As opposed to OpenSSL, GnuTLS will not transparently finish the handshake for us,
         we need to keep calling gnutls_handshake() until the handshake has been finished. */
      auto state = tryHandshake();
      if (state != IOState::Done) {
        return state;
      }
    }

    do {
      ssize_t res = gnutls_record_send(d_conn.get(), reinterpret_cast<const char *>(&buffer.at(pos)), toWrite - pos);
      if (res == 0) {
        throw std::runtime_error("Error writing to TLS connection");
      }
      else if (res > 0) {
        pos += static_cast<size_t>(res);
      }
      else if (res < 0) {
        if (gnutls_error_is_fatal(res)) {
          throw std::runtime_error("Fatal error writing to TLS connection: " + std::string(gnutls_strerror(res)));
        }
        else if (res == GNUTLS_E_AGAIN) {
          return IOState::NeedWrite;
        }
        vinfolog("Warning, non-fatal error while writing to TLS connection: %s", gnutls_strerror(res));
      }
    }
    while (pos < toWrite);
    return IOState::Done;
  }

  IOState tryRead(PacketBuffer& buffer, size_t& pos, size_t toRead, bool allowIncomplete) override
  {
    if (!d_handshakeDone) {
      /* As opposed to OpenSSL, GnuTLS will not transparently finish the handshake for us,
         we need to keep calling gnutls_handshake() until the handshake has been finished. */
      auto state = tryHandshake();
      if (state != IOState::Done) {
        return state;
      }
    }

    do {
      ssize_t res = gnutls_record_recv(d_conn.get(), reinterpret_cast<char *>(&buffer.at(pos)), toRead - pos);
      if (res == 0) {
        throw std::runtime_error("EOF while reading from TLS connection");
      }
      else if (res > 0) {
        pos += static_cast<size_t>(res);
        if (allowIncomplete) {
          break;
        }
      }
      else if (res < 0) {
        if (gnutls_error_is_fatal(res)) {
          throw std::runtime_error("Fatal error reading from TLS connection: " + std::string(gnutls_strerror(res)));
        }
        else if (res == GNUTLS_E_AGAIN) {
          return IOState::NeedRead;
        }
        vinfolog("Warning, non-fatal error while writing to TLS connection: %s", gnutls_strerror(res));
      }
    }
    while (pos < toRead);
    return IOState::Done;
  }

  size_t read(void* buffer, size_t bufferSize, const struct timeval& readTimeout, const struct timeval& totalTimeout, bool allowIncomplete) override
  {
    size_t got = 0;
    struct timeval start{0,0};
    struct timeval  remainingTime = totalTimeout;
    if (totalTimeout.tv_sec != 0 || totalTimeout.tv_usec != 0) {
      gettimeofday(&start, nullptr);
    }

    do {
      ssize_t res = gnutls_record_recv(d_conn.get(), (reinterpret_cast<char *>(buffer) + got), bufferSize - got);
      if (res == 0) {
        throw std::runtime_error("EOF while reading from TLS connection");
      }
      else if (res > 0) {
        got += static_cast<size_t>(res);
        if (allowIncomplete) {
          break;
        }
      }
      else if (res < 0) {
        if (gnutls_error_is_fatal(res)) {
          throw std::runtime_error("Fatal error reading from TLS connection: " + std::string(gnutls_strerror(res)));
        }
        else if (res == GNUTLS_E_AGAIN) {
          int result = waitForData(d_socket, readTimeout.tv_sec, readTimeout.tv_usec);
          if (result <= 0) {
            throw std::runtime_error("Error while waiting to read from TLS connection: " + std::to_string(result));
          }
        }
        else {
          vinfolog("Non-fatal error while reading from TLS connection: %s", gnutls_strerror(res));
        }
      }

      if (totalTimeout.tv_sec != 0 || totalTimeout.tv_usec != 0) {
        struct timeval now;
        gettimeofday(&now, nullptr);
        struct timeval elapsed = now - start;
        if (now < start || remainingTime < elapsed) {
          throw runtime_error("Timeout while reading data");
        }
        start = now;
        remainingTime = remainingTime - elapsed;
      }
    }
    while (got < bufferSize);

    return got;
  }

  size_t write(const void* buffer, size_t bufferSize, const struct timeval& writeTimeout) override
  {
    size_t got = 0;

    do {
      ssize_t res = gnutls_record_send(d_conn.get(), (reinterpret_cast<const char *>(buffer) + got), bufferSize - got);
      if (res == 0) {
        throw std::runtime_error("Error writing to TLS connection");
      }
      else if (res > 0) {
        got += static_cast<size_t>(res);
      }
      else if (res < 0) {
        if (gnutls_error_is_fatal(res)) {
          throw std::runtime_error("Fatal error writing to TLS connection: " + std::string(gnutls_strerror(res)));
        }
        else if (res == GNUTLS_E_AGAIN) {
          int result = waitForRWData(d_socket, false, writeTimeout.tv_sec, writeTimeout.tv_usec);
          if (result <= 0) {
            throw std::runtime_error("Error waiting to write to TLS connection: " + std::to_string(result));
          }
        }
        else {
          vinfolog("Non-fatal error while writing to TLS connection: %s", gnutls_strerror(res));
        }
      }
    }
    while (got < bufferSize);

    return got;
  }

  bool isUsable() const override
  {
    if (!d_conn) {
      return false;
    }

    /* as far as I can tell we can't peek so we cannot do better */
    return isTCPSocketUsable(d_socket);
  }

  std::string getServerNameIndication() const override
  {
    if (d_conn) {
      unsigned int type;
      size_t name_len = 256;
      std::string sni;
      sni.resize(name_len);

      int res = gnutls_server_name_get(d_conn.get(), const_cast<char*>(sni.c_str()), &name_len, &type, 0);
      if (res == GNUTLS_E_SUCCESS) {
        sni.resize(name_len);
        return sni;
      }
    }
    return std::string();
  }

  std::vector<uint8_t> getNextProtocol() const override
  {
    std::vector<uint8_t> result;
    if (!d_conn) {
      return result;
    }
    gnutls_datum_t next;
    if (gnutls_alpn_get_selected_protocol(d_conn.get(), &next) != GNUTLS_E_SUCCESS) {
      return result;
    }
    result.insert(result.end(), next.data, next.data + next.size);
    return result;
  }

  LibsslTLSVersion getTLSVersion() const override
  {
    auto proto = gnutls_protocol_get_version(d_conn.get());
    switch (proto) {
    case GNUTLS_TLS1_0:
      return LibsslTLSVersion::TLS10;
    case GNUTLS_TLS1_1:
      return LibsslTLSVersion::TLS11;
    case GNUTLS_TLS1_2:
      return LibsslTLSVersion::TLS12;
#if GNUTLS_VERSION_NUMBER >= 0x030603
    case GNUTLS_TLS1_3:
      return LibsslTLSVersion::TLS13;
#endif /* GNUTLS_VERSION_NUMBER >= 0x030603 */
    default:
      return LibsslTLSVersion::Unknown;
    }
  }

  bool hasSessionBeenResumed() const override
  {
    if (d_conn) {
      return gnutls_session_is_resumed(d_conn.get()) != 0;
    }
    return false;
  }

  std::vector<std::unique_ptr<TLSSession>> getSessions() override
  {
    return std::move(d_tlsSessions);
  }

  void setSession(std::unique_ptr<TLSSession>& session) override
  {
    auto sess = dynamic_cast<GnuTLSSession*>(session.get());
    if (!sess) {
      throw std::runtime_error("Unable to convert GnuTLS session");
    }

    auto native = sess->getNative();
    auto ret = gnutls_session_set_data(d_conn.get(), native.data, native.size);
    if (ret != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting up GnuTLS session: " + std::string(gnutls_strerror(ret)));
    }
    session.reset();
  }

  void close() override
  {
    if (d_conn) {
      gnutls_bye(d_conn.get(), GNUTLS_SHUT_RDWR);
    }
  }

  bool setALPNProtos(const std::vector<std::vector<uint8_t>>& protos)
  {
    std::vector<gnutls_datum_t> values;
    values.reserve(protos.size());
    for (const auto& proto : protos) {
      gnutls_datum_t value;
      value.data = const_cast<uint8_t*>(proto.data());
      value.size = proto.size();
      values.push_back(value);
    }
    unsigned int flags = 0;
#if GNUTLS_VERSION_NUMBER >= 0x030500
    flags |= GNUTLS_ALPN_MANDATORY;
#elif defined(GNUTLS_ALPN_MAND)
    flags |= GNUTLS_ALPN_MAND;
#endif
    return gnutls_alpn_set_protocols(d_conn.get(), values.data(), values.size(), flags);
  }

  std::vector<int> getAsyncFDs() override
  {
    return {};
  }

private:
  std::shared_ptr<gnutls_certificate_credentials_st> d_creds;
  std::shared_ptr<GnuTLSTicketsKey> d_ticketsKey;
  std::unique_ptr<gnutls_session_int, void(*)(gnutls_session_t)> d_conn;
  std::vector<std::unique_ptr<TLSSession>> d_tlsSessions;
  std::string d_host;
  const bool d_client{false};
  bool d_handshakeDone{false};
};

class GnuTLSIOCtx: public TLSCtx
{
public:
  /* server side context */
  GnuTLSIOCtx(TLSFrontend& frontend): d_protos(getALPNVector(frontend.d_alpn, false)), d_enableTickets(frontend.d_tlsConfig.d_enableTickets)
  {
    int rc = 0;
    d_ticketsKeyRotationDelay = frontend.d_tlsConfig.d_ticketsKeyRotationDelay;

    gnutls_certificate_credentials_t creds;
    rc = gnutls_certificate_allocate_credentials(&creds);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error allocating credentials for TLS context on " + frontend.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
    }

    d_creds = std::shared_ptr<gnutls_certificate_credentials_st>(creds, gnutls_certificate_free_credentials);
    creds = nullptr;

    for (const auto& pair : frontend.d_tlsConfig.d_certKeyPairs) {
      rc = gnutls_certificate_set_x509_key_file(d_creds.get(), pair.d_cert.c_str(), pair.d_key->c_str(), GNUTLS_X509_FMT_PEM);
      if (rc != GNUTLS_E_SUCCESS) {
        throw std::runtime_error("Error loading certificate ('" + pair.d_cert + "') and key ('" + pair.d_key.value() + "') for TLS context on " + frontend.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
      }
    }

#ifndef DISABLE_OCSP_STAPLING
    size_t count = 0;
    for (const auto& file : frontend.d_tlsConfig.d_ocspFiles) {
      rc = gnutls_certificate_set_ocsp_status_request_file(d_creds.get(), file.c_str(), count);
      if (rc != GNUTLS_E_SUCCESS) {
        warnlog("Error loading OCSP response from file '%s' for certificate ('%s') and key ('%s') for TLS context on %s: %s", file, frontend.d_tlsConfig.d_certKeyPairs.at(count).d_cert, frontend.d_tlsConfig.d_certKeyPairs.at(count).d_key.value(), frontend.d_addr.toStringWithPort(), gnutls_strerror(rc));
      }
      ++count;
    }
#endif /* DISABLE_OCSP_STAPLING */

#if GNUTLS_VERSION_NUMBER >= 0x030600
    rc = gnutls_certificate_set_known_dh_params(d_creds.get(), GNUTLS_SEC_PARAM_HIGH);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting DH params for TLS context on " + frontend.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
    }
#endif

    rc = gnutls_priority_init(&d_priorityCache, frontend.d_tlsConfig.d_ciphers.empty() ? "NORMAL" : frontend.d_tlsConfig.d_ciphers.c_str(), nullptr);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting up TLS cipher preferences to '" + frontend.d_tlsConfig.d_ciphers + "' (" + gnutls_strerror(rc) + ") on " + frontend.d_addr.toStringWithPort());
    }

    try {
      if (frontend.d_tlsConfig.d_ticketKeyFile.empty()) {
        handleTicketsKeyRotation(time(nullptr));
      }
      else {
        GnuTLSIOCtx::loadTicketsKeys(frontend.d_tlsConfig.d_ticketKeyFile);
      }
    }
    catch(const std::runtime_error& e) {
      throw std::runtime_error("Error generating tickets key for TLS context on " + frontend.d_addr.toStringWithPort() + ": " + e.what());
    }
  }

  /* client side context */
  GnuTLSIOCtx(const TLSContextParameters& params): d_protos(getALPNVector(params.d_alpn, true)), d_contextParameters(std::make_unique<TLSContextParameters>(params)), d_validateCerts(params.d_validateCertificates)
  {
    int rc = 0;

    gnutls_certificate_credentials_t creds;
    rc = gnutls_certificate_allocate_credentials(&creds);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error allocating credentials for TLS context: " + std::string(gnutls_strerror(rc)));
    }

    d_creds = std::shared_ptr<gnutls_certificate_credentials_st>(creds, gnutls_certificate_free_credentials);
    creds = nullptr;

    if (params.d_validateCertificates) {
      if (params.d_caStore.empty()) {
#if GNUTLS_VERSION_NUMBER >= 0x030700 && GNUTLS_VERSION_NUMBER < 0x030703
        /* see https://gitlab.com/gnutls/gnutls/-/issues/1277 */
        std::cerr<<"Warning: GnuTLS 3.7.0 - 3.7.2 have a memory leak when validating server certificates in some configurations (PKCS11 support enabled, and a default PKCS11 trust store), please consider upgrading GnuTLS, using the OpenSSL provider for outgoing connections, or explicitly setting a CA store"<<std::endl;
#endif /* GNUTLS_VERSION_NUMBER >= 0x030700 && GNUTLS_VERSION_NUMBER < 0x030703 */
        rc = gnutls_certificate_set_x509_system_trust(d_creds.get());
        if (rc < 0) {
          throw std::runtime_error("Error adding the system's default trusted CAs: " + std::string(gnutls_strerror(rc)));
        }
      }
      else {
        rc = gnutls_certificate_set_x509_trust_file(d_creds.get(), params.d_caStore.c_str(), GNUTLS_X509_FMT_PEM);
        if (rc < 0) {
          throw std::runtime_error("Error adding '" + params.d_caStore + "' to the trusted CAs: " + std::string(gnutls_strerror(rc)));
        }
      }
    }

    rc = gnutls_priority_init(&d_priorityCache, params.d_ciphers.empty() ? "NORMAL" : params.d_ciphers.c_str(), nullptr);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting up TLS cipher preferences to 'NORMAL' (" + std::string(gnutls_strerror(rc)) + ")");
    }
  }

  ~GnuTLSIOCtx() override
  {
    d_creds.reset();

    if (d_priorityCache) {
      gnutls_priority_deinit(d_priorityCache);
    }
  }

  std::unique_ptr<TLSConnection> getConnection(int socket, const struct timeval& timeout, time_t now) override
  {
    handleTicketsKeyRotation(now);

    std::shared_ptr<GnuTLSTicketsKey> ticketsKey;
    {
      ticketsKey = *(d_ticketsKey.read_lock());
    }

    auto connection = std::make_unique<GnuTLSConnection>(socket, timeout, d_creds, d_priorityCache, ticketsKey, d_enableTickets);
    if (!d_protos.empty()) {
      connection->setALPNProtos(d_protos);
    }
    return connection;
  }

  static std::shared_ptr<gnutls_certificate_credentials_st> getPerThreadCredentials(bool validate, const std::string& caStore)
  {
    static thread_local std::map<std::pair<bool, std::string>, std::shared_ptr<gnutls_certificate_credentials_st>> t_credentials;
    auto& entry = t_credentials[{validate, caStore}];
    if (!entry) {
      gnutls_certificate_credentials_t creds;
      int rc = gnutls_certificate_allocate_credentials(&creds);
      if (rc != GNUTLS_E_SUCCESS) {
        throw std::runtime_error("Error allocating credentials for TLS context: " + std::string(gnutls_strerror(rc)));
      }

      entry = std::shared_ptr<gnutls_certificate_credentials_st>(creds, gnutls_certificate_free_credentials);
      creds = nullptr;

      if (validate) {
        if (caStore.empty()) {
          rc = gnutls_certificate_set_x509_system_trust(entry.get());
          if (rc < 0) {
            throw std::runtime_error("Error adding the system's default trusted CAs: " + std::string(gnutls_strerror(rc)));
          }
        }
        else {
          rc = gnutls_certificate_set_x509_trust_file(entry.get(), caStore.c_str(), GNUTLS_X509_FMT_PEM);
          if (rc < 0) {
            throw std::runtime_error("Error adding '" + caStore + "' to the trusted CAs: " + std::string(gnutls_strerror(rc)));
          }
        }
      }
    }
    return entry;
  }

  std::unique_ptr<TLSConnection> getClientConnection(const std::string& host, bool, int socket, const struct timeval& timeout) override
  {
    auto creds = getPerThreadCredentials(d_contextParameters->d_validateCertificates, d_contextParameters->d_caStore);
    auto connection = std::make_unique<GnuTLSConnection>(host, socket, timeout, creds, d_priorityCache, d_validateCerts);
    if (!d_protos.empty()) {
      connection->setALPNProtos(d_protos);
    }
    return connection;
  }

  void addTicketsKey(time_t now, std::shared_ptr<GnuTLSTicketsKey>&& newKey)
  {
    if (!d_enableTickets) {
      return;
    }

    {
      *(d_ticketsKey.write_lock()) = std::move(newKey);
    }

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = now + d_ticketsKeyRotationDelay;
    }

    if (TLSCtx::hasTicketsKeyAddedHook()) {
      auto ticketsKey = *(d_ticketsKey.read_lock());
      auto content = ticketsKey->content();
      TLSCtx::getTicketsKeyAddedHook()(content);
      safe_memory_release(content.data(), content.size());
    }
  }
  void rotateTicketsKey(time_t now) override
  {
    if (!d_enableTickets) {
      return;
    }

    auto newKey = std::make_shared<GnuTLSTicketsKey>();
    addTicketsKey(now, std::move(newKey));
  }
  void loadTicketsKey(const std::string& key) final
  {
    if (!d_enableTickets) {
      return;
    }

    auto newKey = std::make_shared<GnuTLSTicketsKey>(key);
    addTicketsKey(time(nullptr), std::move(newKey));
  }

  void loadTicketsKeys(const std::string& keyFile) final
  {
    if (!d_enableTickets) {
      return;
    }

    std::ifstream file(keyFile);
    auto newKey = std::make_shared<GnuTLSTicketsKey>(file);
    addTicketsKey(time(nullptr), std::move(newKey));
    file.close();
  }

  size_t getTicketsKeysCount() override
  {
    return *(d_ticketsKey.read_lock()) != nullptr ? 1 : 0;
  }

  std::string getName() const override
  {
    return "gnutls";
  }

private:
  /* client context parameters */
  std::shared_ptr<gnutls_certificate_credentials_st> d_creds;
  const std::vector<std::vector<uint8_t>> d_protos;
  std::unique_ptr<TLSContextParameters> d_contextParameters{nullptr};
  gnutls_priority_t d_priorityCache{nullptr};
  SharedLockGuarded<std::shared_ptr<GnuTLSTicketsKey>> d_ticketsKey{nullptr};
  bool d_enableTickets{true};
  bool d_validateCerts{true};
};

#endif /* HAVE_GNUTLS */

#endif /* HAVE_DNS_OVER_TLS || HAVE_DNS_OVER_HTTPS */

bool TLSFrontend::setupTLS()
{
#if defined(HAVE_DNS_OVER_TLS) || defined(HAVE_DNS_OVER_HTTPS)
  std::shared_ptr<TLSCtx> newCtx{nullptr};
  if (d_parentFrontend) {
    newCtx = d_parentFrontend->getContext();
    if (newCtx) {
      std::atomic_store_explicit(&d_ctx, std::move(newCtx), std::memory_order_release);
      return true;
    }
  }

  /* get the "best" available provider */
#if defined(HAVE_GNUTLS)
  if (d_provider == "gnutls") {
    newCtx = std::make_shared<GnuTLSIOCtx>(*this);
  }
#endif /* HAVE_GNUTLS */
#if defined(HAVE_LIBSSL)
  if (d_provider == "openssl") {
    newCtx = OpenSSLTLSIOCtx::createServerSideContext(*this);
  }
#endif /* HAVE_LIBSSL */

  if (!newCtx) {
#if defined(HAVE_LIBSSL)
    newCtx = OpenSSLTLSIOCtx::createServerSideContext(*this);
#elif defined(HAVE_GNUTLS)
    newCtx = std::make_shared<GnuTLSIOCtx>(*this);
#else
#error "TLS support needed but neither libssl nor GnuTLS were selected"
#endif
  }

  std::atomic_store_explicit(&d_ctx, std::move(newCtx), std::memory_order_release);
#endif /* HAVE_DNS_OVER_TLS || HAVE_DNS_OVER_HTTPS */
  return true;
}

std::shared_ptr<TLSCtx> getTLSContext([[maybe_unused]] const TLSContextParameters& params)
{
#ifdef HAVE_DNS_OVER_TLS
  /* get the "best" available provider */
  if (!params.d_provider.empty()) {
#if defined(HAVE_GNUTLS)
    if (params.d_provider == "gnutls") {
      return std::make_shared<GnuTLSIOCtx>(params);
    }
#endif /* HAVE_GNUTLS */
#if defined(HAVE_LIBSSL)
    if (params.d_provider == "openssl") {
      return OpenSSLTLSIOCtx::createClientSideContext(params);
    }
#endif /* HAVE_LIBSSL */
  }

#if defined(HAVE_LIBSSL)
  return OpenSSLTLSIOCtx::createClientSideContext(params);
#elif defined(HAVE_GNUTLS)
  return std::make_shared<GnuTLSIOCtx>(params);
#else
#error "DNS over TLS support needed but neither libssl nor GnuTLS were selected"
#endif

#endif /* HAVE_DNS_OVER_TLS */
  return nullptr;
}
