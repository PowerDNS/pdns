
#include "config.h"
#include "dolog.hh"
#include "iputils.hh"
#include "lock.hh"
#include "tcpiohandler.hh"

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif /* HAVE_LIBSODIUM */

#ifdef HAVE_DNS_OVER_TLS
#ifdef HAVE_LIBSSL

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "libssl.hh"

class OpenSSLFrontendContext
{
public:
  OpenSSLFrontendContext(const ComboAddress& addr, const TLSConfig& tlsConfig): d_ticketKeys(tlsConfig.d_numberOfTicketsKeys)
  {
    registerOpenSSLUser();

    d_tlsCtx = libssl_init_server_context(tlsConfig, d_ocspResponses);
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
  std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)> d_tlsCtx{nullptr, SSL_CTX_free};
  std::unique_ptr<FILE, int(*)(FILE*)> d_keyLogFile{nullptr, fclose};
};

class OpenSSLTLSConnection: public TLSConnection
{
public:
  /* server side connection */
  OpenSSLTLSConnection(int socket, const struct timeval& timeout, std::shared_ptr<OpenSSLFrontendContext> feContext): d_feContext(feContext), d_conn(std::unique_ptr<SSL, void(*)(SSL*)>(SSL_new(d_feContext->d_tlsCtx.get()), SSL_free)), d_timeout(timeout)
  {
    d_socket = socket;

    if (!s_initTLSConnIndex.test_and_set()) {
      /* not initialized yet */
      s_tlsConnIndex = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
      if (s_tlsConnIndex == -1) {
        throw std::runtime_error("Error getting an index for TLS connection data");
      }
    }

    if (!d_conn) {
      vinfolog("Error creating TLS object");
      if (g_verbose) {
        ERR_print_errors_fp(stderr);
      }
      throw std::runtime_error("Error creating TLS object");
    }

    if (!SSL_set_fd(d_conn.get(), d_socket)) {
      throw std::runtime_error("Error assigning socket");
    }

    SSL_set_ex_data(d_conn.get(), s_tlsConnIndex, this);
  }

  /* client-side connection */
  OpenSSLTLSConnection(const std::string& hostname, int socket, const struct timeval& timeout, SSL_CTX* tlsCtx): d_conn(std::unique_ptr<SSL, void(*)(SSL*)>(SSL_new(tlsCtx), SSL_free)), d_hostname(hostname), d_timeout(timeout)
  {
    d_socket = socket;

    if (!d_conn) {
      vinfolog("Error creating TLS object");
      if (g_verbose) {
        ERR_print_errors_fp(stderr);
      }
      throw std::runtime_error("Error creating TLS object");
    }

    if (!SSL_set_fd(d_conn.get(), d_socket)) {
      throw std::runtime_error("Error assigning socket");
    }

#if (OPENSSL_VERSION_NUMBER >= 0x1010000fL) && HAVE_SSL_SET_HOSTFLAGS // grrr libressl
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
      throw std::runtime_error("Syscall error while processing TLS connection: " + std::string(strerror(errno)));
    }
    else if (error == SSL_ERROR_ZERO_RETURN) {
      throw std::runtime_error("TLS connection closed by remote end");
    }
    else {
      if (g_verbose) {
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
    return IOState::Done;
  }

  IOState tryRead(PacketBuffer& buffer, size_t& pos, size_t toRead) override
  {
    do {
      int res = SSL_read(d_conn.get(), reinterpret_cast<char *>(&buffer.at(pos)), static_cast<int>(toRead - pos));
      if (res <= 0) {
        return convertIORequestToIOState(res);
      }
      else {
        pos += static_cast<size_t>(res);
      }
    }
    while (pos < toRead);
    return IOState::Done;
  }

  size_t read(void* buffer, size_t bufferSize, const struct timeval& readTimeout, const struct timeval& totalTimeout) override
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

  bool hasBufferedData() const override
  {
    if (d_conn) {
      return SSL_pending(d_conn.get()) > 0;
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

  static int s_tlsConnIndex;

private:
  static std::atomic_flag s_initTLSConnIndex;

  std::shared_ptr<OpenSSLFrontendContext> d_feContext;
  std::unique_ptr<SSL, void(*)(SSL*)> d_conn;
  std::string d_hostname;
  struct timeval d_timeout;
};

std::atomic_flag OpenSSLTLSConnection::s_initTLSConnIndex = ATOMIC_FLAG_INIT;
int OpenSSLTLSConnection::s_tlsConnIndex = -1;

class OpenSSLTLSIOCtx: public TLSCtx
{
public:
  /* server side context */
  OpenSSLTLSIOCtx(TLSFrontend& fe): d_feContext(std::make_shared<OpenSSLFrontendContext>(fe.d_addr, fe.d_tlsConfig)), d_tlsCtx(std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>(nullptr, SSL_CTX_free))
  {
    d_ticketsKeyRotationDelay = fe.d_tlsConfig.d_ticketsKeyRotationDelay;

    if (fe.d_tlsConfig.d_enableTickets && fe.d_tlsConfig.d_numberOfTicketsKeys > 0) {
      /* use our own ticket keys handler so we can rotate them */
      SSL_CTX_set_tlsext_ticket_key_cb(d_feContext->d_tlsCtx.get(), &OpenSSLTLSIOCtx::ticketKeyCb);
      libssl_set_ticket_key_callback_data(d_feContext->d_tlsCtx.get(), d_feContext.get());
    }

    if (!d_feContext->d_ocspResponses.empty()) {
      SSL_CTX_set_tlsext_status_cb(d_feContext->d_tlsCtx.get(), &OpenSSLTLSIOCtx::ocspStaplingCb);
      SSL_CTX_set_tlsext_status_arg(d_feContext->d_tlsCtx.get(), &d_feContext->d_ocspResponses);
    }

    libssl_set_error_counters_callback(d_feContext->d_tlsCtx, &fe.d_tlsCounters);

    if (!fe.d_tlsConfig.d_keyLogFile.empty()) {
      d_feContext->d_keyLogFile = libssl_set_key_log_file(d_feContext->d_tlsCtx, fe.d_tlsConfig.d_keyLogFile);
    }

    try {
      if (fe.d_tlsConfig.d_ticketKeyFile.empty()) {
        handleTicketsKeyRotation(time(nullptr));
      }
      else {
        OpenSSLTLSIOCtx::loadTicketsKeys(fe.d_tlsConfig.d_ticketKeyFile);
      }
    }
    catch (const std::exception& e) {
      throw;
    }
  }

  /* client side context */
  OpenSSLTLSIOCtx(const TLSContextParameters& params): d_tlsCtx(std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>(nullptr, SSL_CTX_free))
  {
    int sslOptions =
      SSL_OP_NO_SSLv2 |
      SSL_OP_NO_SSLv3 |
      SSL_OP_NO_COMPRESSION |
      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
      SSL_OP_SINGLE_DH_USE |
      SSL_OP_SINGLE_ECDH_USE |
      SSL_OP_CIPHER_SERVER_PREFERENCE;

    registerOpenSSLUser();

#ifdef HAVE_TLS_CLIENT_METHOD
    d_tlsCtx = std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
#else
    d_tlsCtx = std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free);
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
  }

  ~OpenSSLTLSIOCtx() override
  {
    d_tlsCtx.reset();
    unregisterOpenSSLUser();
  }

  static int ticketKeyCb(SSL *s, unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
  {
    OpenSSLFrontendContext* ctx = reinterpret_cast<OpenSSLFrontendContext*>(libssl_get_ticket_key_callback_data(s));
    if (ctx == nullptr) {
      return -1;
    }

    int ret = libssl_ticket_key_callback(s, ctx->d_ticketKeys, keyName, iv, ectx, hctx, enc);
    if (enc == 0) {
      if (ret == 0 || ret == 2) {
        OpenSSLTLSConnection* conn = reinterpret_cast<OpenSSLTLSConnection*>(SSL_get_ex_data(s, OpenSSLTLSConnection::s_tlsConnIndex));
        if (conn) {
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

  static int ocspStaplingCb(SSL* ssl, void* arg)
  {
    if (ssl == nullptr || arg == nullptr) {
      return SSL_TLSEXT_ERR_NOACK;
    }
    const auto ocspMap = reinterpret_cast<std::map<int, std::string>*>(arg);
    return libssl_ocsp_stapling_callback(ssl, *ocspMap);
  }

  std::unique_ptr<TLSConnection> getConnection(int socket, const struct timeval& timeout, time_t now) override
  {
    handleTicketsKeyRotation(now);

    return std::make_unique<OpenSSLTLSConnection>(socket, timeout, d_feContext);
  }

  std::unique_ptr<TLSConnection> getClientConnection(const std::string& host, int socket, const struct timeval& timeout) override
  {
    return std::make_unique<OpenSSLTLSConnection>(host, socket, timeout, d_tlsCtx.get());
  }

  void rotateTicketsKey(time_t now) override
  {
    d_feContext->d_ticketKeys.rotateTicketsKey(now);

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = now + d_ticketsKeyRotationDelay;
    }
  }

  void loadTicketsKeys(const std::string& keyFile) override final
  {
    d_feContext->d_ticketKeys.loadTicketsKeys(keyFile);

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = time(nullptr) + d_ticketsKeyRotationDelay;
    }
  }

  size_t getTicketsKeysCount() override
  {
    return d_feContext->d_ticketKeys.getKeysCount();
  }

private:
  std::shared_ptr<OpenSSLFrontendContext> d_feContext;
  std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)> d_tlsCtx; // client context
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

  GnuTLSTicketsKey(const std::string& keyFile)
  {
    /* to be sure we are loading the correct amount of data, which
       may change between versions, let's generate a correct key first */
    if (gnutls_session_ticket_key_generate(&d_key) != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error generating tickets key (before parsing key file) for TLS context");
    }

    safe_memory_lock(d_key.data, d_key.size);

    try {
      ifstream file(keyFile);
      file.read(reinterpret_cast<char*>(d_key.data), d_key.size);

      if (file.fail()) {
        file.close();
        throw std::runtime_error("Invalid GnuTLS tickets key file " + keyFile);
      }

      file.close();
    }
    catch (const std::exception& e) {
      safe_memory_release(d_key.data, d_key.size);
      gnutls_free(d_key.data);
      d_key.data = nullptr;
      throw;
    }
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

class GnuTLSConnection: public TLSConnection
{
public:
  /* server side connection */
  GnuTLSConnection(int socket, const struct timeval& timeout, const gnutls_certificate_credentials_t creds, const gnutls_priority_t priorityCache, std::shared_ptr<GnuTLSTicketsKey>& ticketsKey, bool enableTickets): d_conn(std::unique_ptr<gnutls_session_int, void(*)(gnutls_session_t)>(nullptr, gnutls_deinit)), d_ticketsKey(ticketsKey)
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

    if (gnutls_credentials_set(d_conn.get(), GNUTLS_CRD_CERTIFICATE, creds) != GNUTLS_E_SUCCESS) {
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
  GnuTLSConnection(const std::string& host, int socket, const struct timeval& timeout, const gnutls_certificate_credentials_t creds, const gnutls_priority_t priorityCache, bool validateCerts): d_conn(std::unique_ptr<gnutls_session_int, void(*)(gnutls_session_t)>(nullptr, gnutls_deinit)), d_host(host)
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

    int rc = gnutls_credentials_set(d_conn.get(), GNUTLS_CRD_CERTIFICATE, creds);
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

#if HAVE_GNUTLS_SESSION_SET_VERIFY_CERT
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
  }

  IOState tryConnect(bool fastOpen, const ComboAddress& remote) override
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
        throw std::runtime_error("Error accepting a new connection");
      }
    }
    while (ret < 0 && ret == GNUTLS_E_INTERRUPTED);
  }

  IOState tryHandshake() override
  {
    int ret = 0;

    do {
      ret = gnutls_handshake(d_conn.get());
      if (ret == GNUTLS_E_SUCCESS) {
        return IOState::Done;
      }
      else if (ret == GNUTLS_E_AGAIN) {
        return IOState::NeedRead;
      }
      else if (gnutls_error_is_fatal(ret) || ret == GNUTLS_E_WARNING_ALERT_RECEIVED) {
        throw std::runtime_error("Error accepting a new connection: " + std::string(gnutls_strerror(ret)));
      }
    } while (ret == GNUTLS_E_INTERRUPTED);

    throw std::runtime_error("Error accepting a new connection");
  }

  IOState tryWrite(const PacketBuffer& buffer, size_t& pos, size_t toWrite) override
  {
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
        warnlog("Warning, non-fatal error while writing to TLS connection: %s", gnutls_strerror(res));
      }
    }
    while (pos < toWrite);
    return IOState::Done;
  }

  IOState tryRead(PacketBuffer& buffer, size_t& pos, size_t toRead) override
  {
    do {
      ssize_t res = gnutls_record_recv(d_conn.get(), reinterpret_cast<char *>(&buffer.at(pos)), toRead - pos);
      if (res == 0) {
        throw std::runtime_error("EOF while reading from TLS connection");
      }
      else if (res > 0) {
        pos += static_cast<size_t>(res);
      }
      else if (res < 0) {
        if (gnutls_error_is_fatal(res)) {
          throw std::runtime_error("Fatal error reading from TLS connection: " + std::string(gnutls_strerror(res)));
        }
        else if (res == GNUTLS_E_AGAIN) {
          return IOState::NeedRead;
        }
        warnlog("Warning, non-fatal error while writing to TLS connection: %s", gnutls_strerror(res));
      }
    }
    while (pos < toRead);
    return IOState::Done;
  }

  size_t read(void* buffer, size_t bufferSize, const struct timeval& readTimeout, const struct timeval& totalTimeout) override
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

  bool hasBufferedData() const override
  {
    if (d_conn) {
      return gnutls_record_check_pending(d_conn.get()) > 0;
    }

    return false;
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

  void close() override
  {
    if (d_conn) {
      gnutls_bye(d_conn.get(), GNUTLS_SHUT_RDWR);
    }
  }

private:
  std::unique_ptr<gnutls_session_int, void(*)(gnutls_session_t)> d_conn;
  std::shared_ptr<GnuTLSTicketsKey> d_ticketsKey;
  std::string d_host;
};

class GnuTLSIOCtx: public TLSCtx
{
public:
  /* server side context */
  GnuTLSIOCtx(TLSFrontend& fe): d_creds(std::unique_ptr<gnutls_certificate_credentials_st, void(*)(gnutls_certificate_credentials_t)>(nullptr, gnutls_certificate_free_credentials)), d_enableTickets(fe.d_tlsConfig.d_enableTickets)
  {
    int rc = 0;
    d_ticketsKeyRotationDelay = fe.d_tlsConfig.d_ticketsKeyRotationDelay;

    gnutls_certificate_credentials_t creds;
    rc = gnutls_certificate_allocate_credentials(&creds);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error allocating credentials for TLS context on " + fe.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
    }

    d_creds = std::unique_ptr<gnutls_certificate_credentials_st, void(*)(gnutls_certificate_credentials_t)>(creds, gnutls_certificate_free_credentials);
    creds = nullptr;

    for (const auto& pair : fe.d_tlsConfig.d_certKeyPairs) {
      rc = gnutls_certificate_set_x509_key_file(d_creds.get(), pair.first.c_str(), pair.second.c_str(), GNUTLS_X509_FMT_PEM);
      if (rc != GNUTLS_E_SUCCESS) {
        throw std::runtime_error("Error loading certificate ('" + pair.first + "') and key ('" + pair.second + "') for TLS context on " + fe.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
      }
    }

    size_t count = 0;
    for (const auto& file : fe.d_tlsConfig.d_ocspFiles) {
      rc = gnutls_certificate_set_ocsp_status_request_file(d_creds.get(), file.c_str(), count);
      if (rc != GNUTLS_E_SUCCESS) {
        throw std::runtime_error("Error loading OCSP response from file '" + file + "' for certificate ('" + fe.d_tlsConfig.d_certKeyPairs.at(count).first + "') and key ('" + fe.d_tlsConfig.d_certKeyPairs.at(count).second + "') for TLS context on " + fe.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
      }
      ++count;
    }

#if GNUTLS_VERSION_NUMBER >= 0x030600
    rc = gnutls_certificate_set_known_dh_params(d_creds.get(), GNUTLS_SEC_PARAM_HIGH);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting DH params for TLS context on " + fe.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
    }
#endif

    rc = gnutls_priority_init(&d_priorityCache, fe.d_tlsConfig.d_ciphers.empty() ? "NORMAL" : fe.d_tlsConfig.d_ciphers.c_str(), nullptr);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting up TLS cipher preferences to '" + fe.d_tlsConfig.d_ciphers + "' (" + gnutls_strerror(rc) + ") on " + fe.d_addr.toStringWithPort());
    }

    try {
      if (fe.d_tlsConfig.d_ticketKeyFile.empty()) {
        handleTicketsKeyRotation(time(nullptr));
      }
      else {
        GnuTLSIOCtx::loadTicketsKeys(fe.d_tlsConfig.d_ticketKeyFile);
      }
    }
    catch(const std::runtime_error& e) {
      throw std::runtime_error("Error generating tickets key for TLS context on " + fe.d_addr.toStringWithPort() + ": " + e.what());
    }
  }

  /* client side context */
  GnuTLSIOCtx(const TLSContextParameters& params): d_creds(std::unique_ptr<gnutls_certificate_credentials_st, void(*)(gnutls_certificate_credentials_t)>(nullptr, gnutls_certificate_free_credentials)), d_enableTickets(true), d_validateCerts(params.d_validateCertificates)
  {
    int rc = 0;

    gnutls_certificate_credentials_t creds;
    rc = gnutls_certificate_allocate_credentials(&creds);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error allocating credentials for TLS context: " + std::string(gnutls_strerror(rc)));
    }

    d_creds = std::unique_ptr<gnutls_certificate_credentials_st, void(*)(gnutls_certificate_credentials_t)>(creds, gnutls_certificate_free_credentials);
    creds = nullptr;

    if (params.d_validateCertificates) {
      if (params.d_caStore.empty()) {
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

  virtual ~GnuTLSIOCtx() override
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

    return std::make_unique<GnuTLSConnection>(socket, timeout, d_creds.get(), d_priorityCache, ticketsKey, d_enableTickets);
  }

  std::unique_ptr<TLSConnection> getClientConnection(const std::string& host, int socket, const struct timeval& timeout) override
  {
    return std::make_unique<GnuTLSConnection>(host, socket, timeout, d_creds.get(), d_priorityCache, d_validateCerts);
  }

  void rotateTicketsKey(time_t now) override
  {
    if (!d_enableTickets) {
      return;
    }

    auto newKey = std::make_shared<GnuTLSTicketsKey>();

    {
      *(d_ticketsKey.write_lock()) = newKey;
    }

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = now + d_ticketsKeyRotationDelay;
    }
  }

  void loadTicketsKeys(const std::string& file) override final
  {
    if (!d_enableTickets) {
      return;
    }

    auto newKey = std::make_shared<GnuTLSTicketsKey>(file);
    {
      *(d_ticketsKey.write_lock()) = newKey;
    }

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = time(nullptr) + d_ticketsKeyRotationDelay;
    }
  }

  size_t getTicketsKeysCount() override
  {
    return *(d_ticketsKey.read_lock()) != nullptr ? 1 : 0;
  }

private:
  std::unique_ptr<gnutls_certificate_credentials_st, void(*)(gnutls_certificate_credentials_t)> d_creds;
  gnutls_priority_t d_priorityCache{nullptr};
  SharedLockGuarded<std::shared_ptr<GnuTLSTicketsKey>> d_ticketsKey{nullptr};
  bool d_enableTickets{true};
  bool d_validateCerts{true};
};

#endif /* HAVE_GNUTLS */

#endif /* HAVE_DNS_OVER_TLS */

bool TLSFrontend::setupTLS()
{
#ifdef HAVE_DNS_OVER_TLS
  std::shared_ptr<TLSCtx> newCtx{nullptr};
  /* get the "best" available provider */
  if (!d_provider.empty()) {
#ifdef HAVE_GNUTLS
    if (d_provider == "gnutls") {
      newCtx = std::make_shared<GnuTLSIOCtx>(*this);
      std::atomic_store_explicit(&d_ctx, newCtx, std::memory_order_release);
      return true;
    }
#endif /* HAVE_GNUTLS */
#ifdef HAVE_LIBSSL
    if (d_provider == "openssl") {
      newCtx = std::make_shared<OpenSSLTLSIOCtx>(*this);
      std::atomic_store_explicit(&d_ctx, newCtx, std::memory_order_release);
      return true;
    }
#endif /* HAVE_LIBSSL */
  }
#ifdef HAVE_LIBSSL
  newCtx = std::make_shared<OpenSSLTLSIOCtx>(*this);
#else /* HAVE_LIBSSL */
#ifdef HAVE_GNUTLS
  newCtx = std::make_shared<GnuTLSIOCtx>(*this);
#endif /* HAVE_GNUTLS */
#endif /* HAVE_LIBSSL */

  std::atomic_store_explicit(&d_ctx, newCtx, std::memory_order_release);
#endif /* HAVE_DNS_OVER_TLS */
  return true;
}

std::shared_ptr<TLSCtx> getTLSContext(const TLSContextParameters& params)
{
#ifdef HAVE_DNS_OVER_TLS
  /* get the "best" available provider */
  if (!params.d_provider.empty()) {
#ifdef HAVE_GNUTLS
    if (params.d_provider == "gnutls") {
      return std::make_shared<GnuTLSIOCtx>(params);
    }
#endif /* HAVE_GNUTLS */
#ifdef HAVE_LIBSSL
    if (params.d_provider == "openssl") {
      return std::make_shared<OpenSSLTLSIOCtx>(params);
    }
#endif /* HAVE_LIBSSL */
  }
#ifdef HAVE_GNUTLS
  return std::make_shared<GnuTLSIOCtx>(params);
#else /* HAVE_GNUTLS */
#ifdef HAVE_LIBSSL
  return std::make_shared<OpenSSLTLSIOCtx>(params);
#endif /* HAVE_LIBSSL */
#endif /* HAVE_GNUTLS */

#endif /* HAVE_DNS_OVER_TLS */
  return nullptr;
}
