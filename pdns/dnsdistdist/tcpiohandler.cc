#include <fstream>

#include "config.h"
#include "circular_buffer.hh"
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

#include "libssl.hh"

/* From rfc5077 Section 4. Recommended Ticket Construction */
#define TLS_TICKETS_KEY_NAME_SIZE (16)

/* AES-256 */
#define TLS_TICKETS_CIPHER_KEY_SIZE (32)
#define TLS_TICKETS_CIPHER_ALGO (EVP_aes_256_cbc)

/* HMAC SHA-256 */
#define TLS_TICKETS_MAC_KEY_SIZE (32)
#define TLS_TICKETS_MAC_ALGO (EVP_sha256)

static int s_ticketsKeyIndex{-1};

class OpenSSLTLSTicketKey
{
public:
  OpenSSLTLSTicketKey()
  {
    if (RAND_bytes(d_name, sizeof(d_name)) != 1) {
      throw std::runtime_error("Error while generating the name of the OpenSSL TLS ticket key");
    }

    if (RAND_bytes(d_cipherKey, sizeof(d_cipherKey)) != 1) {
      throw std::runtime_error("Error while generating the cipher key of the OpenSSL TLS ticket key");
    }

    if (RAND_bytes(d_hmacKey, sizeof(d_hmacKey)) != 1) {
      throw std::runtime_error("Error while generating the HMAC key of the OpenSSL TLS ticket key");
    }
#ifdef HAVE_LIBSODIUM
    sodium_mlock(d_name, sizeof(d_name));
    sodium_mlock(d_cipherKey, sizeof(d_cipherKey));
    sodium_mlock(d_hmacKey, sizeof(d_hmacKey));
#endif /* HAVE_LIBSODIUM */
  }

  OpenSSLTLSTicketKey(ifstream& file)
  {
    file.read(reinterpret_cast<char*>(d_name), sizeof(d_name));
    file.read(reinterpret_cast<char*>(d_cipherKey), sizeof(d_cipherKey));
    file.read(reinterpret_cast<char*>(d_hmacKey), sizeof(d_hmacKey));

    if (file.fail()) {
      throw std::runtime_error("Unable to load a ticket key from the OpenSSL tickets key file");
    }
#ifdef HAVE_LIBSODIUM
    sodium_mlock(d_name, sizeof(d_name));
    sodium_mlock(d_cipherKey, sizeof(d_cipherKey));
    sodium_mlock(d_hmacKey, sizeof(d_hmacKey));
#endif /* HAVE_LIBSODIUM */
  }

  ~OpenSSLTLSTicketKey()
  {
#ifdef HAVE_LIBSODIUM
    sodium_munlock(d_name, sizeof(d_name));
    sodium_munlock(d_cipherKey, sizeof(d_cipherKey));
    sodium_munlock(d_hmacKey, sizeof(d_hmacKey));
#else
    OPENSSL_cleanse(d_name, sizeof(d_name));
    OPENSSL_cleanse(d_cipherKey, sizeof(d_cipherKey));
    OPENSSL_cleanse(d_hmacKey, sizeof(d_hmacKey));
#endif /* HAVE_LIBSODIUM */
  }

  bool nameMatches(const unsigned char name[TLS_TICKETS_KEY_NAME_SIZE]) const
  {
    return (memcmp(d_name, name, sizeof(d_name)) == 0);
  }

  int encrypt(unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx) const
  {
    memcpy(keyName, d_name, sizeof(d_name));

    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
      return -1;
    }

    if (EVP_EncryptInit_ex(ectx, TLS_TICKETS_CIPHER_ALGO(), nullptr, d_cipherKey, iv) != 1) {
      return -1;
    }

    if (HMAC_Init_ex(hctx, d_hmacKey, sizeof(d_hmacKey), TLS_TICKETS_MAC_ALGO(), nullptr) != 1) {
      return -1;
    }

    return 1;
  }

  bool decrypt(const unsigned char* iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx) const
  {
    if (HMAC_Init_ex(hctx, d_hmacKey, sizeof(d_hmacKey), TLS_TICKETS_MAC_ALGO(), nullptr) != 1) {
      return false;
    }

    if (EVP_DecryptInit_ex(ectx, TLS_TICKETS_CIPHER_ALGO(), nullptr, d_cipherKey, iv) != 1) {
      return false;
    }

    return true;
  }

private:
  unsigned char d_name[TLS_TICKETS_KEY_NAME_SIZE];
  unsigned char d_cipherKey[TLS_TICKETS_CIPHER_KEY_SIZE];
  unsigned char d_hmacKey[TLS_TICKETS_MAC_KEY_SIZE];
};

class OpenSSLTLSTicketKeysRing
{
public:
  OpenSSLTLSTicketKeysRing(size_t capacity)
  {
    pthread_rwlock_init(&d_lock, nullptr);
    d_ticketKeys.set_capacity(capacity);
  }

  ~OpenSSLTLSTicketKeysRing()
  {
    pthread_rwlock_destroy(&d_lock);
  }

  void addKey(std::shared_ptr<OpenSSLTLSTicketKey> newKey)
  {
    WriteLock wl(&d_lock);
    d_ticketKeys.push_back(newKey);
  }

  std::shared_ptr<OpenSSLTLSTicketKey> getEncryptionKey()
  {
    ReadLock rl(&d_lock);
    return d_ticketKeys.front();
  }

  std::shared_ptr<OpenSSLTLSTicketKey> getDecryptionKey(unsigned char name[TLS_TICKETS_KEY_NAME_SIZE], bool& activeKey)
  {
    ReadLock rl(&d_lock);
    for (auto& key : d_ticketKeys) {
      if (key->nameMatches(name)) {
        activeKey = (key == d_ticketKeys.front());
        return key;
      }
    }
    return nullptr;
  }

  size_t getKeysCount()
  {
    ReadLock rl(&d_lock);
    return d_ticketKeys.size();
  }

private:
  boost::circular_buffer<std::shared_ptr<OpenSSLTLSTicketKey> > d_ticketKeys;
  pthread_rwlock_t d_lock;
};

class OpenSSLTLSConnection: public TLSConnection
{
public:
  OpenSSLTLSConnection(int socket, unsigned int timeout, SSL_CTX* tlsCtx): d_conn(std::unique_ptr<SSL, void(*)(SSL*)>(SSL_new(tlsCtx), SSL_free)), d_timeout(timeout)
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
      throw std::runtime_error("Error while processing TLS connection: " + std::string(strerror(errno)));
    }
    else {
      throw std::runtime_error("Error while processing TLS connection: " + std::to_string(error));
    }
  }

  void handleIORequest(int res, unsigned int timeout)
  {
    auto state = convertIORequestToIOState(res);
    if (state == IOState::NeedRead) {
      res = waitForData(d_socket, timeout);
      if (res == 0) {
        throw std::runtime_error("Timeout while reading from TLS connection");
      }
      else if (res < 0) {
        throw std::runtime_error("Error waiting to read from TLS connection");
      }
    }
    else if (state == IOState::NeedWrite) {
      res = waitForRWData(d_socket, false, timeout, 0);
      if (res == 0) {
        throw std::runtime_error("Timeout while writing to TLS connection");
      }
      else if (res < 0) {
        throw std::runtime_error("Error waiting to write to TLS connection");
      }
    }
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

  IOState tryWrite(std::vector<uint8_t>& buffer, size_t& pos, size_t toWrite) override
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

  IOState tryRead(std::vector<uint8_t>& buffer, size_t& pos, size_t toRead) override
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

  size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout, unsigned int totalTimeout) override
  {
    size_t got = 0;
    time_t start = 0;
    unsigned int remainingTime = totalTimeout;
    if (totalTimeout) {
      start = time(nullptr);
    }

    do {
      int res = SSL_read(d_conn.get(), (reinterpret_cast<char *>(buffer) + got), static_cast<int>(bufferSize - got));
      if (res <= 0) {
        handleIORequest(res, readTimeout);
      }
      else {
        got += static_cast<size_t>(res);
      }

      if (totalTimeout) {
        time_t now = time(nullptr);
        unsigned int elapsed = now - start;
        if (now < start || elapsed >= remainingTime) {
          throw runtime_error("Timeout while reading data");
        }
        start = now;
        remainingTime -= elapsed;
      }
    }
    while (got < bufferSize);

    return got;
  }

  size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout) override
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

  void close() override
  {
    if (d_conn) {
      SSL_shutdown(d_conn.get());
    }
  }

  std::string getServerNameIndication() override
  {
    if (d_conn) {
      const char* value = SSL_get_servername(d_conn.get(), TLSEXT_NAMETYPE_host_name);
      if (value) {
        return std::string(value);
      }
    }
    return std::string();
  }

private:
  std::unique_ptr<SSL, void(*)(SSL*)> d_conn;
  unsigned int d_timeout;
};

class OpenSSLTLSIOCtx: public TLSCtx
{
public:
  OpenSSLTLSIOCtx(const TLSFrontend& fe): d_ticketKeys(fe.d_numberOfTicketsKeys), d_tlsCtx(std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>(nullptr, SSL_CTX_free))
  {
    d_ticketsKeyRotationDelay = fe.d_ticketsKeyRotationDelay;

    int sslOptions =
      SSL_OP_NO_SSLv2 |
      SSL_OP_NO_SSLv3 |
      SSL_OP_NO_COMPRESSION |
      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
      SSL_OP_SINGLE_DH_USE |
      SSL_OP_SINGLE_ECDH_USE |
      SSL_OP_CIPHER_SERVER_PREFERENCE;

    if (!fe.d_enableTickets) {
      sslOptions |= SSL_OP_NO_TICKET;
    }

    if (s_users.fetch_add(1) == 0) {
      registerOpenSSLUser();

      s_ticketsKeyIndex = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);

      if (s_ticketsKeyIndex == -1) {
        throw std::runtime_error("Error getting an index for tickets key");
      }
    }

    d_tlsCtx = std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>(SSL_CTX_new(SSLv23_server_method()), SSL_CTX_free);
    if (!d_tlsCtx) {
      ERR_print_errors_fp(stderr);
      throw std::runtime_error("Error creating TLS context on " + fe.d_addr.toStringWithPort());
    }

    /* use our own ticket keys handler so we can rotate them */
    SSL_CTX_set_tlsext_ticket_key_cb(d_tlsCtx.get(), &OpenSSLTLSIOCtx::ticketKeyCb);
    SSL_CTX_set_ex_data(d_tlsCtx.get(), s_ticketsKeyIndex, this);
    SSL_CTX_set_options(d_tlsCtx.get(), sslOptions);
#if defined(SSL_CTX_set_ecdh_auto)
    SSL_CTX_set_ecdh_auto(d_tlsCtx.get(), 1);
#endif
    if (fe.d_maxStoredSessions == 0) {
      /* disable stored sessions entirely */
      SSL_CTX_set_session_cache_mode(d_tlsCtx.get(), SSL_SESS_CACHE_OFF);
    }
    else {
      /* use the internal built-in cache to store sessions */
      SSL_CTX_set_session_cache_mode(d_tlsCtx.get(), SSL_SESS_CACHE_SERVER);
      SSL_CTX_sess_set_cache_size(d_tlsCtx.get(), fe.d_maxStoredSessions);
    }

    std::vector<int> keyTypes;
    for (const auto& pair : fe.d_certKeyPairs) {
      if (SSL_CTX_use_certificate_chain_file(d_tlsCtx.get(), pair.first.c_str()) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error loading certificate from " + pair.first + " for the TLS context on " + fe.d_addr.toStringWithPort());
      }
      if (SSL_CTX_use_PrivateKey_file(d_tlsCtx.get(), pair.second.c_str(), SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error loading key from " + pair.second + " for the TLS context on " + fe.d_addr.toStringWithPort());
      }
      if (SSL_CTX_check_private_key(d_tlsCtx.get()) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Key from '" + pair.second + "' does not match the certificate from '" + pair.first + "' for the TLS context on " + fe.d_addr.toStringWithPort());
      }

      /* store the type of the new key, we might need it later to select the right OCSP stapling response */
      keyTypes.push_back(libssl_get_last_key_type(d_tlsCtx));
    }

    if (!fe.d_ocspFiles.empty()) {
      try {
        d_ocspResponses = libssl_load_ocsp_responses(fe.d_ocspFiles, keyTypes);
      }
      catch(const std::exception& e) {
        throw std::runtime_error("Error loading responses for the TLS context on " + fe.d_addr.toStringWithPort() + ": " + e.what());
      }

      SSL_CTX_set_tlsext_status_cb(d_tlsCtx.get(), &OpenSSLTLSIOCtx::ocspStaplingCb);
      SSL_CTX_set_tlsext_status_arg(d_tlsCtx.get(), &d_ocspResponses);
    }

    if (!fe.d_ciphers.empty()) {
      if (SSL_CTX_set_cipher_list(d_tlsCtx.get(), fe.d_ciphers.c_str()) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error setting the cipher list to '" + fe.d_ciphers + "' for the TLS context on " + fe.d_addr.toStringWithPort());
      }
    }

#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
    if (!fe.d_ciphers13.empty()) {
      if (SSL_CTX_set_ciphersuites(d_tlsCtx.get(), fe.d_ciphers13.c_str()) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error setting the TLS 1.3 cipher list to '" + fe.d_ciphers13 + "' for the TLS context on " + fe.d_addr.toStringWithPort());
      }
    }
#endif /* HAVE_SSL_CTX_SET_CIPHERSUITES */

    try {
      if (fe.d_ticketKeyFile.empty()) {
        handleTicketsKeyRotation(time(nullptr));
      }
      else {
        loadTicketsKeys(fe.d_ticketKeyFile);
      }
    }
    catch (const std::exception& e) {
      throw;
    }
  }

  virtual ~OpenSSLTLSIOCtx() override
  {
    d_tlsCtx.reset();

    if (s_users.fetch_sub(1) == 1) {
      unregisterOpenSSLUser();
    }
  }

  static int ticketKeyCb(SSL *s, unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
  {
    SSL_CTX* sslCtx = SSL_get_SSL_CTX(s);
    if (sslCtx == nullptr) {
      return -1;
    }

    OpenSSLTLSIOCtx* ctx = reinterpret_cast<OpenSSLTLSIOCtx*>(SSL_CTX_get_ex_data(sslCtx, s_ticketsKeyIndex));
    if (ctx == nullptr) {
      return -1;
    }

    if (enc) {
      const auto key = ctx->d_ticketKeys.getEncryptionKey();
      if (key == nullptr) {
        return -1;
      }

      return key->encrypt(keyName, iv, ectx, hctx);
    }

    bool activeEncryptionKey = false;

    const auto key = ctx->d_ticketKeys.getDecryptionKey(keyName, activeEncryptionKey);
    if (key == nullptr) {
      /* we don't know this key, just create a new ticket */
      return 0;
    }

    if (key->decrypt(iv, ectx, hctx) == false) {
      return -1;
    }

    if (!activeEncryptionKey) {
      /* this key is not active, please encrypt the ticket content with the currently active one */
      return 2;
    }

    return 1;
  }

  static int ocspStaplingCb(SSL* ssl, void* arg)
  {
    if (ssl == nullptr || arg == nullptr) {
      return SSL_TLSEXT_ERR_NOACK;
    }
    const auto ocspMap = reinterpret_cast<std::map<int, std::string>*>(arg);
    return libssl_ocsp_stapling_callback(ssl, *ocspMap);
  }

  std::unique_ptr<TLSConnection> getConnection(int socket, unsigned int timeout, time_t now) override
  {
    handleTicketsKeyRotation(now);

    return std::unique_ptr<OpenSSLTLSConnection>(new OpenSSLTLSConnection(socket, timeout, d_tlsCtx.get()));
  }

  void rotateTicketsKey(time_t now) override
  {
    auto newKey = std::make_shared<OpenSSLTLSTicketKey>();
    d_ticketKeys.addKey(newKey);

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = now + d_ticketsKeyRotationDelay;
    }
  }

  void loadTicketsKeys(const std::string& keyFile) override
  {
    bool keyLoaded = false;
    ifstream file(keyFile);
    try {
      do {
        auto newKey = std::make_shared<OpenSSLTLSTicketKey>(file);
        d_ticketKeys.addKey(newKey);
        keyLoaded = true;
      }
      while (!file.fail());
    }
    catch (const std::exception& e) {
      /* if we haven't been able to load at least one key, fail */
      if (!keyLoaded) {
        throw;
      }
    }

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = time(nullptr) + d_ticketsKeyRotationDelay;
    }

    file.close();
  }

  size_t getTicketsKeysCount() override
  {
    return d_ticketKeys.getKeysCount();
  }

private:
  OpenSSLTLSTicketKeysRing d_ticketKeys;
  std::map<int, std::string> d_ocspResponses;
  std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)> d_tlsCtx;
  static std::atomic<uint64_t> s_users;
};

std::atomic<uint64_t> OpenSSLTLSIOCtx::s_users(0);

#endif /* HAVE_LIBSSL */

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

void safe_memory_lock(void* data, size_t size)
{
#ifdef HAVE_LIBSODIUM
  sodium_mlock(data, size);
#endif
}

void safe_memory_release(void* data, size_t size)
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

  GnuTLSConnection(int socket, unsigned int timeout, const gnutls_certificate_credentials_t creds, const gnutls_priority_t priorityCache, std::shared_ptr<GnuTLSTicketsKey>& ticketsKey, bool enableTickets): d_conn(std::unique_ptr<gnutls_session_int, void(*)(gnutls_session_t)>(nullptr, gnutls_deinit)), d_ticketsKey(ticketsKey)
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
    gnutls_handshake_set_timeout(d_conn.get(), timeout * 1000);
    gnutls_record_set_timeout(d_conn.get(), timeout * 1000);
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
        throw std::runtime_error("Error accepting a new connection");
      }
    } while (ret == GNUTLS_E_INTERRUPTED);

    throw std::runtime_error("Error accepting a new connection");
  }

  IOState tryWrite(std::vector<uint8_t>& buffer, size_t& pos, size_t toWrite) override
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

  IOState tryRead(std::vector<uint8_t>& buffer, size_t& pos, size_t toRead) override
  {
    do {
      ssize_t res = gnutls_record_recv(d_conn.get(), reinterpret_cast<char *>(&buffer.at(pos)), toRead - pos);
      if (res == 0) {
        throw std::runtime_error("Error reading from TLS connection");
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

  size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout, unsigned int totalTimeout) override
  {
    size_t got = 0;
    time_t start = 0;
    unsigned int remainingTime = totalTimeout;
    if (totalTimeout) {
      start = time(nullptr);
    }

    do {
      ssize_t res = gnutls_record_recv(d_conn.get(), (reinterpret_cast<char *>(buffer) + got), bufferSize - got);
      if (res == 0) {
        throw std::runtime_error("Error reading from TLS connection");
      }
      else if (res > 0) {
        got += static_cast<size_t>(res);
      }
      else if (res < 0) {
        if (gnutls_error_is_fatal(res)) {
          throw std::runtime_error("Fatal error reading from TLS connection: " + std::string(gnutls_strerror(res)));
        }
        else if (res == GNUTLS_E_AGAIN) {
          int result = waitForData(d_socket, readTimeout);
          if (result <= 0) {
            throw std::runtime_error("Error while waiting to read from TLS connection: " + std::to_string(result));
          }
        }
        else {
          vinfolog("Non-fatal error while reading from TLS connection: %s", gnutls_strerror(res));
        }
      }

      if (totalTimeout) {
        time_t now = time(nullptr);
        unsigned int elapsed = now - start;
        if (now < start || elapsed >= remainingTime) {
          throw runtime_error("Timeout while reading data");
        }
        start = now;
        remainingTime -= elapsed;
      }
    }
    while (got < bufferSize);

    return got;
  }

  size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout) override
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
          int result = waitForRWData(d_socket, false, writeTimeout, 0);
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

  std::string getServerNameIndication() override
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

  void close() override
  {
    if (d_conn) {
      gnutls_bye(d_conn.get(), GNUTLS_SHUT_WR);
    }
  }

private:
  std::unique_ptr<gnutls_session_int, void(*)(gnutls_session_t)> d_conn;
  std::shared_ptr<GnuTLSTicketsKey> d_ticketsKey;
};

class GnuTLSIOCtx: public TLSCtx
{
public:
  GnuTLSIOCtx(const TLSFrontend& fe): d_creds(std::unique_ptr<gnutls_certificate_credentials_st, void(*)(gnutls_certificate_credentials_t)>(nullptr, gnutls_certificate_free_credentials)), d_enableTickets(fe.d_enableTickets)
  {
    int rc = 0;
    d_ticketsKeyRotationDelay = fe.d_ticketsKeyRotationDelay;

    gnutls_certificate_credentials_t creds;
    rc = gnutls_certificate_allocate_credentials(&creds);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error allocating credentials for TLS context on " + fe.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
    }

    d_creds = std::unique_ptr<gnutls_certificate_credentials_st, void(*)(gnutls_certificate_credentials_t)>(creds, gnutls_certificate_free_credentials);
    creds = nullptr;

    for (const auto& pair : fe.d_certKeyPairs) {
      rc = gnutls_certificate_set_x509_key_file(d_creds.get(), pair.first.c_str(), pair.second.c_str(), GNUTLS_X509_FMT_PEM);
      if (rc != GNUTLS_E_SUCCESS) {
        throw std::runtime_error("Error loading certificate ('" + pair.first + "') and key ('" + pair.second + "') for TLS context on " + fe.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
      }
    }

    size_t count = 0;
    for (const auto& file : fe.d_ocspFiles) {
      rc = gnutls_certificate_set_ocsp_status_request_file(d_creds.get(), file.c_str(), count);
      if (rc != GNUTLS_E_SUCCESS) {
        throw std::runtime_error("Error loading OCSP response from file '" + file + "' for certificate ('" + fe.d_certKeyPairs.at(count).first + "') and key ('" + fe.d_certKeyPairs.at(count).second + "') for TLS context on " + fe.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
      }
      ++count;
    }

#if GNUTLS_VERSION_NUMBER >= 0x030600
    rc = gnutls_certificate_set_known_dh_params(d_creds.get(), GNUTLS_SEC_PARAM_HIGH);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting DH params for TLS context on " + fe.d_addr.toStringWithPort() + ": " + gnutls_strerror(rc));
    }
#endif

    rc = gnutls_priority_init(&d_priorityCache, fe.d_ciphers.empty() ? "NORMAL" : fe.d_ciphers.c_str(), nullptr);
    if (rc != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error setting up TLS cipher preferences to '" + fe.d_ciphers + "' (" + gnutls_strerror(rc) + ") on " + fe.d_addr.toStringWithPort());
    }

    pthread_rwlock_init(&d_lock, nullptr);

    try {
      if (fe.d_ticketKeyFile.empty()) {
        handleTicketsKeyRotation(time(nullptr));
      }
      else {
        loadTicketsKeys(fe.d_ticketKeyFile);
      }
    }
    catch(const std::runtime_error& e) {
      pthread_rwlock_destroy(&d_lock);
      throw std::runtime_error("Error generating tickets key for TLS context on " + fe.d_addr.toStringWithPort() + ": " + e.what());
    }
  }

  virtual ~GnuTLSIOCtx() override
  {
    pthread_rwlock_destroy(&d_lock);

    d_creds.reset();

    if (d_priorityCache) {
      gnutls_priority_deinit(d_priorityCache);
    }
  }

  std::unique_ptr<TLSConnection> getConnection(int socket, unsigned int timeout, time_t now) override
  {
    handleTicketsKeyRotation(now);

    std::shared_ptr<GnuTLSTicketsKey> ticketsKey;
    {
      ReadLock rl(&d_lock);
      ticketsKey = d_ticketsKey;
    }

    return std::unique_ptr<GnuTLSConnection>(new GnuTLSConnection(socket, timeout, d_creds.get(), d_priorityCache, ticketsKey, d_enableTickets));
  }

  void rotateTicketsKey(time_t now) override
  {
    if (!d_enableTickets) {
      return;
    }

    auto newKey = std::make_shared<GnuTLSTicketsKey>();

    {
      WriteLock wl(&d_lock);
      d_ticketsKey = newKey;
    }

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = now + d_ticketsKeyRotationDelay;
    }
  }

  void loadTicketsKeys(const std::string& file) override
  {
    if (!d_enableTickets) {
      return;
    }

    auto newKey = std::make_shared<GnuTLSTicketsKey>(file);
    {
      WriteLock wl(&d_lock);
      d_ticketsKey = newKey;
    }

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = time(nullptr) + d_ticketsKeyRotationDelay;
    }
  }

  size_t getTicketsKeysCount() override
  {
    ReadLock rl(&d_lock);
    return d_ticketsKey != nullptr ? 1 : 0;
  }

private:
  std::unique_ptr<gnutls_certificate_credentials_st, void(*)(gnutls_certificate_credentials_t)> d_creds;
  gnutls_priority_t d_priorityCache{nullptr};
  std::shared_ptr<GnuTLSTicketsKey> d_ticketsKey{nullptr};
  pthread_rwlock_t d_lock;
  bool d_enableTickets{true};
};

#endif /* HAVE_GNUTLS */

#endif /* HAVE_DNS_OVER_TLS */

bool TLSFrontend::setupTLS()
{
#ifdef HAVE_DNS_OVER_TLS
  /* get the "best" available provider */
  if (!d_provider.empty()) {
#ifdef HAVE_GNUTLS
    if (d_provider == "gnutls") {
      d_ctx = std::make_shared<GnuTLSIOCtx>(*this);
      return true;
    }
#endif /* HAVE_GNUTLS */
#ifdef HAVE_LIBSSL
    if (d_provider == "openssl") {
      d_ctx = std::make_shared<OpenSSLTLSIOCtx>(*this);
      return true;
    }
#endif /* HAVE_LIBSSL */
  }
#ifdef HAVE_GNUTLS
  d_ctx = std::make_shared<GnuTLSIOCtx>(*this);
#else /* HAVE_GNUTLS */
#ifdef HAVE_LIBSSL
  d_ctx = std::make_shared<OpenSSLTLSIOCtx>(*this);
#endif /* HAVE_LIBSSL */
#endif /* HAVE_GNUTLS */

#endif /* HAVE_DNS_OVER_TLS */
  return true;
}
