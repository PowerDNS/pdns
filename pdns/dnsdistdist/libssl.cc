
#include "config.h"
#include "libssl.hh"

#ifdef HAVE_LIBSSL

#include <atomic>
#include <fstream>
#include <cstring>
#include <pthread.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif /* HAVE_LIBSODIUM */

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL || defined LIBRESSL_VERSION_NUMBER)
/* OpenSSL < 1.1.0 needs support for threading/locking in the calling application. */
static pthread_mutex_t *openssllocks{nullptr};

extern "C" {
static void openssl_pthreads_locking_callback(int mode, int type, const char *file, int line)
{
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(openssllocks[type]));

  } else {
    pthread_mutex_unlock(&(openssllocks[type]));
  }
}

static unsigned long openssl_pthreads_id_callback()
{
  return (unsigned long)pthread_self();
}
}

static void openssl_thread_setup()
{
  openssllocks = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

  for (int i = 0; i < CRYPTO_num_locks(); i++)
    pthread_mutex_init(&(openssllocks[i]), NULL);

  CRYPTO_set_id_callback(openssl_pthreads_id_callback);
  CRYPTO_set_locking_callback(openssl_pthreads_locking_callback);
}

static void openssl_thread_cleanup()
{
  CRYPTO_set_locking_callback(NULL);

  for (int i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_destroy(&(openssllocks[i]));
  }

  OPENSSL_free(openssllocks);
}

#endif /* (OPENSSL_VERSION_NUMBER < 0x1010000fL || defined LIBRESSL_VERSION_NUMBER) */

static std::atomic<uint64_t> s_users;
static int s_ticketsKeyIndex{-1};
static int s_countersIndex{-1};
static int s_keyLogIndex{-1};

void registerOpenSSLUser()
{
  if (s_users.fetch_add(1) == 0) {
#if (OPENSSL_VERSION_NUMBER < 0x1010000fL || defined LIBRESSL_VERSION_NUMBER)
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    openssl_thread_setup();
#endif
    s_ticketsKeyIndex = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);

    if (s_ticketsKeyIndex == -1) {
      throw std::runtime_error("Error getting an index for tickets key");
    }

    s_countersIndex = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);

    if (s_countersIndex == -1) {
      throw std::runtime_error("Error getting an index for counters");
    }

    s_keyLogIndex = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);

    if (s_keyLogIndex == -1) {
      throw std::runtime_error("Error getting an index for TLS key logging");
    }
  }
}

void unregisterOpenSSLUser()
{
  if (s_users.fetch_sub(1) == 1) {
#if (OPENSSL_VERSION_NUMBER < 0x1010000fL || defined LIBRESSL_VERSION_NUMBER)
    ERR_free_strings();

    EVP_cleanup();

    CONF_modules_finish();
    CONF_modules_free();
    CONF_modules_unload(1);

    CRYPTO_cleanup_all_ex_data();
    openssl_thread_cleanup();
#endif
  }
}

void* libssl_get_ticket_key_callback_data(SSL* s)
{
  SSL_CTX* sslCtx = SSL_get_SSL_CTX(s);
  if (sslCtx == nullptr) {
    return nullptr;
  }

  return SSL_CTX_get_ex_data(sslCtx, s_ticketsKeyIndex);
}

void libssl_set_ticket_key_callback_data(SSL_CTX* ctx, void* data)
{
  SSL_CTX_set_ex_data(ctx, s_ticketsKeyIndex, data);
}

int libssl_ticket_key_callback(SSL *s, OpenSSLTLSTicketKeysRing& keyring, unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
{
  if (enc) {
    const auto key = keyring.getEncryptionKey();
    if (key == nullptr) {
      return -1;
    }

    return key->encrypt(keyName, iv, ectx, hctx);
  }

  bool activeEncryptionKey = false;

  const auto key = keyring.getDecryptionKey(keyName, activeEncryptionKey);
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

static void libssl_info_callback(const SSL *ssl, int where, int ret)
{
  SSL_CTX* sslCtx = SSL_get_SSL_CTX(ssl);
  if (sslCtx == nullptr) {
    return;
  }

  TLSErrorCounters* counters = reinterpret_cast<TLSErrorCounters*>(SSL_CTX_get_ex_data(sslCtx, s_countersIndex));
  if (counters == nullptr) {
    return;
  }

  if (where & SSL_CB_ALERT) {
    const long lastError = ERR_peek_last_error();
    switch (ERR_GET_REASON(lastError)) {
#ifdef SSL_R_DH_KEY_TOO_SMALL
    case SSL_R_DH_KEY_TOO_SMALL:
      ++counters->d_dhKeyTooSmall;
      break;
#endif /* SSL_R_DH_KEY_TOO_SMALL */
    case SSL_R_NO_SHARED_CIPHER:
      ++counters->d_noSharedCipher;
      break;
    case SSL_R_UNKNOWN_PROTOCOL:
      ++counters->d_unknownProtocol;
      break;
    case SSL_R_UNSUPPORTED_PROTOCOL:
#ifdef SSL_R_VERSION_TOO_LOW
    case SSL_R_VERSION_TOO_LOW:
#endif /* SSL_R_VERSION_TOO_LOW */
      ++counters->d_unsupportedProtocol;
      break;
    case SSL_R_INAPPROPRIATE_FALLBACK:
      ++counters->d_inappropriateFallBack;
      break;
    case SSL_R_UNKNOWN_CIPHER_TYPE:
      ++counters->d_unknownCipherType;
      break;
    case SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE:
      ++counters->d_unknownKeyExchangeType;
      break;
    case SSL_R_UNSUPPORTED_ELLIPTIC_CURVE:
      ++counters->d_unsupportedEC;
      break;
    default:
      break;
    }
  }
}

void libssl_set_error_counters_callback(std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>& ctx, TLSErrorCounters* counters)
{
  SSL_CTX_set_ex_data(ctx.get(), s_countersIndex, counters);
  SSL_CTX_set_info_callback(ctx.get(), libssl_info_callback);
}

int libssl_ocsp_stapling_callback(SSL* ssl, const std::map<int, std::string>& ocspMap)
{
  auto pkey = SSL_get_privatekey(ssl);
  if (pkey == nullptr) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  /* look for an OCSP response for the corresponding private key type (RSA, ECDSA..) */
  const auto& data = ocspMap.find(EVP_PKEY_base_id(pkey));
  if (data == ocspMap.end()) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  /* we need to allocate a copy because OpenSSL will free the pointer passed to SSL_set_tlsext_status_ocsp_resp() */
  void* copy = OPENSSL_malloc(data->second.size());
  if (copy == nullptr) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  memcpy(copy, data->second.data(), data->second.size());
  SSL_set_tlsext_status_ocsp_resp(ssl, copy, data->second.size());
  return SSL_TLSEXT_ERR_OK;
}

static bool libssl_validate_ocsp_response(const std::string& response)
{
  auto responsePtr = reinterpret_cast<const unsigned char *>(response.data());
  std::unique_ptr<OCSP_RESPONSE, void(*)(OCSP_RESPONSE*)> resp(d2i_OCSP_RESPONSE(nullptr, &responsePtr, response.size()), OCSP_RESPONSE_free);
  if (resp == nullptr) {
    throw std::runtime_error("Unable to parse OCSP response");
  }

  int status = OCSP_response_status(resp.get());
  if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
    throw std::runtime_error("OCSP response status is not successful: " + std::to_string(status));
  }

  std::unique_ptr<OCSP_BASICRESP, void(*)(OCSP_BASICRESP*)> basic(OCSP_response_get1_basic(resp.get()), OCSP_BASICRESP_free);
  if (basic == nullptr) {
    throw std::runtime_error("Error getting a basic OCSP response");
  }

  if (OCSP_resp_count(basic.get()) != 1) {
    throw std::runtime_error("More than one single response in an OCSP basic response");
  }

  auto singleResponse = OCSP_resp_get0(basic.get(), 0);
  if (singleResponse == nullptr) {
    throw std::runtime_error("Error getting a single response from the basic OCSP response");
  }

  int reason;
  ASN1_GENERALIZEDTIME* revTime = nullptr;
  ASN1_GENERALIZEDTIME* thisUpdate = nullptr;
  ASN1_GENERALIZEDTIME* nextUpdate = nullptr;

  auto singleResponseStatus = OCSP_single_get0_status(singleResponse, &reason, &revTime, &thisUpdate, &nextUpdate);
  if (singleResponseStatus != V_OCSP_CERTSTATUS_GOOD) {
    throw std::runtime_error("Invalid status for OCSP single response (" + std::to_string(singleResponseStatus) + ")");
  }
  if (thisUpdate == nullptr || nextUpdate == nullptr) {
    throw std::runtime_error("Error getting validity of OCSP single response");
  }

  auto validityResult = OCSP_check_validity(thisUpdate, nextUpdate, /* 5 minutes of leeway */ 5 * 60, -1);
  if (validityResult == 0) {
    throw std::runtime_error("OCSP single response is not yet, or no longer, valid");
  }

  return true;
}

std::map<int, std::string> libssl_load_ocsp_responses(const std::vector<std::string>& ocspFiles, std::vector<int> keyTypes)
{
  std::map<int, std::string> ocspResponses;

  if (ocspFiles.size() > keyTypes.size()) {
    throw std::runtime_error("More OCSP files than certificates and keys loaded!");
  }

  size_t count = 0;
  for (const auto& filename : ocspFiles) {
    std::ifstream file(filename, std::ios::binary);
    std::string content;
    while(file) {
      char buffer[4096];
      file.read(buffer, sizeof(buffer));
      if (file.bad()) {
        file.close();
        throw std::runtime_error("Unable to load OCSP response from '" + filename + "'");
      }
      content.append(buffer, file.gcount());
    }
    file.close();

    try {
      libssl_validate_ocsp_response(content);
      ocspResponses.insert({keyTypes.at(count), std::move(content)});
    }
    catch (const std::exception& e) {
      throw std::runtime_error("Error checking the validity of OCSP response from '" + filename + "': " + e.what());
    }
    ++count;
  }

  return ocspResponses;
}

int libssl_get_last_key_type(std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>& ctx)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined LIBRESSL_VERSION_NUMBER)
  auto pkey = SSL_CTX_get0_privatekey(ctx.get());
#else
  auto temp = std::unique_ptr<SSL, void(*)(SSL*)>(SSL_new(ctx.get()), SSL_free);
  if (!temp) {
    return -1;
  }
  auto pkey = SSL_get_privatekey(temp.get());
#endif

  if (!pkey) {
    return -1;
  }

  return EVP_PKEY_base_id(pkey);
}

#ifdef HAVE_OCSP_BASIC_SIGN
bool libssl_generate_ocsp_response(const std::string& certFile, const std::string& caCert, const std::string& caKey, const std::string& outFile, int ndays, int nmin)
{
  const EVP_MD* rmd = EVP_sha256();

  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(certFile.c_str(), "r"), fclose);
  if (!fp) {
    throw std::runtime_error("Unable to open '" + certFile + "' when loading the certificate to generate an OCSP response");
  }
  auto cert = std::unique_ptr<X509, void(*)(X509*)>(PEM_read_X509_AUX(fp.get(), nullptr, nullptr, nullptr), X509_free);

  fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(caCert.c_str(), "r"), fclose);
  if (!fp) {
    throw std::runtime_error("Unable to open '" + caCert + "' when loading the issuer certificate to generate an OCSP response");
  }
  auto issuer = std::unique_ptr<X509, void(*)(X509*)>(PEM_read_X509_AUX(fp.get(), nullptr, nullptr, nullptr), X509_free);
  fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(caKey.c_str(), "r"), fclose);
  if (!fp) {
    throw std::runtime_error("Unable to open '" + caKey + "' when loading the issuer key to generate an OCSP response");
  }
  auto issuerKey = std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>(PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
  fp.reset();

  auto bs = std::unique_ptr<OCSP_BASICRESP, void(*)(OCSP_BASICRESP*)>(OCSP_BASICRESP_new(), OCSP_BASICRESP_free);
  auto thisupd = std::unique_ptr<ASN1_TIME, void(*)(ASN1_TIME*)>(X509_gmtime_adj(nullptr, 0), ASN1_TIME_free);
  auto nextupd = std::unique_ptr<ASN1_TIME, void(*)(ASN1_TIME*)>(X509_time_adj_ex(nullptr, ndays, nmin * 60, nullptr), ASN1_TIME_free);

  auto cid = std::unique_ptr<OCSP_CERTID, void(*)(OCSP_CERTID*)>(OCSP_cert_to_id(rmd, cert.get(), issuer.get()), OCSP_CERTID_free);
  OCSP_basic_add1_status(bs.get(), cid.get(), V_OCSP_CERTSTATUS_GOOD, 0, nullptr, thisupd.get(), nextupd.get());

  if (OCSP_basic_sign(bs.get(), issuer.get(), issuerKey.get(), rmd, nullptr, OCSP_NOCERTS) != 1) {
    throw std::runtime_error("Error while signing the OCSP response");
  }

  auto resp = std::unique_ptr<OCSP_RESPONSE, void(*)(OCSP_RESPONSE*)>(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs.get()), OCSP_RESPONSE_free);
  auto bio = std::unique_ptr<BIO, void(*)(BIO*)>(BIO_new_file(outFile.c_str(), "wb"), BIO_vfree);
  if (!bio) {
    throw std::runtime_error("Error opening file for writing the OCSP response");
  }

  // i2d_OCSP_RESPONSE_bio(bio.get(), resp.get()) is unusable from C++ because of an invalid cast
  ASN1_i2d_bio((i2d_of_void*)i2d_OCSP_RESPONSE, bio.get(), (unsigned char*)resp.get());

  return true;
}
#endif /* HAVE_OCSP_BASIC_SIGN */

LibsslTLSVersion libssl_tls_version_from_string(const std::string& str)
{
  if (str == "tls1.0") {
    return LibsslTLSVersion::TLS10;
  }
  if (str == "tls1.1") {
    return LibsslTLSVersion::TLS11;
  }
  if (str == "tls1.2") {
    return LibsslTLSVersion::TLS12;
  }
  if (str == "tls1.3") {
    return LibsslTLSVersion::TLS13;
  }
  throw std::runtime_error("Unknown TLS version '" + str);
}

const std::string& libssl_tls_version_to_string(LibsslTLSVersion version)
{
  static const std::map<LibsslTLSVersion, std::string> versions = {
    { LibsslTLSVersion::TLS10, "tls1.0" },
    { LibsslTLSVersion::TLS11, "tls1.1" },
    { LibsslTLSVersion::TLS12, "tls1.2" },
    { LibsslTLSVersion::TLS13, "tls1.3" }
  };

  const auto& it = versions.find(version);
  if (it == versions.end()) {
    throw std::runtime_error("Unknown TLS version (" + std::to_string((int)version) + ")");
  }
  return it->second;
}

bool libssl_set_min_tls_version(std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>& ctx, LibsslTLSVersion version)
{
#if (OPENSSL_VERSION_NUMBER >= 0x1010000fL && !defined LIBRESSL_VERSION_NUMBER)
  /* these functions have been introduced in 1.1.0, and the use of SSL_OP_NO_* is deprecated */
  int vers;
  switch(version) {
  case LibsslTLSVersion::TLS10:
    vers = TLS1_VERSION;
    break;
  case LibsslTLSVersion::TLS11:
    vers = TLS1_1_VERSION;
    break;
  case LibsslTLSVersion::TLS12:
    vers = TLS1_2_VERSION;
    break;
  case LibsslTLSVersion::TLS13:
#ifdef TLS1_3_VERSION
    vers = TLS1_3_VERSION;
#else
    return false;
#endif /* TLS1_3_VERSION */
    break;
  default:
    return false;
  }

  if (SSL_CTX_set_min_proto_version(ctx.get(), vers) != 1) {
    return false;
  }
  return true;
#else
  long vers = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
  switch(version) {
  case LibsslTLSVersion::TLS10:
    break;
  case LibsslTLSVersion::TLS11:
    vers |= SSL_OP_NO_TLSv1;
    break;
  case LibsslTLSVersion::TLS12:
    vers |= SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
    break;
  case LibsslTLSVersion::TLS13:
    vers |= SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
    break;
  default:
    return false;
  }

  long options = SSL_CTX_get_options(ctx.get());
  SSL_CTX_set_options(ctx.get(), options | vers);
  return true;
#endif
}

OpenSSLTLSTicketKeysRing::OpenSSLTLSTicketKeysRing(size_t capacity)
{
  pthread_rwlock_init(&d_lock, nullptr);
  d_ticketKeys.set_capacity(capacity);
}

OpenSSLTLSTicketKeysRing::~OpenSSLTLSTicketKeysRing()
{
  pthread_rwlock_destroy(&d_lock);
}

void OpenSSLTLSTicketKeysRing::addKey(std::shared_ptr<OpenSSLTLSTicketKey> newKey)
{
  WriteLock wl(&d_lock);
  d_ticketKeys.push_front(newKey);
}

std::shared_ptr<OpenSSLTLSTicketKey> OpenSSLTLSTicketKeysRing::getEncryptionKey()
{
  ReadLock rl(&d_lock);
  return d_ticketKeys.front();
}

std::shared_ptr<OpenSSLTLSTicketKey> OpenSSLTLSTicketKeysRing::getDecryptionKey(unsigned char name[TLS_TICKETS_KEY_NAME_SIZE], bool& activeKey)
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

size_t OpenSSLTLSTicketKeysRing::getKeysCount()
{
  ReadLock rl(&d_lock);
  return d_ticketKeys.size();
}

void OpenSSLTLSTicketKeysRing::loadTicketsKeys(const std::string& keyFile)
{
  bool keyLoaded = false;
  std::ifstream file(keyFile);
  try {
    do {
      auto newKey = std::make_shared<OpenSSLTLSTicketKey>(file);
      addKey(newKey);
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

  file.close();
}

void OpenSSLTLSTicketKeysRing::rotateTicketsKey(time_t now)
{
  auto newKey = std::make_shared<OpenSSLTLSTicketKey>();
  addKey(newKey);
}

OpenSSLTLSTicketKey::OpenSSLTLSTicketKey()
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

OpenSSLTLSTicketKey::OpenSSLTLSTicketKey(ifstream& file)
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

OpenSSLTLSTicketKey::~OpenSSLTLSTicketKey()
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

bool OpenSSLTLSTicketKey::nameMatches(const unsigned char name[TLS_TICKETS_KEY_NAME_SIZE]) const
{
  return (memcmp(d_name, name, sizeof(d_name)) == 0);
}

int OpenSSLTLSTicketKey::encrypt(unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx) const
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

bool OpenSSLTLSTicketKey::decrypt(const unsigned char* iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx) const
{
  if (HMAC_Init_ex(hctx, d_hmacKey, sizeof(d_hmacKey), TLS_TICKETS_MAC_ALGO(), nullptr) != 1) {
    return false;
  }

  if (EVP_DecryptInit_ex(ectx, TLS_TICKETS_CIPHER_ALGO(), nullptr, d_cipherKey, iv) != 1) {
    return false;
  }

  return true;
}

std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)> libssl_init_server_context(const TLSConfig& config,
                                                                       std::map<int, std::string>& ocspResponses)
{
  auto ctx = std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>(SSL_CTX_new(SSLv23_server_method()), SSL_CTX_free);

  int sslOptions =
    SSL_OP_NO_SSLv2 |
    SSL_OP_NO_SSLv3 |
    SSL_OP_NO_COMPRESSION |
    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
    SSL_OP_SINGLE_DH_USE |
    SSL_OP_SINGLE_ECDH_USE;

  if (!config.d_enableTickets || config.d_numberOfTicketsKeys == 0) {
    /* for TLS 1.3 this means no stateless tickets, but stateful tickets might still be issued,
       which is something we don't want. */
    sslOptions |= SSL_OP_NO_TICKET;
    /* really disable all tickets */
#ifdef HAVE_SSL_CTX_SET_NUM_TICKETS
    SSL_CTX_set_num_tickets(ctx.get(), 0);
#endif /* HAVE_SSL_CTX_SET_NUM_TICKETS */
  }

  if (config.d_preferServerCiphers) {
    sslOptions |= SSL_OP_CIPHER_SERVER_PREFERENCE;
  }

  SSL_CTX_set_options(ctx.get(), sslOptions);
  if (!libssl_set_min_tls_version(ctx, config.d_minTLSVersion)) {
    throw std::runtime_error("Failed to set the minimum version to '" + libssl_tls_version_to_string(config.d_minTLSVersion));
  }

#ifdef SSL_CTX_set_ecdh_auto
  SSL_CTX_set_ecdh_auto(ctx.get(), 1);
#endif

  if (config.d_maxStoredSessions == 0) {
    /* disable stored sessions entirely */
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
  }
  else {
    /* use the internal built-in cache to store sessions */
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_cache_size(ctx.get(), config.d_maxStoredSessions);
  }

  std::vector<int> keyTypes;
  /* load certificate and private key */
  for (const auto& pair : config.d_certKeyPairs) {
    if (SSL_CTX_use_certificate_chain_file(ctx.get(), pair.first.c_str()) != 1) {
      ERR_print_errors_fp(stderr);
      throw std::runtime_error("An error occurred while trying to load the TLS server certificate file: " + pair.first);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), pair.second.c_str(), SSL_FILETYPE_PEM) != 1) {
      ERR_print_errors_fp(stderr);
      throw std::runtime_error("An error occurred while trying to load the TLS server private key file: " + pair.second);
    }
    if (SSL_CTX_check_private_key(ctx.get()) != 1) {
      ERR_print_errors_fp(stderr);
      throw std::runtime_error("The key from '" + pair.second + "' does not match the certificate from '" + pair.first + "'");
    }
    /* store the type of the new key, we might need it later to select the right OCSP stapling response */
    auto keyType = libssl_get_last_key_type(ctx);
    if (keyType < 0) {
      throw std::runtime_error("The key from '" + pair.second + "' has an unknown type");
    }
    keyTypes.push_back(keyType);
  }

  if (!config.d_ocspFiles.empty()) {
    try {
      ocspResponses = libssl_load_ocsp_responses(config.d_ocspFiles, keyTypes);
    }
    catch(const std::exception& e) {
      throw std::runtime_error("Unable to load OCSP responses: " + std::string(e.what()));
    }
  }

  if (!config.d_ciphers.empty() && SSL_CTX_set_cipher_list(ctx.get(), config.d_ciphers.c_str()) != 1) {
    throw std::runtime_error("The TLS ciphers could not be set: " + config.d_ciphers);
  }

#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
  if (!config.d_ciphers13.empty() && SSL_CTX_set_ciphersuites(ctx.get(), config.d_ciphers13.c_str()) != 1) {
    throw std::runtime_error("The TLS 1.3 ciphers could not be set: " + config.d_ciphers13);
  }
#endif /* HAVE_SSL_CTX_SET_CIPHERSUITES */

  return ctx;
}

#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
static void libssl_key_log_file_callback(const SSL* ssl, const char* line)
{
  SSL_CTX* sslCtx = SSL_get_SSL_CTX(ssl);
  if (sslCtx == nullptr) {
    return;
  }

  auto fp = reinterpret_cast<FILE*>(SSL_CTX_get_ex_data(sslCtx, s_keyLogIndex));
  if (fp == nullptr) {
    return;
  }

  fprintf(fp, "%s\n", line);
}
#endif /* HAVE_SSL_CTX_SET_KEYLOG_CALLBACK */

std::unique_ptr<FILE, int(*)(FILE*)> libssl_set_key_log_file(std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>& ctx, const std::string& logFile)
{
#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(logFile.c_str(), "a"), fclose);
  if (!fp) {
    throw std::runtime_error("Error opening TLS log file '" + logFile + "'");
  }

  SSL_CTX_set_ex_data(ctx.get(), s_keyLogIndex, fp.get());
  SSL_CTX_set_keylog_callback(ctx.get(), &libssl_key_log_file_callback);

  return fp;
#else
  return std::unique_ptr<FILE, int(*)(FILE*)>(nullptr, fclose);
#endif /* HAVE_SSL_CTX_SET_KEYLOG_CALLBACK */
}

#endif /* HAVE_LIBSSL */
