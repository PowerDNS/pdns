
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

static std::atomic<uint64_t> s_users;
#endif /* (OPENSSL_VERSION_NUMBER < 0x1010000fL || defined LIBRESSL_VERSION_NUMBER) */

void registerOpenSSLUser()
{
#if (OPENSSL_VERSION_NUMBER < 0x1010000fL || defined LIBRESSL_VERSION_NUMBER)
  if (s_users.fetch_add(1) == 0) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    openssl_thread_setup();
  }
#endif
}

void unregisterOpenSSLUser()
{
#if (OPENSSL_VERSION_NUMBER < 0x1010000fL || defined LIBRESSL_VERSION_NUMBER)
  if (s_users.fetch_sub(1) == 1) {
    ERR_free_strings();

    EVP_cleanup();

    CONF_modules_finish();
    CONF_modules_free();
    CONF_modules_unload(1);

    CRYPTO_cleanup_all_ex_data();
    openssl_thread_cleanup();
  }
#endif
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

#endif /* HAVE_LIBSSL */
