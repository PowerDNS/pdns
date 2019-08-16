#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "config.h"

enum class LibsslTLSVersion { TLS10, TLS11, TLS12, TLS13 };

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>

void registerOpenSSLUser();
void unregisterOpenSSLUser();

int libssl_ocsp_stapling_callback(SSL* ssl, const std::map<int, std::string>& ocspMap);

std::map<int, std::string> libssl_load_ocsp_responses(const std::vector<std::string>& ocspFiles, std::vector<int> keyTypes);
int libssl_get_last_key_type(std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>& ctx);

#ifdef HAVE_OCSP_BASIC_SIGN
bool libssl_generate_ocsp_response(const std::string& certFile, const std::string& caCert, const std::string& caKey, const std::string& outFile, int ndays, int nmin);
#endif

LibsslTLSVersion libssl_tls_version_from_string(const std::string& str);
bool libssl_set_min_tls_version(std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>& ctx, LibsslTLSVersion version);

#endif /* HAVE_LIBSSL */
