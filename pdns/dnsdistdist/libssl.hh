#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "config.h"

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

#endif /* HAVE_LIBSSL */
