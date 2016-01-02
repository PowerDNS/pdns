#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#if HAVE_MBEDTLS2
#include <mbedtls/aes.h>
#elif HAVE_MBEDTLS
#include <polarssl/aes.h>
#include "mbedtlscompat.hh"
#elif HAVE_OPENSSL
#include <openssl/aes.h>
#endif
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <limits>
#include <stdexcept>
#include <stdint.h>
#include "dns_random.hh"

using namespace std;

#ifdef HAVE_MBEDTLS
static mbedtls_aes_context g_ctx;
static size_t g_offset;
#elif defined(HAVE_OPENSSL)
static AES_KEY aes_key;
static unsigned int g_offset;
#endif
static unsigned char g_counter[16], g_stream[16];
static uint32_t g_in;

static bool g_initialized;

void dns_random_init(const char data[16])
{
  g_offset = 0;
  memset(&g_stream, 0, sizeof(g_stream));
#if HAVE_MBEDTLS
  mbedtls_aes_setkey_enc(&g_ctx, (const unsigned char*)data, 128);
#elif HAVE_OPENSSL
  if (AES_set_encrypt_key((const unsigned char*)data, 128, &aes_key) < 0) {
    throw std::runtime_error("AES_set_encrypt_key failed");
  }
#endif

  struct timeval now;
  gettimeofday(&now, 0);

  memcpy(g_counter, &now.tv_usec, sizeof(now.tv_usec));
  memcpy(g_counter+sizeof(now.tv_usec), &now.tv_sec, sizeof(now.tv_sec));
  g_in = getpid() | (getppid()<<16);

  g_initialized = true;
  srandom(dns_random(numeric_limits<uint32_t>::max()));
}

unsigned int dns_random(unsigned int n)
{
  if(!g_initialized)
    abort();
  uint32_t out;
#ifdef HAVE_MBEDTLS
  mbedtls_aes_crypt_ctr(&g_ctx, sizeof(g_in), &g_offset, g_counter, (unsigned char*) &g_stream, (unsigned char*) &g_in, (unsigned char*) &out);
#elif defined(HAVE_OPENSSL)
  AES_ctr128_encrypt((const unsigned char*)&g_in, (unsigned char*) &out, sizeof(g_in), &aes_key, g_counter, g_stream, &g_offset);
#else
#error "No dns_random implementation found"
#endif
  return out % n;
}

#if 0
int main()
{
  dns_random_init("0123456789abcdef");

  for(int n = 0; n < 16; n++)
    cerr<<dns_random(16384)<<endl;
}
#endif
