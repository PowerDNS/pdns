#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_MBEDTLS2
#include <mbedtls/aes.h>
#else
#include <polarssl/aes.h>
#include "mbedtlscompat.hh"
#endif
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <limits>
#include <stdint.h>
#include "dns_random.hh"

using namespace std;

static mbedtls_aes_context g_ctx;
static unsigned char g_counter[16], g_stream[16];
static uint32_t g_in;
static size_t g_offset;

static bool g_initialized;

void dns_random_init(const char data[16])
{
  g_offset = 0;
  mbedtls_aes_setkey_enc(&g_ctx, (const unsigned char*)data, 128);

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
  mbedtls_aes_crypt_ctr(&g_ctx, sizeof(g_in), &g_offset, g_counter, (unsigned char*) &g_stream, (unsigned char*) &g_in, (unsigned char*) &out);
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
