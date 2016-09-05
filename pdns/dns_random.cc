/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <openssl/aes.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER > 0x1010000fL && !defined LIBRESSL_VERSION_NUMBER
// Older OpenSSL does not have CRYPTO_ctr128_encrypt. Before 1.1.0 the header
// file did not have the necessary extern "C" wrapper. In 1.1.0, AES_ctr128_encrypt
// was removed.
#include <openssl/modes.h>
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

static AES_KEY aes_key;
static unsigned int g_offset;
static unsigned char g_counter[16], g_stream[16];
static uint32_t g_in;

static bool g_initialized;

void dns_random_init(const char data[16])
{
  g_offset = 0;
  memset(&g_stream, 0, sizeof(g_stream));
  if (AES_set_encrypt_key((const unsigned char*)data, 128, &aes_key) < 0) {
    throw std::runtime_error("AES_set_encrypt_key failed");
  }

  struct timeval now;
  gettimeofday(&now, 0);

  static_assert(sizeof(g_counter) >= (sizeof(now.tv_usec) + sizeof(now.tv_sec)), "g_counter must be large enough to get tv_sec + tv_usec");
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
#if OPENSSL_VERSION_NUMBER > 0x1010000fL && !defined LIBRESSL_VERSION_NUMBER
  CRYPTO_ctr128_encrypt((const unsigned char*)&g_in, (unsigned char*) &out, sizeof(g_in), &aes_key, g_counter, g_stream, &g_offset, (block128_f) AES_encrypt);
#else
  AES_ctr128_encrypt((const unsigned char*)&g_in, (unsigned char*) &out, sizeof(g_in), &aes_key, g_counter, g_stream, &g_offset);
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
