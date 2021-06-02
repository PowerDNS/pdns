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

#include <string>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_CRYPTO_MEMCMP
#include <openssl/crypto.h>
#endif

static bool constantTimeStringEquals(const std::string& a, const std::string& b)
{
  if (a.size() != b.size()) {
    return false;
  }
  const size_t size = a.size();
#ifdef HAVE_CRYPTO_MEMCMP
  return CRYPTO_memcmp(a.c_str(), b.c_str(), size) == 0;
#else
  const volatile unsigned char* _a = (const volatile unsigned char*)a.c_str();
  const volatile unsigned char* _b = (const volatile unsigned char*)b.c_str();
  unsigned char res = 0;

  for (size_t idx = 0; idx < size; idx++) {
    res |= _a[idx] ^ _b[idx];
  }

  return res == 0;
#endif
}
