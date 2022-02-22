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
#include "config.h"

#include <stdexcept>
#include <sys/time.h>
#include <unistd.h>
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif /* HAVE_LIBSODIUM */
#ifdef HAVE_RAND_BYTES
#include <openssl/rand.h>
#endif /* HAVE_RAND_BYTES */

#include "dnsdist-random.hh"
#include "dns_random.hh"

namespace dnsdist
{
void initRandom()
{
#ifdef HAVE_LIBSODIUM
  srandom(randombytes_random());
#else
  {
    auto getSeed = []() {
#ifdef HAVE_RAND_BYTES
      unsigned int seed;
      if (RAND_bytes(reinterpret_cast<unsigned char*>(&seed), sizeof(seed)) == 1) {
        return seed;
      }
#endif /* HAVE_RAND_BYTES */
      struct timeval tv;
      gettimeofday(&tv, 0);
      return static_cast<unsigned int>(tv.tv_sec ^ tv.tv_usec ^ getpid());
    };

    srandom(getSeed());
  }
#endif
}

uint32_t getRandomValue(uint32_t upperBound)
{
#ifdef HAVE_LIBSODIUM
  return randombytes_uniform(upperBound);
#else /* HAVE_LIBSODIUM */
  uint32_t result;
  unsigned int min = pdns::random_minimum_acceptable_value(upperBound);
#ifdef HAVE_RAND_BYTES
  do {
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&result), sizeof(result)) != 1) {
      throw std::runtime_error("Error getting a random value via RAND_bytes");
    }
  } while (result < min);

  return result % upperBound;
#endif /* HAVE_RAND_BYTES */
  do {
    result = random();
  } while (result < min);

  return result % upperBound;
#endif /* HAVE_LIBSODIUM */
}

uint16_t getRandomDNSID()
{
  return getRandomValue(65536);
}
}
