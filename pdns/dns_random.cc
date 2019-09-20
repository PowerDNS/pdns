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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string>
#include "dns_random.hh"
#include "arguments.hh"
#include "logger.hh"
#include "boost/lexical_cast.hpp"

#if defined(HAVE_RANDOMBYTES_STIR)
#include <sodium.h>
#endif
#if defined(HAVE_RAND_BYTES)
#include <openssl/rand.h>
#endif
#if defined(HAVE_GETRANDOM)
#include <sys/random.h>
#endif

static enum DNS_RNG {
  RNG_UNINITIALIZED = 0,
  RNG_SODIUM,
  RNG_OPENSSL,
  RNG_GETRANDOM,
  RNG_ARC4RANDOM,
  RNG_URANDOM,
  RNG_KISS,
} chosen_rng = RNG_UNINITIALIZED;

static int urandom_fd = -1;

#if defined(HAVE_KISS_RNG)
/* KISS is intended for development use only */
static unsigned int kiss_seed;
static uint32_t kiss_z, kiss_w, kiss_jsr, kiss_jcong;

static void
kiss_init(unsigned int seed)
{
  kiss_seed = seed;
  kiss_jsr = 0x5eed5eed; /* simply musn't be 0 */
  kiss_z = 1 ^ (kiss_w = kiss_jcong = seed); /* w=z=0 is bad, see Rose */
}

static unsigned int
kiss_rand(void)
{
  kiss_z = 36969 * (kiss_z&65535) + (kiss_z>>16);
  kiss_w = 18000 * (kiss_w&65535) + (kiss_w>>16);
  kiss_jcong = 69069 * kiss_jcong + 1234567;
  kiss_jsr^=(kiss_jsr<<13); /* <<17, >>13 gives cycle length 2^28.2 max */
  kiss_jsr^=(kiss_jsr>>17); /* <<13, >>17 gives maximal cycle length */
  kiss_jsr^=(kiss_jsr<<5);
  return (((kiss_z<<16) + kiss_w) ^ kiss_jcong) + kiss_jsr;
}
#endif

static void dns_random_setup(bool force=false)
{
  string rdev;
  string rng;
  /* check if selection has been done */
  if (chosen_rng > RNG_UNINITIALIZED && !force)
    return;

/* XXX: A horrible hack to allow using dns_random in places where arguments are not available.
        Forces /dev/urandom usage
*/
#if defined(USE_URANDOM_ONLY)
  chosen_rng = RNG_URANDOM;
  rdev = "/dev/urandom";
#else
  rng = ::arg()["rng"];
  rdev = ::arg()["entropy-source"];
  if (rng == "auto") {
# if defined(HAVE_GETRANDOM)
    chosen_rng = RNG_GETRANDOM;
# elif defined(HAVE_ARC4RANDOM)
    chosen_rng = RNG_ARC4RANDOM;
# elif defined(HAVE_RANDOMBYTES_STIR)
    chosen_rng = RNG_SODIUM;
# elif defined(HAVE_RAND_BYTES)
    chosen_rng = RNG_OPENSSL;
# else
    chosen_rng = RNG_URANDOM;
# endif
# if defined(HAVE_RANDOMBYTES_STIR)
  } else if (rng == "sodium") {
    chosen_rng = RNG_SODIUM;
# endif
# if defined(HAVE_RAND_BYTES)
  } else if (rng == "openssl") {
    chosen_rng = RNG_OPENSSL;
# endif
# if defined(HAVE_GETRANDOM)
  } else if (rng == "getrandom") {
    chosen_rng = RNG_GETRANDOM;
# endif
# if defined(HAVE_ARC4RANDOM)
  } else if (rng == "arc4random") {
    chosen_rng = RNG_ARC4RANDOM;
# endif
  } else if (rng == "urandom") {
    chosen_rng = RNG_URANDOM;
#if defined(HAVE_KISS_RNG)
  } else if (rng == "kiss") {
    chosen_rng = RNG_KISS;
    g_log<<Logger::Warning<<"kiss rng should not be used in production environment"<<std::endl;
#endif
  } else {
    throw std::runtime_error("Unsupported rng '" + rng + "'");
  }

# if defined(HAVE_RANDOMBYTES_STIR)
  if (chosen_rng == RNG_SODIUM) {
    if (sodium_init() == -1)
      throw std::runtime_error("Unable to initialize sodium crypto library");
    /*  make sure it's set up */
    randombytes_stir();
  }
# endif

# if defined(HAVE_GETRANDOM)
  if (chosen_rng == RNG_GETRANDOM) {
    char buf[1];
    // some systems define getrandom but it does not really work, e.g. because it's
    // not present in kernel.
    if (getrandom(buf, sizeof(buf), 0) == -1 && errno != EINTR) {
       g_log<<Logger::Warning<<"getrandom() failed: "<<stringerror()<<", falling back to " + rdev<<std::endl;
       chosen_rng = RNG_URANDOM;
    }
  }
# endif

# if defined(HAVE_RAND_BYTES)
  if (chosen_rng == RNG_OPENSSL) {
    int ret;
    unsigned char buf[1];
    if ((ret = RAND_bytes(buf, sizeof(buf))) == -1)
      throw std::runtime_error("RAND_bytes not supported by current SSL engine");
    if (ret == 0)
      throw std::runtime_error("Openssl RNG was not seeded");
  }
# endif
#endif /* USE_URANDOM_ONLY */
  if (chosen_rng == RNG_URANDOM) {
    urandom_fd = open(rdev.c_str(), O_RDONLY);
    if (urandom_fd == -1)
      throw std::runtime_error("Cannot open " + rdev + ": " + stringerror());
  }
#if defined(HAVE_KISS_RNG)
  if (chosen_rng == RNG_KISS) {
    unsigned int seed;
    urandom_fd = open(rdev.c_str(), O_RDONLY);
    if (urandom_fd == -1)
      throw std::runtime_error("Cannot open " + rdev + ": " + stringerror());
    if (read(urandom_fd, &seed, sizeof(seed)) < 0) {
      (void)close(urandom_fd);
      throw std::runtime_error("Cannot read random device");
    }
    kiss_init(seed);
    (void)close(urandom_fd);
  }
#endif
}

void dns_random_init(const string& data __attribute__((unused)), bool force) {
  dns_random_setup(force);
  (void)dns_random(1);
  // init should occur already in dns_random_setup
  // this interface is only for KISS
#if defined(HAVE_KISS_RNG)
  unsigned int seed;
  if (chosen_rng != RNG_KISS)
    return;
  if (data.size() != 16)
    throw std::runtime_error("invalid seed");
  seed = (data[0] + (data[1]<<8) + (data[2]<<16) + (data[3]<<24)) ^
         (data[4] + (data[5]<<8) + (data[6]<<16) + (data[7]<<24)) ^
         (data[8] + (data[9]<<8) + (data[10]<<16) + (data[11]<<24)) ^
         (data[12] + (data[13]<<8) + (data[14]<<16) + (data[15]<<24));
  kiss_init(seed);
#endif
}

/* Parts of this code come from arc4random_uniform */
uint32_t dns_random(uint32_t upper_bound) {
  if (chosen_rng == RNG_UNINITIALIZED)
    dns_random_setup();

  unsigned int min;
  if (upper_bound < 2)
    return 0;
  /* To avoid "modulo bias" for some methods, calculate
     minimum acceptable value for random number to improve
     uniformity.

     On applicable rngs, we loop until the rng spews out
     value larger than min, and then take modulo out of that.
  */
#if (ULONG_MAX > 0xffffffffUL)
  min = 0x100000000UL % upper_bound;
#else
  /* Calculate (2**32 % upper_bound) avoiding 64-bit math */
  if (upper_bound > 0x80000000)
    min = 1 + ~upper_bound; /* 2**32 - upper_bound */
  else {
    /* (2**32 - (x * 2)) % x == 2**32 % x when x <= 2**31 */
    min = ((0xffffffff - (upper_bound * 2)) + 1) % upper_bound;
  }
#endif

  switch(chosen_rng) {
  case RNG_UNINITIALIZED:
    throw std::runtime_error("Unreachable at " __FILE__ ":" + boost::lexical_cast<std::string>(__LINE__)); // cannot be reached
  case RNG_SODIUM:
#if defined(HAVE_RANDOMBYTES_STIR) && !defined(USE_URANDOM_ONLY)
    return randombytes_uniform(upper_bound);
#else
    throw std::runtime_error("Unreachable at " __FILE__ ":" + boost::lexical_cast<std::string>(__LINE__)); // cannot be reached
#endif /* RND_SODIUM */
  case RNG_OPENSSL: {
#if defined(HAVE_RAND_BYTES) && !defined(USE_URANDOM_ONLY)
      uint32_t num = 0;
      do {
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&num), sizeof(num)) < 1)
          throw std::runtime_error("Openssl RNG was not seeded");
      }
      while(num < min);

      return num % upper_bound;
#else
      throw std::runtime_error("Unreachable at " __FILE__ ":" + boost::lexical_cast<std::string>(__LINE__)); // cannot be reached
#endif /* RNG_OPENSSL */
     }
  case RNG_GETRANDOM: {
#if defined(HAVE_GETRANDOM) && !defined(USE_URANDOM_ONLY)
      uint32_t num = 0;
      do {
        auto got = getrandom(&num, sizeof(num), 0);
        if (got == -1 && errno == EINTR) {
          continue;
        }
        if (got != sizeof(num)) {
          throw std::runtime_error("getrandom() failed: " + stringerror());
        }
      }
      while(num < min);

      return num % upper_bound;
#else
      throw std::runtime_error("Unreachable at " __FILE__ ":" + boost::lexical_cast<std::string>(__LINE__)); // cannot be reached
#endif
      }
  case RNG_ARC4RANDOM:
#if defined(HAVE_ARC4RANDOM) && !defined(USE_URANDOM_ONLY)
    return arc4random_uniform(upper_bound);
#else
    throw std::runtime_error("Unreachable at " __FILE__ ":" + boost::lexical_cast<std::string>(__LINE__)); // cannot be reached
#endif
  case RNG_URANDOM: {
      uint32_t num = 0;
      size_t attempts = 5;
      do {
        ssize_t got = read(urandom_fd, &num, sizeof(num));
        if (got < 0) {
          if (errno == EINTR) {
            continue;
          }

          (void)close(urandom_fd);
          throw std::runtime_error("Cannot read random device");
        }
        else if (static_cast<size_t>(got) != sizeof(num)) {
          /* short read, let's retry */
          if (attempts == 0) {
            throw std::runtime_error("Too many short reads on random device");
          }
          attempts--;
          continue;
        }
      }
      while(num < min);

      return num % upper_bound;
    }
#if defined(HAVE_KISS_RNG)
  case RNG_KISS: {
      uint32_t num = 0;
      do {
        num = kiss_rand();
      }
      while(num < min);

      return num % upper_bound;
    }
#endif
  default:
    throw std::runtime_error("Unreachable at " __FILE__ ":" + boost::lexical_cast<std::string>(__LINE__)); // cannot be reached
  };
}

uint16_t dns_random_uint16()
{
  return dns_random(0x10000);
}
