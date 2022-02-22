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
#pragma once
#include <cstdint>
#include <limits>
#include <string>

void dns_random_init(const std::string& data = "", bool force_reinit = false);
uint32_t dns_random(uint32_t n);
uint16_t dns_random_uint16();

namespace pdns {
  struct dns_random_engine {

    typedef uint32_t result_type;

    static constexpr result_type min()
    {
      return 0;
    }

    static constexpr result_type max()
    {
      return std::numeric_limits<result_type>::max() - 1;
    }

    result_type operator()()
    {
      return dns_random(std::numeric_limits<result_type>::max());
    }
  };

  /* minimum value that a PRNG should return for this upper bound to avoid a modulo bias */
  inline unsigned int random_minimum_acceptable_value(uint32_t upper_bound)
  {
    /* Parts of this code come from arc4random_uniform */
    /* To avoid "modulo bias" for some methods, calculate
       minimum acceptable value for random number to improve
       uniformity.

       On applicable rngs, we loop until the rng spews out
       value larger than min, and then take modulo out of that.
    */
    unsigned int min;
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
    return min;
  }
}
