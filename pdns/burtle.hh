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

#include <cinttypes>

inline void burtlemix(uint32_t& a, uint32_t& b, uint32_t& c)
{
  a -= b;
  a -= c;
  a ^= (c >> 13);
  b -= c;
  b -= a;
  b ^= (a << 8);
  c -= a;
  c -= b;
  c ^= (b >> 13);
  a -= b;
  a -= c;
  a ^= (c >> 12);
  b -= c;
  b -= a;
  b ^= (a << 16);
  c -= a;
  c -= b;
  c ^= (b >> 5);
  a -= b;
  a -= c;
  a ^= (c >> 3);
  b -= c;
  b -= a;
  b ^= (a << 10);
  c -= a;
  c -= b;
  c ^= (b >> 15);
}

inline uint32_t burtle(const unsigned char* k, uint32_t length, uint32_t initval)
{
  uint32_t a, b, c, len;

  /* Set up the internal state */
  len = length;
  a = b = 0x9e3779b9; /* the golden ratio; an arbitrary value */
  c = initval; /* the previous hash value */

  /*---------------------------------------- handle most of the key */
  while (len >= 12) {
    a += (k[0] + ((uint32_t)k[1] << 8) + ((uint32_t)k[2] << 16) + ((uint32_t)k[3] << 24));
    b += (k[4] + ((uint32_t)k[5] << 8) + ((uint32_t)k[6] << 16) + ((uint32_t)k[7] << 24));
    c += (k[8] + ((uint32_t)k[9] << 8) + ((uint32_t)k[10] << 16) + ((uint32_t)k[11] << 24));
    burtlemix(a, b, c);
    k += 12;
    len -= 12;
  }

  /*------------------------------------- handle the last 11 bytes */
  c += length;
  switch (len) { /* all the case statements fall through */
  case 11:
    c += ((uint32_t)k[10] << 24);
    /* fall-through */
  case 10:
    c += ((uint32_t)k[9] << 16);
    /* fall-through */
  case 9:
    c += ((uint32_t)k[8] << 8);
    /* the first byte of c is reserved for the length */
    /* fall-through */
  case 8:
    b += ((uint32_t)k[7] << 24);
    /* fall-through */
  case 7:
    b += ((uint32_t)k[6] << 16);
    /* fall-through */
  case 6:
    b += ((uint32_t)k[5] << 8);
    /* fall-through */
  case 5:
    b += k[4];
    /* fall-through */
  case 4:
    a += ((uint32_t)k[3] << 24);
    /* fall-through */
  case 3:
    a += ((uint32_t)k[2] << 16);
    /* fall-through */
  case 2:
    a += ((uint32_t)k[1] << 8);
    /* fall-through */
  case 1:
    a += k[0];
    /* case 0: nothing left to add */
  }
  burtlemix(a, b, c);
  /*-------------------------------------------- report the result */
  return c;
}

inline uint32_t burtleCI(const unsigned char* k, uint32_t length, uint32_t initval)
{
  uint32_t a, b, c, len;

  /* Set up the internal state */
  len = length;
  a = b = 0x9e3779b9; /* the golden ratio; an arbitrary value */
  c = initval; /* the previous hash value */

  /*---------------------------------------- handle most of the key */
  while (len >= 12) {
    a += (dns_tolower(k[0]) + ((uint32_t)dns_tolower(k[1]) << 8) + ((uint32_t)dns_tolower(k[2]) << 16) + ((uint32_t)dns_tolower(k[3]) << 24));
    b += (dns_tolower(k[4]) + ((uint32_t)dns_tolower(k[5]) << 8) + ((uint32_t)dns_tolower(k[6]) << 16) + ((uint32_t)dns_tolower(k[7]) << 24));
    c += (dns_tolower(k[8]) + ((uint32_t)dns_tolower(k[9]) << 8) + ((uint32_t)dns_tolower(k[10]) << 16) + ((uint32_t)dns_tolower(k[11]) << 24));
    burtlemix(a, b, c);
    k += 12;
    len -= 12;
  }

  /*------------------------------------- handle the last 11 bytes */
  c += length;
  switch (len) { /* all the case statements fall through */
  case 11:
    c += ((uint32_t)dns_tolower(k[10]) << 24);
    /* fall-through */
  case 10:
    c += ((uint32_t)dns_tolower(k[9]) << 16);
    /* fall-through */
  case 9:
    c += ((uint32_t)dns_tolower(k[8]) << 8);
    /* the first byte of c is reserved for the length */
    /* fall-through */
  case 8:
    b += ((uint32_t)dns_tolower(k[7]) << 24);
    /* fall-through */
  case 7:
    b += ((uint32_t)dns_tolower(k[6]) << 16);
    /* fall-through */
  case 6:
    b += ((uint32_t)dns_tolower(k[5]) << 8);
    /* fall-through */
  case 5:
    b += dns_tolower(k[4]);
    /* fall-through */
  case 4:
    a += ((uint32_t)dns_tolower(k[3]) << 24);
    /* fall-through */
  case 3:
    a += ((uint32_t)dns_tolower(k[2]) << 16);
    /* fall-through */
  case 2:
    a += ((uint32_t)dns_tolower(k[1]) << 8);
    /* fall-through */
  case 1:
    a += dns_tolower(k[0]);
    /* case 0: nothing left to add */
  }
  burtlemix(a, b, c);
  /*-------------------------------------------- report the result */
  return c;
}

inline uint32_t burtleCI(const std::string &k, uint32_t initval)
{
  return burtleCI(reinterpret_cast<const unsigned char *>(k.data()), k.length(), initval);
}
