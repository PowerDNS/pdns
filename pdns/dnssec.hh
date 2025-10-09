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

#include <string>
#include "misc.hh"

class DNSSEC
{
public:

  enum keytype_t : uint8_t
  {
    KSK,
    ZSK,
    CSK
  };
  enum keyalgorithm_t : uint8_t
  {
    RSAMD5 = 1,
    DH = 2,
    DSA = 3,
    RSASHA1 = 5,
    DSANSEC3SHA1 = 6,
    RSASHA1NSEC3SHA1 = 7,
    RSASHA256 = 8,
    RSASHA512 = 10,
    ECCGOST = 12,
    ECDSA256 = 13,
    ECDSA384 = 14,
    ED25519 = 15,
    ED448 = 16
  };

  enum dsdigestalgorithm_t : uint8_t
  {
    DIGEST_SHA1 = 1,
    DIGEST_SHA256 = 2,
    DIGEST_GOST = 3,
    DIGEST_SHA384 = 4
  };

  static std::string keyTypeToString(keytype_t keyType)
  {
    switch (keyType) {
    case DNSSEC::KSK:
      return "KSK";
    case DNSSEC::ZSK:
      return "ZSK";
    case DNSSEC::CSK:
      return "CSK";
    default:
      return "UNKNOWN";
    }
  }

  /*
   * Returns the algorithm number based on the mnemonic (or old PowerDNS value of) a string.
   * See https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml for the mapping
   */
  static int shorthand2algorithm(const std::string& algorithm)
  {
    // XXX map based approach likely better
    if (pdns_iequals(algorithm, "rsamd5")) {
      return RSAMD5;
    }
    if (pdns_iequals(algorithm, "dh")) {
      return DH;
    }
    if (pdns_iequals(algorithm, "dsa")) {
      return DSA;
    }
    if (pdns_iequals(algorithm, "rsasha1")) {
      return RSASHA1;
    }
    if (pdns_iequals(algorithm, "dsa-nsec3-sha1")) {
      return DSANSEC3SHA1;
    }
    if (pdns_iequals(algorithm, "rsasha1-nsec3-sha1")) {
      return RSASHA1NSEC3SHA1;
    }
    if (pdns_iequals(algorithm, "rsasha256")) {
      return RSASHA256;
    }
    if (pdns_iequals(algorithm, "rsasha512")) {
      return RSASHA512;
    }
    if (pdns_iequals(algorithm, "ecc-gost")) {
      return ECCGOST;
    }
    if (pdns_iequals(algorithm, "gost")) {
      return ECCGOST;
    }
    if (pdns_iequals(algorithm, "ecdsa256")) {
      return ECDSA256;
    }
    if (pdns_iequals(algorithm, "ecdsap256sha256")) {
      return ECDSA256;
    }
    if (pdns_iequals(algorithm, "ecdsa384")) {
      return ECDSA384;
    }
    if (pdns_iequals(algorithm, "ecdsap384sha384")) {
      return ECDSA384;
    }
    if (pdns_iequals(algorithm, "ed25519")) {
      return ED25519;
    }
    if (pdns_iequals(algorithm, "ed448")) {
      return ED448;
    }
    if (pdns_iequals(algorithm, "indirect")) {
      return 252;
    }
    if (pdns_iequals(algorithm, "privatedns")) {
      return 253;
    }
    if (pdns_iequals(algorithm, "privateoid")) {
      return 254;
    }
    return -1;
  }

  /*
   * Returns the mnemonic from https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
   */
  static std::string algorithm2name(uint8_t algo)
  {
    switch (algo) {
    case 0:
    case 4:
    case 9:
    case 11:
      return "Reserved";
    case RSAMD5:
      return "RSAMD5";
    case DH:
      return "DH";
    case DSA:
      return "DSA";
    case RSASHA1:
      return "RSASHA1";
    case DSANSEC3SHA1:
      return "DSA-NSEC3-SHA1";
    case RSASHA1NSEC3SHA1:
      return "RSASHA1-NSEC3-SHA1";
    case RSASHA256:
      return "RSASHA256";
    case RSASHA512:
      return "RSASHA512";
    case ECCGOST:
      return "ECC-GOST";
    case ECDSA256:
      return "ECDSAP256SHA256";
    case ECDSA384:
      return "ECDSAP384SHA384";
    case ED25519:
      return "ED25519";
    case ED448:
      return "ED448";
    case 252:
      return "INDIRECT";
    case 253:
      return "PRIVATEDNS";
    case 254:
      return "PRIVATEOID";
    default:
      return "Unallocated/Reserved";
    }
  }
};
