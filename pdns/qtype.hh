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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "namespaces.hh"

/** The QType class is meant to deal easily with the different kind of resource types, like 'A', 'NS',
 *  'CNAME' etcetera. These types have both a name and a number. This class can seamlessly move between
 *   them. Use it like this:

\code
   QType t;
   t="CNAME";
   cout<<t.getCode()<<endl; // prints '5'
   t=6;
   cout<<t.toString()<<endl; // prints 'SOA'
\endcode

*/

class QType
{
public:
  QType(uint16_t qtype = 0) : code(qtype) {}
  QType &operator=(const char *);
  QType &operator=(const string &);

  operator uint16_t() const {
    return code;
  }

  const string toString() const;
  uint16_t getCode() const
  {
    return code;
  }

  /**
   * \brief Return whether we know the name of this type.
   *
   * This does not presume that we have implemented a content representation for this type,
   * for that please see DNSRecordContent::isRegisteredType().
   */
  bool isSupportedType() const;
  /**
   * \brief Whether the type is either a QTYPE or Meta-Type as defined by rfc6895 section 3.1.
   *
   * Note that ANY is 255 and falls outside the range.
   */
  bool isMetadataType() const;

  static uint16_t chartocode(const char* p);

  enum typeenum : uint16_t {
    ENT = 0,
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    SIG = 24,
    KEY = 25,
    AAAA = 28,
    LOC = 29,
    SRV = 33,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    A6 = 38,
    DNAME = 39,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMEA = 53,
    RKEY = 57,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,
    SVCB = 64,
    HTTPS = 65,
    HHIT = 67,
    BRID = 68,
    SPF = 99,
    NID = 104,
    L32 = 105,
    L64 = 106,
    LP = 107,
    EUI48 = 108,
    EUI64 = 109,
    TKEY = 249,
    TSIG = 250,
    IXFR = 251,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ANY = 255,
    URI = 256,
    CAA = 257,
    DLV = 32769,
    ADDR = 65400,
#if !defined(RECURSOR)
    ALIAS = 65401,
    LUA = 65402
#endif
  };

  const static uint16_t rfc6895MetaLowerBound = 128;
  const static uint16_t rfc6895MetaUpperBound = 254; // Note 255: ANY is not included
  const static uint16_t rfc6895Reserved = 65535;

  const static map<const string, uint16_t> names;
  const static map<uint16_t, const string> numbers;

  // QTypes that MUST NOT be used with any other QType on the same name.
  const static std::set<uint16_t> exclusiveEntryTypes;

private:

  uint16_t code;
};

// Define hash function on QType. See https://en.cppreference.com/w/cpp/utility/hash
namespace std {
  template<> struct hash<QType> {
    std::size_t operator()(QType qtype) const noexcept {
      return std::hash<uint16_t>{}(qtype.getCode());
    }
  };
}

inline std::ostream& operator<<(std::ostream& stream, const QType& qtype)
{
  return stream << qtype.toString();
}

// Used by e.g. boost multi-index
inline size_t hash_value(const QType qtype) {
  return qtype.getCode();
}

struct QClass
{
  constexpr QClass(uint16_t code = 0) : qclass(code) {}
  explicit QClass(const std::string& code);

  constexpr operator uint16_t() const {
    return qclass;
  }
  constexpr uint16_t getCode() const
  {
    return qclass;
  }
  std::string toString() const;

  static const QClass IN;
  static const QClass CHAOS;
  static const QClass NONE;
  static const QClass ANY;

private:
  uint16_t qclass;
};

constexpr QClass QClass::IN(1);
constexpr QClass QClass::CHAOS(3);
constexpr QClass QClass::NONE(254);
constexpr QClass QClass::ANY(255);

inline std::ostream& operator<<(std::ostream& s, QClass qclass)
{
  return s << qclass.toString();
}
