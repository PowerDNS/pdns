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

#include "namespaces.hh"
#include <cstdint>

/**
 * The QType class is meant to be used to easily deal with the different kinds of resource
 * types like 'A', 'NS' and 'CNAME'. These types have both a name and a number. This class
 * can seamlessly convert between them. Use it like this:

\code
   QType qtype = QType::fromString("CNAME");
   cout << qtype.getCode() << endl; // prints '5'
   qtype = QType(6);
   cout << qtype.toString() << endl; // prints 'SOA'
\endcode
*/

class QType
{
public:
  constexpr QType(uint16_t code = 0) :
    qtype(code) {}

  static auto fromString(const string&) -> QType;

  operator uint16_t() const
  {
    return qtype;
  }

  auto operator=(std::string& value) -> QType&
  {
    *this = QType::fromString(value);
    return *this;
  }

  [[nodiscard]] string toString() const;

  [[nodiscard]] uint16_t getCode() const
  {
    return qtype;
  }

  /**
   * \brief Return whether we know the name of this type.
   *
   * This does not presume that we have an implemented a content representation for this type,
   * for that please see DNSRecordContent::isRegisteredType().
   */
  [[nodiscard]] bool isSupportedType() const;

  /**
   * \brief Whether the type is either a QTYPE or Meta-Type as defined by rfc6895 section 3.1.
   *
   * Note that ANY is 255 and falls outside the range.
   */
  [[nodiscard]] bool isMetadataType() const;

  enum QTypeEnum : uint16_t
  {
    ENT = 0,
    A = 1,                      // NOLINT(readability-identifier-length)
    NS = 2,                     // NOLINT(readability-identifier-length)
    CNAME = 5,
    SOA = 6,
    MB = 7,                     // NOLINT(readability-identifier-length)
    MG = 8,                     // NOLINT(readability-identifier-length)
    MR = 9,                     // NOLINT(readability-identifier-length)
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,                    // NOLINT(readability-identifier-length)
    TXT = 16,
    RP = 17,                    // NOLINT(readability-identifier-length)
    AFSDB = 18,
    SIG = 24,
    KEY = 25,
    AAAA = 28,
    LOC = 29,
    SRV = 33,
    NAPTR = 35,
    KX = 36,                    // NOLINT(readability-identifier-length)
    CERT = 37,
    A6 = 38,                    // NOLINT(readability-identifier-length)
    DNAME = 39,
    OPT = 41,
    APL = 42,
    DS = 43,                    // NOLINT(readability-identifier-length)
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
    SPF = 99,
    NID = 104,
    L32 = 105,
    L64 = 106,
    LP = 107,                   // NOLINT(readability-identifier-length)
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
    LUA = 65402,
#endif
  };

  static const uint16_t rfc6895MetaLowerBound = 128;
  static const uint16_t rfc6895MetaUpperBound = 254; // Note 255: ANY is not included
  static const uint16_t rfc6895Reserved = 65535;

  static const map<const string, uint16_t> names;
  static const map<uint16_t, const string> numbers;

private:
  uint16_t qtype;
};

// Define hash function on QType. See https://en.cppreference.com/w/cpp/utility/hash
namespace std
{
template <>
struct hash<QType>
{
  std::size_t operator()(QType qtype) const noexcept
  {
    return std::hash<uint16_t>{}(qtype.getCode());
  }
};
}

inline std::ostream& operator<<(std::ostream& stream, const QType& qtype)
{
  return stream << qtype.toString();
}

// Used by e.g. boost multi-index
inline size_t hash_value(const QType qtype)
{
  return qtype.getCode();
}

struct QClass
{
  constexpr QClass(uint16_t code = 0) :
    qclass(code) {}

  constexpr operator uint16_t() const
  {
    return qclass;
  }

  [[nodiscard]] constexpr uint16_t getCode() const
  {
    return qclass;
  }

  [[nodiscard]] std::string toString() const;

  static const QClass IN; // NOLINT(readability-identifier-length)
  static const QClass CHAOS;
  static const QClass NONE;
  static const QClass ANY;

private:
  uint16_t qclass;
};

constexpr QClass QClass::IN(1); // NOLINT(readability-identifier-length)
constexpr QClass QClass::CHAOS(3);
constexpr QClass QClass::NONE(254);
constexpr QClass QClass::ANY(255);

inline std::ostream& operator<<(std::ostream& stream, QClass qclass)
{
  return stream << qclass.toString();
}
