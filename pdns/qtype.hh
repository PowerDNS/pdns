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

/** The QType class is meant to deal easily with the different kind of resource types, like 'A', 'NS',
 *  'CNAME' etcetera. These types have both a name and a number. This class can seamlessly move between
 *   them. Use it like this:

\code
   QType t;
   t="CNAME";
   cout<<t.getCode()<<endl; // prints '5'
   t=6;
   cout<<t.getName()<<endl; // prints 'SOA'
\endcode

*/

class QType
{
public:
  QType(uint16_t qtype = 0) : code(qtype) {}
  QType(const QType& orig) : code(orig.code) {}
  QType &operator=(uint16_t arg)
  {
    code = arg;
    return *this;
  }
  QType &operator=(const char *);
  QType &operator=(const string &);
  QType &operator=(const QType& rhs)
  {
    code = rhs.code;
    return *this;
  }
  bool operator<(const QType rhs) const
  {
    return code < rhs.code;
  }

  operator uint16_t() const {
    return code;
  }

  const string getName() const;
  uint16_t getCode() const
  {
    return code;
  }
  bool isSupportedType() const;
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
    SVCB = 64,
    HTTPS = 65,
    SPF = 99,
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
    ALIAS = 65401,
    LUA = 65402
  };

  typedef pair<string, uint16_t> namenum;
  const static vector<namenum> names;

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

struct QClass
{
  enum QClassEnum { IN = 1, CHAOS = 3, NONE = 254, ANY = 255 };
};
