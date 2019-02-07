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
#ifndef QTYPE_HH
#define QTYPE_HH
// $Id$
#include <string>
#include <vector>
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
  QType(); //!< Naked constructor
  explicit QType(uint16_t); //!< convert from an integer to a QType
  QType(const QType& orig) : code(orig.code)
  {
  }
  QType &operator=(uint16_t);  //!< Assigns integers to us
  QType &operator=(const char *); //!< Assigns strings to us
  QType &operator=(const string &); //!< Assigns strings to us
  QType &operator=(const QType&rhs)  //!< Assigns strings to us
  {
    code=rhs.code;
    return *this;
  }

  bool operator<(const QType& rhs) const 
  {
    return code < rhs.code;
  }

  const string getName() const; //!< Get a string representation of this type
  uint16_t getCode() const; //!< Get the integer representation of this type
  bool isSupportedType();
  bool isMetadataType();

  static int chartocode(const char *p); //!< convert a character string to a code
  enum typeenum : uint16_t {
    ENT=0,
    A=1,
    NS=2,
    CNAME=5,
    SOA=6,
    MB=7,
    MG=8,
    MR=9,
    PTR=12,
    HINFO=13,
    MINFO=14,
    MX=15,
    TXT=16,
    RP=17,
    AFSDB=18,
    SIG=24,
    KEY=25,
    AAAA=28,
    LOC=29,
    SRV=33,
    NAPTR=35,
    KX=36,
    CERT=37,
    A6=38,
    DNAME=39,
    OPT=41,
    DS=43,
    SSHFP=44,
    IPSECKEY=45,
    RRSIG=46,
    NSEC=47,
    DNSKEY=48,
    DHCID=49,
    NSEC3=50,
    NSEC3PARAM=51,
    TLSA=52,
    SMIMEA=53,
    RKEY=57,
    CDS=59,
    CDNSKEY=60,
    OPENPGPKEY=61,
    SPF=99,
    EUI48=108,
    EUI64=109,
    TKEY=249,
    TSIG=250,
    IXFR=251,
    AXFR=252,
    MAILB=253,
    MAILA=254,
    ANY=255,
    URI=256,
    CAA=257,
    DLV=32769,
    ADDR=65400,
    ALIAS=65401,
    LUA=65402
  };

  QType(typeenum orig) : code(orig)
  {
  }

  typedef pair<string,uint16_t> namenum;
  static vector<namenum> names;

  inline bool operator==(const QType &comp) const {
    return(comp.code==code);
  }

  inline bool operator!=(const QType &comp) const {
    return(comp.code!=code);
  }

  inline bool operator==(QType::typeenum comp) const {
    return(comp==code);
  }

  inline bool operator!=(QType::typeenum comp) const {
    return(comp!=code);
  }

  inline bool operator==(uint16_t comp) const {
    return(comp==code);
  }

  inline bool operator!=(uint16_t comp) const {
    return(comp!=code);
  }

private:
  static class init {
    public:
    void qtype_insert(const char* a, uint16_t num) 
    {
      names.push_back(make_pair(string(a), num));
    }

    init()
    {
      qtype_insert("A", 1);
      qtype_insert("NS", 2);
      qtype_insert("CNAME", 5);
      qtype_insert("SOA", 6);
      qtype_insert("MB", 7);
      qtype_insert("MG", 8);
      qtype_insert("MR", 9);
      qtype_insert("PTR", 12);
      qtype_insert("HINFO", 13);
      qtype_insert("MINFO", 14);
      qtype_insert("MX", 15);
      qtype_insert("TXT", 16);
      qtype_insert("RP", 17);
      qtype_insert("AFSDB", 18);
      qtype_insert("SIG", 24);
      qtype_insert("KEY", 25);
      qtype_insert("AAAA", 28);
      qtype_insert("LOC", 29);
      qtype_insert("SRV", 33);
      qtype_insert("NAPTR", 35);
      qtype_insert("KX", 36);
      qtype_insert("CERT", 37);
      qtype_insert("A6", 38);
      qtype_insert("DNAME", 39);
      qtype_insert("OPT", 41);
      qtype_insert("DS", 43);
      qtype_insert("SSHFP", 44);
      qtype_insert("IPSECKEY", 45);
      qtype_insert("RRSIG", 46);
      qtype_insert("NSEC", 47);
      qtype_insert("DNSKEY", 48);
      qtype_insert("DHCID", 49);
      qtype_insert("NSEC3", 50);
      qtype_insert("NSEC3PARAM", 51);
      qtype_insert("TLSA", 52);
      qtype_insert("SMIMEA", 53);
      qtype_insert("RKEY", 57);
      qtype_insert("CDS", 59);
      qtype_insert("CDNSKEY", 60);
      qtype_insert("OPENPGPKEY", 61);
      qtype_insert("SPF", 99);
      qtype_insert("EUI48", 108);
      qtype_insert("EUI64", 109);
      qtype_insert("TKEY", 249);
//      qtype_insert("TSIG", 250);
      qtype_insert("IXFR", 251);
      qtype_insert("AXFR", 252);
      qtype_insert("MAILB", 253);
      qtype_insert("MAILA", 254);
      qtype_insert("ANY", 255);
      qtype_insert("URI", 256);
      qtype_insert("CAA", 257);
      qtype_insert("DLV", 32769);
      qtype_insert("ADDR", 65400);
      qtype_insert("ALIAS", 65401);
      qtype_insert("LUA", 65402);
    }
  } initializer;

  uint16_t code;
};

struct QClass
{
  enum QClassEnum {IN=1, CHAOS=3, NONE=254, ANY=255};
};
#endif
