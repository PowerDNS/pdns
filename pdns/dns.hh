/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
// $Id$ 
/* (C) 2002 POWERDNS.COM BV */
#ifndef DNS_HH
#define DNS_HH
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/version.hpp>


#include "utility.hh"
#include "qtype.hh"
#include <time.h>
#include <sys/types.h>
class DNSBackend;

struct SOAData
{
  SOAData() : db(0), scopeMask(0) {};

  string qname;
  string nameserver;
  string hostmaster;
  uint32_t ttl;
  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  uint32_t default_ttl;
  int domain_id;
  DNSBackend *db;
  uint8_t scopeMask;
};


class RCode
{
public:
  enum rcodes_ { NoError=0, FormErr=1, ServFail=2, NXDomain=3, NotImp=4, Refused=5, YXDomain=6, YXRRSet=7, NXRRSet=8, NotAuth=9, NotZone=10};
  static std::string to_s(unsigned short rcode);
  static std::vector<std::string> rcodes_s;
};

class Opcode
{
public:
  enum { Query=0, IQuery=1, Status=2, Notify=4, Update=5 };
};

//! This class represents a resource record
class DNSResourceRecord
{
public:
  DNSResourceRecord() : qclass(1), signttl(0), last_modified(0), d_place(ANSWER), auth(1), disabled(0), scopeMask(0) {};
  DNSResourceRecord(const struct DNSRecord&);
  ~DNSResourceRecord(){};

  void setContent(const string& content);
  string getZoneRepresentation() const;

  // data
  
  QType qtype; //!< qtype of this record, ie A, CNAME, MX etc
  uint16_t qclass; //!< class of this record
  string qname; //!< the name of this record, for example: www.powerdns.com
  string wildcardname;
  string content; //!< what this record points to. Example: 10.1.2.3
  uint32_t ttl; //!< Time To Live of this record
  uint32_t signttl; //!< If non-zero, use this TTL as original TTL in the RRSIG
  int domain_id; //!< If a backend implements this, the domain_id of the zone this record is in
  time_t last_modified; //!< For autocalculating SOA serial numbers - the backend needs to fill this in
  enum Place {QUESTION=0, ANSWER=1, AUTHORITY=2, ADDITIONAL=3}; //!< Type describing the positioning of a DNSResourceRecord within, say, a DNSPacket
  Place d_place; //!< This specifies where a record goes within the packet

  bool auth;
  bool disabled;
  uint8_t scopeMask;

  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
    ar & qtype;
    ar & qclass;
    ar & qname;
    ar & wildcardname;
    ar & content;
    ar & ttl;
    ar & domain_id;
    ar & last_modified;
    ar & d_place;
    ar & auth;
    ar & disabled;
  }

  bool operator==(const DNSResourceRecord& rhs);

  bool operator<(const DNSResourceRecord &b) const
  {
    if(qname < b.qname)
      return true;
    if(qname == b.qname)
      return(content < b.content);
    return false;
  }
};

#define GCCPACKATTRIBUTE __attribute__((packed))

struct dnsrecordheader
{
  uint16_t d_type;
  uint16_t d_class;
  uint32_t d_ttl;
  uint16_t d_clen;
} GCCPACKATTRIBUTE;

struct EDNS0Record 
{ 
        uint8_t extRCode, version; 
        uint16_t Z; 
} GCCPACKATTRIBUTE;

#if __FreeBSD__ || __APPLE__ || __OpenBSD__ || __DragonFly__ || defined(__FreeBSD_kernel__)
#include <machine/endian.h>
#elif __linux__ || __GNU__
# include <endian.h>

#else  // with thanks to <arpa/nameser.h> 

# define LITTLE_ENDIAN   1234    /* least-significant byte first (vax, pc) */
# define BIG_ENDIAN      4321    /* most-significant byte first (IBM, net) */
# define PDP_ENDIAN      3412    /* LSB first in word, MSW first in long (pdp) */

#if defined(vax) || defined(ns32000) || defined(sun386) || defined(i386) || \
        defined(__i386) || defined(__ia64) || defined(__amd64) || \
        defined(MIPSEL) || defined(_MIPSEL) || defined(BIT_ZERO_ON_RIGHT) || \
        defined(__alpha__) || defined(__alpha) || \
        (defined(__Lynx__) && defined(__x86__))
# define BYTE_ORDER      LITTLE_ENDIAN
#endif

#if defined(sel) || defined(pyr) || defined(mc68000) || defined(sparc) || \
    defined(__sparc) || \
    defined(is68k) || defined(tahoe) || defined(ibm032) || defined(ibm370) || \
    defined(MIPSEB) || defined(_MIPSEB) || defined(_IBMR2) || defined(DGUX) ||\
    defined(apollo) || defined(__convex__) || defined(_CRAY) || \
    defined(__hppa) || defined(__hp9000) || \
    defined(__hp9000s300) || defined(__hp9000s700) || \
    defined(__hp3000s900) || defined(MPE) || \
    defined(BIT_ZERO_ON_LEFT) || defined(m68k) || \
        (defined(__Lynx__) && \
        (defined(__68k__) || defined(__sparc__) || defined(__powerpc__)))
# define BYTE_ORDER      BIG_ENDIAN
#endif

#endif

struct dnsheader {
        unsigned        id :16;         /* query identification number */
#if BYTE_ORDER == BIG_ENDIAN
                        /* fields in third byte */
        unsigned        qr: 1;          /* response flag */
        unsigned        opcode: 4;      /* purpose of message */
        unsigned        aa: 1;          /* authoritative answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        rcode :4;       /* response code */
#elif BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritative answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
#endif
                        /* remaining bytes */
        unsigned        qdcount :16;    /* number of question entries */
        unsigned        ancount :16;    /* number of answer entries */
        unsigned        nscount :16;    /* number of authority entries */
        unsigned        arcount :16;    /* number of resource entries */
};


#define L theL()
extern time_t s_starttime;
std::string questionExpand(const char* packet, uint16_t len, uint16_t& type);
uint32_t hashQuestion(const char* packet, uint16_t len, uint32_t init);
bool dnspacketLessThan(const std::string& a, const std::string& b);

/** helper function for both DNSPacket and addSOARecord() - converts a line into a struct, for easier parsing */
void fillSOAData(const string &content, SOAData &data);

/** for use by DNSPacket, converts a SOAData class to a ascii line again */
string serializeSOAData(const SOAData &data);
string &attodot(string &str);  //!< for when you need to insert an email address in the SOA
#endif
