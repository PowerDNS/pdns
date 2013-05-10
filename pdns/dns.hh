/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

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
  SOAData() : scopeMask(0) {};

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
  enum rcodes_ { NoError=0, FormErr=1, ServFail=2, NXDomain=3, NotImp=4, Refused=5, NotAuth=9 };
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
  DNSResourceRecord() : qclass(1), priority(0), signttl(0), last_modified(0), d_place(ANSWER), auth(1), scopeMask(0) {};
  ~DNSResourceRecord(){};

  // data
  
  QType qtype; //!< qtype of this record, ie A, CNAME, MX etc
  uint16_t qclass; //!< class of this record
  string qname; //!< the name of this record, for example: www.powerdns.com
  string wildcardname;
  string content; //!< what this record points to. Example: 10.1.2.3
  uint16_t priority; //!< For qtypes that support a priority or preference (MX, SRV)
  uint32_t ttl; //!< Time To Live of this record
  uint32_t signttl; //!< If non-zero, use this TTL as original TTL in the RRSIG
  int domain_id; //!< If a backend implements this, the domain_id of the zone this record is in
  time_t last_modified; //!< For autocalculating SOA serial numbers - the backend needs to fill this in
  enum Place {QUESTION=0, ANSWER=1, AUTHORITY=2, ADDITIONAL=3}; //!< Type describing the positioning of a DNSResourceRecord within, say, a DNSPacket
  Place d_place; //!< This specifies where a record goes within the packet

  bool auth;
  uint8_t scopeMask;

  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
    ar & qtype;
    ar & qclass;
    ar & qname;
    ar & wildcardname;
    ar & content;
    ar & priority;
    ar & ttl;
    ar & domain_id;
    ar & last_modified;
    ar & d_place;
    ar & auth;
  }

  bool operator<(const DNSResourceRecord &b) const
  {
    if(qname < b.qname)
      return true;
    if(qname == b.qname)
      return(content < b.content);
    return false;
  }
};

#ifdef _MSC_VER
# pragma pack ( push )
# pragma pack ( 1 )
# define GCCPACKATTRIBUTE
#else
# define GCCPACKATTRIBUTE __attribute__((packed))
#endif
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
#ifdef _MSC_VER
#pragma pack (pop)
#endif 

enum  {
        ns_t_invalid = 0,       /* Cookie. */
        ns_t_a = 1,             /* Host address. */
        ns_t_ns = 2,            /* Authoritative server. */
        ns_t_md = 3,            /* Mail destination. */
        ns_t_mf = 4,            /* Mail forwarder. */
        ns_t_cname = 5,         /* Canonical name. */
        ns_t_soa = 6,           /* Start of authority zone. */
        ns_t_mb = 7,            /* Mailbox domain name. */
        ns_t_mg = 8,            /* Mail group member. */
        ns_t_mr = 9,            /* Mail rename name. */
        ns_t_null = 10,         /* Null resource record. */
        ns_t_wks = 11,          /* Well known service. */
        ns_t_ptr = 12,          /* Domain name pointer. */
        ns_t_hinfo = 13,        /* Host information. */
        ns_t_minfo = 14,        /* Mailbox information. */
        ns_t_mx = 15,           /* Mail routing information. */
        ns_t_txt = 16,          /* Text strings. */
        ns_t_rp = 17,           /* Responsible person. */
        ns_t_afsdb = 18,        /* AFS cell database. */
        ns_t_x25 = 19,          /* X_25 calling address. */
        ns_t_isdn = 20,         /* ISDN calling address. */
        ns_t_rt = 21,           /* Router. */
        ns_t_nsap = 22,         /* NSAP address. */
        ns_t_nsap_ptr = 23,     /* Reverse NSAP lookup (deprecated). */
        ns_t_sig = 24,          /* Security signature. */
        ns_t_key = 25,          /* Security key. */
        ns_t_px = 26,           /* X.400 mail mapping. */
        ns_t_gpos = 27,         /* Geographical position (withdrawn). */
        ns_t_aaaa = 28,         /* Ip6 Address. */
        ns_t_loc = 29,          /* Location Information. */
        ns_t_nxt = 30,          /* Next domain (security). */
        ns_t_eid = 31,          /* Endpoint identifier. */
        ns_t_nimloc = 32,       /* Nimrod Locator. */
        ns_t_srv = 33,          /* Server Selection. */
        ns_t_atma = 34,         /* ATM Address */
        ns_t_naptr = 35,        /* Naming Authority PoinTeR */
        ns_t_kx = 36,           /* Key Exchange */
        ns_t_cert = 37,         /* Certification record */
        ns_t_a6 = 38,           /* IPv6 address (deprecates AAAA) */
        ns_t_dname = 39,        /* Non-terminal DNAME (for IPv6) */
        ns_t_sink = 40,         /* Kitchen sink (experimental) */
        ns_t_opt = 41,          /* EDNS0 option (meta-RR) */
        ns_t_ds = 43,           /* Delegation signer */
        ns_t_rrsig = 46,        /* Resoure Record signature */
        ns_t_nsec = 47,         /* Next Record */
        ns_t_dnskey = 48,       /* DNSKEY record */
        ns_t_nsec3 = 50,        /* Next Record v3 */
        ns_t_nsec3param = 51,   /* NSEC Parameters */
        ns_t_tlsa = 52,         /* TLSA */
        ns_t_eui48 = 108,       /* EUI-48 */
        ns_t_eui64 = 109,       /* EUI-64 */
        ns_t_tsig = 250,        /* Transaction signature. */
        ns_t_ixfr = 251,        /* Incremental zone transfer. */
        ns_t_axfr = 252,        /* Transfer zone of authority. */
        ns_t_mailb = 253,       /* Transfer mailbox records. */
        ns_t_maila = 254,       /* Transfer mail agent records. */
        ns_t_any = 255,         /* Wildcard match. */
};

#ifdef WIN32
#define BYTE_ORDER 1
#define LITTLE_ENDIAN 1
#elif __FreeBSD__ || __APPLE__ || __OpenBSD__
#include <machine/endian.h>
#elif __linux__
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
        unsigned        aa: 1;          /* authoritive answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        rcode :4;       /* response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritive answer */
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
bool dnspacketLessThan(const std::string& a, const std::string& b);

/** helper function for both DNSPacket and addSOARecord() - converts a line into a struct, for easier parsing */
void fillSOAData(const string &content, SOAData &data);

/** for use by DNSPacket, converts a SOAData class to a ascii line again */
string serializeSOAData(const SOAData &data);
string &attodot(string &str);  //!< for when you need to insert an email address in the SOA
string strrcode(unsigned char rcode);
#endif
