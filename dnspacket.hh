/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifndef DNSPACKET_HH

#if __GNUC__ == 2
#if __GNUC_MINOR__ < 95
	#error Your compiler is too old! Try g++ 3.3 or higher
#else
	#warning There are known problems with PowerDNS binaries compiled by gcc version 2.95 and 2.96!
#endif
#endif

#define DNSPACKET_HH

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/types.h>
#include "iputils.hh"

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>

#endif // WIN32

#include <iostream>
#include <string>

#include <vector>
#include "qtype.hh"
#include "dns.hh"
#include "misc.hh"
#include "utility.hh"
#include "logger.hh"
#include "ahuexception.hh"

#ifdef HAVE_CONFIG_H
#include "config.h"
 #endif // HAVE_CONFIG_H


#ifdef WIN32
# ifdef BYTE_ORDER
#   undef BYTE_ORDER
# endif // BYTE_ORDER
# define BYTE_ORDER LITTLE_ENDIAN
#endif // WIN32

class DNSBackend;

/** helper function for both DNSPacket and addSOARecord() - converts a line into a struct, for easier parsing */
void fillSOAData(const string &content, SOAData &data);

/** for use by DNSPacket, converts a SOAData class to a ascii line again */
string serializeSOAData(const SOAData &data);

string &attodot(string &str);  //!< for when you need to insert an email address in the SOA

//! This class represents DNS packets, either received or to be sent.
class DNSPacket
{
public:
  DNSPacket();
  DNSPacket(const DNSPacket &orig);

  inline int parse(const char *mesg, int len); //!< parse a raw UDP or TCP packet and suck the data inward
  string getString(); //!< for serialization - just passes the whole packet

  //! the raw DNS header
  struct dnsheader 
  {
    unsigned int id:16;  //!< id of this query/response
#ifdef WORDS_BIGENDIAN     // ultrasparc
    unsigned int qr:1;      //!< 1 if this is a query, 0 if response
    unsigned int opcode:4;  //!< the opcode
    unsigned int aa:1;   //!< packet contains authoritative data
    unsigned int tc:1;   //!< packet is truncated
    unsigned int rd:1;   //!< this packets wants us to recurse
    unsigned int ra:1;     //!< ??
    unsigned int unused:1; //!< 
    unsigned int ad:1;     //!< authentic data
    unsigned int cd:1;     //!< checking disabled by resolver
    unsigned int rcode:4;  //!< ??
#else
    unsigned int rd:1;   //!< this packets wants us to recurse
    unsigned int tc:1;   //!< packet is truncated
    unsigned int aa:1;   //!< packet contains authoritative data
    unsigned int opcode:4;  //!< the opcode
    unsigned int qr:1;      //!< 1 if this is a query, 0 if response

    /////////// 

    unsigned int rcode:4;  //!< ??
    unsigned int cd:1;     //!< checking disabled by resolver
    unsigned int ad:1;     //!< authentic data
    unsigned int unused:1; //!< 
    unsigned int ra:1;     //!< recursion available
#endif
    ////////////////
    
    unsigned int qdcount:16;  //!< number of questions
    unsigned int ancount:16;  //!< number of answers
    unsigned int nscount:16;  //!< number of authoritative nameservers included in answer
    unsigned int arcount:16;  //!< number of additional resource records
  };

  // address & socket manipulation
  inline void setRemote(const ComboAddress*);
  string getLocal() const;
  string getRemote() const;
  uint16_t getRemotePort() const;

  Utility::sock_t getSocket() const
  {
    return d_socket;
  }
  inline void setSocket(Utility::sock_t sock);


  // these manipulate 'd'
  void setA(bool); //!< make this packet authoritative - manipulates 'd'
  void setID(uint16_t); //!< set the DNS id of this packet - manipulates 'd'
  void setRA(bool); //!< set the Recursion Available flag - manipulates 'd'
  void setRD(bool); //!< set the Recursion Desired flag - manipulates 'd'
  void setAnswer(bool); //!< Make this packet an answer - clears the 'stringbuffer' first, if passed 'true', does nothing otherwise, manipulates 'd'

  void setOpcode(uint16_t);  //!< set the Opcode of this packet - manipulates 'd'
  void setRcode(int v); //!< set the Rcode of this packet - manipulates 'd'

  void clearRecords(); //!< when building a packet, wipe all previously added records (clears 'rrs')

  /** Add a DNSResourceRecord to this packet. A DNSPacket (as does a DNS Packet) has 4 kinds of resource records. Questions, 
      Answers, Authority and Additional. See RFC 1034 and 1035 for details. You can specify where a record needs to go in the
      DNSResourceRecord d_place field */
  void addRecord(const DNSResourceRecord &);  // adds to 'rrs'

  void setQuestion(int op, const string &qdomain, int qtype);  // wipes 'd', sets a random id, creates start of packet (label, type, class etc)
  vector<DNSResourceRecord> getAnswers(); // this can be called only when a packet has been parsed

  DTime d_dt; //!< the time this packet was created. replyPacket() copies this in for you, so d_dt becomes the time spent processing the question+answer
  void wrapup(void);  // writes out queued rrs, and generates the binary packet. also shuffles. also rectifies dnsheader 'd', and copies it to the stringbuffer
  inline const char *getData(void); //!< get binary representation of packet, will call 'wrapup' for you

  const char *getRaw(void); //!< provides access to the raw packet, possibly on a packet that has never been 'wrapped'
  inline void spoofID(uint16_t id); //!< change the ID of an existing packet. Useful for fixing up packets returned from the PacketCache
  inline void spoofQuestion(const string &qd); //!< paste in the exact right case of the question. Useful for PacketCache
  void truncate(int new_length); // has documentation in source

  bool needAP(); //!< query this to find out if this packet needs additional processing, based on rrs
  vector<DNSResourceRecord*> getAPRecords(); //!< get a vector with DNSResourceRecords that need additional processing
  void setCompress(bool compress);

  DNSPacket *replyPacket() const; //!< convenience function that creates a virgin answer packet to this question

  inline void commitD(); //!< copies 'd' into the stringbuffer

  //////// DATA !

  ComboAddress remote;
  uint16_t len; //!< length of the raw binary packet 2
  uint16_t qclass;  //!< class of the question - should always be INternet 2
  struct dnsheader d; //!< dnsheader at the start of the databuffer 12

  QType qtype;  //!< type of the question 8

  string qdomain;  //!< qname of the question 4 - unsure how this is used
  bool d_tcp;

private:
  void pasteQ(const char *question, int length); //!< set the question of this packet, useful for crafting replies

  int expand(const unsigned char *begin, const unsigned char *end, string &expanded, int depth=0);

  string compress(const string &qd);
  void addARecord(const string&, uint32_t, uint32_t ttl, DNSResourceRecord::Place place); //!< add an A record to the packet
  void addARecord(const DNSResourceRecord &); //!< add an A record to the packet

  void addAAAARecord(const string &, unsigned char addr[16], uint32_t ttl, DNSResourceRecord::Place place); //!< add an A record to the packet
  void addAAAARecord(const DNSResourceRecord &); //!< add an A record to the packet

  void addMXRecord(const string &domain, const string &mx, int priority, uint32_t ttl); //!< add an MX record to the packet
  void addMXRecord(const DNSResourceRecord &); //!< add an MX record to the packet

  void addSRVRecord(const string &domain, const string &srv, int priority, uint32_t ttl); //!< add an SRVMX record to the packet
  void addSRVRecord(const DNSResourceRecord &); //!< add an SRV record to the packet

  void addMRRecord(const string &domain, const string &alias, uint32_t ttl); //!< add a MR record to the packet
  void addMRRecord(const DNSResourceRecord &); //!< add a MR record to the packet

  void addCNAMERecord(const string &domain, const string &alias, uint32_t ttl); //!< add a CNAME record to the packet
  void addCNAMERecord(const DNSResourceRecord &); //!< add a CNAME record to the packet

  void addRPRecord(const string &domain, const string &content, uint32_t ttl); //!< add a RP record to the packet
  void addRPRecord(const DNSResourceRecord &); //!< add a RP record to the packet

  void addNAPTRRecord(const string &domain, const string &content, uint32_t ttl); //!< add a NAPTR record to the packet
  void addNAPTRRecord(const DNSResourceRecord &); //!< add a NAPTR record to the packet


  void addPTRRecord(const string &domain, const string &alias, uint32_t ttl); //!< add a PTR record to the packet
  void addPTRRecord(const DNSResourceRecord &); //!< add a PTR record to the packet

  void addLOCRecord(const string &domain, const string &content, uint32_t ttl); 
  void addLOCRecord(const DNSResourceRecord &); //!< add a LOC record to the packet


  /** Adds a SOA record to the packet. The SOA record is very special because we have a lot of default values, 
      that may be overridden by the contents of the database. Content can have a variety of content:
      
      (nothing)
      hostmaster
      hostmaster serial-number
      hostmaster serial-number [refresh [retry [expire [ minimum] ] ] ]

      Suggested values are: 

      10800           ;refresh every three hours
      300             ;retry every 5 min
      604800          ;expire after a week
      86400           ;default ttl 

      An empty field means that we supply hostmaster+@+domain name as hostmaster. An empty serial number is replaced by the 
      number of seconds since 1 jan 1970 (unix timestamp). The other values are substituted as indicated

  */
  void addSOARecord(const string &domain, const string &content, uint32_t ttl, DNSResourceRecord::Place place); 
  void addSOARecord(const DNSResourceRecord &); //!< add a SOA record to the packet

  void addTXTorSPFRecord(uint16_t qtype, string domain, string, uint32_t ttl); //!< add a TXT or SPF record to the packet

  void addTXTRecord(const DNSResourceRecord &); //!< add a TXT record to the packet
  void addSPFRecord(const DNSResourceRecord &); //!< add a SPF record to the packet

  void addHINFORecord(string domain, string, uint32_t ttl); //!< add a HINFO record to the packet
  void addHINFORecord(const DNSResourceRecord &); //!< add a HINFO record to the packet

  void addNSRecord(string domain, string server, uint32_t ttl, DNSResourceRecord::Place place); //!< add an NS record to the packet
  void addNSRecord(const DNSResourceRecord &); //!< add an NS record to the packet
  void addGenericRecord(const DNSResourceRecord& rr);

  bool d_wrapped; // 1
  bool d_compress; // 1
  uint16_t d_qlen; // length of the question (including class & type) in this packet 2
  
  int d_socket; // 4
  
  int findlabel(string &label);
  int toqname(const char *name, string &qname, bool compress = true);
  int toqname(const string &name, string &qname, bool compress = true);
  int toqname(const string &name, string *qname, bool compress = true); 
  const string makeSoaHostmasterPiece(const string &hostmaster);
  static string parseLOC(const unsigned char *p, unsigned int length);
  void makeHeader(char *p,uint16_t qtype, uint32_t ttl);
  int domprint();
  int getq();

  // MORE DATA!

  string stringbuffer; // this is where everything lives 4

  vector<DNSResourceRecord> rrs; // 4
};


inline void DNSPacket::spoofQuestion(const string &qd)
{
  string label=compress(qd);
  for(string::size_type i=0;i<label.size();++i)
    stringbuffer[i+sizeof(d)]=label[i];
  d_wrapped=true; // if we do this, don't later on wrapup
}

/** This function takes data from the network, possibly received with recvfrom, and parses
    it into our class. Results of calling this function multiple times on one packet are
    unknown. Returns -1 if the packet cannot be parsed.
*/
int DNSPacket::parse(const char *mesg, int length)
{
  stringbuffer.assign(mesg,length); 
  len=length;
  if(length < 12) { 
    L << Logger::Warning << "Ignoring packet: too short from "
      << getRemote() << endl;
    return -1;
  }

  memcpy((void *)&d,(const void *)stringbuffer.c_str(),12);

  int offset=0;
  d_qlen=0;

  if(!ntohs(d.qdcount)) {
    if(!d_tcp) {
      L << Logger::Warning << "No question section in packet from " << getRemote() <<", rcode="<<(int)d.rcode<<endl;
      return -1;
    }
  }
  else {
    offset = getq(); // also sets this->qdomain!
    d_qlen=offset+4; // this points to the start of any answers
  }
  if(offset < 0) {
    //    L << Logger::Warning << "Ignoring packet: invalid label in question from "
    //  << inet_ntoa(remote.sin_addr) << endl;
    return -1;
  }
  if(qdomain.length() > 255) { // this prevents crap from the rootservers
    return -1;
  }


  
  if((unsigned int)(15+offset)>=stringbuffer.length()) {
    L << Logger::Warning << "Ignoring packet: question too short from "<< getRemote()<<", offset "<<
      15+offset<<">="<<stringbuffer.length()<<endl;
    return -1;
  }

  qtype=((unsigned char)stringbuffer[12+offset])*256+(unsigned char)stringbuffer[13+offset];
  qclass=((unsigned char)stringbuffer[14+offset]*256)+(unsigned char)stringbuffer[15+offset];
  return 0;
}

//! Use this to set where this packet was received from or should be sent to
inline void DNSPacket::setRemote(const ComboAddress *s)
{
  remote=*s;
}

inline void DNSPacket::spoofID(uint16_t id)
{
  stringbuffer[1]=(id>>8)&0xff; 
  stringbuffer[0]=id&0xff;
  d.id=id;
}

inline void DNSPacket::setSocket(Utility::sock_t sock)
{
  d_socket=sock;
}

inline void DNSPacket::commitD()
{
  stringbuffer.replace(0,12,(char *)&d,12); // copy in d
}

inline const char *DNSPacket::getData(void)
{
  if(!d_wrapped)
    wrapup();

  return stringbuffer.data();
}


#endif
