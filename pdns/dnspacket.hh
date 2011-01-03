/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011  PowerDNS.COM BV

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
class DNSSECKeeper;

//! This class represents DNS packets, either received or to be sent.
class DNSPacket
{
public:
  DNSPacket();
  DNSPacket(const DNSPacket &orig);

  int noparse(const char *mesg, int len); //!< parse a raw UDP or TCP packet and suck the data inward
  int parse(const char *mesg, int len); //!< parse a raw UDP or TCP packet and suck the data inward
  string getString(); //!< for serialization - just passes the whole packet

  // address & socket manipulation
  void setRemote(const ComboAddress*);
  string getRemote() const;
  string getLocal() const
  {
    ComboAddress ca;
    socklen_t len=sizeof(ca);
    getsockname(d_socket, (sockaddr*)&ca, &len);
    return ca.toString();
  }
  uint16_t getRemotePort() const;

  Utility::sock_t getSocket() const
  {
    return d_socket;
  }
  void setSocket(Utility::sock_t sock);


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

  DTime d_dt; //!< the time this packet was created. replyPacket() copies this in for you, so d_dt becomes the time spent processing the question+answer
  void wrapup(DNSSECKeeper* dk=0);  // writes out queued rrs, and generates the binary packet. also shuffles. also rectifies dnsheader 'd', and copies it to the stringbuffer
  const char *getData(void); //!< get binary representation of packet, will call 'wrapup' for you

  const char *getRaw(void); //!< provides access to the raw packet, possibly on a packet that has never been 'wrapped'
  void spoofQuestion(const string &qd); //!< paste in the exact right case of the question. Useful for PacketCache
  void truncate(int new_length); // has documentation in source

  vector<DNSResourceRecord*> getAPRecords(); //!< get a vector with DNSResourceRecords that need additional processing
  vector<DNSResourceRecord*> getAnswerRecords(); //!< get a vector with DNSResourceRecords that are answers
  void setCompress(bool compress);

  DNSPacket *replyPacket() const; //!< convenience function that creates a virgin answer packet to this question

  void commitD(); //!< copies 'd' into the stringbuffer
  int getMaxReplyLen(); //!< retrieve the maximum length of the packet we should send in response
  void setMaxReplyLen(int bytes); //!< set the max reply len (used when retrieving from the packet cache, and this changed)

  bool couldBeCached(); //!< returns 0 if this query should bypass the packet cache

  //////// DATA !

  ComboAddress remote;
  uint16_t len; //!< length of the raw binary packet 2
  uint16_t qclass;  //!< class of the question - should always be INternet 2
  struct dnsheader d; //!< dnsheader at the start of the databuffer 12

  QType qtype;  //!< type of the question 8

  string qdomain;  //!< qname of the question 4 - unsure how this is used
  bool d_tcp;
  bool d_dnssecOk;
private:
  void pasteQ(const char *question, int length); //!< set the question of this packet, useful for crafting replies

  bool d_wrapped; // 1
  bool d_compress; // 1
  uint16_t d_qlen; // length of the question (including class & type) in this packet 2
  
  int d_socket; // 4

  string stringbuffer; // this is where everything lives 4
  int d_maxreplylen;
  string d_ednsping;
  bool d_wantsnsid;

  vector<DNSResourceRecord> d_rrs; // 4
};



#endif
