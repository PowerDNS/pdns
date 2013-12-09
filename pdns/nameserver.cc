/*
    Copyright (C) 2002 - 2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation.

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

#include "utility.hh"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <iostream>
#include <string>
#include <sys/types.h>
#include "responsestats.hh"
#include <boost/shared_ptr.hpp>
#include "dns.hh"
#include "dnsbackend.hh"
#include "dnspacket.hh"
#include "nameserver.hh"
#include "distributor.hh"
#include "logger.hh"
#include "arguments.hh"
#include "statbag.hh"

#include "namespaces.hh"

extern StatBag S;

/** \mainpage 
    PowerDNS is a very versatile nameserver that can answer questions from different backends. To implement your
    own backend, see the documentation for the DNSBackend class.

    \section copyright Copyright and License
    PowerDNS is (C) 2001-2008 PowerDNS.COM BV. It is distributed according to the terms of the General Public License version 2.

    \section overview High level overview

    The Distributor contains a configurable number of PacketHandler instances, each in its own thread, for connection pooling. 
    PacketHandler instances are recycled of they let escape an PDNSException.

    The PacketHandler implements the RFC1034 algorithm and converts question packets into DNSBackend queries.

    A DNSBackend is an entity that returns DNSResourceRecord objects in return to explicit questions for domains with a specified QType

    PowerDNS uses the UeberBackend as its DNSBackend. The UeberBackend by default has no DNSBackends within itself, those are loaded
    using the pdns_control tool. This way DNSBackend implementations can be kept completely separate (but they often aren't).s

    If one or more DNSBackends are loaded, the UeberBackend fields the queries to all of them until one answers.

    \section TCP TCP Operations

    The TCP operation runs within a single thread called tcpreceiver(), that also queries the PacketHandler. 

    \section Cache Caching
 
    On its own, this setup is not suitable for high performance operations. A single DNS query can turn into many DNSBackend questions,
    each taking many milliseconds to complete. This is why the qthread() first checks the PacketCache to see if an answer is known to a packet
    asking this question. If so, the entire Distributor is shunted, and the answer is sent back *directly*, within a few microseconds.

    \section misc Miscellaneous
    Configuration details are available via the ArgvMap instance arg. Statistics are created by making calls to the StatBag object called S. 
    These statistics are made available via the UeberBackend on the same socket that is used for dynamic module commands.

    \section Main Main 
    The main() of PowerDNS can be found in receiver.cc - start reading there for further insights into the operation of the nameserver
*/

#ifdef IP_PKTINFO
  #define GEN_IP_PKTINFO IP_PKTINFO
#endif
#ifdef IP_RECVDSTADDR
  #define GEN_IP_PKTINFO IP_RECVDSTADDR 
#endif

vector<ComboAddress> g_localaddresses; // not static, our unit tests need to poke this

void UDPNameserver::bindIPv4()
{
  vector<string>locals;
  stringtok(locals,::arg()["local-address"]," ,");

  if(locals.empty())
    throw PDNSException("No local address specified");

  int s;
  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    string localname(*i);
    ComboAddress locala;

    s=socket(AF_INET,SOCK_DGRAM,0);

    if(s<0) {
      L<<Logger::Error<<"Unable to acquire a UDP socket: "+string(strerror(errno)) << endl;
      throw PDNSException("Unable to acquire a UDP socket: "+string(strerror(errno)));
    }
  
    Utility::setCloseOnExec(s);
  
    if(!Utility::setNonBlocking(s))
      throw PDNSException("Unable to set UDP socket to non-blocking: "+stringerror());
  
    memset(&locala,0,sizeof(locala));
    locala.sin4.sin_family=AF_INET;

    if(localname=="0.0.0.0") {
      int val=1;
      setsockopt(s, IPPROTO_IP, GEN_IP_PKTINFO, &val, sizeof(val));
    }
    locala=ComboAddress(localname, ::arg().asNum("local-port"));
    if(locala.sin4.sin_family != AF_INET) 
      throw PDNSException("Attempting to bind IPv4 socket to IPv6 address");

    g_localaddresses.push_back(locala);
    if(::bind(s, (sockaddr*)&locala, locala.getSocklen()) < 0) {
      L<<Logger::Error<<"binding UDP socket to '"+locala.toStringWithPort()+": "<<strerror(errno)<<endl;
      throw PDNSException("Unable to bind to UDP socket");
    }
    d_sockets.push_back(s);
    L<<Logger::Error<<"UDP server bound to "<<locala.toStringWithPort()<<endl;
    struct pollfd pfd;
    pfd.fd = s;
    pfd.events = POLLIN;
    pfd.revents = 0;
    d_rfds.push_back(pfd);
  }
}

static bool IsAnyAddress(const ComboAddress& addr)
{
  if(addr.sin4.sin_family == AF_INET)
    return addr.sin4.sin_addr.s_addr == 0;
  else if(addr.sin4.sin_family == AF_INET6)
    return !memcmp(&addr.sin6.sin6_addr, &in6addr_any, sizeof(addr.sin6.sin6_addr));
  
  return false;
}


bool AddressIsUs(const ComboAddress& remote)
{
  BOOST_FOREACH(const ComboAddress& us, g_localaddresses) {
    if(remote == us)
      return true;
    if(IsAnyAddress(us)) {
      int s = socket(remote.sin4.sin_family, SOCK_DGRAM, 0);
      if(s < 0) 
        continue;

      if(connect(s, (struct sockaddr*)&remote, remote.getSocklen()) < 0) {
        close(s);
        continue;
      }
    
      ComboAddress actualLocal;
      actualLocal.sin4.sin_family = remote.sin4.sin_family;
      socklen_t socklen = actualLocal.getSocklen();

      if(getsockname(s, (struct sockaddr*) &actualLocal, &socklen) < 0) {
        close(s);
        continue;
      }
      close(s);
      actualLocal.sin4.sin_port = us.sin4.sin_port;
      if(actualLocal == remote)
        return true;
    }
  }
  return false;
}


void UDPNameserver::bindIPv6()
{
#if HAVE_IPV6
  vector<string> locals;
  stringtok(locals,::arg()["local-ipv6"]," ,");

  if(locals.empty())
    return;

  int s;
  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    string localname(*i);

    s=socket(AF_INET6,SOCK_DGRAM,0);
    if(s<0) {
      L<<Logger::Error<<"Unable to acquire a UDPv6 socket: "+string(strerror(errno)) << endl;
      throw PDNSException("Unable to acquire a UDPv6 socket: "+string(strerror(errno)));
    }

    Utility::setCloseOnExec(s);
    if(!Utility::setNonBlocking(s))
      throw PDNSException("Unable to set UDPv6 socket to non-blocking: "+stringerror());


    ComboAddress locala(localname, ::arg().asNum("local-port"));
    
    if(IsAnyAddress(locala)) {
      int val=1;
      setsockopt(s, IPPROTO_IP, GEN_IP_PKTINFO, &val, sizeof(val));     // linux supports this, so why not - might fail on other systems
      setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val)); 
      setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));      // if this fails, we report an error in tcpreceiver too
    }
    g_localaddresses.push_back(locala);
    if(::bind(s, (sockaddr*)&locala, sizeof(locala))<0) {
      L<<Logger::Error<<"binding to UDP ipv6 socket: "<<strerror(errno)<<endl;
      throw PDNSException("Unable to bind to UDP ipv6 socket");
    }
    d_sockets.push_back(s);
    struct pollfd pfd;
    pfd.fd = s;
    pfd.events = POLLIN;
    pfd.revents = 0;
    d_rfds.push_back(pfd);
    L<<Logger::Error<<"UDPv6 server bound to "<<locala.toStringWithPort()<<endl;
    
  }
#endif
}

UDPNameserver::UDPNameserver()
{
  if(!::arg()["local-address"].empty())
    bindIPv4();
  if(!::arg()["local-ipv6"].empty())
    bindIPv6();

  if(::arg()["local-address"].empty() && ::arg()["local-ipv6"].empty()) 
    L<<Logger::Critical<<"PDNS is deaf and mute! Not listening on any interfaces"<<endl;    
}

ResponseStats g_rs;

void UDPNameserver::send(DNSPacket *p)
{
  const string& buffer=p->getString();
  static unsigned int &numanswered=*S.getPointer("udp-answers");
  static unsigned int &numanswered4=*S.getPointer("udp4-answers");
  static unsigned int &numanswered6=*S.getPointer("udp6-answers");
  static unsigned int &bytesanswered=*S.getPointer("udp-answers-bytes");

  g_rs.submitResponse(p->qtype.getCode(), buffer.length(), true);

  struct msghdr msgh;
  struct cmsghdr *cmsg;
  struct iovec iov;
  char cbuf[256];

  /* Query statistics */
  if(p->d.aa) {
    if (p->d.rcode==RCode::NXDomain)
      S.ringAccount("nxdomain-queries",p->qdomain+"/"+p->qtype.getName());
  } else if (p->isEmpty()) {
    S.ringAccount("unauth-queries",p->qdomain+"/"+p->qtype.getName());
    S.ringAccount("remotes-unauth",p->getRemote());
  }

  /* Count responses (total/v4/v6) and byte counts */
  numanswered++;
  bytesanswered+=buffer.length();
  if(p->d_remote.sin4.sin_family==AF_INET)
    numanswered4++;
  else
    numanswered6++;

  /* Set up iov and msgh structures. */
  memset(&msgh, 0, sizeof(struct msghdr));
  iov.iov_base = (void*)buffer.c_str();
  iov.iov_len = buffer.length();
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  msgh.msg_name = (struct sockaddr*)&p->d_remote;
  msgh.msg_namelen = p->d_remote.getSocklen();

  if(p->d_anyLocal) {
    if(p->d_anyLocal->sin4.sin_family == AF_INET6) {
      struct in6_pktinfo *pkt;
          
      msgh.msg_control = cbuf;
      msgh.msg_controllen = CMSG_SPACE(sizeof(*pkt));
                  
      cmsg = CMSG_FIRSTHDR(&msgh);
      cmsg->cmsg_level = IPPROTO_IPV6;
      cmsg->cmsg_type = IPV6_PKTINFO;
      cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));
                                  
      pkt = (struct in6_pktinfo *) CMSG_DATA(cmsg);
      memset(pkt, 0, sizeof(*pkt));
      pkt->ipi6_addr = p->d_anyLocal->sin6.sin6_addr;
      msgh.msg_controllen = cmsg->cmsg_len; // makes valgrind happy and is slightly better style
    }
    else {
#ifdef IP_PKTINFO
      struct in_pktinfo *pkt;
      msgh.msg_control = cbuf;
      msgh.msg_controllen = CMSG_SPACE(sizeof(*pkt));

      cmsg = CMSG_FIRSTHDR(&msgh);
      cmsg->cmsg_level = IPPROTO_IP;
      cmsg->cmsg_type = IP_PKTINFO;
      cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

      pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
      memset(pkt, 0, sizeof(*pkt));
      pkt->ipi_spec_dst = p->d_anyLocal->sin4.sin_addr;
#endif
#ifdef IP_SENDSRCADDR
      struct in_addr *in;
    
      msgh.msg_control = cbuf;
      msgh.msg_controllen = CMSG_SPACE(sizeof(*in));
            
      cmsg = CMSG_FIRSTHDR(&msgh);
      cmsg->cmsg_level = IPPROTO_IP;
      cmsg->cmsg_type = IP_SENDSRCADDR;
      cmsg->cmsg_len = CMSG_LEN(sizeof(*in));
                            
      in = (struct in_addr *) CMSG_DATA(cmsg);
      *in = p->d_anyLocal->sin4.sin_addr;
#endif
      msgh.msg_controllen = cmsg->cmsg_len;
    }
  }
  DLOG(L<<Logger::Notice<<"Sending a packet to "<< p->getRemote() <<" ("<< buffer.length()<<" octets)"<<endl);
  if(buffer.length() > p->getMaxReplyLen()) {
    L<<Logger::Error<<"Weird, trying to send a message that needs truncation, "<< buffer.length()<<" > "<<p->getMaxReplyLen()<<endl;
  }
  if(sendmsg(p->getSocket(), &msgh, 0) < 0)
    L<<Logger::Error<<"Error sending reply with sendmsg (socket="<<p->getSocket()<<"): "<<strerror(errno)<<endl;
}

static bool HarvestDestinationAddress(struct msghdr* msgh, ComboAddress* destination)
{
  memset(destination, 0, sizeof(*destination));
  struct cmsghdr *cmsg;
  for (cmsg = CMSG_FIRSTHDR(msgh); cmsg != NULL; cmsg = CMSG_NXTHDR(msgh,cmsg)) {
#ifdef IP_PKTINFO
     if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_PKTINFO)) {
        struct in_pktinfo *i = (struct in_pktinfo *) CMSG_DATA(cmsg);
        destination->sin4.sin_addr = i->ipi_addr;
        destination->sin4.sin_family = AF_INET;
        return true;
    }
#endif
#ifdef IP_RECVDSTADDR
    if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_RECVDSTADDR)) {
      struct in_addr *i = (struct in_addr *) CMSG_DATA(cmsg);
      destination->sin4.sin_addr = *i;
      destination->sin4.sin_family = AF_INET;      
      return true;
    }
#endif

    if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO)) {
        struct in6_pktinfo *i = (struct in6_pktinfo *) CMSG_DATA(cmsg);
        destination->sin6.sin6_addr = i->ipi6_addr;
        destination->sin4.sin_family = AF_INET6;
        return true;
    }
  }
  return false;
}

DNSPacket *UDPNameserver::receive(DNSPacket *prefilled)
{
  ComboAddress remote;
  extern StatBag S;
  int len=-1;
  char mesg[DNSPacket::s_udpTruncationThreshold];
  Utility::sock_t sock=-1;

  struct msghdr msgh;
  struct iovec iov;
  char cbuf[256];

  iov.iov_base = mesg;
  iov.iov_len  = sizeof(mesg);

  memset(&msgh, 0, sizeof(struct msghdr));
  
  msgh.msg_control = cbuf;
  msgh.msg_controllen = sizeof(cbuf);
  msgh.msg_name = &remote;
  msgh.msg_namelen = sizeof(remote);
  msgh.msg_iov  = &iov;
  msgh.msg_iovlen = 1;
  msgh.msg_flags = 0;
  
  int err;
  vector<struct pollfd> rfds= d_rfds;

  BOOST_FOREACH(struct pollfd &pfd, rfds) {
    pfd.events = POLLIN;
    pfd.revents = 0;
  }
    
  err = poll(&rfds[0], rfds.size(), -1);
  if(err < 0)
    unixDie("Unable to poll for new UDP events");
    
  BOOST_FOREACH(struct pollfd &pfd, rfds) {
    if(pfd.revents & POLLIN) {
      sock=pfd.fd;        
      if((len=recvmsg(sock, &msgh, 0)) < 0 ) {
        if(errno != EAGAIN)
          L<<Logger::Error<<"recvfrom gave error, ignoring: "<<strerror(errno)<<endl;
        return 0;
      }
      break;
    }
  }
  if(sock==-1)
    throw PDNSException("poll betrayed us! (should not happen)");
  

  DLOG(L<<"Received a packet " << len <<" bytes long from "<< remote.toString()<<endl);
  
  DNSPacket *packet;
  if(prefilled)  // they gave us a preallocated packet
    packet=prefilled;
  else
    packet=new DNSPacket; // don't forget to free it!
  packet->d_dt.set(); // timing
  packet->setSocket(sock);
  packet->setRemote(&remote);

  ComboAddress dest;
  if(HarvestDestinationAddress(&msgh, &dest)) {
//    cerr<<"Setting d_anyLocal to '"<<dest.toString()<<"'"<<endl;
    packet->d_anyLocal = dest;
  }            

  if(packet->parse(mesg, len)<0) {
    S.inc("corrupt-packets");
    S.ringAccount("remotes-corrupt", packet->getRemote());

    if(!prefilled)
      delete packet;
    return 0; // unable to parse
  }
  
  return packet;
}
