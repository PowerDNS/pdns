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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "utility.hh"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <iostream>
#include <string>
#include <sys/types.h>
#include "responsestats.hh"

#include "auth-main.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "dnspacket.hh"
#include "nameserver.hh"
#include "distributor.hh"
#include "logger.hh"
#include "arguments.hh"
#include "statbag.hh"
#include "proxy-protocol.hh"

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

    PowerDNS uses the UeberBackend, which hosts DNSBackends. By default it has no DNSBackends within itself, those are loaded
    by setting --load=<list of backends>. This way DNSBackend implementations can be kept completely separate, but most aren't.

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
    The main() of PowerDNS can be found in auth-main.cc - start reading there for further insights into the operation of the nameserver
*/

vector<ComboAddress> g_localaddresses; // not static, our unit tests need to poke this

void UDPNameserver::bindAddresses()
{
  vector<string>locals;
  stringtok(locals,::arg()["local-address"]," ,");

  if(locals.empty())
    throw PDNSException("No local address specified");

  int s;
  // for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
  for (const auto &local : locals) {

    if (local.find("fdgram:") == 0) {
      s = std::stoi(local.substr(8, local.length()));
      g_log<<Logger::Error<<"UDP server listening on "<<local<<endl;
    } else if (local.find("fd:") == 0) {
      continue;
    } else {
      ComboAddress locala(local, ::arg().asNum("local-port"));
      s = createSocket(locala);
      if (s == -1) {
        continue;
      }
    }
    d_sockets.push_back(s);
    struct pollfd pfd;
    pfd.fd = s;
    pfd.events = POLLIN;
    pfd.revents = 0;
    d_rfds.push_back(pfd);
  }
}

int UDPNameserver::createSocket(ComboAddress &locala)
{
  int s = socket(locala.sin4.sin_family, SOCK_DGRAM, 0);

  if(s < 0) {
    if(errno == EAFNOSUPPORT) {
      g_log<<Logger::Error<<"Binding "<<locala.toStringWithPort()<<": Address Family is not supported - skipping bind" << endl;
      return -1;
    }
    throw PDNSException("Unable to acquire a UDP socket: "+stringerror());
  }

  setCloseOnExec(s);
  if(!setNonBlocking(s))
    throw PDNSException("Unable to set UDP socket " + locala.toStringWithPort() + " to non-blocking: "+stringerror());

  if(IsAnyAddress(locala)) {
    int one = 1;
    (void)setsockopt(s, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one));
    if (locala.isIPv6()) {
      (void)setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));      // if this fails, we report an error in tcpreceiver too
#ifdef IPV6_RECVPKTINFO
      (void)setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
#endif
    }
  }

  if (!setSocketTimestamps(s))
    g_log<<Logger::Warning<<"Unable to enable timestamp reporting for socket "<<locala.toStringWithPort()<<endl;

  try {
    setSocketIgnorePMTU(s, locala.sin4.sin_family);
  }
  catch(const std::exception& e) {
    g_log<<Logger::Warning<<"Failed to set IP_MTU_DISCOVER on UDP server socket: "<<e.what()<<endl;
  }

  if (d_can_reuseport) {
    if (!setReusePort(s)) {
      d_can_reuseport = false;
    }
  }

  if( ::arg().mustDo("non-local-bind") )
    Utility::setBindAny(locala.sin4.sin_family, s);

  if( !d_additional_socket )
      g_localaddresses.push_back(locala);

  if(::bind(s, (sockaddr*)&locala, locala.getSocklen()) < 0) {
    int err = errno;
    close(s);
    if (err == EADDRNOTAVAIL && !::arg().mustDo("local-address-nonexist-fail")) {
      g_log<<Logger::Error<<"Address " << locala << " does not exist on this server - skipping UDP bind" << endl;
      return -1;
    } else {
      g_log<<Logger::Error<<"Unable to bind UDP socket to '"+locala.toStringWithPort()+"': "<<stringerror(err)<<endl;
      throw PDNSException("Unable to bind to UDP socket");
    }
  }
  g_log<<Logger::Error<<"UDP server bound to "<<locala.toStringWithPort()<<endl;
  return s;
}

bool AddressIsUs(const ComboAddress& remote)
{
  for(const ComboAddress& us :  g_localaddresses) {
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

UDPNameserver::UDPNameserver( bool additional_socket )
{
  d_can_reuseport = ::arg().mustDo("reuseport");
  // Are we the main socket (false) or a rebinding using SO_REUSEPORT ?
  d_additional_socket = additional_socket;

  if(::arg()["local-address"].empty())
    g_log<<Logger::Critical<<"PDNS is deaf and mute! Not listening on any interfaces"<<endl;    

  bindAddresses();
}

void UDPNameserver::send(DNSPacket& p)
{
  const string& buffer=p.getString();
  g_rs.submitResponse(p, true);

  struct msghdr msgh;
  struct iovec iov;
  cmsgbuf_aligned cbuf;

  fillMSGHdr(&msgh, &iov, &cbuf, 0, (char*)buffer.c_str(), buffer.length(), &p.d_remote);

  msgh.msg_control=nullptr;
  if(p.d_anyLocal) {
    addCMsgSrcAddr(&msgh, &cbuf, p.d_anyLocal.get_ptr(), 0);
  }
  DLOG(g_log<<Logger::Notice<<"Sending a packet to "<< p.getRemote() <<" ("<< buffer.length()<<" octets)"<<endl);
  if(buffer.length() > p.getMaxReplyLen()) {
    g_log<<Logger::Error<<"Weird, trying to send a message that needs truncation, "<< buffer.length()<<" > "<<p.getMaxReplyLen()<<". Question was for "<<p.qdomain<<"|"<<p.qtype.toString()<<endl;
  }
  if (sendOnNBSocket(p.getSocket(), &msgh) < 0) {
    int err = errno;
    g_log<<Logger::Error<<"Error sending reply with sendmsg (socket="<<p.getSocket()<<", dest="<<p.d_remote.toStringWithPort()<<"): "<<stringerror(err)<<endl;
  }
}

bool UDPNameserver::receive(DNSPacket& packet, std::string& buffer)
{
  ComboAddress remote;
  extern StatBag S;
  ssize_t len=-1;
  Utility::sock_t sock=-1;

  struct msghdr msgh;
  struct iovec iov;
  cmsgbuf_aligned cbuf;

  remote.sin6.sin6_family=AF_INET6; // make sure it is big enough
  fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), &buffer.at(0), buffer.size(), &remote);
  
  int err;
  vector<struct pollfd> rfds= d_rfds;

  for(auto &pfd :  rfds) {
    pfd.events = POLLIN;
    pfd.revents = 0;
  }
    
  retry:;
  
  err = poll(&rfds[0], rfds.size(), -1);
  if(err < 0) {
    if(errno==EINTR)
      goto retry;
    unixDie("Unable to poll for new UDP events");
  }
    
  for(auto &pfd :  rfds) {
    if(pfd.revents & POLLIN) {
      sock=pfd.fd;        
      if((len=recvmsg(sock, &msgh, 0)) < 0 ) {
        if(errno != EAGAIN)
          g_log<<Logger::Error<<"recvfrom gave error, ignoring: "<<stringerror()<<endl;
        return false;
      }
      break;
    }
  }
  if(sock==-1)
    throw PDNSException("poll betrayed us! (should not happen)");
  
  DLOG(g_log<<"Received a packet " << len <<" bytes long from "<< remote.toString()<<endl);

  BOOST_STATIC_ASSERT(offsetof(sockaddr_in, sin_port) == offsetof(sockaddr_in6, sin6_port));

  if(remote.sin4.sin_port == 0) // would generate error on responding. sin4 also works for ipv6
    return false;
  
  packet.setSocket(sock);
  packet.setRemote(&remote);

  ComboAddress dest;
  if(HarvestDestinationAddress(&msgh, &dest)) {
//    cerr<<"Setting d_anyLocal to '"<<dest.toString()<<"'"<<endl;
    packet.d_anyLocal = dest;
  }            

  struct timeval recvtv;
  if(HarvestTimestamp(&msgh, &recvtv)) {
    packet.d_dt.setTimeval(recvtv);
  }
  else
    packet.d_dt.set(); // timing

  if (g_proxyProtocolACL.match(remote)) {
    ComboAddress psource, pdestination;
    bool proxyProto, tcp;
    std::vector<ProxyProtocolValue> ppvalues;

    buffer.resize(len);
    ssize_t used = parseProxyHeader(buffer, proxyProto, psource, pdestination, tcp, ppvalues);
    if (used <= 0 || (size_t) used > g_proxyProtocolMaximumSize || (len - used) > DNSPacket::s_udpTruncationThreshold) {
      S.inc("corrupt-packets");
      S.ringAccount("remotes-corrupt", packet.d_remote);
      return false;
    }
    buffer.erase(0, used);
    packet.d_inner_remote = psource;
    packet.d_tcp = tcp;
  }
  else {
    packet.d_inner_remote.reset();
  }

  if(packet.parse(&buffer.at(0), (size_t) len)<0) {
    S.inc("corrupt-packets");
    S.ringAccount("remotes-corrupt", packet.getInnerRemote());

    return false; // unable to parse
  }
  
  return true;
}
