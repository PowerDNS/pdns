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

std::vector<ComboAddress> g_localaddresses;

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

bool Nameserver::parseQuery(DNSPacket& packet, std::string& buffer)
{
  if(packet.parse(buffer.data(), buffer.size())<0) {
    S.inc("corrupt-packets");
    S.ringAccount("remotes-corrupt", packet.getInnerRemote());

    return false; // unable to parse
  }

  ComboAddress accountremote = packet.d_remote;
  if (packet.d_inner_remote)
    accountremote = *packet.d_inner_remote;

  uint64_t latency = std::max(packet.d_dt.udiffNoReset(), 0);
  this->stats.countQuery(
    latency,
    packet.d_dnssecOk,
    packet.hasEDNSCookie(),
    accountremote.sin4.sin_family == AF_INET
  );

  if (packet.d.qr) {
    // This is a response, ignore
    return false;
  }

  S.ringAccount("queries", packet.qdomain, packet.qtype);
  S.ringAccount("remotes", packet.getInnerRemote());

  if (this->logDNSQueries) {
    g_log << Logger::Notice << "Remote " << packet.getRemoteString() << " wants '" << packet.qdomain << "|" << packet.qtype << "', do = " << packet.d_dnssecOk << ", bufsize = " << packet.getMaxReplyLen();
    if (packet.d_ednsRawPacketSizeLimit > 0 && packet.getMaxReplyLen() != (unsigned int)packet.d_ednsRawPacketSizeLimit)
      g_log << " (" << packet.d_ednsRawPacketSizeLimit << ")";
  }

  return true;
}

bool Nameserver::tryCache(DNSPacket& question, DNSPacket& cached)
{
  if (PC.enabled() && (question.d.opcode != Opcode::Notify && question.d.opcode != Opcode::Update) && question.couldBeCached()) {
    uint64_t start = question.d_dt.udiffNoReset();
    bool haveSomething = PC.get(question, cached); // does the PacketCache recognize this question?
    if (haveSomething) {
      if (logDNSQueries)
        g_log << ": packetcache HIT" << endl;
      cached.setRemote(&question.d_remote); // inlined
      cached.d_inner_remote = question.d_inner_remote;
      cached.setSocket(question.getSocket()); // inlined
      cached.d_anyLocal = question.d_anyLocal;
      cached.setMaxReplyLen(question.getMaxReplyLen());
      cached.d.rd = question.d.rd; // copy in recursion desired bit
      cached.d.id = question.d.id;
      cached.commitD(); // commit d to the packet                        inlined

      stats.logCacheLatency(std::max(question.d_dt.udiffNoReset() - start, (uint64_t)0));

      return true;
    }
    stats.logCacheLatency(std::max(question.d_dt.udiffNoReset() - start, (uint64_t)0));
    if (this->logDNSQueries) {
      g_log << ": packetcache MISS" << endl;
    }
  }
  return false;
}

std::unique_ptr<DNSPacket> Nameserver::processQuery(std::unique_ptr<PacketHandler>& packetHandler, DNSPacket& packet)
{
  uint64_t start = packet.d_dt.udiff();

  std::unique_ptr<DNSPacket> answer = nullptr;
  bool allowRetry = true;
  while (allowRetry) {
    try {
      if (!packetHandler) {
        allowRetry=false;
        packetHandler=make_unique<PacketHandler>();
      }
      answer=packetHandler->question(packet); // answer can be NULL!
      return answer;
    }
    catch(const PDNSException &e) {
      packetHandler.reset();
      if (!allowRetry) {
        g_log<<Logger::Error<<"Backend error: "<<e.reason<<endl;
        answer=packet.replyPacket();

        answer->setRcode(RCode::ServFail);
        S.inc("servfail-packets");
        S.ringAccount("servfail-queries", packet.qdomain, packet.qtype);
        return answer;
      } else {
        g_log<<Logger::Notice<<"Backend error (retry once): "<<e.reason<<endl;
      }
    }
    catch(...) {
      packetHandler.reset();
      if (!allowRetry) {
        g_log<<Logger::Error<<"Caught unknown exception in handling query"<<endl;
        answer=packet.replyPacket();

        answer->setRcode(RCode::ServFail);
        S.inc("servfail-packets");
        S.ringAccount("servfail-queries", packet.qdomain, packet.qtype);
        return answer;
      } else {
        g_log<<Logger::Warning<<"Caught unknown exception in handling query (retry once)"<<endl;
      }
    }
  }
  uint64_t diff = packet.d_dt.udiffNoReset();
  this->stats.logBackendLatency(std::max(diff-start, (uint64_t)0));

  return answer;
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

UDPNameserver::UDPNameserver(NameserverStats a_stats, bool a_logDnsQueries, UDPBindAddress address) : Nameserver(a_stats, true, a_logDnsQueries)
{
  this->listeningSocket = address.getSocket();
  this->handler = make_unique<PacketHandler>();
}

void UDPNameserver::run()
{
  DNSPacket question(true);
  DNSPacket cached(false);
  std::string buffer;

  for (;;) {
    if (g_proxyProtocolACL.empty()) {
      buffer.resize(DNSPacket::s_udpTruncationThreshold);
    }
    else {
      buffer.resize(DNSPacket::s_udpTruncationThreshold + g_proxyProtocolMaximumSize);
    }
    this->receiveAndProcessPacket(question, cached, buffer);
  }
}

void UDPNameserver::receiveAndProcessPacket(DNSPacket& question, DNSPacket& cached, std::string& buffer)
{
  ComboAddress remote;
  extern StatBag S;
  ssize_t len=-1;

  struct msghdr msgh;
  struct iovec iov;
  cmsgbuf_aligned cbuf;

  remote.sin6.sin6_family=AF_INET6; // make sure it is big enough
  fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), buffer.data(), buffer.capacity(), &remote);

  if((len=recvmsg(this->listeningSocket, &msgh, 0)) < 0 ) {
    if(errno != EAGAIN && errno != EINTR)
      g_log<<Logger::Error<<"recvfrom gave error, ignoring: "<<stringerror()<<endl;
    return;
  }

  buffer.resize(len);

  DLOG(g_log<<"Received a packet " << len <<" bytes long from "<< remote.toString()<<endl);

  BOOST_STATIC_ASSERT(offsetof(sockaddr_in, sin_port) == offsetof(sockaddr_in6, sin6_port));

  if(remote.sin4.sin_port == 0) // would generate error on responding. sin4 also works for ipv6
    return;

  question.setSocket(this->listeningSocket);
  question.setRemote(&remote);

  ComboAddress dest;
  if(HarvestDestinationAddress(&msgh, &dest)) {
    //    cerr<<"Setting d_anyLocal to '"<<dest.toString()<<"'"<<endl;
    question.d_anyLocal = dest;
  }

  struct timeval recvtv;
  if(HarvestTimestamp(&msgh, &recvtv)) {
    question.d_dt.setTimeval(recvtv);
  }
  else
    question.d_dt.set(); // timing

  if (g_proxyProtocolACL.match(remote)) {
    ComboAddress psource, pdestination;
    bool proxyProto, tcp;
    std::vector<ProxyProtocolValue> ppvalues;

    ssize_t used = parseProxyHeader(buffer, proxyProto, psource, pdestination, tcp, ppvalues);
    if (used <= 0 || (size_t) used > g_proxyProtocolMaximumSize || (len - used) > DNSPacket::s_udpTruncationThreshold) {
      S.inc("corrupt-packets");
      S.ringAccount("remotes-corrupt", question.d_remote);
      return;
    }
    buffer.erase(0, used);
    question.d_inner_remote = psource;
    question.d_tcp = tcp;
  }
  else {
    question.d_inner_remote.reset();
  }

  if (!this->parseQuery(question, buffer)) {
    return;
  }

  if (this->tryCache(question, cached)) {
    this->send(cached);
    return;
  }

  this->handlePacket(question);
}

void UDPNameserver::handlePacket(DNSPacket& packet)
{
  auto answer = this->processQuery(this->handler, packet);
  if (answer) {
    this->send(*answer);
  }
}

void UDPNameserver::send(DNSPacket& p)
{
  try {
    uint64_t start = p.d_dt.udiffNoReset();
    const string& buffer = p.getString();
    g_rs.submitResponse(p, true);

    struct msghdr msgh;
    struct iovec iov;
    cmsgbuf_aligned cbuf;

    fillMSGHdr(&msgh, &iov, &cbuf, 0, (char*)buffer.c_str(), buffer.length(), &p.d_remote);

    msgh.msg_control = nullptr;
    if (p.d_anyLocal) {
      addCMsgSrcAddr(&msgh, &cbuf, p.d_anyLocal.get_ptr(), 0);
    }
    DLOG(g_log << Logger::Notice << "Sending a packet to " << p.getRemote() << " (" << buffer.length() << " octets)" << endl);
    if (buffer.length() > p.getMaxReplyLen()) {
      g_log << Logger::Error << "Weird, trying to send a message that needs truncation, " << buffer.length() << " > " << p.getMaxReplyLen() << ". Question was for " << p.qdomain << "|" << p.qtype.toString() << endl;
    }
    if (sendmsg(p.getSocket(), &msgh, 0) < 0)
      g_log << Logger::Error << "Error sending reply with sendmsg (socket=" << p.getSocket() << ", dest=" << p.d_remote.toStringWithPort() << "): " << stringerror() << endl;
    uint64_t diff = p.d_dt.udiff();
    this->stats.logResponseLatency(std::max(diff-start, (uint64_t)0), std::max(diff, (uint64_t)0));
  } catch (const std::exception& e){
    g_log << Logger::Error << "Caught unhandled exception while sending a response: " << e.what() << endl;
  }
}

