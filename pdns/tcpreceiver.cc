/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2012  PowerDNS.COM BV

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
#include "pdns/auth-zonecache.hh"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/algorithm/string.hpp>
#include <boost/scoped_array.hpp>
#include "auth-packetcache.hh"
#include "utility.hh"
#include "threadname.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include <cstdio>
#include "base32.hh"
#include <cstring>
#include <cstdlib>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <iostream>
#include <string>
#include "tcpreceiver.hh"
#include "sstuff.hh"

#include <cerrno>
#include <csignal>
#include "base64.hh"
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "nameserver.hh"
#include "distributor.hh"
#include "lock.hh"
#include "logger.hh"
#include "arguments.hh"

#include "auth-main.hh"
#include "packethandler.hh"
#include "statbag.hh"
#include "communicator.hh"
#include "namespaces.hh"
#include "signingpipe.hh"
#include "stubresolver.hh"
#include "proxy-protocol.hh"
#include "noinitvector.hh"
#include "gss_context.hh"
#include "pdnsexception.hh"

/**
\file tcpreceiver.cc
\brief This file implements the tcpreceiver that receives and answers questions over TCP/IP
*/

std::unique_ptr<Semaphore> TCPNameserver::d_connectionroom_sem{nullptr};
LockGuarded<std::unique_ptr<PacketHandler>> TCPNameserver::s_P{nullptr};
unsigned int TCPNameserver::d_maxTCPConnections = 0;
NetmaskGroup TCPNameserver::d_ng;
size_t TCPNameserver::d_maxTransactionsPerConn;
size_t TCPNameserver::d_maxConnectionsPerClient;
unsigned int TCPNameserver::d_idleTimeout;
unsigned int TCPNameserver::d_maxConnectionDuration;
LockGuarded<std::map<ComboAddress,size_t,ComboAddress::addressOnlyLessThan>> TCPNameserver::s_clientsCount;

void TCPNameserver::go()
{
  SLOG(g_log<<Logger::Error<<"Creating backend connection for TCP"<<endl,
       d_slog->info(Logr::Error, "Creating backend connection for TCP"));
  s_P.lock()->reset();
  try {
    *(s_P.lock()) = make_unique<PacketHandler>(d_slog);
  }
  catch(PDNSException &ae) {
    SLOG(g_log<<Logger::Error<<"TCP server is unable to launch backends - will try again when questions come in: "<<ae.reason<<endl,
         d_slog->error(Logr::Error, ae.reason, "TCP server is unable to launch backends, will try again when questions come in"));
  }

  std::thread th([this](){thread();});
  th.detach();
}

// throws PDNSException if things didn't go according to plan, returns 0 if really 0 bytes were read
static int readnWithTimeout(int fd, void* buffer, unsigned int n, unsigned int idleTimeout, bool throwOnEOF=true, unsigned int totalTimeout=0)
{
  unsigned int bytes=n;
  char *ptr = (char*)buffer;
  int ret;
  time_t start = 0;
  unsigned int remainingTotal = totalTimeout;
  if (totalTimeout) {
    start = time(nullptr);
  }
  while(bytes) {
    ret=read(fd, ptr, bytes);
    if(ret < 0) {
      if(errno==EAGAIN) {
        ret=waitForData(fd, (totalTimeout == 0 || idleTimeout <= remainingTotal) ? idleTimeout : remainingTotal);
        if(ret < 0)
          throw NetworkError("Waiting for data read");
        if(!ret)
          throw NetworkError("Timeout reading data");
        continue;
      }
      else
        throw NetworkError("Reading data: "+stringerror());
    }
    if(!ret) {
      if(!throwOnEOF && n == bytes)
        return 0;
      else
        throw NetworkError("Did not fulfill read from TCP due to EOF");
    }

    ptr += ret;
    bytes -= ret;
    if (totalTimeout) {
      time_t now = time(nullptr);
      const auto elapsed = now - start;
      if (elapsed >= static_cast<time_t>(remainingTotal)) {
        throw NetworkError("Timeout while reading data");
      }
      start = now;
      if (elapsed > 0) {
        remainingTotal -= elapsed;
      }
    }
  }
  return n;
}

// ditto
static void writenWithTimeout(int fd, const void *buffer, unsigned int n, unsigned int idleTimeout)
{
  unsigned int bytes=n;
  const char *ptr = (char*)buffer;
  int ret;
  while(bytes) {
    ret=write(fd, ptr, bytes);
    if(ret < 0) {
      if(errno==EAGAIN) {
        ret=waitForRWData(fd, false, idleTimeout, 0);
        if(ret < 0)
          throw NetworkError("Waiting for data write");
        if(!ret)
          throw NetworkError("Timeout writing data");
        continue;
      }
      else
        throw NetworkError("Writing data: "+stringerror());
    }
    if(!ret) {
      throw NetworkError("Did not fulfill TCP write due to EOF");
    }

    ptr += ret;
    bytes -= ret;
  }
}

void TCPNameserver::sendPacket(std::unique_ptr<DNSPacket>& p, int outsock, bool last)
{
  uint16_t len=htons(p->getString(true).length());

  // this also calls p->getString; call it after our explicit call so throwsOnTruncation=true is honoured
  g_rs.submitResponse(*p, false, last);

  string buffer((const char*)&len, 2);
  buffer.append(p->getString());
  writenWithTimeout(outsock, buffer.c_str(), buffer.length(), d_idleTimeout);
}


void TCPNameserver::getQuestion(int fd, char *mesg, int pktlen, const ComboAddress &remote, unsigned int totalTime)
try
{
  readnWithTimeout(fd, mesg, pktlen, d_idleTimeout, true, totalTime);
}
catch(NetworkError& ae) {
  throw NetworkError("Error reading DNS data from TCP client "+remote.toString()+": "+ae.what());
}

static bool maxConnectionDurationReached(unsigned int maxConnectionDuration, time_t start, unsigned int& remainingTime)
{
  if (maxConnectionDuration) {
    time_t elapsed = time(nullptr) - start;
    if (elapsed >= maxConnectionDuration) {
      return true;
    }
    if (elapsed > 0) {
      remainingTime = static_cast<unsigned int>(maxConnectionDuration - elapsed);
    }
  }
  return false;
}

void TCPNameserver::decrementClientCount(const ComboAddress& remote)
{
  if (d_maxConnectionsPerClient) {
    auto count = s_clientsCount.lock();
    auto it = count->find(remote);
    if (it == count->end()) {
      // this is worrying, but nothing we can do at this point
      return;
    }
    --it->second;
    if (it->second == 0) {
      count->erase(it);
    }
  }
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
void TCPNameserver::doConnection(int fd, Logr::log_t slog)
{
  setThreadName("pdns/tcpConnect");
  std::unique_ptr<DNSPacket> packet;
  ComboAddress remote, accountremote;
  socklen_t remotelen=sizeof(remote);
  size_t transactions = 0;
  time_t start = 0;
  if (d_maxConnectionDuration) {
    start = time(nullptr);
  }

  if(getpeername(fd, (struct sockaddr *)&remote, &remotelen) < 0) {
    SLOG(g_log<<Logger::Warning<<"Received question from socket which had no remote address, dropping ("<<stringerror()<<")"<<endl,
         slog->error(Logr::Warning, errno, "Received question from socket which had no remote address, dropping"));
    d_connectionroom_sem->post();
    try {
      closesocket(fd);
    }
    catch(const PDNSException& e) {
      SLOG(g_log<<Logger::Error<<"Error closing TCP socket: "<<e.reason<<endl,
           slog->error(Logr::Error, e.reason, "Error closing TCP socket"));
    }
    return;
  }

  setNonBlocking(fd);
  try {
    int mesgsize=65535;
    boost::scoped_array<char> mesg(new char[mesgsize]);
    std::optional<ComboAddress> inner_remote;
    bool inner_tcp = false;

    DLOG(SLOG(g_log<<"TCP Connection accepted on fd "<<fd<<endl,
              slog->info(Logr::Debug, "TCP Connection accepted", "fd", Logging::Loggable(fd))));
    if (g_proxyProtocolACL.match(remote)) {
      unsigned int remainingTime = 0;
      PacketBuffer proxyData;
      proxyData.reserve(g_proxyProtocolMaximumSize);
      ssize_t used;

      // this for-loop ends by throwing, or by having gathered a complete proxy header
      for (;;) {
        used = isProxyHeaderComplete(proxyData);
        if (used < 0) {
          size_t origsize = proxyData.size();
          auto extra = static_cast<size_t>(-used);
          if (origsize + extra > g_proxyProtocolMaximumSize) {
            throw NetworkError("Error reading PROXYv2 header from TCP client "+remote.toString()+": PROXYv2 header too big");
          }
          proxyData.resize(origsize + extra);
          if (maxConnectionDurationReached(d_maxConnectionDuration, start, remainingTime)) {
            throw NetworkError("Error reading PROXYv2 header from TCP client "+remote.toString()+": maximum TCP connection duration exceeded");
          }

          try {
            readnWithTimeout(fd, &proxyData[origsize], extra, d_idleTimeout, true, remainingTime);
          }
          catch(NetworkError& ae) {
            throw NetworkError("Error reading PROXYv2 header from TCP client "+remote.toString()+": "+ae.what());
          }
        }
        else if (used == 0) {
          throw NetworkError("Error reading PROXYv2 header from TCP client "+remote.toString()+": PROXYv2 header was invalid");
        }
        else if (static_cast<size_t>(used) > g_proxyProtocolMaximumSize) {
          throw NetworkError("Error reading PROXYv2 header from TCP client "+remote.toString()+": PROXYv2 header too big");
        }
        else { // used > 0 && used <= g_proxyProtocolMaximumSize
          break;
        }
      }
      ComboAddress psource, pdestination;
      bool proxyProto, tcp;
      std::vector<ProxyProtocolValue> ppvalues;

      used = parseProxyHeader(proxyData, proxyProto, psource, pdestination, tcp, ppvalues);
      if (used <= 0) {
        throw NetworkError("Error reading PROXYv2 header from TCP client "+remote.toString()+": PROXYv2 header was invalid");
      }
      if (static_cast<size_t>(used) > g_proxyProtocolMaximumSize) {
        throw NetworkError("Error reading PROXYv2 header from TCP client "+remote.toString()+": PROXYv2 header was oversized");
      }
      inner_remote = psource;
      inner_tcp = tcp;
      accountremote = psource;
    }
    else {
      accountremote = remote;
    }

    for(;;) {
      unsigned int remainingTime = 0;
      transactions++;
      if (d_maxTransactionsPerConn && transactions > d_maxTransactionsPerConn) {
        SLOG(g_log << Logger::Notice<<"TCP Remote "<< remote <<" exceeded the number of transactions per connection, dropping.",
             slog->info(Logr::Notice, "TCP Remote exceeded the number of transactions per connection, dropping", "remote", Logging::Loggable(remote)));
        break;
      }
      if (maxConnectionDurationReached(d_maxConnectionDuration, start, remainingTime)) {
        SLOG(g_log << Logger::Notice<<"TCP Remote "<< remote <<" exceeded the maximum TCP connection duration, dropping.",
             slog->info(Logr::Notice, "TCP Remote exceeded the maximum TCP connection duration, dropping", "remote", Logging::Loggable(remote)));
        break;
      }

      uint16_t pktlen;
      if(!readnWithTimeout(fd, &pktlen, 2, d_idleTimeout, false, remainingTime))
        break;
      else
        pktlen=ntohs(pktlen);

      // this check will always be false *if* no one touches
      // the mesg array. pktlen can be maximum of 65535 as
      // it is 2 byte unsigned variable. In getQuestion, we
      // write to 0 up to pktlen-1 so 65535 is just right.

      // do not remove this check as it will catch if someone
      // decreases the mesg buffer size for some reason.
      if(pktlen > mesgsize) {
        SLOG(g_log<<Logger::Warning<<"Received an overly large question from "<<remote.toString()<<", dropping"<<endl,
             slog->info(Logr::Warning, "Received an overly large question, dropping", "remote", Logging::Loggable(remote)));
        break;
      }

      if (maxConnectionDurationReached(d_maxConnectionDuration, start, remainingTime)) {
        SLOG(g_log << Logger::Notice<<"TCP Remote "<< remote <<" exceeded the maximum TCP connection duration, dropping.",
             slog->info(Logr::Notice, "TCP Remote exceeded the maximum TCP connection duration, dropping", "remote", Logging::Loggable(remote)));
        break;
      }

      getQuestion(fd, mesg.get(), pktlen, remote, remainingTime);
      S.inc("tcp-queries");
      if (accountremote.sin4.sin_family == AF_INET6)
        S.inc("tcp6-queries");
      else
        S.inc("tcp4-queries");

      packet=make_unique<DNSPacket>(slog, true);
      packet->setRemote(&remote);
      packet->d_tcp=true;
      if (inner_remote) {
        packet->d_inner_remote = inner_remote;
        packet->d_tcp = inner_tcp;
      }
      packet->setSocket(fd);
      if(packet->parse(mesg.get(), pktlen)<0)
        break;

      if (packet->hasEDNSCookie())
        S.inc("tcp-cookie-queries");

      if(packet->qtype.getCode()==QType::AXFR) {
        packet->d_xfr=true;
        g_zoneCache.setZoneVariant(*packet);
        doAXFR(packet, fd, slog);
        continue;
      }

      if(packet->qtype.getCode()==QType::IXFR) {
        packet->d_xfr=true;
        g_zoneCache.setZoneVariant(*packet);
        doIXFR(packet, fd, slog);
        continue;
      }

      std::unique_ptr<DNSPacket> reply;
      auto cached = make_unique<DNSPacket>(slog, false);
      std::shared_ptr<Logr::Logger> slogger;
      if(g_logDNSQueries)  {
        if (g_slogStructured) {
          slogger = slog->withValues("remote", Logging::Loggable(packet->getRemoteString()), "query", Logging::Loggable(packet->qdomain), "type", Logging::Loggable(packet->qtype), "dnssecok", Logging::Loggable(packet->d_dnssecOk), "bufsize", Logging::Loggable(packet->getMaxReplyLen()));
        }
        else {
          g_log << Logger::Notice<<"TCP Remote "<< packet->getRemoteString() <<" wants '" << packet->qdomain<<"|"<<packet->qtype.toString() <<
               "', do = " <<packet->d_dnssecOk <<", bufsize = "<< packet->getMaxReplyLen();
        }
      }

      bool logAtNewline{false};
      if (PC.enabled()) {
        if (packet->couldBeCached()) {
          std::string view{};
          if (g_views) {
            if (!g_slogStructured) {
              g_log << endl;
              logAtNewline = true; // because of getViewFromNetwork below
            }
            Netmask netmask(packet->getInnerRemote());
            view = g_zoneCache.getViewFromNetwork(&netmask);
          }
          if (PC.get(*packet, *cached, view)) { // short circuit - does the PacketCache recognize this question?
            if(g_logDNSQueries) {
              SLOG(g_log << (logAtNewline ? "" : ": ") << "packetcache HIT"<<endl,
                   slogger->info(Logr::Notice, "Received TCP query", "packetcache", Logging::Loggable("hit")));
            }
            cached->setRemote(&packet->d_remote);
            cached->d_inner_remote = packet->d_inner_remote;
            cached->d.id=packet->d.id;
            cached->d.rd=packet->d.rd; // copy in recursion desired bit
            cached->commitD(); // commit d to the packet                        inlined

            sendPacket(cached, fd); // presigned, don't do it again
            continue;
          }
        }
        if(g_logDNSQueries) {
          SLOG(g_log<< (logAtNewline ? "" : ": ") << "packetcache MISS"<<endl,
               slogger->info(Logr::Notice, "Received TCP query", "packetcache", Logging::Loggable("miss")));
        }
      } else {
        if (g_logDNSQueries) {
          SLOG(g_log<<endl,
               slogger->info(Logr::Notice, "Received TCP query"));
        }
      }
      {
        auto packetHandler = s_P.lock();
        if (!*packetHandler) {
          SLOG(g_log<<Logger::Warning<<"TCP server is without backend connections, launching"<<endl,
               slog->info(Logr::Warning, "TCP server is without backend connection, launching"));
          *packetHandler = make_unique<PacketHandler>(slog);
        }

        reply = (*packetHandler)->doQuestion(*packet); // we really need to ask the backend :-)
      }

      if(!reply)  // unable to write an answer?
        break;

      sendPacket(reply, fd);
#ifdef ENABLE_GSS_TSIG
      if (g_doGssTSIG) {
        packet->cleanupGSS(reply->d.rcode);
      }
#endif
    }
  }
  catch(PDNSException &ae) {
    s_P.lock()->reset(); // on next call, backend will be recycled
    SLOG(g_log << Logger::Error << "TCP Connection Thread for client " << remote << " failed, cycling backend: " << ae.reason << endl,
         slog->error(Logr::Error, ae.reason, "TCP Connection Thread failed, cycling backend", "remote", Logging::Loggable(remote)));
  }
  catch(NetworkError &e) {
    SLOG(g_log << Logger::Info << "TCP Connection Thread for client " << remote << " died because of network error: " << e.what() << endl,
         slog->error(Logr::Info, e.what(), "TCP Connection Thread died because of network error", "remote", Logging::Loggable(remote)));
  }

  catch(std::exception &e) {
    s_P.lock()->reset(); // on next call, backend will be recycled
    SLOG(g_log << Logger::Error << "TCP Connection Thread for client " << remote << " died because of STL error, cycling backend: " << e.what() << endl,
         slog->error(Logr::Info, e.what(), "TCP Connection Thread died because of STL error", "remote", Logging::Loggable(remote)));
  }
  catch( ... )
  {
    s_P.lock()->reset(); // on next call, backend will be recycled
    SLOG(g_log << Logger::Error << "TCP Connection Thread for client " << remote << " caught unknown exception, cycling backend." << endl,
         slog->info(Logr::Error, "TCP Connection Thread caught unknomn exception, cycling backend", "remote", Logging::Loggable(remote)));
  }
  d_connectionroom_sem->post();

  try {
    closesocket(fd);
  }
  catch(const PDNSException& e) {
    SLOG(g_log << Logger::Error << "Error closing TCP socket for client " << remote << ": " << e.reason << endl,
         slog->error(Logr::Error, e.reason, "Error closing TCP socket", "remote", Logging::Loggable(remote)));
  }
 decrementClientCount(remote);
}

namespace {
  struct NSECXEntry
  {
    NSECBitmap d_set;
    unsigned int d_ttl{0};
    bool d_auth{false};
  };
}

class TCPNameserver::XFRContext
{
public:
  XFRContext(std::unique_ptr<DNSPacket>& qry, int sock, Logr::log_t log, bool isAXFR);
  XFRContext(const XFRContext&) = delete;
  XFRContext& operator=(const XFRContext&) = delete;
  XFRContext(XFRContext&&) = delete;
  XFRContext& operator=(XFRContext&&) = delete;
  ~XFRContext() = default;

  void setupOutputPacket();
  void sendIntermediatePacket();

  // NOLINTBEGIN(cppcoreguidelines-non-private-member-variables-in-classes)
  const ZoneName& targetZone; // domain being XFR'ed
  DomainInfo info;
  SOAData soa;
  bool soaValid{false};

  bool presignedZone{false};
  bool securedZone{false};
  bool NSEC3Zone{false};
  bool isCatalogZone{false};
  NSEC3PARAMRecordContent ns3pr;

  bool haveTSIGDetails{false};
  TSIGRecordContent trc;
  DNSName tsigkeyname;
  string tsigsecret;

  // Network-related fields
  int outsock;
  std::unique_ptr<DNSPacket> outpacket;

  // Logging-related fields
  std::string xfrType;
  std::string client;
  std::string logPrefix;
  Logr::log_t slog;
  // NOLINTEND(cppcoreguidelines-non-private-member-variables-in-classes)

private:
  std::unique_ptr<DNSPacket>& query;
};

TCPNameserver::XFRContext::XFRContext(std::unique_ptr<DNSPacket>& qry, int sock, Logr::log_t log, bool isAXFR) :
  targetZone(qry->qdomainzone), outsock(sock), slog(log), query(qry)
{
  setupOutputPacket();
  if (query->d_dnssecOk) {
    outpacket->d_dnssecOk = true; // RFC 5936, 2.2.5 'SHOULD'
  }

  xfrType = isAXFR ? "AXFR" : "IXFR";
  client = query->getRemoteStringWithPort();
  if (!g_slogStructured) {
    logPrefix = xfrType + "-out zone '" + targetZone.toLogString() + "', client '" + client + "', ";
  }
}

void TCPNameserver::XFRContext::setupOutputPacket()
{
  outpacket = std::unique_ptr<DNSPacket>(query->replyPacket());
  outpacket->setCompress(false);
  outpacket->d_dnssecOk=false; // RFC 5936, 2.2.5
  outpacket->d_tcp = true;
}

void TCPNameserver::XFRContext::sendIntermediatePacket()
{
  try {
    sendPacket(outpacket, outsock, false);
  }
  catch (PDNSException& pe) {
    throw PDNSException("during " + xfrType + "-out of " + targetZone.toLogString() + ", this happened: "+pe.reason);
  }
  trc.d_mac = outpacket->d_trc.d_mac;

  setupOutputPacket();
}

bool TCPNameserver::canDoAXFR(std::unique_ptr<DNSPacket>& q, XFRContext& ctx, std::unique_ptr<PacketHandler>& packetHandler) // NOLINT(readability-identifier-length)
{
  if(::arg().mustDo("disable-axfr")) {
    return false;
  }

  if(q->d_havetsig) { // if you have one, it must be good
    if (!packetHandler->checkForCorrectTSIG(*q, &ctx.tsigkeyname, &ctx.tsigsecret, &ctx.trc)) {
      return false;
    }
    ctx.haveTSIGDetails = true;
    getTSIGHashEnum(ctx.trc.d_algoName, q->d_tsig_algo);
#ifdef ENABLE_GSS_TSIG
    if (g_doGssTSIG && q->d_tsig_algo == TSIG_GSS) {
      GssContext gssctx(ctx.tsigkeyname);
      if (!gssctx.getPeerPrincipal(q->d_peer_principal)) {
        SLOG(g_log<<Logger::Warning<<"Failed to extract peer principal from GSS context with keyname '"<<ctx.tsigkeyname<<"'"<<endl,
             ctx.slog->info(Logr::Warning, "Failed to extract peer principal from GSS context", "keyname", Logging::Loggable(ctx.tsigkeyname)));
      }
    }
#endif

    DNSSECKeeper dk(ctx.slog, packetHandler->getBackend()); // NOLINT(readability-identifier-length)
#ifdef ENABLE_GSS_TSIG
    if (g_doGssTSIG && q->d_tsig_algo == TSIG_GSS) {
      vector<string> princs;
      packetHandler->getBackend()->getDomainMetadata(ctx.targetZone, "GSS-ALLOW-AXFR-PRINCIPAL", princs);
      for(const std::string& princ :  princs) {
        if (q->d_peer_principal == princ) {
          SLOG(g_log<<Logger::Warning<<ctx.xfrType<<" of domain '"<<ctx.targetZone<<"' allowed: TSIG signed request with authorized principal '"<<q->d_peer_principal<<"' and algorithm 'gss-tsig'"<<endl,
               ctx.slog->info(Logr::Warning, ctx.xfrType + " allowed: TSIG signed request with authorized principal", "zone", Logging::Loggable(ctx.targetZone), "principal", Logging::Loggable(q->d_peer_principal), "key", Logging::Loggable(ctx.tsigkeyname), "algorithm", Logging::Loggable("gss-tsig")));
          return true;
        }
      }
      SLOG(g_log<<Logger::Warning<<ctx.xfrType<<" of domain '"<<ctx.targetZone<<"' denied: TSIG signed request with principal '"<<q->d_peer_principal<<"' and algorithm 'gss-tsig' is not permitted"<<endl,
           ctx.slog->info(Logr::Warning, ctx.xfrType + " denied: TSIG signed request with unauthorized principal", "zone", Logging::Loggable(ctx.targetZone), "principal", Logging::Loggable(q->d_peer_principal), "key", Logging::Loggable(ctx.tsigkeyname), "algorithm", Logging::Loggable("gss-tsig")));
      return false;
    }
#endif
    if(!dk.TSIGGrantsAccess(ctx.targetZone, ctx.tsigkeyname)) {
      SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"denied: key with name '"<<ctx.tsigkeyname<<"' and algorithm '"<<getTSIGAlgoName(q->d_tsig_algo)<<"' does not grant access"<<endl,
           ctx.slog->info(Logr::Warning, ctx.xfrType + " denied: key and algorithm do not grant access", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "key", Logging::Loggable(ctx.tsigkeyname), "algorithm", Logging::Loggable(getTSIGAlgoName(q->d_tsig_algo))));
      return false;
    }
    SLOG(g_log<<Logger::Notice<<ctx.logPrefix<<"allowed: TSIG signed request with authorized key '"<<ctx.tsigkeyname<<"' and algorithm '"<<getTSIGAlgoName(q->d_tsig_algo)<<"'"<<endl,
         ctx.slog->info(Logr::Notice, ctx.xfrType + " allowed: TSIG signed request", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "key", Logging::Loggable(ctx.tsigkeyname), "algorithm", Logging::Loggable(getTSIGAlgoName(q->d_tsig_algo))));
    return true;
  }

  if(!(::arg()["allow-axfr-ips"].empty()) && d_ng.match( q->getInnerRemote() )) {
    SLOG(g_log<<Logger::Notice<<ctx.logPrefix<<"allowed: client IP is in allow-axfr-ips"<<endl,
         ctx.slog->info(Logr::Notice, ctx.xfrType + " allowed: client IP is in allow-axfr-ips", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
    return true;
  }

  FindNS fns;

  if(packetHandler->getBackend()->getSOAUncached(ctx.targetZone,ctx.soa)) {
    ctx.soaValid = true;
    vector<string> acl;
    packetHandler->getBackend()->getDomainMetadata(ctx.targetZone, "ALLOW-AXFR-FROM", acl);
    for (const auto & entry : acl) {
      if(pdns_iequals(entry, "AUTO-NS")) {
        DNSResourceRecord rr; // NOLINT(readability-identifier-length)
        set<DNSName> nsset;

        ctx.soa.db->lookup(QType(QType::NS), q->qdomain, ctx.soa.domain_id);
        while (ctx.soa.db->get(rr)) {
          nsset.insert(DNSName(rr.content));
        }
        for(const auto & nameserver: nsset) {
          vector<string> nsips=fns.lookup(nameserver, packetHandler->getBackend());
          for(const auto & nsip : nsips) {
            if(nsip == q->getInnerRemote().toString()) {
              SLOG(g_log<<Logger::Notice<<ctx.logPrefix<<"allowed: client IP is in NSset"<<endl,
                   ctx.slog->info(Logr::Notice, ctx.xfrType + " allowed: client IP is in NSset", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
              return true;
            }
          }
        }
      }
      else
      {
        auto nm = Netmask(entry); // NOLINT(readability-identifier-length)
        if(nm.match( q->getInnerRemote() )) {
          SLOG(g_log<<Logger::Notice<<ctx.logPrefix<<"allowed: client IP is in per-zone ACL"<<endl,
               ctx.slog->info(Logr::Notice, ctx.xfrType + " allowed: client IP is in per-zone ACL", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
          return true;
        }
      }
    }
  }

  if(Communicator.justNotified(ctx.targetZone, q->getInnerRemote().toString())) { // we just notified this ip
    SLOG(g_log<<Logger::Notice<<ctx.logPrefix<<"allowed: client IP is from recently notified secondary"<<endl,
         ctx.slog->info(Logr::Notice, ctx.xfrType + " allowed: client IP is from recently notified secondary", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
    return true;
  }

  SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"denied: client IP has no permission"<<endl,
       ctx.slog->info(Logr::Warning, ctx.xfrType + " denied: client IP has no permission", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
  return false;
}

// NOLINTNEXTLINE(readability-identifier-length)
int TCPNameserver::doAXFR(std::unique_ptr<DNSPacket>& q, int outsock, Logr::log_t slog)
{
  XFRContext ctx(q, outsock, slog, true);

  SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"transfer initiated"<<endl,
       ctx.slog->info(Logr::Warning, "AXFR transfer initiated", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));

  // determine if zone exists and AXFR is allowed using existing backend before spawning a new backend.
  DLOG(SLOG(g_log<<ctx.logPrefix<<"looking for SOA"<<endl,
            ctx.slog->info(Logr::Debug, "AXFR: looking for SOA", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client))));
  {
    auto packetHandler = s_P.lock();
    if(!*packetHandler) {
      SLOG(g_log<<Logger::Warning<<"TCP server is without backend connections in doAXFR, launching"<<endl,
           ctx.slog->info(Logr::Warning, "TCP server is without backend connections in doAXFR, launching", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
      *packetHandler = make_unique<PacketHandler>(ctx.slog);
    }

    // canDoAXFR does all the ACL checks, and has the if(disable-axfr) shortcut, call it first.
    if (!canDoAXFR(q, ctx, *packetHandler)) {
      SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"failed: client may not request AXFR"<<endl,
           ctx.slog->info(Logr::Warning, "AXFR failed: client may not request AXFR", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
      ctx.outpacket->setRcode(RCode::NotAuth);
      sendPacket(ctx.outpacket,ctx.outsock);
      return 0;
    }

    // ctx.soaValid has been computed by canDoAXFR above
    if (!ctx.soaValid && !(*packetHandler)->getBackend()->getSOAUncached(ctx.targetZone, ctx.soa)) {
      SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"failed: not authoritative"<<endl,
           ctx.slog->info(Logr::Warning, "AXFR failed: not authoritative", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
      ctx.outpacket->setRcode(RCode::NotAuth);
      sendPacket(ctx.outpacket,ctx.outsock);
      return 0;
    }
  }

  return doAXFRinternal(ctx);
}

bool TCPNameserver::axfrCheckTSIG(XFRContext& ctx, UeberBackend& db, bool alwaysCheck) // NOLINT(readability-identifier-length)
{
  // TSIG-related fields in ctx have been computed as part of the
  // checkForCorrectTSIG() call in canDoAXFR
  if(ctx.haveTSIGDetails && !ctx.tsigkeyname.empty()) {
    string tsig64;
    DNSName algorithm=ctx.trc.d_algoName;
    if (algorithm == g_hmacmd5dnsname_long) {
      algorithm = g_hmacmd5dnsname;
    }
    if (algorithm != g_gsstsigdnsname || alwaysCheck) {
      if(!db.getTSIGKey(ctx.tsigkeyname, algorithm, tsig64)) {
        SLOG(g_log << Logger::Error << "TSIG key '" << ctx.tsigkeyname << "' for domain '" << ctx.targetZone << "' not found" << endl,
             ctx.slog->info(Logr::Error, ctx.xfrType + " refused: TSIG key not found", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "key", Logging::Loggable(ctx.tsigkeyname), "algorithm", Logging::Loggable(algorithm)));
        ctx.outpacket->setRcode(RCode::NotAuth);
        sendPacket(ctx.outpacket,ctx.outsock);
        return false;
      }
      if (B64Decode(tsig64, ctx.tsigsecret) == -1) {
        SLOG(g_log<<Logger::Error<<ctx.logPrefix<<"unable to Base-64 decode TSIG key '"<<ctx.tsigkeyname<<"'"<<endl,
             ctx.slog->info(Logr::Error, "AXFR: Unable to Base-64 decode TSIG key", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "key", Logging::Loggable(ctx.tsigkeyname), "algorithm", Logging::Loggable(algorithm)));
        ctx.outpacket->setRcode(RCode::ServFail);
        sendPacket(ctx.outpacket,ctx.outsock);
        return false;
      }
    }
  }

  return true;
}

/** do the actual zone transfer. Return 0 in case of error, 1 in case of success */
int TCPNameserver::doAXFRinternal(XFRContext& ctx)
{
  const DNSName& target = ctx.targetZone.operator const DNSName&();

  // find domain_id via SOA and list complete domain. No SOA, no AXFR
  UeberBackend db; // NOLINT(readability-identifier-length)
  if(!db.getSOAUncached(ctx.targetZone, ctx.soa)) {
    SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"failed: not authoritative in second instance"<<endl,
         ctx.slog->info(Logr::Warning, "AXFR failed: not authoritative in second instance", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
    ctx.outpacket->setRcode(RCode::NotAuth);
    sendPacket(ctx.outpacket,ctx.outsock);
    return 0;
  }

  // Reset these - if we come from doIXFR, they may have been used already.
  ctx.presignedZone = false;
  ctx.securedZone = false;
  ctx.NSEC3Zone = false;
  bool narrow = false;

  ctx.isCatalogZone = ctx.soa.db->getDomainInfo(ctx.targetZone, ctx.info, false) && ctx.info.isCatalogType();

  DNSSECKeeper dk(ctx.slog, &db); // NOLINT(readability-identifier-length)
  DNSSECKeeper::clearCaches(ctx.targetZone);
  if (!ctx.isCatalogZone) {
    ctx.securedZone = dk.isSecuredZone(ctx.targetZone);
    ctx.presignedZone = dk.isPresigned(ctx.targetZone);
  }

  if(ctx.securedZone && dk.getNSEC3PARAM(ctx.targetZone, &ctx.ns3pr, &narrow)) {
    ctx.NSEC3Zone=true;
    if(narrow) {
      SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"failed: not doing AXFR of an NSEC3 narrow zone"<<endl,
           ctx.slog->info(Logr::Warning, "AXFR failed: not doing AXFR of an NSEC3 narrow zone", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
      ctx.outpacket->setRcode(RCode::Refused);
      sendPacket(ctx.outpacket,ctx.outsock);
      return 0;
    }
  }

  if (!axfrCheckTSIG(ctx, db, false)) {
    return 0;
  }

  // SOA *must* go out first, our signing pipe might reorder
  DLOG(SLOG(g_log<<ctx.logPrefix<<"sending out SOA"<<endl,
            ctx.slog->info(Logr::Debug, /*"I send an SOA to the world"*/"AXFR: sending out SOA", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client))));
  DNSZoneRecord soa = makeEditedDNSZRFromSOAData(dk, ctx.soa, DNSResourceRecord::ANSWER, ctx.slog);
  ctx.outpacket->addRecord(DNSZoneRecord(soa));
  if(ctx.securedZone && !ctx.presignedZone) {
    set<ZoneName> authSet;
    authSet.insert(ctx.targetZone);
    addRRSigs(dk, db, authSet, ctx.outpacket->getRRS());
  }

  if(ctx.haveTSIGDetails && !ctx.tsigkeyname.empty()) {
    ctx.outpacket->setTSIGDetails(ctx.trc, ctx.tsigkeyname, ctx.tsigsecret, ctx.trc.d_mac); // first answer is 'normal'
  }

  ctx.sendIntermediatePacket();

  DNSZoneRecord zrr;
  vector<DNSZoneRecord> zrrs;

  zrr.dr.d_name = target;
  zrr.dr.d_ttl = ctx.soa.minimum;

  axfrKeys(ctx, zrrs, dk);

  // now stuff in the NSEC3PARAM
  if(ctx.NSEC3Zone) {
    uint8_t flags = ctx.ns3pr.d_flags;
    zrr.dr.d_type = QType::NSEC3PARAM;
    ctx.ns3pr.d_flags = 0;
    zrr.dr.setContent(std::make_shared<NSEC3PARAMRecordContent>(ctx.ns3pr));
    ctx.ns3pr.d_flags = flags;
    DNSName keyname = DNSName(toBase32Hex(hashQNameWithSalt(ctx.ns3pr, zrr.dr.d_name)));
    zrrs.push_back(zrr);
  }

  // Catalog zones need a specific processing at this point.
  auto zoneKindSpecificOp = ctx.info.kind == DomainInfo::Producer ? axfrProducerZone : axfrRegularZone;
  if (!zoneKindSpecificOp(ctx, zrrs)) {
    return 0;
  }

  /* now write all other records */

  ChunkedSigningPipe csp(ctx.slog, ctx.targetZone, (ctx.securedZone && !ctx.presignedZone), ::arg().asNum("signing-threads", 1), ::arg().mustDo("workaround-11804") ? 1 : 100);

  DTime dt; // NOLINT(readability-identifier-length)
  dt.set();

  axfrSubmitRecords(ctx, zrrs, csp);
  for(;;) {
    ctx.outpacket->getRRS() = csp.getChunk(true); // flush the pipe
    if(!ctx.outpacket->getRRS().empty()) {
      if(ctx.haveTSIGDetails && !ctx.tsigkeyname.empty()) {
        ctx.outpacket->setTSIGDetails(ctx.trc, ctx.tsigkeyname, ctx.tsigsecret, ctx.trc.d_mac, true); // first answer is 'normal'
      }
      ctx.sendIntermediatePacket();
    }
    else {
      break;
    }
  }

  unsigned int udiff=dt.udiffNoReset();
  if(ctx.securedZone) {
    SLOG(g_log<<Logger::Debug<<ctx.logPrefix<<"done signing: "<<csp.d_signed/(udiff/1000000.0)<<" sigs/s, "<<endl,
         ctx.slog->info(Logr::Debug, "AXFR: done signing", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "duration (microseconds)", Logging::Loggable(udiff), "signatures per second", Logging::Loggable(csp.d_signed/(udiff/1000000.0))));
  }

  DLOG(SLOG(g_log<<ctx.logPrefix<<"done writing out records"<<endl,
            ctx.slog->info(Logr::Debug, "AXFR: done writing out records", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client))));
  /* and terminate with yet again the SOA record */
  ctx.setupOutputPacket();
  ctx.outpacket->addRecord(std::move(soa));
  if(ctx.haveTSIGDetails && !ctx.tsigkeyname.empty()) {
    ctx.outpacket->setTSIGDetails(ctx.trc, ctx.tsigkeyname, ctx.tsigsecret, ctx.trc.d_mac, true);
  }

  sendPacket(ctx.outpacket, ctx.outsock);

  DLOG(SLOG(g_log<<ctx.logPrefix<<"last packet - close"<<endl,
            ctx.slog->info(Logr::Debug, "AXFR: last packet sent", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client))));
  SLOG(g_log<<Logger::Notice<<ctx.logPrefix<<"AXFR finished"<<endl,
       ctx.slog->info(Logr::Notice, "AXFR completed", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));

  return 1;
}

void TCPNameserver::axfrKeys(XFRContext& ctx, vector<DNSZoneRecord> &zrrs, DNSSECKeeper& dk) // NOLINT(readability-identifier-length)
{
  const DNSName& target = ctx.targetZone.operator const DNSName&();

  DNSZoneRecord zrr;
  zrr.dr.d_name = target;
  zrr.dr.d_ttl = ctx.soa.minimum;

  if(ctx.securedZone && !ctx.presignedZone) { // this is where the DNSKEYs, CDNSKEYs and CDSs go in
    bool doCDNSKEY{true};
    bool doCDS{true};
    string publishCDNSKEY;
    string publishCDS;
    dk.getPublishCDNSKEY(ctx.targetZone, publishCDNSKEY);
    dk.getPublishCDS(ctx.targetZone, publishCDS);

    set<uint32_t> entryPointIds;
    DNSSECKeeper::keyset_t entryPoints = dk.getEntryPoints(ctx.targetZone);
    for (auto const& value : entryPoints) {
      entryPointIds.insert(value.second.id);
    }

    DNSSECKeeper::keyset_t keys = dk.getKeys(ctx.targetZone);
    for(const DNSSECKeeper::keyset_t::value_type& value :  keys) {
      if (!value.second.published) {
        continue;
      }
      zrr.dr.d_type = QType::DNSKEY;
      zrr.dr.setContent(std::make_shared<DNSKEYRecordContent>(value.first.getDNSKEY()));
      DNSName keyname = ctx.NSEC3Zone ? DNSName(toBase32Hex(hashQNameWithSalt(ctx.ns3pr, zrr.dr.d_name))) : zrr.dr.d_name;
      zrrs.push_back(zrr);

      // generate CDS and CDNSKEY records
      if(doCDNSKEY && entryPointIds.count(value.second.id) > 0){
        if(!publishCDNSKEY.empty()) {
          zrr.dr.d_type=QType::CDNSKEY;
          if (publishCDNSKEY == "0") {
            doCDNSKEY = false;
            zrr.dr.setContent(PacketHandler::s_deleteCDNSKEYContent);
            zrrs.push_back(zrr);
          } else {
            zrr.dr.setContent(std::make_shared<DNSKEYRecordContent>(value.first.getDNSKEY()));
            zrrs.push_back(zrr);
          }
        }

        if(doCDS && !publishCDS.empty()){
          zrr.dr.d_type=QType::CDS;
          vector<string> digestAlgos;
          stringtok(digestAlgos, publishCDS, ", ");
          if(std::find(digestAlgos.begin(), digestAlgos.end(), "0") != digestAlgos.end()) {
            doCDS = false;
            zrr.dr.setContent(PacketHandler::s_deleteCDSContent);
            zrrs.push_back(zrr);
          } else {
            for(auto const &digestAlgo : digestAlgos) {
              zrr.dr.setContent(std::make_shared<DSRecordContent>(makeDSFromDNSKey(ctx.slog, target, value.first.getDNSKEY(), pdns::checked_stoi<uint8_t>(digestAlgo))));
              zrrs.push_back(zrr);
            }
          }
        }
      }
    }

  }
}

bool TCPNameserver::axfrProducerZone(XFRContext& ctx, vector<DNSZoneRecord> &zrrs)
{
  const DNSName& target = ctx.targetZone.operator const DNSName&();

  DNSZoneRecord zrr;

  // Ignore all records except NS at apex
  ctx.soa.db->lookup(QType::NS, target, ctx.info.id);
  while (ctx.soa.db->get(zrr)) {
    zrrs.emplace_back(zrr);
  }
  if (zrrs.empty()) {
    zrr.dr.d_name = target;
    zrr.dr.d_ttl = 0;
    zrr.dr.d_type = QType::NS;
    zrr.dr.setContent(std::make_shared<NSRecordContent>("invalid."));
    zrrs.emplace_back(zrr);
  }

  zrrs.emplace_back(CatalogInfo::getCatalogVersionRecord(ctx.targetZone));

  vector<CatalogInfo> members;
  if (!ctx.soa.db->getCatalogMembers(ctx.targetZone, members, CatalogInfo::CatalogType::Producer)) {
    SLOG(g_log << Logger::Error << ctx.logPrefix << "getting catalog members failed, aborting AXFR" << endl,
         ctx.slog->info(Logr::Error, "AXFR aborted: getting catalog members failed", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
    ctx.outpacket->setRcode(RCode::ServFail);
    sendPacket(ctx.outpacket, ctx.outsock);
    return false;
  }
  for (const auto& catalog : members) {
    catalog.toDNSZoneRecords(ctx.targetZone, zrrs);
  }
  if (members.empty()) {
    SLOG(g_log << Logger::Warning << ctx.logPrefix << "catalog zone '" << ctx.targetZone << "' has no members" << endl,
         ctx.slog->info(Logr::Warning, "AXFR: Catalog zone has no members", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
  }

  return true;
}

bool TCPNameserver::axfrRegularZone(XFRContext& ctx, vector<DNSZoneRecord> &zrrs)
{
  const DNSName& target = ctx.targetZone.operator const DNSName&();

  // now start list zone
  if (!ctx.soa.db->list(ctx.targetZone, ctx.soa.domain_id, ctx.isCatalogZone)) {
    SLOG(g_log<<Logger::Error<<ctx.logPrefix<<"backend signals error condition, aborting AXFR"<<endl,
         ctx.slog->info(Logr::Error, "AXFR aborted: backend signals error condition", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
    ctx.outpacket->setRcode(RCode::ServFail);
    sendPacket(ctx.outpacket,ctx.outsock);
    return false;
  }

  const bool rectify = !(ctx.presignedZone || ::arg().mustDo("disable-axfr-rectify"));
  set<DNSName> qnames;
  set<DNSName> nsset;

  DNSZoneRecord zrr;

  while(ctx.soa.db->get(zrr)) {
    if (!ctx.presignedZone) {
      if (zrr.dr.d_type == QType::RRSIG) {
        continue;
      }
      if (zrr.dr.d_type == QType::DNSKEY || zrr.dr.d_type == QType::CDNSKEY || zrr.dr.d_type == QType::CDS) {
        if(!::arg().mustDo("direct-dnskey")) {
          continue;
        }
        zrr.dr.d_ttl = ctx.soa.minimum;
      }
    }
    zrr.dr.d_name.makeUsLowerCase();
    if(zrr.dr.d_name.isPartOf(target)) {
      if (zrr.dr.d_type == QType::ALIAS && (::arg().mustDo("outgoing-axfr-expand-alias") || ::arg()["outgoing-axfr-expand-alias"] == "ignore-errors")) {
        if (!axfrAlias(ctx, zrrs, zrr)) {
          return false;
        }
        continue;
      }

      if (rectify) {
        if (zrr.dr.d_type != QType::ENT) {
          qnames.insert(zrr.dr.d_name);
          if(zrr.dr.d_type == QType::NS && zrr.dr.d_name!=target) {
            nsset.insert(zrr.dr.d_name);
          }
        } else {
          // remove existing ents
          continue;
        }
      }
      zrrs.push_back(zrr);
    } else {
      if (zrr.dr.d_type != QType::ENT) {
        SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"zone contains out-of-zone data '"<<zrr.dr.d_name<<"|"<<DNSRecordContent::NumberToType(zrr.dr.d_type)<<"', ignoring"<<endl,
             ctx.slog->info(Logr::Warning, "AXFR: ignoring out-of-zone data", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "record", Logging::Loggable(zrr.dr.d_name), "type", Logging::Loggable(zrr.dr.d_type)));
      }
    }
  }

  // Process SVCB and HTTP hints
  axfrHints(ctx, zrrs);

  // Group records by name and type, signpipe stumbles over interrupted rrsets
  if(ctx.securedZone && !ctx.presignedZone) {
    sort(zrrs.begin(), zrrs.end(), [](const DNSZoneRecord& a, const DNSZoneRecord& b) { // NOLINT(readability-identifier-length)
      return std::tie(a.dr.d_name, a.dr.d_type) < std::tie(b.dr.d_name, b.dr.d_type);
    });
  }

  // Add ENT records if necessary
  if (rectify) {
    return axfrRectify(ctx, zrrs, qnames, nsset);
  }

  return true;
}

bool TCPNameserver::axfrAlias(XFRContext& ctx, vector<DNSZoneRecord>& zrrs, DNSZoneRecord& zrr)
{
  vector<DNSZoneRecord> ips;

  int ret1 = stubDoResolve(ctx.slog, getRR<ALIASRecordContent>(zrr.dr)->getContent(), QType::A, ips);
  int ret2 = stubDoResolve(ctx.slog, getRR<ALIASRecordContent>(zrr.dr)->getContent(), QType::AAAA, ips);
  if (ret1 != RCode::NoError || ret2 != RCode::NoError) {
    if (::arg()["outgoing-axfr-expand-alias"] == "ignore-errors") {
      if (ret1 != RCode::NoError) {
        SLOG(g_log << Logger::Error << ctx.logPrefix << zrr.dr.d_name.toLogString() << ": error resolving A record for ALIAS target " << zrr.dr.getContent()->getZoneRepresentation() << ", continuing AXFR" << endl,
             ctx.slog->info(Logr::Error, "AXFR: Error resolving A record for ALIAS target, continuing", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "record", Logging::Loggable(zrr.dr.d_name), "content", Logging::Loggable(zrr.dr.getContent()->getZoneRepresentation())));
      }
      if (ret2 != RCode::NoError) {
        SLOG(g_log << Logger::Error << ctx.logPrefix << zrr.dr.d_name.toLogString() << ": error resolving AAAA record for ALIAS target " << zrr.dr.getContent()->getZoneRepresentation() << ", continuing AXFR" << endl,
             ctx.slog->info(Logr::Error, "AXFR: Error resolving AAAA record for ALIAS target, continuing", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "record", Logging::Loggable(zrr.dr.d_name), "content", Logging::Loggable(zrr.dr.getContent()->getZoneRepresentation())));
      }
    }
    else {
      SLOG(g_log << Logger::Warning << ctx.logPrefix << zrr.dr.d_name.toLogString() << ": error resolving for ALIAS " << zrr.dr.getContent()->getZoneRepresentation() << ", aborting AXFR" << endl,
           ctx.slog->info(Logr::Error, "AXFR aborted: error resolving for ALIAS target", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "record", Logging::Loggable(zrr.dr.d_name), "content", Logging::Loggable(zrr.dr.getContent()->getZoneRepresentation())));
      ctx.outpacket->setRcode(RCode::ServFail);
      sendPacket(ctx.outpacket, ctx.outsock);
      return false;
    }
  }
  for (auto& dzr: ips) {
    zrr.dr.d_type = dzr.dr.d_type;
    zrr.dr.setContent(dzr.dr.getContent());
    zrrs.push_back(zrr);
  }
  return true;
}

void TCPNameserver::axfrHints(XFRContext& ctx, vector<DNSZoneRecord>& zrrs)
{
  for (auto& loopRR : zrrs) {
    if (loopRR.dr.d_type == QType::SVCB || loopRR.dr.d_type == QType::HTTPS) {
      // Process auto hints
      // TODO this is an almost copy of the code in the packethandler
      auto rrc = getRR<SVCBBaseRecordContent>(loopRR.dr);
      if (rrc == nullptr) {
        continue;
      }
      auto newRRC = rrc->clone();
      if (!newRRC) {
        continue;
      }
      DNSName svcTarget = newRRC->getTarget().isRoot() ? loopRR.dr.d_name : newRRC->getTarget();
      if (newRRC->autoHint(SvcParam::ipv4hint)) {
        ctx.soa.db->lookup(QType::A, svcTarget, ctx.soa.domain_id);
        vector<ComboAddress> hints;
        DNSZoneRecord rr; // NOLINT(readability-identifier-length)
        while (ctx.soa.db->get(rr)) {
          auto arrc = getRR<ARecordContent>(rr.dr);
          hints.push_back(arrc->getCA());
        }
        if (hints.empty()) {
          newRRC->removeParam(SvcParam::ipv4hint);
        } else {
          newRRC->setHints(SvcParam::ipv4hint, hints);
        }
      }

      if (newRRC->autoHint(SvcParam::ipv6hint)) {
        ctx.soa.db->lookup(QType::AAAA, svcTarget, ctx.soa.domain_id);
        vector<ComboAddress> hints;
        DNSZoneRecord rr; // NOLINT(readability-identifier-length)
        while (ctx.soa.db->get(rr)) {
          auto arrc = getRR<AAAARecordContent>(rr.dr);
          hints.push_back(arrc->getCA());
        }
        if (hints.empty()) {
          newRRC->removeParam(SvcParam::ipv6hint);
        } else {
          newRRC->setHints(SvcParam::ipv6hint, hints);
        }
      }

      loopRR.dr.setContent(std::move(newRRC));
    }
  }
}

bool TCPNameserver::axfrRectify(XFRContext& ctx, vector<DNSZoneRecord> &zrrs, const set<DNSName>& qnames, const set<DNSName>& nsset)
{
  const DNSName& target = ctx.targetZone.operator const DNSName&();

  DNSZoneRecord zrr;

  // set auth
  for(auto &loopZRR : zrrs) {
    loopZRR.auth=true;
    if (loopZRR.dr.d_type != QType::NS || loopZRR.dr.d_name!=target) {
      DNSName shorter(loopZRR.dr.d_name);
      do {
        if (shorter==target) { // apex is always auth
          break;
        }
        if(nsset.count(shorter) != 0 && !(loopZRR.dr.d_name==shorter && loopZRR.dr.d_type == QType::DS)) {
          loopZRR.auth=false;
          break;
        }
      } while(shorter.chopOff());
    }
  }

  if(ctx.NSEC3Zone) {
    // ents are only required for NSEC3 zones
    uint32_t maxent = ::arg().asNum("max-ent-entries");
    set<DNSName> nsec3set;
    set<DNSName> nonterm;
    for (auto &loopZRR: zrrs) {
      bool skip=false;
      DNSName shorter = loopZRR.dr.d_name;
      if (shorter != target && shorter.chopOff() && shorter != target) {
        do {
          if(nsset.count(shorter) != 0) {
            skip=true;
            break;
          }
        } while(shorter.chopOff() && shorter != target);
      }
      shorter = loopZRR.dr.d_name;
      if(!skip && (loopZRR.dr.d_type != QType::NS || ctx.ns3pr.d_flags == 0)) {
        do {
          if(nsec3set.count(shorter) == 0) {
            nsec3set.insert(shorter);
          }
        } while(shorter != target && shorter.chopOff());
      }
    }

    for(auto &loopZRR : zrrs) {
      DNSName shorter(loopZRR.dr.d_name);
      while(shorter != target && shorter.chopOff()) {
        if(qnames.count(shorter) == 0 && nonterm.count(shorter) == 0 && nsec3set.count(shorter) != 0) {
          if(maxent == 0) {
            SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"zone has too many empty non terminals, aborting AXFR"<<endl,
                 ctx.slog->info(Logr::Warning, "AXFR aborted, too many empty non-terminals in zone", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
            ctx.outpacket->setRcode(RCode::ServFail);
            sendPacket(ctx.outpacket,ctx.outsock);
            return false;
          }
          nonterm.insert(shorter);
          --maxent;
        }
      }
    }

    for(const auto& nt : nonterm) { // NOLINT(readability-identifier-length)
      DNSZoneRecord tempRR;
      tempRR.dr.d_name=nt;
      tempRR.dr.d_type=QType::ENT;
      tempRR.auth=true;
      zrrs.push_back(tempRR);
    }
  }

  return true;
}

void TCPNameserver::axfrSubmitRecords(XFRContext& ctx, vector<DNSZoneRecord> &zrrs, ChunkedSigningPipe& csp) // NOLINT(readability-function-cognitive-complexity)
{
  DNSZoneRecord zrr;

  using nsecxrepo_t = map<DNSName, NSECXEntry, CanonDNSNameCompare>;
  nsecxrepo_t nsecxrepo;

  for(DNSZoneRecord &loopZRR :  zrrs) {
    if(ctx.securedZone && (loopZRR.auth || loopZRR.dr.d_type == QType::NS)) {
      if (ctx.NSEC3Zone || loopZRR.dr.d_type != QType::ENT) {
        DNSName keyname;
        if (ctx.presignedZone && ctx.NSEC3Zone && loopZRR.dr.d_type == QType::RRSIG && getRR<RRSIGRecordContent>(loopZRR.dr)->d_type == QType::NSEC3) {
          keyname = loopZRR.dr.d_name.makeRelative(ctx.soa.qname());
        } else {
          keyname = ctx.NSEC3Zone ? DNSName(toBase32Hex(hashQNameWithSalt(ctx.ns3pr, loopZRR.dr.d_name))) : loopZRR.dr.d_name;
        }
        NSECXEntry& ne = nsecxrepo[keyname]; // NOLINT(readability-identifier-length)
        ne.d_ttl = ctx.soa.getNegativeTTL();
        ne.d_auth = (ne.d_auth || loopZRR.auth || (ctx.NSEC3Zone && (ctx.ns3pr.d_flags == 0)));
        if (loopZRR.dr.d_type != QType::ENT && loopZRR.dr.d_type != QType::RRSIG) {
          ne.d_set.set(loopZRR.dr.d_type);
        }
      }
    }

    if (loopZRR.dr.d_type == QType::ENT) {
      continue; // skip empty non-terminals
    }

    if(loopZRR.dr.d_type == QType::SOA) {
      continue; // skip SOA - would indicate end of AXFR
    }

    if(csp.submit(loopZRR)) {
      for(;;) {
        ctx.outpacket->getRRS() = csp.getChunk();
        if(!ctx.outpacket->getRRS().empty()) {
          if(ctx.haveTSIGDetails && !ctx.tsigkeyname.empty()) {
            ctx.outpacket->setTSIGDetails(ctx.trc, ctx.tsigkeyname, ctx.tsigsecret, ctx.trc.d_mac, true);
          }
          ctx.sendIntermediatePacket();
        }
        else {
          break;
        }
      }
    }
  }
  if(ctx.securedZone) {
    if(ctx.NSEC3Zone) {
      for(auto iter = nsecxrepo.cbegin(); iter != nsecxrepo.cend(); ++iter) {
        if(iter->second.d_auth) {
          NSEC3RecordContent n3rc;
          n3rc.set(iter->second.d_set);
          const auto numberOfTypesSet = n3rc.numberOfTypesSet();
          if (numberOfTypesSet != 0 && (numberOfTypesSet != 1 || !n3rc.isSet(QType::NS))) {
            n3rc.set(QType::RRSIG);
          }
          n3rc.d_salt = ctx.ns3pr.d_salt;
          n3rc.d_flags = ctx.ns3pr.d_flags;
          n3rc.d_iterations = ctx.ns3pr.d_iterations;
          n3rc.d_algorithm = DNSSECKeeper::DIGEST_SHA1; // SHA1, fixed in PowerDNS for now
          auto inext = iter;
          ++inext;
          if(inext == nsecxrepo.cend()) {
            inext = nsecxrepo.cbegin();
          }
          while(!inext->second.d_auth && inext != iter)
          {
            ++inext;
            if(inext == nsecxrepo.cend()) {
              inext = nsecxrepo.cbegin();
            }
          }
          n3rc.d_nexthash = fromBase32Hex(inext->first.toStringNoDot());

          zrr.dr.d_name = iter->first+ctx.soa.qname();
          zrr.dr.d_ttl = ctx.soa.getNegativeTTL();
          zrr.dr.setContent(std::make_shared<NSEC3RecordContent>(std::move(n3rc)));
          zrr.dr.d_type = QType::NSEC3;
          zrr.dr.d_place = DNSResourceRecord::ANSWER;
          zrr.auth=true;
          if(csp.submit(zrr)) {
            for(;;) {
              ctx.outpacket->getRRS() = csp.getChunk();
              if(!ctx.outpacket->getRRS().empty()) {
                if(ctx.haveTSIGDetails && !ctx.tsigkeyname.empty()) {
                  ctx.outpacket->setTSIGDetails(ctx.trc, ctx.tsigkeyname, ctx.tsigsecret, ctx.trc.d_mac, true);
                }
                ctx.sendIntermediatePacket();
              }
              else {
                break;
              }
            }
          }
        }
      }
    }
    else {
      for(auto iter = nsecxrepo.cbegin(); iter != nsecxrepo.cend(); ++iter) {
        NSECRecordContent nrc;
        nrc.set(iter->second.d_set);
        nrc.set(QType::RRSIG);
        nrc.set(QType::NSEC);

        if(boost::next(iter) != nsecxrepo.cend()) {
          nrc.d_next = boost::next(iter)->first;
        }
        else {
          nrc.d_next=nsecxrepo.cbegin()->first;
        }
        zrr.dr.d_name = iter->first;

        zrr.dr.d_ttl = ctx.soa.getNegativeTTL();
        zrr.dr.setContent(std::make_shared<NSECRecordContent>(std::move(nrc)));
        zrr.dr.d_type = QType::NSEC;
        zrr.dr.d_place = DNSResourceRecord::ANSWER;
        zrr.auth=true;
        if(csp.submit(zrr)) {
          for(;;) {
            ctx.outpacket->getRRS() = csp.getChunk();
            if(!ctx.outpacket->getRRS().empty()) {
              if(ctx.haveTSIGDetails && !ctx.tsigkeyname.empty()) {
                ctx.outpacket->setTSIGDetails(ctx.trc, ctx.tsigkeyname, ctx.tsigsecret, ctx.trc.d_mac, true);
              }
              ctx.sendIntermediatePacket();
            }
            else {
              break;
            }
          }
        }
      }
    }
  }
}
int TCPNameserver::doIXFR(std::unique_ptr<DNSPacket>& q, int outsock, Logr::log_t slog) // NOLINT(readability-identifier-length)
{
  XFRContext ctx(q, outsock, slog, false);

  uint32_t serial = 0;
  MOADNSParser mdp(false, q->getString());
  for(const auto & answer : mdp.d_answers) {
    const DNSRecord *dnsRecord = &answer;
    if (dnsRecord->d_type == QType::SOA && dnsRecord->d_place == DNSResourceRecord::AUTHORITY) {
      vector<string>parts;
      stringtok(parts, dnsRecord->getContent()->getZoneRepresentation());
      if (parts.size() >= 3) {
        try {
          pdns::checked_stoi_into(serial, parts[2]);
        }
        catch(const std::logic_error& exc) {
          SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"invalid serial in IXFR query"<<endl,
               ctx.slog->error(Logr::Warning, exc.what(), "IXFR: invalid serial in query", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
          ctx.outpacket->setRcode(RCode::FormErr);
          sendPacket(ctx.outpacket,ctx.outsock);
          return 0;
        }
      } else {
        SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"no serial in IXFR query"<<endl,
             ctx.slog->info(Logr::Warning, "IXFR: no serial in query", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
        ctx.outpacket->setRcode(RCode::FormErr);
        sendPacket(ctx.outpacket,ctx.outsock);
        return 0;
      }
    } else if (dnsRecord->d_type != QType::TSIG && dnsRecord->d_type != QType::OPT) {
      SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"additional records in IXFR query, type: "<<QType(dnsRecord->d_type).toString()<<endl,
             ctx.slog->info(Logr::Warning, "IXFR: additional record in query", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "type", Logging::Loggable(dnsRecord->d_type)));
      ctx.outpacket->setRcode(RCode::FormErr);
      sendPacket(ctx.outpacket,ctx.outsock);
      return 0;
    }
  }

  SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"transfer initiated with serial "<<serial<<endl,
       ctx.slog->info(Logr::Warning, "IXFR: transfer initiated", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client), "serial", Logging::Loggable(serial)));

  // determine if zone exists, XFR is allowed, and if IXFR can proceed using existing backend before spawning a new backend.
  DLOG(SLOG(g_log<<ctx.logPrefix<<"Looking for SOA"<<endl,
            ctx.slog->info(Logr::Warning, "IXFR: looking for SOA", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client))));
  bool serialPermitsIXFR{false};
  {
    auto packetHandler = s_P.lock();
    if(!*packetHandler) {
      SLOG(g_log<<Logger::Warning<<"TCP server is without backend connections in doIXFR, launching"<<endl,
           ctx.slog->info(Logr::Warning, "IXFR: TCP server is without backend connections in doIXFR, launching", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
      *packetHandler = make_unique<PacketHandler>(ctx.slog);
    }

    // canDoAXFR does all the ACL checks, and has the if(disable-axfr) shortcut, call it first.
    if(!canDoAXFR(q, ctx, *packetHandler)) {
      SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"failed: client may not request IXFR"<<endl,
           ctx.slog->info(Logr::Warning, "IXFR failed: client may not request IXFR", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
      ctx.outpacket->setRcode(RCode::NotAuth);
      sendPacket(ctx.outpacket,ctx.outsock);
      return 0;
    }

    // ctx.soaValid has been computed by canDoAXFR above
    if(!ctx.soaValid && !(*packetHandler)->getBackend()->getSOAUncached(ctx.targetZone, ctx.soa)) {
      SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"failed: not authoritative"<<endl,
           ctx.slog->info(Logr::Warning, "IXFR failed: not authoritative", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
      ctx.outpacket->setRcode(RCode::NotAuth);
      sendPacket(ctx.outpacket,ctx.outsock);
      return 0;
    }

    DNSSECKeeper dk(ctx.slog, (*packetHandler)->getBackend()); // NOLINT(readability-identifier-length)
    DNSSECKeeper::clearCaches(ctx.targetZone);
    bool narrow = false;
    ctx.securedZone = dk.isSecuredZone(ctx.targetZone);
    if(dk.getNSEC3PARAM(ctx.targetZone, nullptr, &narrow)) {
      if(narrow) {
        SLOG(g_log<<Logger::Warning<<ctx.logPrefix<<"not doing IXFR of an NSEC3 narrow zone"<<endl,
           ctx.slog->info(Logr::Warning, "IXFR refused: not doing IXFR of an NSEC3 narrow zone", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
        ctx.outpacket->setRcode(RCode::Refused);
        sendPacket(ctx.outpacket,ctx.outsock);
        return 0;
      }
    }

    serialPermitsIXFR = !rfc1982LessThan(serial, calculateEditSOA(ctx.soa.serial, dk, ctx.soa.zonename, ctx.slog));
  }

  if (serialPermitsIXFR) {
    UeberBackend db; // NOLINT(readability-identifier-length)
    DNSSECKeeper dk(ctx.slog, &db); // NOLINT(readability-identifier-length)

    if (!axfrCheckTSIG(ctx, db, true)) {
      return 0;
    }

    // SOA *must* go out first, our signing pipe might reorder
    DLOG(SLOG(g_log<<ctx.logPrefix<<"sending out SOA"<<endl,
              ctx.slog->info(Logr::Debug, /*"I send an SOA to the world"*/"IXFR: sending out SOA", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client))));
    DNSZoneRecord soa = makeEditedDNSZRFromSOAData(dk, ctx.soa, DNSResourceRecord::ANSWER, ctx.slog);
    ctx.outpacket->addRecord(std::move(soa));
    if(ctx.securedZone && ctx.outpacket->d_dnssecOk) {
      set<ZoneName> authSet;
      authSet.insert(ctx.targetZone);
      addRRSigs(dk, db, authSet, ctx.outpacket->getRRS());
    }

    if(ctx.haveTSIGDetails && !ctx.tsigkeyname.empty()) {
      ctx.outpacket->setTSIGDetails(ctx.trc, ctx.tsigkeyname, ctx.tsigsecret, ctx.trc.d_mac); // first answer is 'normal'
    }

    sendPacket(ctx.outpacket, ctx.outsock);

    SLOG(g_log<<Logger::Notice<<ctx.logPrefix<<"IXFR finished"<<endl,
         ctx.slog->info(Logr::Notice, "IXFR finished", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));

    return 1;
  }

  SLOG(g_log<<Logger::Notice<<ctx.logPrefix<<"IXFR fallback to AXFR"<<endl,
       ctx.slog->info(Logr::Notice, "IXFR fallback to AXFR", "zone", Logging::Loggable(ctx.targetZone), "client", Logging::Loggable(ctx.client)));
  // Update log prefix as well
  if (!g_slogStructured) {
    ctx.logPrefix.at(0) = 'A';
  }
  return doAXFRinternal(ctx);
}

TCPNameserver::~TCPNameserver() = default;
TCPNameserver::TCPNameserver(Logr::log_t slog)
{
  d_slog = slog;
  d_maxTransactionsPerConn = ::arg().asNum("max-tcp-transactions-per-conn");
  d_idleTimeout = ::arg().asNum("tcp-idle-timeout");
  d_maxConnectionDuration = ::arg().asNum("max-tcp-connection-duration");
  d_maxConnectionsPerClient = ::arg().asNum("max-tcp-connections-per-client");

//  sem_init(&d_connectionroom_sem,0,::arg().asNum("max-tcp-connections"));
  d_connectionroom_sem = make_unique<Semaphore>( ::arg().asNum( "max-tcp-connections" ));
  d_maxTCPConnections = ::arg().asNum( "max-tcp-connections" );

  vector<string>locals;
  stringtok(locals,::arg()["local-address"]," ,");
  if(locals.empty())
    throw PDNSException("No local addresses specified");

  d_ng.toMasks(::arg()["allow-axfr-ips"] );

  signal(SIGPIPE,SIG_IGN);

  for(auto const &laddr : locals) {
    ComboAddress local(laddr, ::arg().asNum("local-port"));

    int s=socket(local.sin4.sin_family, SOCK_STREAM, 0);
    if(s<0)
      throw PDNSException("Unable to acquire TCP socket: "+stringerror());
    setCloseOnExec(s);

    int tmp=1;
    if(setsockopt(s, SOL_SOCKET,SO_REUSEADDR, (char*)&tmp, sizeof tmp) < 0) {
      SLOG(g_log<<Logger::Error<<"Setsockopt failed"<<endl,
           d_slog->error(Logr::Error, errno, "setsockopt failed"));
      _exit(1);
    }

    if (::arg().asNum("tcp-fast-open") > 0) {
#ifdef TCP_FASTOPEN
      int fastOpenQueueSize = ::arg().asNum("tcp-fast-open");
      if (setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN, &fastOpenQueueSize, sizeof fastOpenQueueSize) < 0) {
        SLOG(g_log<<Logger::Error<<"Failed to enable TCP Fast Open for listening socket "<<local.toStringWithPort()<<": "<<stringerror()<<endl,
             d_slog->error(Logr::Error, errno, "Failed to enable TCP Fast Open for listening socket", "socket", Logging::Loggable(local.toStringWithPort())));
      }
#else
      SLOG(g_log<<Logger::Warning<<"TCP Fast Open configured but not supported for listening socket"<<endl,
           d_slog->info(Logr::Warning, "TCP Fast Open configured but not supported for listening socket"));
#endif
    }

    if(::arg().mustDo("non-local-bind"))
      Utility::setBindAny(local.sin4.sin_family, s);

    if(local.isIPv6() && setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &tmp, sizeof(tmp)) < 0) {
      SLOG(g_log<<Logger::Error<<"Failed to set IPv6 socket to IPv6 only, continuing anyhow: "<<stringerror()<<endl,
           d_slog->error(Logr::Error, errno, "Failed to set IPv6 socket to IPv6 only, continuing anyhow"));
    }

    if(::bind(s, (sockaddr*)&local, local.getSocklen())<0) {
      int err = errno;
      close(s);
      if( err == EADDRNOTAVAIL && ! ::arg().mustDo("local-address-nonexist-fail") ) {
        SLOG(g_log<<Logger::Error<<"Address " << local.toString() << " does not exist on this server - skipping TCP bind" << endl,
             d_slog->info(Logr::Error, "Address does not exist on this server - skipping TCP bind", "socket", Logging::Loggable(local)));
        continue;
      } else {
        SLOG(g_log<<Logger::Error<<"Unable to bind to TCP socket " << local.toStringWithPort() << ": "<<stringerror(err)<<endl,
             d_slog->error(Logr::Error, errno, "Unable to bind to TCP socket", "socket", Logging::Loggable(local)));
        throw PDNSException("Unable to bind to TCP socket");
      }
    }

    listen(s, 128);
    SLOG(g_log<<Logger::Error<<"TCP server bound to "<<local.toStringWithPort()<<endl,
         d_slog->info(Logr::Error, "TCP server bound", "socket", Logging::Loggable(local)));
    d_sockets.push_back(s);
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = s;
    pfd.events = POLLIN;
    d_prfds.push_back(pfd);
  }
}


//! Start of TCP operations thread, we launch a new thread for each incoming TCP question
void TCPNameserver::thread()
{
  setThreadName("pdns/tcpnameser");
  try {
    for(;;) {
      int fd;
      ComboAddress remote;
      Utility::socklen_t addrlen=remote.getSocklen();

      int ret=poll(&d_prfds[0], d_prfds.size(), -1); // blocks, forever if need be
      if(ret <= 0)
        continue;

      int sock=-1;
      for(const pollfd& pfd :  d_prfds) {
        if(pfd.revents & POLLIN) {
          sock = pfd.fd;
          remote.sin4.sin_family = AF_INET6;
          addrlen=remote.getSocklen();

          if((fd=accept(sock, (sockaddr*)&remote, &addrlen))<0) {
            int err = errno;
            SLOG(g_log<<Logger::Error<<"TCP question accept error: "<<stringerror(err)<<endl,
                 d_slog->error(Logr::Error, errno, "TCP question accept() error"));

            if(err==EMFILE) {
              SLOG(g_log<<Logger::Error<<"TCP handler out of filedescriptors, exiting, won't recover from this"<<endl,
                   d_slog->info(Logr::Error, "TCP handler out of filedescriptors, exiting, won't recover from this"));
              _exit(1);
            }
          }
          else {
            if (d_maxConnectionsPerClient) {
              auto clientsCount = s_clientsCount.lock();
              if ((*clientsCount)[remote] >= d_maxConnectionsPerClient) {
                SLOG(g_log<<Logger::Notice<<"Limit of simultaneous TCP connections per client reached for "<< remote<<", dropping"<<endl,
                     d_slog->info(Logr::Notice, "Limit of simultaneous TCP connections per client reached, dropping", "client", Logging::Loggable(remote)));
                close(fd);
                continue;
              }
              (*clientsCount)[remote]++;
            }

            d_connectionroom_sem->wait(); // blocks if no connections are available

            int room;
            d_connectionroom_sem->getValue( &room);
            if(room<1)
              SLOG(g_log<<Logger::Warning<<"Limit of simultaneous TCP connections reached - raise max-tcp-connections"<<endl,
                   d_slog->info(Logr::Warning, "Limit of simultaneous TCP connections reached - raise max-tcp-connections"));

            try {
              std::thread connThread(doConnection, fd, d_slog);
              connThread.detach();
            }
            catch (std::exception& e) {
              SLOG(g_log<<Logger::Error<<"Error creating thread: "<<e.what()<<endl,
                   d_slog->error(Logr::Error, e.what(), "Error creating thread"));
              d_connectionroom_sem->post();
              close(fd);
              decrementClientCount(remote);
            }
          }
        }
      }
    }
  }
  catch(PDNSException &AE) {
    SLOG(g_log<<Logger::Error<<"TCP Nameserver thread dying because of fatal error: "<<AE.reason<<endl,
         d_slog->error(Logr::Error, AE.reason, "TCP Nameserver thread dying because of fatal error"));
  }
  catch(...) {
    SLOG(g_log<<Logger::Error<<"TCPNameserver dying because of an unexpected fatal error"<<endl,
         d_slog->info(Logr::Error, "TCP Nameserver thread dying because of an unexpected fatal error"));
  }
  _exit(1); // take rest of server with us
}


unsigned int TCPNameserver::numTCPConnections()
{
  int room;
  d_connectionroom_sem->getValue( &room);
  return d_maxTCPConnections - room;
}
