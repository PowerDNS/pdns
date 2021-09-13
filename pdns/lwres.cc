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
#include "lwres.hh"
#include <iostream>
#include "dnsrecords.hh"
#include <errno.h>
#include "misc.hh"
#include <algorithm>
#include <sstream>
#include <cstring>
#include <string>
#include <vector>
#include "dns.hh"
#include "qtype.hh"
#include "pdnsexception.hh"
#include "arguments.hh"
#include "sstuff.hh"
#include "syncres.hh"
#include "dnswriter.hh"
#include "dnsparser.hh"
#include "logger.hh"
#include "dns_random.hh"
#include <boost/scoped_array.hpp>
#include <boost/algorithm/string.hpp>
#include "validate-recursor.hh"
#include "ednssubnet.hh"
#include "query-local-address.hh"
#include "tcpiohandler.hh"

#include "rec-protozero.hh"
#include "uuid-utils.hh"

#ifdef HAVE_FSTRM
#include "dnstap.hh"
#include "fstrm_logger.hh"

#include "rec-tcpout.hh"

thread_local TCPOutConnectionManager t_tcp_manager;

bool g_syslog;

static bool isEnabledForQueries(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers)
{
  if (fstreamLoggers == nullptr) {
    return false;
  }
  for (auto& logger : *fstreamLoggers) {
    if (logger->logQueries()) {
      return true;
    }
  }
  return false;
}

static void logFstreamQuery(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers, const struct timeval &queryTime, const ComboAddress& localip, const ComboAddress& ip, DnstapMessage::ProtocolType protocol, boost::optional<const DNSName&> auth, const vector<uint8_t>& packet)
{
  if (fstreamLoggers == nullptr)
    return;

  struct timespec ts;
  TIMEVAL_TO_TIMESPEC(&queryTime, &ts);
  std::string str;
  DnstapMessage message(str, DnstapMessage::MessageType::resolver_query, SyncRes::s_serverID, &localip, &ip, protocol, reinterpret_cast<const char*>(&*packet.begin()), packet.size(), &ts, nullptr, auth);

  for (auto& logger : *fstreamLoggers) {
    logger->queueData(str);
  }
}

static bool isEnabledForResponses(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers)
{
  if (fstreamLoggers == nullptr) {
    return false;
  }
  for (auto& logger : *fstreamLoggers) {
    if (logger->logResponses()) {
      return true;
    }
  }
  return false;
}

static void logFstreamResponse(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers, const ComboAddress&localip, const ComboAddress& ip, DnstapMessage::ProtocolType protocol, boost::optional<const DNSName&> auth, const PacketBuffer& packet, const struct timeval& queryTime, const struct timeval& replyTime)
{
  if (fstreamLoggers == nullptr)
    return;

  struct timespec ts1, ts2;
  TIMEVAL_TO_TIMESPEC(&queryTime, &ts1);
  TIMEVAL_TO_TIMESPEC(&replyTime, &ts2);
  std::string str;
  DnstapMessage message(str, DnstapMessage::MessageType::resolver_response, SyncRes::s_serverID, &localip, &ip, protocol, reinterpret_cast<const char*>(packet.data()), packet.size(), &ts1, &ts2, auth);

  for (auto& logger : *fstreamLoggers) {
    logger->queueData(str);
  }
}

#endif // HAVE_FSTRM

static void logOutgoingQuery(const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, boost::optional<const boost::uuids::uuid&> initialRequestId, const boost::uuids::uuid& uuid, const ComboAddress& ip, const DNSName& domain, int type, uint16_t qid, bool doTCP, size_t bytes, boost::optional<Netmask>& srcmask)
{
  if (!outgoingLoggers) {
    return;
  }

  bool log = false;
  for (auto& logger : *outgoingLoggers) {
    if (logger->logQueries()) {
      log = true;
      break;
    }
  }

  if (!log) {
    return;
  }

  static thread_local std::string buffer;
  buffer.clear();
  pdns::ProtoZero::Message m{buffer};
  m.setType(pdns::ProtoZero::Message::MessageType::DNSOutgoingQueryType);
  m.setMessageIdentity(uuid);
  m.setSocketFamily(ip.sin4.sin_family);
  m.setSocketProtocol(doTCP);
  m.setTo(ip);
  m.setInBytes(bytes);
  m.setTime();
  m.setId(qid);
  m.setQuestion(domain, type, QClass::IN);
  m.setToPort(ip.getPort());
  m.setServerIdentity(SyncRes::s_serverID);

  if (initialRequestId) {
    m.setInitialRequestID(*initialRequestId);
  }

  if (srcmask) {
    m.setEDNSSubnet(*srcmask, 128);
  }

  for (auto& logger : *outgoingLoggers) {
    if (logger->logQueries()) {
      logger->queueData(buffer);
    }
  }
}

static void logIncomingResponse(const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, boost::optional<const boost::uuids::uuid&> initialRequestId, const boost::uuids::uuid& uuid, const ComboAddress& ip, const DNSName& domain, int type, uint16_t qid, bool doTCP, boost::optional<Netmask>& srcmask, size_t bytes, int rcode, const std::vector<DNSRecord>& records, const struct timeval& queryTime, const std::set<uint16_t>& exportTypes)
{
  if (!outgoingLoggers) {
    return;
  }

  bool log = false;
  for (auto& logger : *outgoingLoggers) {
    if (logger->logResponses()) {
      log = true;
      break;
    }
  }

  if (!log) {
    return;
  }

  static thread_local std::string buffer;
  buffer.clear();
  pdns::ProtoZero::RecMessage m{buffer};
  m.setType(pdns::ProtoZero::Message::MessageType::DNSIncomingResponseType);
  m.setMessageIdentity(uuid);
  m.setSocketFamily(ip.sin4.sin_family);
  m.setSocketProtocol(doTCP);
  m.setTo(ip);
  m.setInBytes(bytes);
  m.setTime();
  m.setId(qid);
  m.setQuestion(domain, type, QClass::IN);
  m.setToPort(ip.getPort());
  m.setServerIdentity(SyncRes::s_serverID);

  if (initialRequestId) {
    m.setInitialRequestID(*initialRequestId);
  }

  if (srcmask) {
    m.setEDNSSubnet(*srcmask, 128);
  }

  m.startResponse();
  m.setQueryTime(queryTime.tv_sec, queryTime.tv_usec);
  if (rcode == -1) {
    m.setNetworkErrorResponseCode();
  }
  else {
    m.setResponseCode(rcode);
  }

  for (const auto& record : records) {
    m.addRR(record, exportTypes, false);
  }
  m.commitResponse();

  for (auto& logger : *outgoingLoggers) {
    if (logger->logResponses()) {
      logger->queueData(buffer);
    }
  }
}

static bool tcpconnect(const struct timeval& now, const ComboAddress& ip, TCPOutConnectionManager::Connection& connection, bool& dnsOverTLS)
{
  dnsOverTLS = SyncRes::s_dot_to_port_853 && ip.getPort() == 853;


  while (true) {
    connection = t_tcp_manager.get(ip);
    if (connection.d_handler) {
      return false;
    }

    const struct timeval timeout{ g_networkTimeoutMsec / 1000, static_cast<suseconds_t>(g_networkTimeoutMsec) % 1000 * 1000};
    Socket s(ip.sin4.sin_family, SOCK_STREAM);
    s.setNonBlocking();
    ComboAddress localip = pdns::getQueryLocalAddress(ip.sin4.sin_family, 0);
    s.bind(localip);

    std::shared_ptr<TLSCtx> tlsCtx{nullptr};
    if (dnsOverTLS) {
      TLSContextParameters tlsParams;
      tlsParams.d_provider = "openssl";
      tlsParams.d_validateCertificates = false;
      //tlsParams.d_caStore = caaStore;
      tlsCtx = getTLSContext(tlsParams);
      if (tlsCtx == nullptr) {
        g_log << Logger::Error << "DoT to " << ip << " requested but not available" << endl;
        dnsOverTLS = false;
      }
    }
    connection.d_handler = std::make_shared<TCPIOHandler>("", s.releaseHandle(), timeout, tlsCtx, now.tv_sec);
    // Returned state ignored
    // This can throw an excepion, retry will need to happen at higher level
    connection.d_handler->tryConnect(SyncRes::s_tcp_fast_open_connect, ip);
    return true;
  }
}

static LWResult::Result tcpsendrecv(const ComboAddress& ip, TCPOutConnectionManager::Connection& connection,
                                    ComboAddress& localip, const vector<uint8_t>& vpacket, size_t& len, PacketBuffer& buf)
{
  socklen_t slen = ip.getSocklen();
  uint16_t tlen = htons(vpacket.size());
  const char *lenP = reinterpret_cast<const char*>(&tlen);
  const char *msgP = reinterpret_cast<const char*>(&*vpacket.begin());

  localip.sin4.sin_family = ip.sin4.sin_family;
  getsockname(connection.d_handler->getDescriptor(), reinterpret_cast<sockaddr*>(&localip), &slen);

  PacketBuffer packet;
  packet.reserve(2 + vpacket.size());
  packet.insert(packet.end(), lenP, lenP + 2);
  packet.insert(packet.end(), msgP, msgP + vpacket.size());

  LWResult::Result ret = asendtcp(packet, connection.d_handler);
  if (ret != LWResult::Result::Success) {
    return ret;
  }

  ret = arecvtcp(packet, 2, connection.d_handler, false);
  if (ret != LWResult::Result::Success) {
    return ret;
  }

  memcpy(&tlen, packet.data(), sizeof(tlen));
  len = ntohs(tlen); // switch to the 'len' shared with the rest of the calling function

  // XXX receive into buf directly?
  packet.resize(len);
  ret = arecvtcp(packet, len, connection.d_handler, false);
  if (ret != LWResult::Result::Success) {
    return ret;
  }
  buf.resize(len);
  memcpy(buf.data(), packet.data(), len);
  return LWResult::Result::Success;
}

/** lwr is only filled out in case 1 was returned, and even when returning 1 for 'success', lwr might contain DNS errors
    Never throws! 
 */
static LWResult::Result asyncresolve(const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstrmLoggers, const std::set<uint16_t>& exportTypes, LWResult *lwr, bool* chained, TCPOutConnectionManager::Connection& connection)
{
  size_t len;
  size_t bufsize=g_outgoingEDNSBufsize;
  PacketBuffer buf;
  buf.resize(bufsize);
  vector<uint8_t> vpacket;
  //  string mapped0x20=dns0x20(domain);
  uint16_t qid = dns_random_uint16();
  DNSPacketWriter pw(vpacket, domain, type);

  pw.getHeader()->rd=sendRDQuery;
  pw.getHeader()->id=qid;
  /* RFC 6840 section 5.9:
   *  This document further specifies that validating resolvers SHOULD set
   *  the CD bit on every upstream query.  This is regardless of whether
   *  the CD bit was set on the incoming query [...]
   *
   * sendRDQuery is only true if the qname is part of a forward-zone-recurse (or
   * set in the forward-zone-file), so we use this as an indicator for it being
   * an "upstream query". To stay true to "dnssec=off means 3.X behaviour", we
   * only set +CD on forwarded query in any mode other than dnssec=off.
   */
  pw.getHeader()->cd=(sendRDQuery && g_dnssecmode != DNSSECMode::Off);

  string ping;
  bool weWantEDNSSubnet=false;
  uint8_t outgoingECSBits = 0;
  ComboAddress outgoingECSAddr;
  if(EDNS0Level > 0) {
    DNSPacketWriter::optvect_t opts;
    if(srcmask) {
      EDNSSubnetOpts eo;
      eo.source = *srcmask;
      outgoingECSBits = srcmask->getBits();
      outgoingECSAddr = srcmask->getNetwork();
      //      cout<<"Adding request mask: "<<eo.source.toString()<<endl;
      opts.push_back(make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(eo)));
      weWantEDNSSubnet=true;
    }

    pw.addOpt(g_outgoingEDNSBufsize, 0, g_dnssecmode == DNSSECMode::Off ? 0 : EDNSOpts::DNSSECOK, opts); 
    pw.commit();
  }
  lwr->d_rcode = 0;
  lwr->d_haveEDNS = false;
  LWResult::Result ret;

  DTime dt;
  dt.set();
  *now=dt.getTimeval();

  boost::uuids::uuid uuid;
  const struct timeval queryTime = *now;

  if (outgoingLoggers) {
    uuid = getUniqueID();
    logOutgoingQuery(outgoingLoggers, context ? context->d_initialRequestId : boost::none, uuid, ip, domain, type, qid, doTCP, vpacket.size(), srcmask);
  }

  srcmask = boost::none; // this is also our return value, even if EDNS0Level == 0

  // We only store the localip if needed for fstrm logging
  ComboAddress localip;
  bool dnsOverTLS = false;
#ifdef HAVE_FSTRM
  bool fstrmQEnabled = false;
  bool fstrmREnabled = false;
  
  if (isEnabledForQueries(fstrmLoggers)) {
    fstrmQEnabled = true;
  }
  if (isEnabledForResponses(fstrmLoggers)) {
    fstrmREnabled = true;
  }
#endif

  if(!doTCP) {
    int queryfd;
    if (ip.sin4.sin_family==AF_INET6) {
      g_stats.ipv6queries++;
    }

    ret = asendto((const char*)&*vpacket.begin(), vpacket.size(), 0, ip, qid, domain, type, &queryfd);

    if (ret != LWResult::Result::Success) {
      return ret;
    }

    if (queryfd == -1) {
      *chained = true;
    }

#ifdef HAVE_FSTRM
    if (!*chained) {
      if (fstrmQEnabled || fstrmREnabled) {
        localip.sin4.sin_family = ip.sin4.sin_family;
        socklen_t slen = ip.getSocklen();
        getsockname(queryfd, reinterpret_cast<sockaddr*>(&localip), &slen);
      }
      if (fstrmQEnabled) {
        logFstreamQuery(fstrmLoggers, queryTime, localip, ip, DnstapMessage::ProtocolType::DoUDP, context ? context->d_auth : boost::none, vpacket);
      }
    }
#endif /* HAVE_FSTRM */

    // sleep until we see an answer to this, interface to mtasker
    ret = arecvfrom(buf, 0, ip, &len, qid, domain, type, queryfd, now);
  }
  else {
      bool isNew;
      do {
        try {
          // If we get a new (not re-used) TCP connection that does not
          // work, we give up. For reused connections, we assume the
          // peer has closed it on error, so we retry. At some point we
          // *will* get a new connection, so this loop is not endless.
          isNew = tcpconnect(*now, ip, connection, dnsOverTLS);
          ret = tcpsendrecv(ip, connection, localip, vpacket, len, buf);
#ifdef HAVE_FSTRM
          if (fstrmQEnabled) {
            logFstreamQuery(fstrmLoggers, queryTime, localip, ip, !dnsOverTLS ? DnstapMessage::ProtocolType::DoTCP : DnstapMessage::ProtocolType::DoT, context ? context->d_auth : boost::none, vpacket);
          }
#endif /* HAVE_FSTRM */
          if (ret == LWResult::Result::Success) {
            break;
          }
          connection.d_handler->close();
        }
        catch (const NetworkError&) {
          ret = LWResult::Result::OSLimitError; // OS limits error
        }
        catch (const runtime_error&) {
          ret = LWResult::Result::OSLimitError; // OS limits error (PermanentError is transport related)
        }
      } while (!isNew);
  }

  lwr->d_usec=dt.udiff();
  *now=dt.getTimeval();

  if (ret != LWResult::Result::Success) { // includes 'timeout'
      if (outgoingLoggers) {
        logIncomingResponse(outgoingLoggers, context ? context->d_initialRequestId : boost::none, uuid, ip, domain, type, qid, doTCP, srcmask, 0, -1, {}, queryTime, exportTypes);
      }
    return ret;
  }

  buf.resize(len);

#ifdef HAVE_FSTRM
  if (fstrmREnabled && (!*chained || doTCP)) {
    DnstapMessage::ProtocolType protocol = doTCP ? DnstapMessage::ProtocolType::DoTCP : DnstapMessage::ProtocolType::DoUDP;
    if (dnsOverTLS) {
      protocol = DnstapMessage::ProtocolType::DoT;
    }
    logFstreamResponse(fstrmLoggers, localip, ip, protocol, context ? context->d_auth : boost::none, buf, queryTime, *now);
  }
#endif /* HAVE_FSTRM */

  lwr->d_records.clear();
  try {
    lwr->d_tcbit=0;
    MOADNSParser mdp(false, reinterpret_cast<const char*>(buf.data()), buf.size());
    lwr->d_aabit=mdp.d_header.aa;
    lwr->d_tcbit=mdp.d_header.tc;
    lwr->d_rcode=mdp.d_header.rcode;
    
    if(mdp.d_header.rcode == RCode::FormErr && mdp.d_qname.empty() && mdp.d_qtype == 0 && mdp.d_qclass == 0) {
      if(outgoingLoggers) {
        logIncomingResponse(outgoingLoggers, context ? context->d_initialRequestId : boost::none, uuid, ip, domain, type, qid, doTCP, srcmask, len, lwr->d_rcode, lwr->d_records, queryTime, exportTypes);
      }
      lwr->d_validpacket = true;
      return LWResult::Result::Success; // this is "success", the error is set in lwr->d_rcode
    }

    if(domain != mdp.d_qname) { 
      if(!mdp.d_qname.empty() && domain.toString().find((char)0) == string::npos /* ugly */) {// embedded nulls are too noisy, plus empty domains are too
        g_log<<Logger::Notice<<"Packet purporting to come from remote server "<<ip.toString()<<" contained wrong answer: '" << domain << "' != '" << mdp.d_qname << "'" << endl;
      }
      // unexpected count has already been done @ pdns_recursor.cc
      goto out;
    }

    lwr->d_records.reserve(mdp.d_answers.size());
    for(const auto& a : mdp.d_answers)
      lwr->d_records.push_back(a.first);

    EDNSOpts edo;
    if(EDNS0Level > 0 && getEDNSOpts(mdp, &edo)) {
      lwr->d_haveEDNS = true;

      if(weWantEDNSSubnet) {
        for(const auto& opt : edo.d_options) {
          if(opt.first==EDNSOptionCode::ECS) {
            EDNSSubnetOpts reso;
            if(getEDNSSubnetOptsFromString(opt.second, &reso)) {
              //	    cerr<<"EDNS Subnet response: "<<reso.source.toString()<<", scope: "<<reso.scope.toString()<<", family = "<<reso.scope.getNetwork().sin4.sin_family<<endl;
              /* rfc7871 states that 0 "indicate[s] that the answer is suitable for all addresses in FAMILY",
                 so we might want to still pass the information along to be able to differentiate between
                 IPv4 and IPv6. Still I'm pretty sure it doesn't matter in real life, so let's not duplicate
                 entries in our cache. */
              if(reso.scope.getBits()) {
                uint8_t bits = std::min(reso.scope.getBits(), outgoingECSBits);
                outgoingECSAddr.truncate(bits);
                srcmask = Netmask(outgoingECSAddr, bits);
              }
            }
          }
        }
      }
    }
        
    if(outgoingLoggers) {
      logIncomingResponse(outgoingLoggers, context ? context->d_initialRequestId : boost::none, uuid, ip, domain, type, qid, doTCP, srcmask, len, lwr->d_rcode, lwr->d_records, queryTime, exportTypes);
    }
    
    lwr->d_validpacket = true;
    return LWResult::Result::Success;
  }
  catch (const std::exception &mde) {
    if (::arg().mustDo("log-common-errors")) {
      g_log<<Logger::Notice<<"Unable to parse packet from remote server "<<ip.toString()<<": "<<mde.what()<<endl;
    }

    lwr->d_rcode = RCode::FormErr;
    lwr->d_validpacket = false;
    g_stats.serverParseError++;

    if(outgoingLoggers) {
      logIncomingResponse(outgoingLoggers, context ? context->d_initialRequestId : boost::none, uuid, ip, domain, type, qid, doTCP, srcmask, len, lwr->d_rcode, lwr->d_records, queryTime, exportTypes);
    }

    return LWResult::Result::Success; // success - oddly enough
  }
  catch (...) {
    g_log<<Logger::Notice<<"Unknown error parsing packet from remote server"<<endl;
  }
  
  g_stats.serverParseError++; 
  
 out:
  if (!lwr->d_rcode) {
    lwr->d_rcode=RCode::ServFail;
  }

  return LWResult::Result::PermanentError;
}

LWResult::Result asyncresolve(const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstrmLoggers, const std::set<uint16_t>& exportTypes, LWResult *lwr, bool* chained)
{
  TCPOutConnectionManager::Connection connection;
  auto ret = asyncresolve(ip, domain, type, doTCP, sendRDQuery, EDNS0Level, now, srcmask, context, outgoingLoggers, fstrmLoggers, exportTypes, lwr, chained, connection);

  if (doTCP) {
    if (!lwr->d_validpacket) {
      ret = asyncresolve(ip, domain, type, doTCP, sendRDQuery, EDNS0Level, now, srcmask, context, outgoingLoggers, fstrmLoggers, exportTypes, lwr, chained, connection);
    }
    if (connection.d_handler && lwr->d_validpacket) {
      t_tcp_manager.store(*now, ip, std::move(connection));
    }
  }
  return ret;
}

