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
#include "rec-tcp-out.hh"

#include "rec-protozero.hh"
#include "uuid-utils.hh"

#ifdef HAVE_FSTRM
#include "dnstap.hh"
#include "fstrm_logger.hh"


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

static void logFstreamQuery(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers, const struct timeval &queryTime, const ComboAddress& ip, bool doTCP,
  boost::optional<const DNSName&> auth, const vector<uint8_t>& packet)
{
  if (fstreamLoggers == nullptr)
    return;

  struct timespec ts;
  TIMEVAL_TO_TIMESPEC(&queryTime, &ts);
  std::string str;
  DnstapMessage message(str, DnstapMessage::MessageType::resolver_query, SyncRes::s_serverID, nullptr, &ip, doTCP, reinterpret_cast<const char*>(&*packet.begin()), packet.size(), &ts, nullptr, auth);

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

static void logFstreamResponse(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers, const ComboAddress& ip, bool doTCP,
  boost::optional<const DNSName&> auth, const std::string& packet, const struct timeval& queryTime, const struct timeval& replyTime)
{
  if (fstreamLoggers == nullptr)
    return;

  struct timespec ts1, ts2;
  TIMEVAL_TO_TIMESPEC(&queryTime, &ts1);
  TIMEVAL_TO_TIMESPEC(&replyTime, &ts2);
  std::string str;
  DnstapMessage message(str, DnstapMessage::MessageType::resolver_response, SyncRes::s_serverID, nullptr, &ip, doTCP, static_cast<const char*>(&*packet.begin()), packet.size(), &ts1, &ts2, auth);

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

/** lwr is only filled out in case 1 was returned, and even when returning 1 for 'success', lwr might contain DNS errors
    Never throws! 
 */
LWResult::Result asyncresolve(const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstrmLoggers, const std::set<uint16_t>& exportTypes, LWResult *lwr, bool* chained)
{
  size_t len;
  size_t bufsize=g_outgoingEDNSBufsize;
  std::string buf;
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

#ifdef HAVE_FSTRM
  if (isEnabledForQueries(fstrmLoggers)) {
    logFstreamQuery(fstrmLoggers, queryTime, ip, doTCP, context ? context->d_auth : boost::none, vpacket);
  }
#endif /* HAVE_FSTRM */

  srcmask = boost::none; // this is also our return value, even if EDNS0Level == 0

  if(!doTCP) {
    int queryfd;
    if (ip.sin4.sin_family==AF_INET6) {
      g_stats.ipv6queries++;
    }

    ret = asendto((const char*)&*vpacket.begin(), vpacket.size(), 0, ip, qid,
                  domain, type, &queryfd);

    if (ret != LWResult::Result::Success) {
      return ret;
    }

    if (queryfd == -1) {
      *chained = true;
    }

    // sleep until we see an answer to this, interface to mtasker
    ret = arecvfrom(buf, 0, ip, &len, qid,
                    domain, type, queryfd, now);
  }
  else {
    try {
      // We try first existing connections from the pool if available
      // Only if a new, fresh connetcion fails, we give up
      while (1) {
        bool isNew;
        auto tcp = t_tcpConnections.getConnection(ip, *now, isNew);
        uint16_t tlen=htons(vpacket.size());
        char *lenP=(char*)&tlen;
        const char *msgP=(const char*)&*vpacket.begin();
        string packet=string(lenP, lenP+2)+string(msgP, msgP+vpacket.size());
        ret = asendtcp(packet, &tcp->getSocket());
        if (ret != LWResult::Result::Success) {
          if (!isNew) {
            continue;
          }
        }

        packet.clear();
        ret = arecvtcp(packet, 2, &tcp->getSocket(), false);
        if (ret != LWResult::Result::Success) {
          if (!isNew) {
            continue;
          }
          return ret;
        }

        memcpy(&tlen, packet.c_str(), sizeof(tlen));
        len=ntohs(tlen); // switch to the 'len' shared with the rest of the function

        ret = arecvtcp(packet, len, &tcp->getSocket(), false);
        if (ret != LWResult::Result::Success) {
          return ret;
        }

        buf.resize(len);
        memcpy(const_cast<char*>(buf.data()), packet.c_str(), len);

        ret = LWResult::Result::Success;
        t_tcpConnections.setIdle(ip, std::move(tcp), *now);
        break;
      }
    }
    catch (const NetworkError& ne) {
      ret = LWResult::Result::OSLimitError; // OS limits error
    }
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
  if (isEnabledForResponses(fstrmLoggers)) {
    logFstreamResponse(fstrmLoggers, ip, doTCP, context ? context->d_auth : boost::none, buf, queryTime, *now);
  }
#endif /* HAVE_FSTRM */

  lwr->d_records.clear();
  try {
    lwr->d_tcbit=0;
    MOADNSParser mdp(false, buf);
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

