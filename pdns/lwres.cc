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

#ifdef HAVE_PROTOBUF

static void logOutgoingQuery(std::shared_ptr<RemoteLogger> outgoingLogger, boost::optional<const boost::uuids::uuid&> initialRequestId, const boost::uuids::uuid& uuid, const ComboAddress& ip, const DNSName& domain, int type, uint16_t qid, bool doTCP, size_t bytes)
{
  if(!outgoingLogger)
    return;

  RecProtoBufMessage message(DNSProtoBufMessage::OutgoingQuery, uuid, nullptr, &ip, domain, type, QClass::IN, qid, doTCP, bytes);
  if (initialRequestId) {
    message.setInitialRequestID(*initialRequestId);
  }

//  cerr <<message.toDebugString()<<endl;
  std::string str;
  message.serialize(str);
  outgoingLogger->queueData(str);
}

static void logIncomingResponse(std::shared_ptr<RemoteLogger> outgoingLogger, boost::optional<const boost::uuids::uuid&> initialRequestId, const boost::uuids::uuid& uuid, const ComboAddress& ip, const DNSName& domain, int type, uint16_t qid, bool doTCP, size_t bytes, int rcode, const std::vector<DNSRecord>& records, const struct timeval& queryTime)
{
  if(!outgoingLogger)
    return;

  RecProtoBufMessage message(DNSProtoBufMessage::IncomingResponse, uuid, nullptr, &ip, domain, type, QClass::IN, qid, doTCP, bytes);
  if (initialRequestId) {
    message.setInitialRequestID(*initialRequestId);
  }
  message.setQueryTime(queryTime.tv_sec, queryTime.tv_usec);
  message.setResponseCode(rcode);
  message.addRRs(records);

//  cerr <<message.toDebugString()<<endl;
  std::string str;
  message.serialize(str);
  outgoingLogger->queueData(str);
}
#endif /* HAVE_PROTOBUF */

//! returns -2 for OS limits error, -1 for permanent error that has to do with remote **transport**, 0 for timeout, 1 for success
/** lwr is only filled out in case 1 was returned, and even when returning 1 for 'success', lwr might contain DNS errors
    Never throws! 
 */
int asyncresolve(const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult *lwr)
{
  size_t len;
  size_t bufsize=g_outgoingEDNSBufsize;
  scoped_array<unsigned char> buf(new unsigned char[bufsize]);
  vector<uint8_t> vpacket;
  //  string mapped0x20=dns0x20(domain);
  uint16_t qid = dns_random(0xffff);
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
  if(EDNS0Level > 0) {
    DNSPacketWriter::optvect_t opts;
    if(srcmask) {
      EDNSSubnetOpts eo;
      eo.source = *srcmask;
      //      cout<<"Adding request mask: "<<eo.source.toString()<<endl;
      opts.push_back(make_pair(8, makeEDNSSubnetOptsString(eo)));
      weWantEDNSSubnet=true;
    }

    pw.addOpt(g_outgoingEDNSBufsize, 0, g_dnssecmode == DNSSECMode::Off ? 0 : EDNSOpts::DNSSECOK, opts); 
    pw.commit();
  }
  srcmask = boost::none; // this is also our return value, even if EDNS0Level == 0
  lwr->d_rcode = 0;
  lwr->d_haveEDNS = false;
  int ret;

  DTime dt;
  dt.set();
  *now=dt.getTimeval();

#ifdef HAVE_PROTOBUF
  boost::uuids::uuid uuid;
  const struct timeval queryTime = *now;

  if (outgoingLogger) {
    uuid = (*t_uuidGenerator)();
    logOutgoingQuery(outgoingLogger, context ? context->d_initialRequestId : boost::none, uuid, ip, domain, type, qid, doTCP, vpacket.size());
  }
#endif

  errno=0;
  if(!doTCP) {
    int queryfd;
    if(ip.sin4.sin_family==AF_INET6)
      g_stats.ipv6queries++;

    if((ret=asendto((const char*)&*vpacket.begin(), vpacket.size(), 0, ip, qid,
                    domain, type, &queryfd)) < 0) {
      return ret; // passes back the -2 EMFILE
    }
  
    // sleep until we see an answer to this, interface to mtasker
    
    ret=arecvfrom(reinterpret_cast<char *>(buf.get()), bufsize, 0, ip, &len, qid,
                  domain, type, queryfd, now);
  }
  else {
    try {
      Socket s(ip.sin4.sin_family, SOCK_STREAM);

      s.setNonBlocking();
      ComboAddress local = getQueryLocalAddress(ip.sin4.sin_family, 0);

      s.bind(local);
        
      s.connect(ip);
      
      uint16_t tlen=htons(vpacket.size());
      char *lenP=(char*)&tlen;
      const char *msgP=(const char*)&*vpacket.begin();
      string packet=string(lenP, lenP+2)+string(msgP, msgP+vpacket.size());
      
      ret=asendtcp(packet, &s);
      if(!(ret>0))           
        return ret;
      
      packet.clear();
      ret=arecvtcp(packet, 2, &s, false);
      if(!(ret > 0))
        return ret;
      
      memcpy(&tlen, packet.c_str(), sizeof(tlen));
      len=ntohs(tlen); // switch to the 'len' shared with the rest of the function
      
      ret=arecvtcp(packet, len, &s, false);
      if(!(ret > 0))
        return ret;
      
      if(len > bufsize) {
        bufsize=len;
        scoped_array<unsigned char> narray(new unsigned char[bufsize]);
        buf.swap(narray);
      }
      memcpy(buf.get(), packet.c_str(), len);

      ret=1;
    }
    catch(NetworkError& ne) {
      ret = -2; // OS limits error
    }
  }

  
  lwr->d_usec=dt.udiff();
  *now=dt.getTimeval();

  if(ret <= 0) // includes 'timeout'
    return ret;

  lwr->d_records.clear();
  try {
    lwr->d_tcbit=0;
    MOADNSParser mdp(false, (const char*)buf.get(), len);
    lwr->d_aabit=mdp.d_header.aa;
    lwr->d_tcbit=mdp.d_header.tc;
    lwr->d_rcode=mdp.d_header.rcode;
    
    if(mdp.d_header.rcode == RCode::FormErr && mdp.d_qname.empty() && mdp.d_qtype == 0 && mdp.d_qclass == 0) {
#ifdef HAVE_PROTOBUF
      if(outgoingLogger) {
        logIncomingResponse(outgoingLogger, context ? context->d_initialRequestId : boost::none, uuid, ip, domain, type, qid, doTCP, len, lwr->d_rcode, lwr->d_records, queryTime);
      }
#endif
      return 1; // this is "success", the error is set in lwr->d_rcode
    }

    if(domain != mdp.d_qname) { 
      if(!mdp.d_qname.empty() && domain.toString().find((char)0) == string::npos /* ugly */) {// embedded nulls are too noisy, plus empty domains are too
        g_log<<Logger::Notice<<"Packet purporting to come from remote server "<<ip.toString()<<" contained wrong answer: '" << domain << "' != '" << mdp.d_qname << "'" << endl;
      }
      // unexpected count has already been done @ pdns_recursor.cc
      goto out;
    }
    
    for(const auto& a : mdp.d_answers)
      lwr->d_records.push_back(a.first);

    EDNSOpts edo;
    if(EDNS0Level > 0 && getEDNSOpts(mdp, &edo)) {
      lwr->d_haveEDNS = true;

      if(weWantEDNSSubnet) {
        for(const auto& opt : edo.d_options) {
          if(opt.first==8) {
            EDNSSubnetOpts reso;
            if(getEDNSSubnetOptsFromString(opt.second, &reso)) {
              //	    cerr<<"EDNS Subnet response: "<<reso.source.toString()<<", scope: "<<reso.scope.toString()<<", family = "<<reso.scope.getNetwork().sin4.sin_family<<endl;
              /* rfc7871 states that 0 "indicate[s] that the answer is suitable for all addresses in FAMILY",
                 so we might want to still pass the information along to be able to differentiate between
                 IPv4 and IPv6. Still I'm pretty sure it doesn't matter in real life, so let's not duplicate
                 entries in our cache. */
              if(reso.scope.getBits())
                srcmask = reso.scope;
            }
          }
        }
      }
    }
        
#ifdef HAVE_PROTOBUF
    if(outgoingLogger) {
      logIncomingResponse(outgoingLogger, context ? context->d_initialRequestId : boost::none, uuid, ip, domain, type, qid, doTCP, len, lwr->d_rcode, lwr->d_records, queryTime);
    }
#endif
    return 1;
  }
  catch(std::exception &mde) {
    if(::arg().mustDo("log-common-errors"))
      g_log<<Logger::Notice<<"Unable to parse packet from remote server "<<ip.toString()<<": "<<mde.what()<<endl;
    lwr->d_rcode = RCode::FormErr;
    g_stats.serverParseError++;
#ifdef HAVE_PROTOBUF
    if(outgoingLogger) {
      logIncomingResponse(outgoingLogger, context ? context->d_initialRequestId : boost::none, uuid, ip, domain, type, qid, doTCP, len, lwr->d_rcode, lwr->d_records, queryTime);
    }
#endif
    return 1; // success - oddly enough
  }
  catch(...) {
    g_log<<Logger::Notice<<"Unknown error parsing packet from remote server"<<endl;
  }
  
  g_stats.serverParseError++; 
  
 out:
  if(!lwr->d_rcode)
    lwr->d_rcode=RCode::ServFail;

  return -1;
}

