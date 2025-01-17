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

#include <sys/types.h>
#include <thread>

#include "packetcache.hh"
#include "utility.hh"
#include "dnsproxy.hh"
#include "pdnsexception.hh"
#include "dns.hh"
#include "logger.hh"
#include "statbag.hh"
#include "dns_random.hh"
#include "stubresolver.hh"
#include "arguments.hh"
#include "threadname.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"

#include <boost/uuid/uuid_io.hpp>

extern StatBag S;

DNSProxy::DNSProxy(const string& remote, const string& udpPortRange) :
  d_xor(dns_random_uint16())
{
  d_resanswers = S.getPointer("recursing-answers");
  d_resquestions = S.getPointer("recursing-questions");
  d_udpanswers = S.getPointer("udp-answers");

  vector<string> addresses;
  stringtok(addresses, remote, " ,\t");
  d_remote = ComboAddress(addresses[0], 53);

  vector<string> parts;
  stringtok(parts, udpPortRange, " ");
  if (parts.size() != 2) {
    throw PDNSException("DNS Proxy UDP port range must contain exactly one lower and one upper bound");
  }
  unsigned long portRangeLow = std::stoul(parts.at(0));
  unsigned long portRangeHigh = std::stoul(parts.at(1));
  if (portRangeLow < 1 || portRangeHigh > 65535) {
    throw PDNSException("DNS Proxy UDP port range values out of valid port bounds (1 to 65535)");
  }
  if (portRangeLow >= portRangeHigh) {
    throw PDNSException("DNS Proxy UDP port range upper bound " + std::to_string(portRangeHigh) + " must be higher than lower bound (" + std::to_string(portRangeLow) + ")");
  }

  if ((d_sock = socket(d_remote.sin4.sin_family, SOCK_DGRAM, 0)) < 0) {
    throw PDNSException(string("socket: ") + stringerror());
  }

  ComboAddress local;
  if (d_remote.sin4.sin_family == AF_INET) {
    local = ComboAddress("0.0.0.0");
  }
  else {
    local = ComboAddress("::");
  }

  unsigned int attempts = 0;
  for (; attempts < 10; attempts++) {
    local.sin4.sin_port = htons(portRangeLow + dns_random(portRangeHigh - portRangeLow));

    if (::bind(d_sock, (struct sockaddr*)&local, local.getSocklen()) >= 0) { // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)
      break;
    }
  }
  if (attempts == 10) {
    closesocket(d_sock);
    d_sock = -1;
    throw PDNSException(string("binding dnsproxy socket: ") + stringerror());
  }

  if (connect(d_sock, (sockaddr*)&d_remote, d_remote.getSocklen()) < 0) { // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)
    throw PDNSException("Unable to UDP connect to remote nameserver " + d_remote.toStringWithPort() + ": " + stringerror());
  }

  g_log << Logger::Error << "DNS Proxy launched, local port " << ntohs(local.sin4.sin_port) << ", remote " << d_remote.toStringWithPort() << endl;
}

void DNSProxy::go()
{
  std::thread proxythread([this]() { mainloop(); });
  proxythread.detach();
}

//! look up qname 'target' with reply->qtype, plonk it in the answer section of 'reply' with name 'aname'
bool DNSProxy::completePacket(std::unique_ptr<DNSPacket>& reply, const DNSName& target, const DNSName& aname, const uint8_t scopeMask)
{
  string ECSOptionStr;

  if (reply->hasEDNSSubnet()) {
    DLOG(g_log << "dnsproxy::completePacket: Parsed edns source: " << reply->d_eso.getSource().toString() << ", scope: " << Netmask(reply->d_eso.getSource().getNetwork(), reply->d_eso.getScopePrefixLength()).toString() << ", family = " << std::to_string(reply->d_eso.getFamily()) << endl);
    ECSOptionStr = reply->d_eso.makeOptString();
    DLOG(g_log << "from dnsproxy::completePacket: Creating ECS option string " << makeHexDump(ECSOptionStr) << endl);
  }

  if (reply->d_tcp) {
    vector<DNSZoneRecord> ips;
    int ret1 = 0;
    int ret2 = 0;
    // rip out edns info here, pass it to the stubDoResolve
    if (reply->qtype == QType::A || reply->qtype == QType::ANY) {
      ret1 = stubDoResolve(target, QType::A, ips, reply->hasEDNSSubnet() ? &reply->d_eso : nullptr);
    }
    if (reply->qtype == QType::AAAA || reply->qtype == QType::ANY) {
      ret2 = stubDoResolve(target, QType::AAAA, ips, reply->hasEDNSSubnet() ? &reply->d_eso : nullptr);
    }

    if (ret1 != RCode::NoError || ret2 != RCode::NoError) {
      g_log << Logger::Error << "Error resolving for " << aname << " ALIAS " << target << " over UDP, original query came in over TCP";
      if (ret1 != RCode::NoError) {
        g_log << Logger::Error << ", A-record query returned " << RCode::to_s(ret1);
      }
      if (ret2 != RCode::NoError) {
        g_log << Logger::Error << ", AAAA-record query returned " << RCode::to_s(ret2);
      }
      g_log << Logger::Error << ", returning SERVFAIL" << endl;
      reply->clearRecords();
      reply->setRcode(RCode::ServFail);
    }
    else {
      for (auto& ip : ips) { // NOLINT(readability-identifier-length)
        ip.dr.d_name = aname;
        reply->addRecord(std::move(ip));
      }
    }

    uint16_t len = htons(reply->getString().length());
    string buffer((const char*)&len, 2);
    buffer.append(reply->getString());
    writen2WithTimeout(reply->getSocket(), buffer.c_str(), buffer.length(), timeval{::arg().asNum("tcp-idle-timeout"), 0});

    return true;
  }

  uint16_t id;
  uint16_t qtype = reply->qtype.getCode();
  {
    auto conntrack = d_conntrack.lock();
    id = getID_locked(*conntrack);

    ConntrackEntry ce;
    ce.id = reply->d.id;
    ce.remote = reply->d_remote;
    ce.outsock = reply->getSocket();
    ce.created = time(nullptr);
    ce.qtype = reply->qtype.getCode();
    ce.qname = target;
    ce.anyLocal = reply->d_anyLocal;
    ce.complete = std::move(reply);
    ce.aname = aname;
    ce.anameScopeMask = scopeMask;
    (*conntrack)[id] = std::move(ce);
  }

  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, target, qtype);
  pw.getHeader()->rd = true;
  pw.getHeader()->id = id ^ d_xor;
  // Add EDNS Subnet if the client sent one - issue #5469
  if (!ECSOptionStr.empty()) {
    DLOG(g_log << "from dnsproxy::completePacket: adding ECS option string to packet options " << makeHexDump(ECSOptionStr) << endl);
    DNSPacketWriter::optvect_t opts;
    opts.emplace_back(EDNSOptionCode::ECS, ECSOptionStr);
    pw.addOpt(512, 0, 0, opts);
    pw.commit();
  }

  if (send(d_sock, packet.data(), packet.size(), 0) < 0) { // zoom
    g_log << Logger::Error << "Unable to send a packet to our recursing backend: " << stringerror() << endl;
  }

  return true;
}

/** This finds us an unused or stale ID. Does not actually clean the contents */
int DNSProxy::getID_locked(map_t& conntrack)
{
  map_t::iterator iter;
  for (int n = 0;; ++n) { // NOLINT(readability-identifier-length)
    iter = conntrack.find(n);
    if (iter == conntrack.end()) {
      return n;
    }
    if (iter->second.created < time(nullptr) - 60) {
      if (iter->second.created != 0) {
        g_log << Logger::Warning << "Recursive query for remote " << iter->second.remote.toStringWithPort() << " with internal id " << n << " was not answered by backend within timeout, reusing id" << endl;
        iter->second.complete.reset();
        S.inc("recursion-unanswered");
      }
      return n;
    }
  }
}

void DNSProxy::mainloop()
{
  setThreadName("pdns/dnsproxy");
  try {
    char buffer[1500];
    ssize_t len;

    struct msghdr msgh;
    struct iovec iov;
    cmsgbuf_aligned cbuf;
    ComboAddress fromaddr;

    for (;;) {
      socklen_t fromaddrSize = sizeof(fromaddr);
      len = recvfrom(d_sock, &buffer[0], sizeof(buffer), 0, (struct sockaddr*)&fromaddr, &fromaddrSize); // answer from our backend  NOLINT(cppcoreguidelines-pro-type-cstyle-cast)
      if (len < (ssize_t)sizeof(dnsheader)) {
        if (len < 0) {
          g_log << Logger::Error << "Error receiving packet from recursor backend: " << stringerror() << endl;
        }
        else if (len == 0) {
          g_log << Logger::Error << "Error receiving packet from recursor backend, EOF" << endl;
        }
        else {
          g_log << Logger::Error << "Short packet from recursor backend, " << len << " bytes" << endl;
        }

        continue;
      }
      if (fromaddr != d_remote) {
        g_log << Logger::Error << "Got answer from unexpected host " << fromaddr.toStringWithPort() << " instead of our recursor backend " << d_remote.toStringWithPort() << endl;
        continue;
      }
      (*d_resanswers)++;
      (*d_udpanswers)++;
      dnsheader dHead{};
      memcpy(&dHead, &buffer[0], sizeof(dHead));
      {
        auto conntrack = d_conntrack.lock();
        if (BYTE_ORDER == BIG_ENDIAN) {
          // this is needed because spoof ID down below does not respect the native byteorder
          dHead.id = (256 * (uint16_t)buffer[1]) + (uint16_t)buffer[0];
        }

        auto iter = conntrack->find(dHead.id ^ d_xor);
        if (iter == conntrack->end()) {
          g_log << Logger::Error << "Discarding untracked packet from recursor backend with id " << (dHead.id ^ d_xor) << ". Conntrack table size=" << conntrack->size() << endl;
          continue;
        }
        if (iter->second.created == 0) {
          g_log << Logger::Error << "Received packet from recursor backend with id " << (dHead.id ^ d_xor) << " which is a duplicate" << endl;
          continue;
        }

        dHead.id = iter->second.id;
        memcpy(&buffer[0], &dHead, sizeof(dHead)); // commit spoofed id

        DNSPacket packet(false);
        packet.parse(&buffer[0], (size_t)len);

        if (packet.qtype.getCode() != iter->second.qtype || packet.qdomain != iter->second.qname) {
          g_log << Logger::Error << "Discarding packet from recursor backend with id " << (dHead.id ^ d_xor) << ", qname or qtype mismatch (" << packet.qtype.getCode() << " v " << iter->second.qtype << ", " << packet.qdomain << " v " << iter->second.qname << ")" << endl;
          continue;
        }

        /* Set up iov and msgh structures. */
        memset(&msgh, 0, sizeof(struct msghdr));
        string reply; // needs to be alive at time of sendmsg!
        MOADNSParser mdp(false, packet.getString());
        // update the EDNS options with info from the resolver - issue #5469
        // note that this relies on the ECS string encoder to use the source network, and only take the prefix length from scope
        iter->second.complete->d_eso.setScopePrefixLength(packet.d_eso.getScopePrefixLength());
        DLOG(g_log << "from dnsproxy::mainLoop: updated EDNS options from resolver EDNS source: " << iter->second.complete->d_eso.getSource().toString() << " EDNS scope: " << iter->second.complete->d_eso.getScope().toString() << endl);

        if (mdp.d_header.rcode == RCode::NoError) {
          for (const auto& answer : mdp.d_answers) {
            if (answer.d_place == DNSResourceRecord::ANSWER || (answer.d_place == DNSResourceRecord::AUTHORITY && answer.d_type == QType::SOA)) {

              if (answer.d_type == iter->second.qtype || (iter->second.qtype == QType::ANY && (answer.d_type == QType::A || answer.d_type == QType::AAAA))) {
                DNSZoneRecord dzr;
                dzr.dr.d_name = iter->second.aname;
                dzr.dr.d_type = answer.d_type;
                dzr.dr.d_ttl = answer.d_ttl;
                dzr.dr.d_place = answer.d_place;
                dzr.dr.setContent(answer.getContent());
                iter->second.complete->addRecord(std::move(dzr));
              }
            }
          }

          iter->second.complete->setRcode(mdp.d_header.rcode);
        }
        else {
          g_log << Logger::Error << "Error resolving for " << iter->second.aname << " ALIAS " << iter->second.qname << " over UDP, " << QType(iter->second.qtype).toString() << "-record query returned " << RCode::to_s(mdp.d_header.rcode) << ", returning SERVFAIL" << endl;
          iter->second.complete->clearRecords();
          iter->second.complete->setRcode(RCode::ServFail);
        }
        reply = iter->second.complete->getString();
        iov.iov_base = (void*)reply.c_str();
        iov.iov_len = reply.length();
        iter->second.complete.reset();
        msgh.msg_iov = &iov;
        msgh.msg_iovlen = 1;
        msgh.msg_name = (struct sockaddr*)&iter->second.remote; // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)
        msgh.msg_namelen = iter->second.remote.getSocklen();
        msgh.msg_control = nullptr;

        if (iter->second.anyLocal) {
          addCMsgSrcAddr(&msgh, &cbuf, iter->second.anyLocal.get_ptr(), 0);
        }
        if (sendmsg(iter->second.outsock, &msgh, 0) < 0) {
          int err = errno;
          g_log << Logger::Warning << "dnsproxy.cc: Error sending reply with sendmsg (socket=" << iter->second.outsock << "): " << stringerror(err) << endl;
        }
        iter->second.created = 0;
      }
    }
  }
  catch (PDNSException& ae) {
    g_log << Logger::Error << "Fatal error in DNS proxy: " << ae.reason << endl;
  }
  catch (std::exception& e) {
    g_log << Logger::Error << "Communicator thread died because of STL error: " << e.what() << endl;
  }
  catch (...) {
    g_log << Logger::Error << "Caught unknown exception." << endl;
  }
  g_log << Logger::Error << "Exiting because DNS proxy failed" << endl;
  _exit(1);
}

DNSProxy::~DNSProxy()
{
  if (d_sock > -1) {
    try {
      closesocket(d_sock);
    }
    catch (const PDNSException& e) {
    }
  }

  d_sock = -1;
}
