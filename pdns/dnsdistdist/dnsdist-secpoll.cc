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

#include "config.h"

#include <string>
#include <vector>

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif /* HAVE_LIBSODIUM */

#include "dnsparser.hh"
#include "dolog.hh"
#include "iputils.hh"
#include "misc.hh"
#include "sstuff.hh"

#include "dnsdist.hh"
#include "dnsdist-secpoll.hh"

#ifndef PACKAGEVERSION
#define PACKAGEVERSION PACKAGE_VERSION
#endif

static std::string getFirstTXTAnswer(const std::string& answer)
{
  if (answer.size() <= sizeof(struct dnsheader)) {
    throw std::runtime_error("Looking for a TXT record in an answer smaller than the DNS header");
  }

  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(answer.data());
  PacketReader pr(answer);
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);

  DNSName rrname;
  uint16_t rrtype;
  uint16_t rrclass;

  size_t idx = 0;
  /* consume qd */
  for(; idx < qdcount; idx++) {
    rrname = pr.getName();
    rrtype = pr.get16BitInt();
    rrclass = pr.get16BitInt();
    (void) rrtype;
    (void) rrclass;
  }

  /* parse AN */
  for (idx = 0; idx < ancount; idx++) {
    string blob;
    struct dnsrecordheader ah;
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type == QType::TXT) {
      string txt;
      pr.xfrText(txt);

      return txt;
    }
    else {
      pr.xfrBlob(blob);
    }
  }

  throw std::runtime_error("No TXT record in answer");
}

static std::string getSecPollStatus(const std::string& queriedName, int timeout=2)
{
  const DNSName& sentName = DNSName(queriedName);
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, sentName, QType::TXT);
  pw.getHeader()->id = getRandomDNSID();
  pw.getHeader()->rd = 1;

  const auto& resolversForStub = getResolvers("/etc/resolv.conf");

  for(const auto& dest : resolversForStub) {
    Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
    sock.setNonBlocking();
    sock.connect(dest);
    sock.send(string(packet.begin(), packet.end()));

    string reply;
    int ret = waitForData(sock.getHandle(), timeout, 0);
    if (ret < 0) {
      if (g_verbose) {
        warnlog("Error while waiting for the secpoll response from stub resolver %s: %d", dest.toString(), ret);
      }
      continue;
    }
    else if (ret == 0) {
      if (g_verbose) {
        warnlog("Timeout while waiting for the secpoll response from stub resolver %s", dest.toString());
      }
      continue;
    }

    try {
      sock.read(reply);
    }
    catch(const std::exception& e) {
      if (g_verbose) {
        warnlog("Error while reading for the secpoll response from stub resolver %s: %s", dest.toString(), e.what());
      }
      continue;
    }

    if (reply.size() <= sizeof(struct dnsheader)) {
      if (g_verbose) {
        warnlog("Too short answer of size %d received from the secpoll stub resolver %s", reply.size(), dest.toString());
      }
      continue;
    }

    struct dnsheader d;
    memcpy(&d, reply.c_str(), sizeof(d));
    if (d.id != pw.getHeader()->id) {
      if (g_verbose) {
        warnlog("Invalid ID (%d / %d) received from the secpoll stub resolver %s", d.id, pw.getHeader()->id, dest.toString());
      }
      continue;
    }

    if (d.rcode != RCode::NoError) {
      if (g_verbose) {
        warnlog("Response code '%s' received from the secpoll stub resolver %s for '%s'", RCode::to_s(d.rcode), dest.toString(), queriedName);
      }

      /* no need to try another resolver if the domain does not exist */
      if (d.rcode == RCode::NXDomain) {
        throw std::runtime_error("Unable to get a valid Security Status update");
      }
      continue;
    }

    if (ntohs(d.qdcount) != 1 || ntohs(d.ancount) != 1) {
      if (g_verbose) {
        warnlog("Invalid answer (qdcount %d / ancount %d) received from the secpoll stub resolver %s", ntohs(d.qdcount), ntohs(d.ancount), dest.toString());
      }
      continue;
    }

    uint16_t receivedType;
    uint16_t receivedClass;
    DNSName receivedName(reply.c_str(), reply.size(), sizeof(dnsheader), false, &receivedType, &receivedClass);

    if (receivedName != sentName || receivedType != QType::TXT || receivedClass != QClass::IN) {
      if (g_verbose) {
        warnlog("Invalid answer, either the qname (%s / %s), qtype (%s / %s) or qclass (%d / %d) does not match, received from the secpoll stub resolver %s", receivedName, sentName, QType(receivedType).getName(), QType(QType::TXT).getName(), receivedClass, QClass::IN, dest.toString());
      }
      continue;
    }

    return getFirstTXTAnswer(reply);
  }

  throw std::runtime_error("Unable to get a valid Security Status update");
}

static bool g_secPollDone{false};
std::string g_secPollSuffix{"secpoll.powerdns.com."};
time_t g_secPollInterval{3600};

void doSecPoll(const std::string& suffix)
{
  if (suffix.empty()) {
    return;
  }

  const std::string pkgv(PACKAGEVERSION);
  bool releaseVersion = std::count(pkgv.begin(), pkgv.end(), '.') == 2;
  const std::string version = "dnsdist-" + pkgv;
  std::string queriedName = version.substr(0, 63) + ".security-status." + suffix;

  if (*queriedName.rbegin() != '.') {
    queriedName += '.';
  }

  boost::replace_all(queriedName, "+", "_");
  boost::replace_all(queriedName, "~", "_");

  try {
    std::string status = getSecPollStatus(queriedName);
    pair<string, string> split = splitField(unquotify(status), ' ');

    int securityStatus = std::stoi(split.first);
    std::string securityMessage = split.second;

    if(securityStatus == 1 && !g_secPollDone) {
      warnlog("Polled security status of version %s at startup, no known issues reported: %s", std::string(VERSION), securityMessage);
    }
    if(securityStatus == 2) {
      errlog("PowerDNS DNSDist Security Update Recommended: %s", securityMessage);
    }
    else if(securityStatus == 3) {
      errlog("PowerDNS DNSDist Security Update Mandatory: %s", securityMessage);
    }

    g_stats.securityStatus = securityStatus;
    g_secPollDone = true;
    return;
  }
  catch(const std::exception& e) {
    if (releaseVersion) {
      warnlog("Error while retrieving the security update for version %s: %s", version, e.what());
    }
    else if (!g_secPollDone) {
      infolog("Error while retrieving the security update for version %s: %s", version, e.what());
    }
  }

  if (releaseVersion) {
    warnlog("Could not retrieve security status update for '%s' on %s", pkgv, queriedName);
  }
  else if (!g_secPollDone) {
    infolog("Not validating response for security status update, this is a non-release version.");

    /* for non-released versions, there is no use sending the same message several times,
       let's just accept that there will be no security polling for this exact version */
    g_secPollDone = true;
  }
}
