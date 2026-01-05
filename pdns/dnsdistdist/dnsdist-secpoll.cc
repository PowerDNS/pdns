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

#include "dnsdist-secpoll.hh"
#ifndef DISABLE_SECPOLL

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
#include "dnsdist-metrics.hh"
#include "dnsdist-random.hh"

#ifndef PACKAGEVERSION
#define PACKAGEVERSION PACKAGE_VERSION
#endif

static std::string getFirstTXTAnswer(const std::string& answer)
{
  if (answer.size() <= sizeof(struct dnsheader)) {
    throw std::runtime_error("Looking for a TXT record in an answer smaller than the DNS header");
  }

  const dnsheader_aligned dnsHeader(answer.data());
  PacketReader reader(answer);
  uint16_t qdcount = ntohs(dnsHeader->qdcount);
  uint16_t ancount = ntohs(dnsHeader->ancount);

  DNSName rrname;
  uint16_t rrtype{};
  uint16_t rrclass{};

  size_t idx = 0;
  /* consume qd */
  for (; idx < qdcount; idx++) {
    rrname = reader.getName();
    rrtype = reader.get16BitInt();
    rrclass = reader.get16BitInt();
    (void)rrtype;
    (void)rrclass;
  }

  /* parse AN */
  for (idx = 0; idx < ancount; idx++) {
    string blob;
    dnsrecordheader answerHeader{};
    rrname = reader.getName();
    reader.getDnsrecordheader(answerHeader);

    if (answerHeader.d_type == QType::TXT) {
      string txt;
      reader.xfrText(txt);

      return txt;
    }
    reader.xfrBlob(blob);
  }

  throw std::runtime_error("No TXT record in answer");
}

static std::string getSecPollStatus(const Logr::Logger& logger, const std::string& queriedName, int timeout = 2)
{
  const DNSName sentName(queriedName);
  std::vector<uint8_t> packet;
  DNSPacketWriter writer(packet, sentName, QType::TXT);
  writer.getHeader()->id = dnsdist::getRandomDNSID();
  writer.getHeader()->rd = 1;

  const auto& resolversForStub = getResolvers("/etc/resolv.conf");

  if (resolversForStub.empty()) {
    throw std::runtime_error("No resolver to query to check for Security Status update");
  }

  for (const auto& dest : resolversForStub) {
    const auto resolverLogger = logger.withValues("network.peer.address", Logging::Loggable(dest));
    Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
    sock.setNonBlocking();
    sock.connect(dest);
    sock.send(string(packet.begin(), packet.end()));

    string reply;
    int ret = waitForData(sock.getHandle(), timeout, 0);
    if (ret < 0) {
      VERBOSESLOG(warnlog("Error while waiting for the secpoll response from stub resolver %s: %d", dest.toString(), ret),
                  resolverLogger->error(Logr::Warning, ret, "Error while waiting for the security status polling response from stub resolver"));
      continue;
    }
    if (ret == 0) {
      VERBOSESLOG(warnlog("Timeout while waiting for the secpoll response from stub resolver %s", dest.toString()),
                  resolverLogger->info(Logr::Warning, "Timeout while waiting for the security status polling response from stub resolver"));
      continue;
    }

    try {
      sock.read(reply);
    }
    catch (const std::exception& exp) {
      VERBOSESLOG(warnlog("Error while reading for the secpoll response from stub resolver %s: %s", dest.toString(), exp.what()),
                  resolverLogger->error(Logr::Warning, exp.what(), "Error while reading the security status polling response from stub resolver"));
      continue;
    }

    if (reply.size() <= sizeof(struct dnsheader)) {
      VERBOSESLOG(warnlog("Too short answer of size %d received from the secpoll stub resolver %s", reply.size(), dest.toString()),
                  resolverLogger->info(Logr::Warning, "Security status polling response received from the stub resolver is too small", "dns.response.size", Logging::Loggable(reply.size())));
      continue;
    }

    dnsheader dnsHeader{};
    memcpy(&dnsHeader, reply.c_str(), sizeof(dnsHeader));
    if (dnsHeader.id != writer.getHeader()->id) {
      VERBOSESLOG(warnlog("Invalid ID (%d / %d) received from the secpoll stub resolver %s", dnsHeader.id, writer.getHeader()->id, dest.toString()),
                  resolverLogger->info(Logr::Warning, "Invalid ID in security status polling response received from the stub resolver", "dns.response.size", Logging::Loggable(reply.size()), "dns.response.id", Logging::Loggable(dnsHeader.id), "dns.query.id", Logging::Loggable(writer.getHeader()->id)));
      continue;
    }

    if (dnsHeader.rcode != RCode::NoError) {
      VERBOSESLOG(warnlog("Response code '%s' received from the secpoll stub resolver %s for '%s'", RCode::to_s(dnsHeader.rcode), dest.toString(), queriedName),
                  resolverLogger->info(Logr::Warning, "Non-zero response code in status polling response received from the stub resolver", "dns.response.size", Logging::Loggable(reply.size()), "dns.response.id", Logging::Loggable(dnsHeader.id), "dns.response.code", Logging::Loggable(RCode::to_s(dnsHeader.rcode))));

      /* no need to try another resolver if the domain does not exist */
      if (dnsHeader.rcode == RCode::NXDomain) {
        throw std::runtime_error("Unable to get a valid Security Status update, domain does not exist");
      }
      continue;
    }

    if (ntohs(dnsHeader.qdcount) != 1 || ntohs(dnsHeader.ancount) != 1) {
      VERBOSESLOG(warnlog("Invalid answer (qdcount %d / ancount %d) received from the secpoll stub resolver %s", ntohs(dnsHeader.qdcount), ntohs(dnsHeader.ancount), dest.toString()),
                  resolverLogger->info(Logr::Warning, "Invalid status polling response received from the stub resolver", "dns.response.size", Logging::Loggable(reply.size()), "dns.response.id", Logging::Loggable(dnsHeader.id), "dns.response.qdcount", Logging::Loggable(ntohs(dnsHeader.qdcount)), "dns.response.ancount", Logging::Loggable(ntohs(dnsHeader.ancount))));
      continue;
    }

    uint16_t receivedType{};
    uint16_t receivedClass{};
    DNSName receivedName(reply.c_str(), reply.size(), sizeof(dnsheader), false, &receivedType, &receivedClass);

    if (receivedName != sentName || receivedType != QType::TXT || receivedClass != QClass::IN) {
      VERBOSESLOG(warnlog("Invalid answer, either the qname (%s / %s), qtype (%s / %s) or qclass (%s / %s) does not match, received from the secpoll stub resolver %s", receivedName, sentName, QType(receivedType).toString(), QType(QType::TXT).toString(), QClass(receivedClass).toString(), QClass::IN.toString(), dest.toString()),
                  resolverLogger->info(Logr::Warning, "Invalid status polling response received from the stub resolver, either the name, type or qclass does not match", "dns.response.size", Logging::Loggable(reply.size()), "dns.response.id", Logging::Loggable(dnsHeader.id), "dns.response.name", Logging::Loggable(receivedName), "dns.response.type", Logging::Loggable(receivedType), "dns.response.class", Logging::Loggable(receivedClass)));
      continue;
    }

    return getFirstTXTAnswer(reply);
  }

  throw std::runtime_error("Unable to get a valid Security Status update");
}

namespace dnsdist::secpoll
{
void doSecPoll(const std::string& suffix)
{
  static bool s_secPollDone{false};
  constexpr std::string_view pkgv(PACKAGEVERSION);
  const bool releaseVersion = std::count(pkgv.begin(), pkgv.end(), '.') == 2;

  if (suffix.empty()) {
    return;
  }

  const std::string version = std::string("dnsdist-") + std::string(pkgv);
  std::string queriedName = version.substr(0, 63) + ".security-status." + suffix;

  if (*queriedName.rbegin() != '.') {
    queriedName += '.';
  }

  std::replace(queriedName.begin(), queriedName.end(), '+', '_');
  std::replace(queriedName.begin(), queriedName.end(), '~', '_');

  auto logger = dnsdist::logging::getTopLogger()->withName("security-status-polling")->withValues("version", Logging::Loggable(pkgv), "dns.query.name", Logging::Loggable(queriedName));

  try {
    const std::string status = getSecPollStatus(*logger, queriedName);
    const std::pair<string, string> split = splitField(unquotify(status), ' ');

    const auto securityStatus = pdns::checked_stoi<uint8_t>(split.first);
    const std::string& securityMessage = split.second;

    if (securityStatus == 1 && !s_secPollDone) {
      SLOG(infolog("Polled security status of version %s at startup, no known issues reported: %s", std::string(VERSION), securityMessage),
           logger->info(Logr::Info, "Polled security status at startup, no known issues reported", "message", Logging::Loggable(securityMessage), "status", Logging::Loggable(securityStatus)));
    }
    if (securityStatus == 2) {
      SLOG(errlog("PowerDNS DNSDist Security Update Recommended: %s", securityMessage),
           logger->error(Logr::Error, securityMessage, "PowerDNS DNSDist Security Update Recommended", "status", Logging::Loggable(securityStatus)));
    }
    else if (securityStatus == 3) {
      SLOG(errlog("PowerDNS DNSDist Security Update Mandatory: %s", securityMessage),
           logger->error(Logr::Error, securityMessage, "PowerDNS DNSDist Security Update Mandatory", "status", Logging::Loggable(securityStatus)));
    }

    dnsdist::metrics::g_stats.securityStatus = securityStatus;
    s_secPollDone = true;
    return;
  }
  catch (const std::exception& exp) {
    if (releaseVersion) {
      SLOG(warnlog("Error while retrieving the security update for version %s: %s", version, exp.what()),
           logger->error(Logr::Warning, exp.what(), "Error while retrieving the security status"));
    }
    else if (!s_secPollDone) {
      SLOG(infolog("Error while retrieving the security update for version %s: %s", version, exp.what()),
           logger->error(Logr::Info, exp.what(), "Error while retrieving the security status"));
    }
  }

  if (releaseVersion) {
    SLOG(warnlog("Failed to retrieve security status update for '%s' on %s", pkgv, queriedName),
         logger->info(Logr::Warning, "Failed to retrieve security status"));
  }
  else if (!s_secPollDone) {
    SLOG(infolog("Not validating response for security status update, this is a non-release version."),
         logger->info(Logr::Info, "Not validating response for security status update, this is a non-release version."));
    /* for non-released versions, there is no use sending the same message several times,
       let's just accept that there will be no security polling for this exact version */
    s_secPollDone = true;
  }
}
}

#endif /* DISABLE_SECPOLL */
