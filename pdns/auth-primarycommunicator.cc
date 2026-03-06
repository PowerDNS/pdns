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
#include "auth-caches.hh"
#include "auth-zonecache.hh"
#include "utility.hh"
#include <cerrno>
#include "communicator.hh"
#include <set>
#include <boost/utility.hpp>

#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "packethandler.hh"
#include "nameserver.hh"
#include "resolver.hh"
#include "logger.hh"
#include "dns.hh"
#include "arguments.hh"
#include "packetcache.hh"
#include "base64.hh"
#include "namespaces.hh"
#include "query-local-address.hh"

void CommunicatorClass::queueNotifyDomain(const DomainInfo& di, UeberBackend* B)
{
  bool hasQueuedItem = false;
  set<string> ips;
  set<DNSName> nsset;
  DNSZoneRecord rr;
  FindNS fns;

  try {
    if (d_onlyNotify.size()) {
      B->lookup(QType(QType::NS), di.zone.operator const DNSName&(), di.id);
      while (B->get(rr))
        nsset.insert(getRR<NSRecordContent>(rr.dr)->getNS());

      for (const auto& ns : nsset) {
        vector<string> nsips = fns.lookup(ns, B);
        if (nsips.empty()) {
          SLOG(g_log << Logger::Warning << "Unable to queue notification of domain '" << di.zone << "' to nameserver '" << ns << "': nameserver does not resolve!" << endl,
               d_slog->info(Logr::Warning, "Unable to queue notification, nameserver does not resolve!", "domain", Logging::Loggable(di.zone), "nameserver", Logging::Loggable(ns)));
        }
        else {
          for (const auto& nsip : nsips) {
            const ComboAddress caIp(nsip, 53);
            if (!d_preventSelfNotification || !AddressIsUs(caIp)) {
              if (!d_onlyNotify.match(&caIp)) {
                SLOG(g_log << Logger::Notice << "Skipped notification of domain '" << di.zone << "' to " << ns << " because " << caIp << " does not match only-notify." << endl,
                     d_slog->info(Logr::Notice, "Skipped notification because address does not match only-notify", "domain", Logging::Loggable(di.zone), "nameserver", Logging::Loggable(ns), "address", Logging::Loggable(caIp)));
              }
              else {
                ips.insert(caIp.toStringWithPort());
              }
            }
          }
        }
      }

      for (const auto& ip : ips) {
        SLOG(g_log << Logger::Notice << "Queued notification of domain '" << di.zone << "' to " << ip << endl,
             d_slog->info(Logr::Notice, "Queued notification", "domain", Logging::Loggable(di.zone), "address", Logging::Loggable(ip)));
        d_nq.add(di.zone, ip, d_delayNotifications);
        hasQueuedItem = true;
      }
    }
  }
  catch (PDNSException& ae) {
    SLOG(g_log << Logger::Error << "Error looking up name servers for " << di.zone << ", cannot notify: " << ae.reason << endl,
         d_slog->error(Logr::Error, ae.reason, "Error looking up name servers, cannot notify", "domain", Logging::Loggable(di.zone)));
    return;
  }
  catch (std::exception& e) {
    SLOG(g_log << Logger::Error << "Error looking up name servers for " << di.zone << ", cannot notify: " << e.what() << endl,
         d_slog->error(Logr::Error, e.what(), "Error looking up name servers, cannot notify", "domain", Logging::Loggable(di.zone)));
    return;
  }

  set<string> alsoNotify(d_alsoNotify);
  B->alsoNotifies(di.zone, &alsoNotify);

  for (const auto& j : alsoNotify) {
    try {
      const ComboAddress caIp(j, 53);
      SLOG(g_log << Logger::Notice << "Queued also-notification of domain '" << di.zone << "' to " << caIp.toStringWithPort() << endl,
           d_slog->info(Logr::Notice, "Queued also-notification", "domain", Logging::Loggable(di.zone), "target", Logging::Loggable(caIp.toStringWithPort())));
      if (!ips.count(caIp.toStringWithPort())) {
        ips.insert(caIp.toStringWithPort());
        d_nq.add(di.zone, caIp.toStringWithPort(), d_delayNotifications);
      }
      hasQueuedItem = true;
    }
    catch (PDNSException& e) {
      SLOG(g_log << Logger::Warning << "Unparseable IP in ALSO-NOTIFY metadata of domain '" << di.zone << "'. Warning: " << e.reason << endl,
           d_slog->error(Logr::Warning, e.reason, "Unparseable IP in ALSO-NOTIFY metadata", "domain", Logging::Loggable(di.zone)));
    }
  }

  if (!hasQueuedItem) {
    SLOG(g_log << Logger::Warning << "Request to queue notification for domain '" << di.zone << "' was processed, but no valid nameservers or ALSO-NOTIFYs found. Not notifying!" << endl,
         d_slog->info(Logr::Warning, "Request to queue notification was processed, but no valid nameservers or ALSO-NOTIFYs found. Not notifying!", "domain", Logging::Loggable(di.zone)));
  }
}

bool CommunicatorClass::notifyDomain(const ZoneName& domain, UeberBackend* ueber)
{
  DomainInfo di;
  if (!ueber->getDomainInfo(domain, di)) {
    SLOG(g_log << Logger::Warning << "No such domain '" << domain << "' in our database" << endl,
         d_slog->info(Logr::Warning, "No such domain in our database", "domain", Logging::Loggable(domain)));
    return false;
  }
  queueNotifyDomain(di, ueber);
  // call backend and tell them we sent out the notification - even though that is premature
  if (di.serial != di.notified_serial)
    di.backend->setNotified(di.id, di.serial);

  return true;
}

void NotificationQueue::dump()
{
  cerr << "Waiting for notification responses: " << endl;
  for (NotificationRequest& nr : d_nqueue) {
    cerr << nr.domain << ", " << nr.ip << endl;
  }
}

void CommunicatorClass::getUpdatedProducers(UeberBackend* B, vector<DomainInfo>& domains, const std::unordered_set<DNSName>& catalogs, CatalogHashMap& catalogHashes)
{
  std::string metaHash;
  std::string mapHash;
  for (auto& ch : catalogHashes) {
    if (catalogs.count(ch.first.operator const DNSName&()) == 0) {
      SLOG(g_log << Logger::Warning << "orphaned member zones found with catalog '" << ch.first << "'" << endl,
           d_slog->info(Logr::Warning, "orphaned member zones found with catalog", "catalog", Logging::Loggable(ch.first)));
      continue;
    }

    if (!B->getDomainMetadata(ch.first, "CATALOG-HASH", metaHash)) {
      metaHash.clear();
    }

    mapHash = Base64Encode(ch.second.digest());
    if (mapHash != metaHash) {
      DomainInfo di;
      if (B->getDomainInfo(ch.first, di)) {
        if (di.kind != DomainInfo::Producer) {
          SLOG(g_log << Logger::Warning << "zone '" << di.zone << "' is no producer zone" << endl,
               d_slog->info(Logr::Warning, "zone is no producer zone", "zone", Logging::Loggable(di.zone)));
          continue;
        }

        B->setDomainMetadata(di.zone, "CATALOG-HASH", mapHash);

        SLOG(g_log << Logger::Warning << "new CATALOG-HASH '" << mapHash << "' for zone '" << di.zone << "'" << endl,
             d_slog->info(Logr::Warning, "new CATALOG-HASH for zone", "zone", Logging::Loggable(di.zone), "hash", Logging::Loggable(mapHash)));

        SOAData sd;
        if (!B->getSOAUncached(di.zone, sd)) {
          SLOG(g_log << Logger::Warning << "SOA lookup failed for producer zone '" << di.zone << "'" << endl,
               d_slog->info(Logr::Warning, "SOA lookup failed for producer zone", "zone", Logging::Loggable(di.zone)));
          continue;
        }

        DNSResourceRecord rr;
        makeIncreasedSOARecord(sd, "EPOCH", "", rr, d_slog);
        di.backend->startTransaction(sd.zonename, UnknownDomainID);
        if (!di.backend->replaceRRSet(di.id, rr.qname, rr.qtype, vector<DNSResourceRecord>(1, rr))) {
          di.backend->abortTransaction();
          throw PDNSException("backend hosting producer zone '" + sd.zonename.toLogString() + "' does not support editing records");
        }
        di.backend->commitTransaction();

        domains.emplace_back(di);
      }
    }
  }
}

void CommunicatorClass::primaryUpdateCheck(PacketHandler* P)
{
  if (!::arg().mustDo("primary"))
    return;

  UeberBackend* B = P->getBackend();
  vector<DomainInfo> cmdomains;
  std::unordered_set<DNSName> catalogs;
  CatalogHashMap catalogHashes;
  B->getUpdatedPrimaries(cmdomains, catalogs, catalogHashes);
  getUpdatedProducers(B, cmdomains, catalogs, catalogHashes);

  if (cmdomains.empty()) {
    SLOG(g_log << Logger::Info << "no primary or producer domains need notifications" << endl,
         d_slog->info(Logr::Info, "no primary or producer domain needs notifications"));
  }
  else {
    SLOG(g_log << Logger::Info << cmdomains.size() << " domain" << addS(cmdomains.size()) << " for which we are primary or producer need" << addS(cmdomains.size()) << " notifications" << endl,
         d_slog->info(Logr::Info, "domains for which we are primary or producer in need of notification", "count", Logging::Loggable(cmdomains.size())));
  }

  for (auto& di : cmdomains) {
    // VIEWS TODO: if this zone has a variant, try to figure out which
    // views contain it, and purge these views only.
    purgeAuthCachesExact(di.zone.operator const DNSName&());
    g_zoneCache.add(di.zone, di.id);
    queueNotifyDomain(di, B);
    di.backend->setNotified(di.id, di.serial);
  }
}

time_t CommunicatorClass::doNotifications(PacketHandler* P)
{
  UeberBackend* B = P->getBackend();
  ComboAddress from;
  char buffer[1500];
  int sock;
  set<int> fds = {d_nsock4, d_nsock6};

  // receive incoming notifications on the nonblocking socket and take them off the list
  while (waitForMultiData(fds, 0, 0, &sock) > 0) {
    Utility::socklen_t fromlen = sizeof(from);
    const auto size = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &fromlen);
    if (size < 0) {
      break;
    }
    DNSPacket p(d_slog, true);

    p.setRemote(&from);

    if (p.parse(buffer, (size_t)size) < 0) {
      SLOG(g_log << Logger::Warning << "Unable to parse SOA notification answer from " << p.getRemote() << endl,
           d_slog->info(Logr::Warning, "Unable to parse SOA notification answer", "remote", Logging::Loggable(p.getRemote())));
      continue;
    }

    if (p.d.rcode) {
      SLOG(g_log << Logger::Warning << "Received unsuccessful notification report for '" << p.qdomain << "' from " << from.toStringWithPort() << ", error: " << RCode::to_s(p.d.rcode) << endl,
           d_slog->error(Logr::Warning, RCode::to_s(p.d.rcode), "Received unsucessful notification report", "domain", Logging::Loggable(p.qdomain), "remote", Logging::Loggable(from.toStringWithPort())));
    }

    if (d_nq.removeIf(from, p.d.id, ZoneName(p.qdomain))) {
      SLOG(g_log << Logger::Notice << "Removed from notification list: '" << p.qdomain << "' to " << from.toStringWithPort() << " " << (p.d.rcode ? RCode::to_s(p.d.rcode) : "(was acknowledged)") << endl,
           d_slog->info(Logr::Notice, "Removed from notification list", "domain", Logging::Loggable(p.qdomain), "remote", Logging::Loggable(from.toStringWithPort()), "result", Logging::Loggable(p.d.rcode != RCode::NoError ? RCode::to_s(p.d.rcode) : "acknowledged")));
    }
    else {
      SLOG(g_log << Logger::Warning << "Received spurious notify answer for '" << p.qdomain << "' from " << from.toStringWithPort() << endl,
           d_slog->info(Logr::Warning, "Received spurious notify answer", "domain", Logging::Loggable(p.qdomain), "remote", Logging::Loggable(from.toStringWithPort())));
#if 0
      d_nq.dump();
#endif
    }
  }

  // send out possible new notifications
  ZoneName domain;
  string ip;
  uint16_t id = 0;

  bool purged;
  while (d_nq.getOne(domain, ip, &id, purged)) {
    if (!purged) {
      try {
        ComboAddress remote(ip, 53); // default to 53
        if ((d_nsock6 < 0 && remote.sin4.sin_family == AF_INET6) || (d_nsock4 < 0 && remote.sin4.sin_family == AF_INET)) {
          SLOG(g_log << Logger::Warning << "Unable to notify " << remote.toStringWithPort() << " for domain '" << domain << "', address family is disabled. Is an IPv" << (remote.sin4.sin_family == AF_INET ? "4" : "6") << " address set in query-local-address?" << endl,
               d_slog->info(Logr::Warning, "Unable to notify due to address family being disabled. Check query-local-address for an address of the proper family", "domain", Logging::Loggable(domain), "remote", Logging::Loggable(remote.toStringWithPort()), "address family", Logging::Loggable(remote.sin4.sin_family == AF_INET ? 4 : 6)));
          d_nq.removeIf(remote, id, domain); // Remove, we'll never be able to notify
          continue; // don't try to notify what we can't!
        }
        if (d_preventSelfNotification && AddressIsUs(remote)) {
          continue;
        }

	CommunicatorClass::sendNotification(remote.sin4.sin_family == AF_INET ? d_nsock4 : d_nsock6, domain, remote, id, B);
        drillHole(domain, ip);
      }
      catch (ResolverException& re) {
        SLOG(g_log << Logger::Warning << "Error trying to resolve '" << ip << "' for notifying '" << domain << "' to server: " << re.reason << endl,
             d_slog->error(Logr::Warning, re.reason, "Error trying to resolve remote server for notifying", "domain", Logging::Loggable(domain), "remote", Logging::Loggable(ip)));
      }
    }
    else {
      SLOG(g_log << Logger::Warning << "Notification for " << domain << " to " << ip << " failed after retries" << endl,
           d_slog->info(Logr::Warning, "Notification failed after retries", "domain", Logging::Loggable(domain), "remote", Logging::Loggable(ip)));
    }
  }

  return d_nq.earliest();
}

void CommunicatorClass::sendNotification(int sock, const ZoneName& domain, const ComboAddress& remote, uint16_t notificationId, UeberBackend* ueber)
{
  vector<string> meta;
  DNSName tsigkeyname;
  DNSName tsigalgorithm;
  string tsigsecret64;
  string tsigsecret;

  if (::arg().mustDo("send-signed-notify") && ueber->getDomainMetadata(domain, "TSIG-ALLOW-AXFR", meta) && !meta.empty()) {
    tsigkeyname = DNSName(meta[0]);
  }

  vector<uint8_t> packet;
  DNSPacketWriter pwriter(packet, domain.operator const DNSName&(), QType::SOA, 1, Opcode::Notify);
  pwriter.getHeader()->id = notificationId;
  pwriter.getHeader()->aa = true;

  if (tsigkeyname.empty() == false) {
    if (!ueber->getTSIGKey(tsigkeyname, tsigalgorithm, tsigsecret64)) {
      SLOG(g_log << Logger::Error << "TSIG key '" << tsigkeyname << "' for domain '" << domain << "' not found" << endl,
           d_slog->info(Logr::Error, "TSIG key not found", "domain", Logging::Loggable(domain), "key", Logging::Loggable(tsigkeyname)));
      return;
    }
    TSIGRecordContent trc;
    if (tsigalgorithm == g_hmacmd5dnsname) {
      trc.d_algoName = g_hmacmd5dnsname_long;
    }
    else {
      trc.d_algoName = std::move(tsigalgorithm);
    }
    trc.d_time = time(nullptr);
    trc.d_fudge = 300;
    trc.d_origID = ntohs(notificationId);
    trc.d_eRcode = 0;
    if (B64Decode(tsigsecret64, tsigsecret) == -1) {
      SLOG(g_log << Logger::Error << "Unable to Base-64 decode TSIG key '" << tsigkeyname << "' for domain '" << domain << "'" << endl,
           d_slog->info(Logr::Error, "Unable to Base-64 decode TSIG key", "domain", Logging::Loggable(domain), "key", Logging::Loggable(tsigkeyname)));
      return;
    }
    addTSIG(d_slog, pwriter, trc, tsigkeyname, tsigsecret, "", false);
  }

  if (sendto(sock, &packet[0], packet.size(), 0, (struct sockaddr*)(&remote), remote.getSocklen()) < 0) {
    throw ResolverException("Unable to send notify to " + remote.toStringWithPort() + ": " + stringerror());
  }
}

void CommunicatorClass::drillHole(const ZoneName& domain, const string& ipAddress)
{
  (*d_holes.lock())[pair(domain, ipAddress)] = time(nullptr);
}

bool CommunicatorClass::justNotified(const ZoneName& domain, const string& ipAddress)
{
  auto holes = d_holes.lock();
  auto iter = holes->find(pair(domain, ipAddress));
  if (iter == holes->end()) {
    // no hole
    return false;
  }

  if (iter->second > time(nullptr) - 900) {
    // recent hole
    return true;
  }

  // do we want to purge this? XXX FIXME
  return false;
}

void CommunicatorClass::makeNotifySockets()
{
  if (pdns::isQueryLocalAddressFamilyEnabled(AF_INET)) {
    d_nsock4 = makeQuerySocket(pdns::getQueryLocalAddress(AF_INET, 0), true, ::arg().mustDo("non-local-bind"));
  }
  else {
    d_nsock4 = -1;
  }
  if (pdns::isQueryLocalAddressFamilyEnabled(AF_INET6)) {
    d_nsock6 = makeQuerySocket(pdns::getQueryLocalAddress(AF_INET6, 0), true, ::arg().mustDo("non-local-bind"));
  }
  else {
    d_nsock6 = -1;
  }
}

void CommunicatorClass::notify(const ZoneName& domain, const string& ipAddress)
{
  d_nq.add(domain, ipAddress);
}
