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
      B->lookup(QType(QType::NS), di.zone, di.id);
      while (B->get(rr))
        nsset.insert(getRR<NSRecordContent>(rr.dr)->getNS());

      for (const auto& ns : nsset) {
        vector<string> nsips = fns.lookup(ns, B);
        if (nsips.empty())
          g_log << Logger::Warning << "Unable to queue notification of domain '" << di.zone << "' to nameserver '" << ns << "': nameserver does not resolve!" << endl;
        else
          for (const auto& nsip : nsips) {
            const ComboAddress caIp(nsip, 53);
            if (!d_preventSelfNotification || !AddressIsUs(caIp)) {
              if (!d_onlyNotify.match(&caIp))
                g_log << Logger::Notice << "Skipped notification of domain '" << di.zone << "' to " << ns << " because " << caIp << " does not match only-notify." << endl;
              else
                ips.insert(caIp.toStringWithPort());
            }
          }
      }

      for (const auto& ip : ips) {
        g_log << Logger::Notice << "Queued notification of domain '" << di.zone << "' to " << ip << endl;
        d_nq.add(di.zone, ip, d_delayNotifications);
        hasQueuedItem = true;
      }
    }
  }
  catch (PDNSException& ae) {
    g_log << Logger::Error << "Error looking up name servers for " << di.zone << ", cannot notify: " << ae.reason << endl;
    return;
  }
  catch (std::exception& e) {
    g_log << Logger::Error << "Error looking up name servers for " << di.zone << ", cannot notify: " << e.what() << endl;
    return;
  }

  set<string> alsoNotify(d_alsoNotify);
  B->alsoNotifies(di.zone, &alsoNotify);

  for (const auto& j : alsoNotify) {
    try {
      const ComboAddress caIp(j, 53);
      g_log << Logger::Notice << "Queued also-notification of domain '" << di.zone << "' to " << caIp.toStringWithPort() << endl;
      if (!ips.count(caIp.toStringWithPort())) {
        ips.insert(caIp.toStringWithPort());
        d_nq.add(di.zone, caIp.toStringWithPort(), d_delayNotifications);
      }
      hasQueuedItem = true;
    }
    catch (PDNSException& e) {
      g_log << Logger::Warning << "Unparseable IP in ALSO-NOTIFY metadata of domain '" << di.zone << "'. Warning: " << e.reason << endl;
    }
  }

  if (!hasQueuedItem)
    g_log << Logger::Warning << "Request to queue notification for domain '" << di.zone << "' was processed, but no valid nameservers or ALSO-NOTIFYs found. Not notifying!" << endl;
}

bool CommunicatorClass::notifyDomain(const DNSName& domain, UeberBackend* B)
{
  DomainInfo di;
  if (!B->getDomainInfo(domain, di)) {
    g_log << Logger::Warning << "No such domain '" << domain << "' in our database" << endl;
    return false;
  }
  queueNotifyDomain(di, B);
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
    if (!catalogs.count(ch.first)) {
      g_log << Logger::Warning << "orphaned member zones found with catalog '" << ch.first << "'" << endl;
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
          g_log << Logger::Warning << "zone '" << di.zone << "' is no producer zone" << endl;
          continue;
        }

        B->setDomainMetadata(di.zone, "CATALOG-HASH", mapHash);

        g_log << Logger::Warning << "new CATALOG-HASH '" << mapHash << "' for zone '" << di.zone << "'" << endl;

        SOAData sd;
        if (!B->getSOAUncached(di.zone, sd)) {
          g_log << Logger::Warning << "SOA lookup failed for producer zone '" << di.zone << "'" << endl;
          continue;
        }

        DNSResourceRecord rr;
        makeIncreasedSOARecord(sd, "EPOCH", "", rr);
        di.backend->startTransaction(sd.qname, -1);
        if (!di.backend->replaceRRSet(di.id, rr.qname, rr.qtype, vector<DNSResourceRecord>(1, rr))) {
          di.backend->abortTransaction();
          throw PDNSException("backend hosting producer zone '" + sd.qname.toLogString() + "' does not support editing records");
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
    g_log << Logger::Info << "no primary or producer domains need notifications" << endl;
  }
  else {
    g_log << Logger::Info << cmdomains.size() << " domain" << addS(cmdomains.size()) << " for which we are primary or producer need" << addS(cmdomains.size()) << " notifications" << endl;
  }

  for (auto& di : cmdomains) {
    purgeAuthCachesExact(di.zone);
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
    DNSPacket p(true);

    p.setRemote(&from);

    if (p.parse(buffer, (size_t)size) < 0) {
      g_log << Logger::Warning << "Unable to parse SOA notification answer from " << p.getRemote() << endl;
      continue;
    }

    if (p.d.rcode) {
      g_log << Logger::Warning << "Received unsuccessful notification report for '" << p.qdomain << "' from " << from.toStringWithPort() << ", error: " << RCode::to_s(p.d.rcode) << endl;
    }

    if (d_nq.removeIf(from, p.d.id, p.qdomain)) {
      g_log << Logger::Notice << "Removed from notification list: '" << p.qdomain << "' to " << from.toStringWithPort() << " " << (p.d.rcode ? RCode::to_s(p.d.rcode) : "(was acknowledged)") << endl;
    }
    else {
      g_log << Logger::Warning << "Received spurious notify answer for '" << p.qdomain << "' from " << from.toStringWithPort() << endl;
      // d_nq.dump();
    }
  }

  // send out possible new notifications
  DNSName domain;
  string ip;
  uint16_t id = 0;

  bool purged;
  while (d_nq.getOne(domain, ip, &id, purged)) {
    if (!purged) {
      try {
        ComboAddress remote(ip, 53); // default to 53
        if ((d_nsock6 < 0 && remote.sin4.sin_family == AF_INET6) || (d_nsock4 < 0 && remote.sin4.sin_family == AF_INET)) {
          g_log << Logger::Warning << "Unable to notify " << remote.toStringWithPort() << " for domain '" << domain << "', address family is disabled. Is an IPv" << (remote.sin4.sin_family == AF_INET ? "4" : "6") << " address set in query-local-address?" << endl;
          d_nq.removeIf(remote, id, domain); // Remove, we'll never be able to notify
          continue; // don't try to notify what we can't!
        }
        if (d_preventSelfNotification && AddressIsUs(remote)) {
          continue;
        }

        sendNotification(remote.sin4.sin_family == AF_INET ? d_nsock4 : d_nsock6, domain, remote, id, B);
        drillHole(domain, ip);
      }
      catch (ResolverException& re) {
        g_log << Logger::Warning << "Error trying to resolve '" << ip << "' for notifying '" << domain << "' to server: " << re.reason << endl;
      }
    }
    else {
      g_log << Logger::Warning << "Notification for " << domain << " to " << ip << " failed after retries" << endl;
    }
  }

  return d_nq.earliest();
}

void CommunicatorClass::sendNotification(int sock, const DNSName& domain, const ComboAddress& remote, uint16_t id, UeberBackend* B)
{
  vector<string> meta;
  DNSName tsigkeyname;
  DNSName tsigalgorithm;
  string tsigsecret64;
  string tsigsecret;

  if (::arg().mustDo("send-signed-notify") && B->getDomainMetadata(domain, "TSIG-ALLOW-AXFR", meta) && meta.size() > 0) {
    tsigkeyname = DNSName(meta[0]);
  }

  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, domain, QType::SOA, 1, Opcode::Notify);
  pw.getHeader()->id = id;
  pw.getHeader()->aa = true;

  if (tsigkeyname.empty() == false) {
    if (!B->getTSIGKey(tsigkeyname, tsigalgorithm, tsigsecret64)) {
      g_log << Logger::Error << "TSIG key '" << tsigkeyname << "' for domain '" << domain << "' not found" << endl;
      return;
    }
    TSIGRecordContent trc;
    if (tsigalgorithm.toStringNoDot() == "hmac-md5")
      trc.d_algoName = DNSName(tsigalgorithm.toStringNoDot() + ".sig-alg.reg.int.");
    else
      trc.d_algoName = tsigalgorithm;
    trc.d_time = time(nullptr);
    trc.d_fudge = 300;
    trc.d_origID = ntohs(id);
    trc.d_eRcode = 0;
    if (B64Decode(tsigsecret64, tsigsecret) == -1) {
      g_log << Logger::Error << "Unable to Base-64 decode TSIG key '" << tsigkeyname << "' for domain '" << domain << "'" << endl;
      return;
    }
    addTSIG(pw, trc, tsigkeyname, tsigsecret, "", false);
  }

  if (sendto(sock, &packet[0], packet.size(), 0, (struct sockaddr*)(&remote), remote.getSocklen()) < 0) {
    throw ResolverException("Unable to send notify to " + remote.toStringWithPort() + ": " + stringerror());
  }
}

void CommunicatorClass::drillHole(const DNSName& domain, const string& ip)
{
  (*d_holes.lock())[pair(domain, ip)] = time(nullptr);
}

bool CommunicatorClass::justNotified(const DNSName& domain, const string& ip)
{
  auto holes = d_holes.lock();
  auto it = holes->find(pair(domain, ip));
  if (it == holes->end()) {
    // no hole
    return false;
  }

  if (it->second > time(nullptr) - 900) {
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

void CommunicatorClass::notify(const DNSName& domain, const string& ip)
{
  d_nq.add(domain, ip);
}
