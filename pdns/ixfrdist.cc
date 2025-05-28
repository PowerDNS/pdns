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
#include "dns.hh"
#include "dnsparser.hh"
#include <stdexcept>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/program_options.hpp>
#include <arpa/inet.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <mutex>
#include <thread>
#include "threadname.hh"
#include <dirent.h>
#include <queue>
#include <condition_variable>
#include <thread>
#include <chrono>
#include "ixfr.hh"
#include "ixfrutils.hh"
#include "axfr-retriever.hh"
#include "dns_random.hh"
#include "sstuff.hh"
#include "mplexer.hh"
#include "misc.hh"
#include "iputils.hh"
#include "lock.hh"
#include "communicator.hh"
#include "query-local-address.hh"
#include "logger.hh"
#include "ixfrdist-stats.hh"
#include "ixfrdist-web.hh"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop
#include "auth-packetcache.hh"
#include "auth-querycache.hh"
#include "auth-zonecache.hh"

/* BEGIN Needed because of deeper dependencies */
#include "arguments.hh"
#include "statbag.hh"
StatBag S;
// NOLINTNEXTLINE(readability-identifier-length)
AuthPacketCache PC;
// NOLINTNEXTLINE(readability-identifier-length)
AuthQueryCache QC;
AuthZoneCache g_zoneCache;

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}
/* END Needed because of deeper dependencies */

// Allows reading/writing ComboAddresses and ZoneNames in YAML-cpp
namespace YAML {
template<>
struct convert<ComboAddress> {
  static Node encode(const ComboAddress& rhs) {
    return Node(rhs.toStringWithPort());
  }
  static bool decode(const Node& node, ComboAddress& rhs) {
    if (!node.IsScalar()) {
      return false;
    }
    try {
      rhs = ComboAddress(node.as<string>(), 53);
      return true;
    } catch(const runtime_error &e) {
      return false;
    } catch (const PDNSException &e) {
      return false;
    }
  }
};

template<>
struct convert<ZoneName> {
  static Node encode(const ZoneName& rhs) {
    return Node(rhs.toStringRootDot());
  }
  static bool decode(const Node& node, ZoneName& rhs) {
    if (!node.IsScalar()) {
      return false;
    }
    try {
      rhs = ZoneName(node.as<string>());
      return true;
    } catch(const runtime_error &e) {
      return false;
    } catch (const PDNSException &e) {
      return false;
    }
  }
};

template<>
struct convert<Netmask> {
  static Node encode(const Netmask& rhs) {
    return Node(rhs.toString());
  }
  static bool decode(const Node& node, Netmask& rhs) {
    if (!node.IsScalar()) {
      return false;
    }
    try {
      rhs = Netmask(node.as<string>());
      return true;
    } catch(const runtime_error &e) {
      return false;
    } catch (const PDNSException &e) {
      return false;
    }
  }
};
} // namespace YAML

struct ixfrdiff_t {
  shared_ptr<const SOARecordContent> oldSOA;
  shared_ptr<const SOARecordContent> newSOA;
  vector<DNSRecord> removals;
  vector<DNSRecord> additions;
  uint32_t oldSOATTL;
  uint32_t newSOATTL;
};

struct ixfrinfo_t {
  shared_ptr<const SOARecordContent> soa; // The SOA of the latest AXFR
  records_t latestAXFR;             // The most recent AXFR
  vector<std::shared_ptr<ixfrdiff_t>> ixfrDiffs;
  uint32_t soaTTL;
};

// Why a struct? This way we can add more options to a domain in the future
struct ixfrdistdomain_t {
  set<ComboAddress> primaries; // A set so we can do multiple primary addresses in the future
  std::set<ComboAddress> notify; // Set of addresses to forward NOTIFY to
  uint32_t maxSOARefresh{0}; // Cap SOA refresh value to the given value in seconds
};

// This contains the configuration for each domain
static map<ZoneName, ixfrdistdomain_t> g_domainConfigs;

// Map domains and their data
static LockGuarded<std::map<ZoneName, std::shared_ptr<ixfrinfo_t>>> g_soas;

// Queue of received NOTIFYs, already verified against their primary IPs
// Lazily implemented as a set
static LockGuarded<std::set<ZoneName>> g_notifiesReceived;

// Queue of outgoing NOTIFY
static LockGuarded<NotificationQueue> g_notificationQueue;

// Condition variable for TCP handling
static std::condition_variable g_tcpHandlerCV;
static std::queue<pair<int, ComboAddress>> g_tcpRequestFDs;
static std::mutex g_tcpRequestFDsMutex;

namespace po = boost::program_options;

static bool g_exiting = false;

static NetmaskGroup g_acl;            // networks that can QUERY us
static NetmaskGroup g_notifySources;  // networks (well, IPs) that can NOTIFY us
static bool g_compress = false;

static ixfrdistStats g_stats;

// g_stats is static, so local to this file. But the webserver needs this info
string doGetStats() {
  return g_stats.getStats();
}

static void handleSignal(int signum) {
  g_log<<Logger::Notice<<"Got "<<strsignal(signum)<<" signal";
  if (g_exiting) {
    g_log<<Logger::Notice<<", this is the second time we were asked to stop, forcefully exiting"<<endl;
    exit(EXIT_FAILURE);
  }
  g_log<<Logger::Notice<<", stopping, this may take a few second due to in-progress transfers and cleanup. Send this signal again to forcefully stop"<<endl;
  g_exiting = true;
}

static void usage(po::options_description &desc) {
  cerr << "Usage: ixfrdist [OPTION]..."<<endl;
  cerr << desc << "\n";
}

// The compiler does not like using rfc1982LessThan in std::sort directly
static bool sortSOA(uint32_t i, uint32_t j) {
  return rfc1982LessThan(i, j);
}

static void cleanUpDomain(const ZoneName& domain, const uint16_t& keep, const string& workdir) {
  string dir = workdir + "/" + domain.toString();
  vector<uint32_t> zoneVersions;
  auto directoryError = pdns::visit_directory(dir, [&zoneVersions]([[maybe_unused]] ino_t inodeNumber, const std::string_view& name) {
    if (name != "." && name != "..") {
      try {
        auto version = pdns::checked_stoi<uint32_t>(std::string(name));
        zoneVersions.push_back(version);
      }
      catch (...) {
      }
    }
    return true;
  });

  if (directoryError) {
    return;
  }

  g_log<<Logger::Info<<"Found "<<zoneVersions.size()<<" versions of "<<domain<<", asked to keep "<<keep<<", ";
  if (zoneVersions.size() <= keep) {
    g_log<<Logger::Info<<"not cleaning up"<<endl;
    return;
  }
  g_log<<Logger::Info<<"cleaning up the oldest "<<zoneVersions.size() - keep<<endl;

  // Sort the versions
  std::sort(zoneVersions.begin(), zoneVersions.end(), sortSOA);

  // And delete all the old ones
  {
    // Lock to ensure no one reads this.
    auto lock = g_soas.lock();
    for (auto iter = zoneVersions.cbegin(); iter != zoneVersions.cend() - keep; ++iter) {
      string fname = dir + "/" + std::to_string(*iter);
      g_log<<Logger::Debug<<"Removing "<<fname<<endl;
      unlink(fname.c_str());
    }
  }
}

static void getSOAFromRecords(const records_t& records, shared_ptr<const SOARecordContent>& soa, uint32_t& soaTTL) {
  for (const auto& dnsrecord : records) {
    if (dnsrecord.d_type == QType::SOA) {
      soa = getRR<SOARecordContent>(dnsrecord);
      if (soa == nullptr) {
        throw PDNSException("Unable to determine SOARecordContent from old records");
      }
      soaTTL = dnsrecord.d_ttl;
      return;
    }
  }
  throw PDNSException("No SOA in supplied records");
}

static void makeIXFRDiff(const records_t& from, const records_t& to, std::shared_ptr<ixfrdiff_t>& diff, const shared_ptr<const SOARecordContent>& fromSOA = nullptr, uint32_t fromSOATTL=0, const shared_ptr<const SOARecordContent>& toSOA = nullptr, uint32_t toSOATTL = 0) {
  set_difference(from.cbegin(), from.cend(), to.cbegin(), to.cend(), back_inserter(diff->removals), from.value_comp());
  set_difference(to.cbegin(), to.cend(), from.cbegin(), from.cend(), back_inserter(diff->additions), from.value_comp());
  diff->oldSOA = fromSOA;
  diff->oldSOATTL = fromSOATTL;
  if (fromSOA == nullptr) {
    getSOAFromRecords(from, diff->oldSOA, diff->oldSOATTL);
  }
  diff->newSOA = toSOA;
  diff->newSOATTL = toSOATTL;
  if (toSOA == nullptr) {
    getSOAFromRecords(to, diff->newSOA, diff->newSOATTL);
  }
}

/* you can _never_ alter the content of the resulting shared pointer */
static std::shared_ptr<ixfrinfo_t> getCurrentZoneInfo(const ZoneName& domain)
{
  return (*g_soas.lock())[domain];
}

static void updateCurrentZoneInfo(const ZoneName& domain, std::shared_ptr<ixfrinfo_t>& newInfo)
{
  auto soas = g_soas.lock();
  (*soas)[domain] = newInfo;
  g_stats.setSOASerial(domain, newInfo->soa->d_st.serial);
  // FIXME: also report zone size?
}

static void sendNotification(int sock, const ZoneName& domain, const ComboAddress& remote, uint16_t notificationId)
{
  std::vector<std::string> meta;
  std::vector<uint8_t> packet;
  DNSPacketWriter packetWriter(packet, domain.operator const DNSName&(), QType::SOA, 1, Opcode::Notify);
  packetWriter.getHeader()->id = notificationId;
  packetWriter.getHeader()->aa = true;

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (sendto(sock, packet.data(), packet.size(), 0, reinterpret_cast<const struct sockaddr*>(&remote), remote.getSocklen()) < 0) {
    throw std::runtime_error("Unable to send notify to " + remote.toStringWithPort() + ": " + stringerror());
  }
}

static void communicatorReceiveNotificationAnswers(const int sock4, const int sock6)
{
  std::set<int> fds = {sock4};
  if (sock6 > 0) {
    fds.insert(sock6);
  }
  ComboAddress from;
  std::array<char, 1500> buffer{};
  int sock{-1};

  // receive incoming notification answers on the nonblocking sockets and take them off the list
  while (waitForMultiData(fds, 0, 0, &sock) > 0) {
    Utility::socklen_t fromlen = sizeof(from);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto size = recvfrom(sock, buffer.data(), buffer.size(), 0, reinterpret_cast<struct sockaddr*>(&from), &fromlen);
    if (size < 0) {
      break;
    }
    DNSPacket packet(true);
    packet.setRemote(&from);

    if (packet.parse(buffer.data(), (size_t)size) < 0) {
      g_log << Logger::Warning << "Unable to parse SOA notification answer from " << packet.getRemote() << endl;
      continue;
    }

    if (packet.d.rcode != 0) {
      g_log << Logger::Warning << "Received unsuccessful notification report for '" << packet.qdomain << "' from " << from.toStringWithPort() << ", error: " << RCode::to_s(packet.d.rcode) << endl;
    }

    if (g_notificationQueue.lock()->removeIf(from, packet.d.id, ZoneName(packet.qdomain))) {
      g_log << Logger::Notice << "Removed from notification list: '" << packet.qdomain << "' to " << from.toStringWithPort() << " " << (packet.d.rcode != 0 ? RCode::to_s(packet.d.rcode) : "(was acknowledged)") << endl;
    }
    else {
      g_log << Logger::Warning << "Received spurious notify answer for '" << packet.qdomain << "' from " << from.toStringWithPort() << endl;
    }
  }
}

static void communicatorSendNotifications(const int sock4, const int sock6)
{
  ZoneName domain;
  string destinationIp;
  uint16_t notificationId = 0;
  bool purged{false};

  while (g_notificationQueue.lock()->getOne(domain, destinationIp, &notificationId, purged)) {
    if (!purged) {
      ComboAddress remote(destinationIp, 53); // default to 53
      if (remote.sin4.sin_family == AF_INET) {
        sendNotification(sock4, domain, remote, notificationId);
      } else if (sock6 > 0) {
        sendNotification(sock6, domain, remote, notificationId);
      } else {
        g_log << Logger::Warning << "Unable to notify " << destinationIp << " for " << domain << " as v6 support is not enabled" << std::endl;
      }
    } else {
      g_log << Logger::Warning << "Notification for " << domain << " to " << destinationIp << " failed after retries" << std::endl;
    }
  }
}

static void communicatorThread()
{
  setThreadName("ixfrdist/communicator");
  auto sock4 = makeQuerySocket(pdns::getQueryLocalAddress(AF_INET, 0), true);
  auto sock6 = makeQuerySocket(pdns::getQueryLocalAddress(AF_INET6, 0), true);

  if (sock4 < 0) {
    throw std::runtime_error("Unable to create local query socket");
  }
  // sock6 can be negative if there is no v6 support, but this is handled later while sending notifications

  while (true) {
    if (g_exiting) {
      g_log << Logger::Notice << "Communicator thread stopped" << std::endl;
      break;
    }
    communicatorReceiveNotificationAnswers(sock4, sock6);
    communicatorSendNotifications(sock4, sock6);
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  if (sock4 >= 0) {
    closesocket(sock4);
  }
  if (sock6 >= 0) {
    closesocket(sock6);
  }
}

static void updateThread(const string& workdir, const uint16_t& keep, const uint16_t& axfrTimeout, const uint16_t& soaRetry, const uint32_t axfrMaxRecords) { // NOLINT(readability-function-cognitive-complexity) 13400 https://github.com/PowerDNS/pdns/issues/13400 Habbie:  ixfrdist: reduce complexity
  setThreadName("ixfrdist/update");
  std::map<ZoneName, time_t> lastCheck;

  // Initialize the serials we have
  for (const auto &domainConfig : g_domainConfigs) {
    ZoneName domain = domainConfig.first;
    lastCheck[domain] = 0;
    string dir = workdir + "/" + domain.toString();
    try {
      g_log<<Logger::Info<<"Trying to initially load domain "<<domain<<" from disk"<<endl;
      auto serial = getSerialFromDir(dir);
      shared_ptr<const SOARecordContent> soa;
      uint32_t soaTTL{0};
      {
        string fname = workdir + "/" + domain.toString() + "/" + std::to_string(serial);
        loadSOAFromDisk(domain, fname, soa, soaTTL);
        records_t records;
        if (soa == nullptr) {
          g_log<<Logger::Error<<"Could not load SOA from disk for zone "<<domain<<", removing file '"<<fname<<"'"<<endl;
          unlink(fname.c_str());
        }
        loadZoneFromDisk(records, fname, domain);
        auto zoneInfo = std::make_shared<ixfrinfo_t>();
        zoneInfo->latestAXFR = std::move(records);
        zoneInfo->soa = soa;
        zoneInfo->soaTTL = soaTTL;
        updateCurrentZoneInfo(domain, zoneInfo);
      }
      if (soa != nullptr) {
        g_log<<Logger::Notice<<"Loaded zone "<<domain<<" with serial "<<soa->d_st.serial<<endl;
        // Initial cleanup
        cleanUpDomain(domain, keep, workdir);
      }
    } catch (runtime_error &e) {
      // Most likely, the directory does not exist.
      g_log<<Logger::Info<<e.what()<<", attempting to create"<<endl;
      // Attempt to create it, if _that_ fails, there is no hope
      if (mkdir(dir.c_str(), 0777) == -1 && errno != EEXIST) {
        g_log<<Logger::Error<<"Could not create '"<<dir<<"': "<<stringerror()<<endl;
        _exit(EXIT_FAILURE);
      }
    }
  }

  g_log<<Logger::Notice<<"Update Thread started"<<endl;

  while (true) {
    if (g_exiting) {
      g_log<<Logger::Notice<<"UpdateThread stopped"<<endl;
      break;
    }
    time_t now = time(nullptr);
    for (const auto &domainConfig : g_domainConfigs) {

      if (g_exiting) {
        break;
      }

      ZoneName domain = domainConfig.first;
      shared_ptr<const SOARecordContent> current_soa;
      const auto& zoneInfo = getCurrentZoneInfo(domain);
      if (zoneInfo != nullptr) {
        current_soa = zoneInfo->soa;
      }

      auto& zoneLastCheck = lastCheck[domain];
      uint32_t refresh = soaRetry; // default if we don't get an update at all
      if (current_soa != nullptr) {
        // Check every `refresh` seconds as advertised in the SOA record
        refresh = current_soa->d_st.refresh;
        if (domainConfig.second.maxSOARefresh > 0) {
          // Cap refresh value to the configured one if any
          refresh = std::min(refresh, domainConfig.second.maxSOARefresh);
        }
      }


      if (now - zoneLastCheck < refresh && g_notifiesReceived.lock()->erase(domain) == 0) {
        continue;
      }

      // TODO Keep track of 'down' primaries
      set<ComboAddress>::const_iterator it(domainConfig.second.primaries.begin());
      std::advance(it, dns_random(domainConfig.second.primaries.size()));
      ComboAddress primary = *it;

      string dir = workdir + "/" + domain.toString();
      g_log << Logger::Info << "Attempting to retrieve SOA Serial update for '" << domain << "' from '" << primary.toStringWithPort() << "'" << endl;
      shared_ptr<const SOARecordContent> sr;
      try {
        zoneLastCheck = now;
        g_stats.incrementSOAChecks(domain);
        auto newSerial = getSerialFromPrimary(primary, domain, sr); // TODO TSIG
        if(current_soa != nullptr) {
          g_log << Logger::Info << "Got SOA Serial for " << domain << " from " << primary.toStringWithPort() << ": " << newSerial << ", had Serial: " << current_soa->d_st.serial;
          if (newSerial == current_soa->d_st.serial) {
            g_log<<Logger::Info<<", not updating."<<endl;
            continue;
          }
          g_log<<Logger::Info<<", will update."<<endl;
        }
      } catch (runtime_error &e) {
        g_log << Logger::Warning << "Unable to get SOA serial update for '" << domain << "' from primary " << primary.toStringWithPort() << ": " << e.what() << endl;
        g_stats.incrementSOAChecksFailed(domain);
        continue;
      }
      // Now get the full zone!
      g_log<<Logger::Info<<"Attempting to receive full zonedata for '"<<domain<<"'"<<endl;
      ComboAddress local = primary.isIPv4() ? ComboAddress("0.0.0.0") : ComboAddress("::");
      TSIGTriplet tt;

      // The *new* SOA
      shared_ptr<const SOARecordContent> soa;
      uint32_t soaTTL = 0;
      records_t records;
      try {
        AXFRRetriever axfr(primary, domain, tt, &local);
        uint32_t nrecords=0;
        Resolver::res_t nop;
        vector<DNSRecord> chunk;
        time_t t_start = time(nullptr);
        time_t axfr_now = time(nullptr);
        while(axfr.getChunk(nop, &chunk, (axfr_now - t_start + axfrTimeout))) {
          for(auto& dr : chunk) {
            if(dr.d_type == QType::TSIG)
              continue;
            if(!dr.d_name.isPartOf(domain)) {
              throw PDNSException("Out-of-zone data received during AXFR of "+domain.toLogString());
            }
            dr.d_name.makeUsRelative(domain);
            records.insert(dr);
            nrecords++;
            if (dr.d_type == QType::SOA) {
              soa = getRR<SOARecordContent>(dr);
              soaTTL = dr.d_ttl;
            }
          }
          if (axfrMaxRecords != 0 && nrecords > axfrMaxRecords) {
            throw PDNSException("Received more than " + std::to_string(axfrMaxRecords) + " records in AXFR, aborted");
          }
          axfr_now = time(nullptr);
          if (axfr_now - t_start > axfrTimeout) {
            g_stats.incrementAXFRFailures(domain);
            throw PDNSException("Total AXFR time exceeded!");
          }
        }
        if (soa == nullptr) {
          g_stats.incrementAXFRFailures(domain);
          g_log<<Logger::Warning<<"No SOA was found in the AXFR of "<<domain<<endl;
          continue;
        }
        g_log<<Logger::Notice<<"Retrieved all zone data for "<<domain<<". Received "<<nrecords<<" records."<<endl;
      } catch (PDNSException &e) {
        g_stats.incrementAXFRFailures(domain);
        g_log<<Logger::Warning<<"Could not retrieve AXFR for '"<<domain<<"': "<<e.reason<<endl;
        continue;
      } catch (runtime_error &e) {
        g_stats.incrementAXFRFailures(domain);
        g_log<<Logger::Warning<<"Could not retrieve AXFR for zone '"<<domain<<"': "<<e.what()<<endl;
        continue;
      }

      try {

        writeZoneToDisk(records, domain, dir);
        g_log<<Logger::Notice<<"Wrote zonedata for "<<domain<<" with serial "<<soa->d_st.serial<<" to "<<dir<<endl;

        const auto oldZoneInfo = getCurrentZoneInfo(domain);
        auto ixfrInfo = std::make_shared<ixfrinfo_t>();

        if (oldZoneInfo && !oldZoneInfo->latestAXFR.empty()) {
          auto diff = std::make_shared<ixfrdiff_t>();
          ixfrInfo->ixfrDiffs = oldZoneInfo->ixfrDiffs;
          g_log<<Logger::Debug<<"Calculating diff for "<<domain<<endl;
          makeIXFRDiff(oldZoneInfo->latestAXFR, records, diff, oldZoneInfo->soa, oldZoneInfo->soaTTL, soa, soaTTL);
          g_log<<Logger::Debug<<"Calculated diff for "<<domain<<", we had "<<diff->removals.size()<<" removals and "<<diff->additions.size()<<" additions"<<endl;
          ixfrInfo->ixfrDiffs.push_back(std::move(diff));
        }

        // Clean up the diffs
        while (ixfrInfo->ixfrDiffs.size() > keep) {
          ixfrInfo->ixfrDiffs.erase(ixfrInfo->ixfrDiffs.begin());
        }

        g_log<<Logger::Debug<<"Zone "<<domain<<" previously contained "<<(oldZoneInfo ? oldZoneInfo->latestAXFR.size() : 0)<<" entries, "<<records.size()<<" now"<<endl;
        ixfrInfo->latestAXFR = std::move(records);
        ixfrInfo->soa = std::move(soa);
        ixfrInfo->soaTTL = soaTTL;
        updateCurrentZoneInfo(domain, ixfrInfo);
      } catch (PDNSException &e) {
        g_stats.incrementAXFRFailures(domain);
        g_log<<Logger::Warning<<"Could not save zone '"<<domain<<"' to disk: "<<e.reason<<endl;
      } catch (runtime_error &e) {
        g_stats.incrementAXFRFailures(domain);
        g_log<<Logger::Warning<<"Could not save zone '"<<domain<<"' to disk: "<<e.what()<<endl;
      }

      // Now clean up the directory
      cleanUpDomain(domain, keep, workdir);
    } /* for (const auto &domain : domains) */
    sleep(1);
  } /* while (true) */
} /* updateThread */

enum class ResponseType {
  Unknown,
  ValidQuery,
  RefusedOpcode,
  RefusedQuery,
  EmptyNoError
};

static ResponseType maybeHandleNotify(const MOADNSParser& mdp, const ComboAddress& saddr, const string& logPrefix="") {
  if (mdp.d_header.opcode != Opcode::Notify) { // NOLINT(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions) opcode is 4 bits, this is not a dangerous conversion
    return ResponseType::Unknown;
  }

  g_log<<Logger::Info<<logPrefix<<"NOTIFY for "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).toString()<<" "<< Opcode::to_s(mdp.d_header.opcode) <<" from "<<saddr.toStringWithPort()<<endl;

  ZoneName zonename(mdp.d_qname);
  auto found = g_domainConfigs.find(zonename);
  if (found == g_domainConfigs.end()) {
    g_log<<Logger::Info<<("Domain name '" + mdp.d_qname.toLogString() + "' is not configured for notification")<<endl;
    return ResponseType::RefusedQuery;
  }

  auto primaries = found->second.primaries;

  bool primaryFound = false;

  for (const auto& primary : primaries) {
    if (ComboAddress::addressOnlyEqual()(saddr, primary)) {
      primaryFound = true;
      break;
    }
  }

  if (primaryFound) {
    g_notifiesReceived.lock()->insert(zonename);

    if (!found->second.notify.empty()) {
      for (const auto& address : found->second.notify) {
        g_log << Logger::Debug << logPrefix << "Queuing notification for " << mdp.d_qname << " to " << address.toStringWithPort() << std::endl;
        g_notificationQueue.lock()->add(zonename, address);
      }
    }
    return ResponseType::EmptyNoError;
  }

  return ResponseType::RefusedQuery;
}

static ResponseType checkQuery(const MOADNSParser& mdp, const ComboAddress& saddr, const bool udp = true, const string& logPrefix="") {
  vector<string> info_msg;

  auto ret = ResponseType::ValidQuery;

  g_log<<Logger::Debug<<logPrefix<<"Had "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).toString()<<" query from "<<saddr.toStringWithPort()<<endl;

  if (mdp.d_header.opcode != Opcode::Query) { // NOLINT(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions) opcode is 4 bits, this is not a dangerous conversion
    info_msg.push_back("Opcode is unsupported (" + Opcode::to_s(mdp.d_header.opcode) + "), expected QUERY"); // note that we also emit this for a NOTIFY from a wrong source
    ret = ResponseType::RefusedOpcode;
  }
  else {
    if (udp && mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::IXFR) {
      info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).toString() + " is not in {SOA,IXFR})");
      ret = ResponseType::RefusedQuery;
    }

    if (!udp && mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::IXFR && mdp.d_qtype != QType::AXFR) {
      info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).toString() + " is not in {SOA,IXFR,AXFR})");
      ret = ResponseType::RefusedQuery;
    }

    {
      ZoneName zonename(mdp.d_qname);
      if (g_domainConfigs.find(zonename) == g_domainConfigs.end()) {
        info_msg.push_back("Domain name '" + mdp.d_qname.toLogString() + "' is not configured for distribution");
        ret = ResponseType::RefusedQuery;
      }
      else {
        const auto zoneInfo = getCurrentZoneInfo(zonename);
        if (zoneInfo == nullptr) {
          info_msg.emplace_back("Domain has not been transferred yet");
          ret = ResponseType::RefusedQuery;
        }
      }
    }
  }

  if (!info_msg.empty()) {  // which means ret is not SOA
    g_log<<Logger::Warning<<logPrefix<<"Refusing "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).toString()<<" "<< Opcode::to_s(mdp.d_header.opcode) <<" from "<<saddr.toStringWithPort();
    g_log<<Logger::Warning<<": ";
    bool first = true;
    for (const auto& s : info_msg) {
      if (!first) {
        g_log<<Logger::Warning<<", ";
      }
      first = false;
      g_log<<Logger::Warning<<s;
    }
    g_log<<Logger::Warning<<endl;
    // fall through to return below
  }

  return ret;
}

/*
 * Returns a vector<uint8_t> that represents the full empty NOERROR response.
 * QNAME is read from mdp.
 */
static bool makeEmptyNoErrorPacket(const MOADNSParser& mdp, vector<uint8_t>& packet) {
  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->opcode = mdp.d_header.opcode;
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;
  pw.getHeader()->aa = 1;

  pw.commit();

  return true;
}

/*
 * Returns a vector<uint8_t> that represents the full positive response to a SOA
 * query. QNAME is read from mdp.
 */
static bool makeSOAPacket(const MOADNSParser& mdp, vector<uint8_t>& packet) {

  auto zoneInfo = getCurrentZoneInfo(ZoneName(mdp.d_qname));
  if (zoneInfo == nullptr) {
    return false;
  }

  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->opcode = mdp.d_header.opcode;
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;
  pw.getHeader()->aa = 1;

  pw.startRecord(mdp.d_qname, QType::SOA, zoneInfo->soaTTL);
  zoneInfo->soa->toPacket(pw);
  pw.commit();

  return true;
}

/*
 * Returns a vector<uint8_t> that represents the full REFUSED response to a
 * query. QNAME and type are read from mdp.
 */
static bool makeRefusedPacket(const MOADNSParser& mdp, vector<uint8_t>& packet) {
  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->opcode = mdp.d_header.opcode;
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;
  pw.getHeader()->rcode = RCode::Refused;

  return true;
}

/*
 * Returns a vector<uint8_t> that represents the full NOTIMP response to a
 * query. QNAME and type are read from mdp.
 */
static bool makeNotimpPacket(const MOADNSParser& mdp, vector<uint8_t>& packet) {
  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->opcode = mdp.d_header.opcode;
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;
  pw.getHeader()->rcode = RCode::NotImp;

  return true;
}

static vector<uint8_t> getSOAPacket(const MOADNSParser& mdp, const shared_ptr<const SOARecordContent>& soa, uint32_t soaTTL) {
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;

  // Add the first SOA
  pw.startRecord(mdp.d_qname, QType::SOA, soaTTL);
  soa->toPacket(pw);
  pw.commit();
  return packet;
}

static bool sendPacketOverTCP(int fd, const std::vector<uint8_t>& packet)
{
  char sendBuf[2];
  sendBuf[0]=packet.size()/256;
  sendBuf[1]=packet.size()%256;

  writen2(fd, sendBuf, 2);
  writen2(fd, &packet[0], packet.size());
  return true;
}

static bool addRecordToWriter(DNSPacketWriter& pw, const DNSName& zoneName, const DNSRecord& record, bool compress)
{
  pw.startRecord(record.d_name + zoneName, record.d_type, record.d_ttl, QClass::IN, DNSResourceRecord::ANSWER, compress);
  record.getContent()->toPacket(pw);
  if (pw.size() > 16384) {
    pw.rollback();
    return false;
  }
  return true;
}

template <typename T> static bool sendRecordsOverTCP(int fd, const MOADNSParser& mdp, const T& records)
{
  vector<uint8_t> packet;

  for (auto it = records.cbegin(); it != records.cend();) {
    bool recordsAdded = false;
    packet.clear();
    DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
    pw.getHeader()->id = mdp.d_header.id;
    pw.getHeader()->rd = mdp.d_header.rd;
    pw.getHeader()->qr = 1;

    while (it != records.cend()) {
      if (it->d_type == QType::SOA) {
        it++;
        continue;
      }

      if (addRecordToWriter(pw, mdp.d_qname, *it, g_compress)) {
        recordsAdded = true;
        it++;
      }
      else {
        if (recordsAdded) {
          pw.commit();
          sendPacketOverTCP(fd, packet);
        }
        if (it == records.cbegin()) {
          /* something is wrong */
          return false;
        }

        break;
      }
    }

    if (it == records.cend() && recordsAdded) {
      pw.commit();
      sendPacketOverTCP(fd, packet);
    }
  }

  return true;
}


static bool handleAXFR(int fd, const MOADNSParser& mdp) {
  /* we get a shared pointer of the zone info that we can't modify, ever.
     A newer one may arise in the meantime, but this one will stay valid
     until we release it.
  */

  ZoneName zonename(mdp.d_qname);
  g_stats.incrementAXFRinQueries(zonename);

  auto zoneInfo = getCurrentZoneInfo(zonename);
  if (zoneInfo == nullptr) {
    return false;
  }

  shared_ptr<const SOARecordContent> soa = zoneInfo->soa;
  uint32_t soaTTL = zoneInfo->soaTTL;
  const records_t& records = zoneInfo->latestAXFR;

  // Initial SOA
  const auto soaPacket = getSOAPacket(mdp, soa, soaTTL);
  if (!sendPacketOverTCP(fd, soaPacket)) {
    return false;
  }

  if (!sendRecordsOverTCP(fd, mdp, records)) {
    return false;
  }

  // Final SOA
  if (!sendPacketOverTCP(fd, soaPacket)) {
    return false;
  }

  return true;
}

/* Produces an IXFR if one can be made according to the rules in RFC 1995 and
 * creates a SOA or AXFR packet when required by the RFC.
 */
static bool handleIXFR(int fd, const MOADNSParser& mdp, const shared_ptr<const SOARecordContent>& clientSOA) {
  vector<std::shared_ptr<ixfrdiff_t>> toSend;

  /* we get a shared pointer of the zone info that we can't modify, ever.
     A newer one may arise in the meantime, but this one will stay valid
     until we release it.
  */

  ZoneName zonename(mdp.d_qname);
  g_stats.incrementIXFRinQueries(zonename);

  auto zoneInfo = getCurrentZoneInfo(zonename);
  if (zoneInfo == nullptr) {
    return false;
  }

  uint32_t ourLatestSerial = zoneInfo->soa->d_st.serial;

  if (rfc1982LessThan(ourLatestSerial, clientSOA->d_st.serial) || ourLatestSerial == clientSOA->d_st.serial) {
    /* RFC 1995 Section 2
     *    If an IXFR query with the same or newer version number than that of
     *    the server is received, it is replied to with a single SOA record of
     *    the server's current version.
     */
    vector<uint8_t> packet;
    bool ret = makeSOAPacket(mdp, packet);
    if (ret) {
      sendPacketOverTCP(fd, packet);
    }
    return ret;
  }

  // as we use push_back in the updater, we know the vector is sorted as oldest first
  bool shouldAdd = false;
  // Get all relevant IXFR differences
  for (const auto& diff : zoneInfo->ixfrDiffs) {
    if (shouldAdd) {
      toSend.push_back(diff);
      continue;
    }
    if (diff->oldSOA->d_st.serial == clientSOA->d_st.serial) {
      toSend.push_back(diff);
      // Add all consecutive diffs
      shouldAdd = true;
    }
  }

  if (toSend.empty()) {
    // FIXME: incrementIXFRFallbacks
    g_log<<Logger::Warning<<"No IXFR available from serial "<<clientSOA->d_st.serial<<" for zone "<<mdp.d_qname<<", attempting to send AXFR"<<endl;
    return handleAXFR(fd, mdp);
  }


  /* An IXFR packet's ANSWER section looks as follows:
    * SOA latest_serial C

    First set of changes:
    * SOA requested_serial A
    * ... removed records ...
    * SOA intermediate_serial B
    * ... added records ...

    Next set of changes:
    * SOA intermediate_serial B
    * ... removed records ...
    * SOA latest_serial C
    * ... added records ...

    * SOA latest_serial C
    */

  const auto latestSOAPacket = getSOAPacket(mdp, zoneInfo->soa, zoneInfo->soaTTL);
  if (!sendPacketOverTCP(fd, latestSOAPacket)) {
    return false;
  }

  for (const auto& diff : toSend) {
    const auto newSOAPacket = getSOAPacket(mdp, diff->newSOA, diff->newSOATTL);
    const auto oldSOAPacket = getSOAPacket(mdp, diff->oldSOA, diff->oldSOATTL);

    if (!sendPacketOverTCP(fd, oldSOAPacket)) {
      return false;
    }

    if (!sendRecordsOverTCP(fd, mdp, diff->removals)) {
      return false;
    }

    if (!sendPacketOverTCP(fd, newSOAPacket)) {
      return false;
    }

    if (!sendRecordsOverTCP(fd, mdp, diff->additions)) {
      return false;
    }
  }

  if (!sendPacketOverTCP(fd, latestSOAPacket)) {
    return false;
  }

  return true;
}

static bool allowedByACL(const ComboAddress& addr, bool forNotify = false) {
  if (forNotify) {
    return g_notifySources.match(addr);
  }

  return g_acl.match(addr);
}

static void handleUDPRequest(int fd, boost::any& /*unused*/)
try
{
  // TODO make the buffer-size configurable
  char buf[4096];
  ComboAddress saddr;
  socklen_t fromlen = sizeof(saddr);
  int res = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*) &saddr, &fromlen);

  if (res == 0) {
    g_log<<Logger::Warning<<"Got an empty message from "<<saddr.toStringWithPort()<<endl;
    return;
  }

  if(res < 0) {
    auto savedErrno = errno;
    g_log<<Logger::Warning<<"Could not read message from "<<saddr.toStringWithPort()<<": "<<strerror(savedErrno)<<endl;
    return;
  }

  if (saddr == ComboAddress("0.0.0.0", 0)) {
    g_log<<Logger::Warning<<"Could not determine source of message"<<endl;
    return;
  }

  if (!allowedByACL(saddr, true) && !allowedByACL(saddr, false)) {
    g_log<<Logger::Warning<<"UDP query from "<<saddr.toString()<<" did not match any valid query or NOTIFY source, dropping"<<endl;
    return;
  }

  MOADNSParser mdp(true, string(&buf[0], static_cast<size_t>(res)));
  vector<uint8_t> packet;

  ResponseType respt = ResponseType::Unknown;

  if (allowedByACL(saddr, true)) {
    respt = maybeHandleNotify(mdp, saddr);
  }
  else if (!allowedByACL(saddr)) {
    g_log<<Logger::Warning<<"UDP query from "<<saddr.toString()<<" is not allowed, dropping"<<endl;
    return;
  }

  if (respt == ResponseType::Unknown) {
    // query was not handled yet (so not a valid NOTIFY)
    respt = checkQuery(mdp, saddr);
  }
  if (respt == ResponseType::ValidQuery) {
    /* RFC 1995 Section 2
     *    Transport of a query may be by either UDP or TCP.  If an IXFR query
     *    is via UDP, the IXFR server may attempt to reply using UDP if the
     *    entire response can be contained in a single DNS packet.  If the UDP
     *    reply does not fit, the query is responded to with a single SOA
     *    record of the server's current version to inform the client that a
     *    TCP query should be initiated.
     *
     * Let's not complicate this with IXFR over UDP (and looking if we need to truncate etc).
     * Just send the current SOA and let the client try over TCP
     */
    g_stats.incrementSOAinQueries(ZoneName(mdp.d_qname)); // FIXME: this also counts IXFR queries (but the response is the same as to a SOA query)
    makeSOAPacket(mdp, packet);
  } else if (respt == ResponseType::EmptyNoError) {
    makeEmptyNoErrorPacket(mdp, packet);
  } else if (respt == ResponseType::RefusedQuery) {
    g_stats.incrementUnknownDomainInQueries(ZoneName(mdp.d_qname));
    makeRefusedPacket(mdp, packet);
  } else if (respt == ResponseType::RefusedOpcode) {
    g_stats.incrementNotImplemented(mdp.d_header.opcode);
    makeNotimpPacket(mdp, packet);
  }

  if(sendto(fd, &packet[0], packet.size(), 0, (struct sockaddr*) &saddr, fromlen) < 0) {
    auto savedErrno = errno;
    g_log<<Logger::Warning<<"Could not send reply for "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).toString()<<" to "<<saddr.toStringWithPort()<<": "<<strerror(savedErrno)<<endl;
  }
  return;
}
catch(std::exception& e) {
  return;
}


static void handleTCPRequest(int fd, boost::any&) {
  ComboAddress saddr;
  int cfd = 0;

  try {
    cfd = SAccept(fd, saddr);
    setBlocking(cfd);
  } catch(runtime_error &e) {
    g_log<<Logger::Error<<e.what()<<endl;
    return;
  }

  if (saddr == ComboAddress("0.0.0.0", 0)) {
    g_log<<Logger::Warning<<"Could not determine source of message"<<endl;
    close(cfd);
    return;
  }

  // we allow the connection if this is a legit client or a legit NOTIFY source
  // need to check per-operation later
  if (!allowedByACL(saddr) && !allowedByACL(saddr, true)) {
    g_log<<Logger::Warning<<"TCP query from "<<saddr.toString()<<" is not allowed, dropping"<<endl;
    close(cfd);
    return;
  }

  {
    std::lock_guard<std::mutex> lg(g_tcpRequestFDsMutex);
    g_tcpRequestFDs.push({cfd, saddr});
  }
  g_tcpHandlerCV.notify_one();
}

/* Thread to handle TCP traffic
 */
static void tcpWorker(int tid) {
  setThreadName("ixfrdist/tcpWor");
  string prefix = "TCP Worker " + std::to_string(tid) + ": ";

  while(true) {
    g_log<<Logger::Debug<<prefix<<"ready for a new request!"<<endl;
    std::unique_lock<std::mutex> lk(g_tcpRequestFDsMutex);
    g_tcpHandlerCV.wait(lk, []{return g_tcpRequestFDs.size() || g_exiting ;});
    if (g_exiting) {
      g_log<<Logger::Debug<<prefix<<"Stopping thread"<<endl;
      break;
    }
    g_log<<Logger::Debug<<prefix<<"Going to handle a query"<<endl;
    auto request = g_tcpRequestFDs.front();
    g_tcpRequestFDs.pop();
    lk.unlock();

    int cfd = request.first;
    ComboAddress saddr = request.second;

    char buf[4096];
    ssize_t res;
    try {
      uint16_t toRead;
      readn2(cfd, &toRead, sizeof(toRead));
      toRead = std::min(ntohs(toRead), static_cast<uint16_t>(sizeof(buf)));
      res = readn2WithTimeout(cfd, &buf, toRead, timeval{2,0});
      g_log<<Logger::Debug<<prefix<<"Had message of "<<std::to_string(toRead)<<" bytes from "<<saddr.toStringWithPort()<<endl;
    } catch (runtime_error &e) {
      g_log<<Logger::Warning<<prefix<<"Could not read message from "<<saddr.toStringWithPort()<<": "<<e.what()<<endl;
      close(cfd);
      continue;
    }

    try {
      MOADNSParser mdp(true, string(buf, res));

      ResponseType respt = ResponseType::Unknown;

      // this code is duplicated from the UDP path
      if (allowedByACL(saddr, true)) {
        respt = maybeHandleNotify(mdp, saddr);
      }
      else if (!allowedByACL(saddr)) {
        close(cfd);
        continue;
      }

      if (respt == ResponseType::Unknown) {
        respt = checkQuery(mdp, saddr, false, prefix);
      }

      if (respt != ResponseType::ValidQuery && respt != ResponseType::EmptyNoError) { // on TCP, we currently do not bother with sending useful errors
        close(cfd);
        continue;
      }

      vector<uint8_t> packet;

      if (respt == ResponseType::EmptyNoError) {
        bool ret = makeEmptyNoErrorPacket(mdp, packet);
        if (!ret) {
          close(cfd);
          continue;
        }
        sendPacketOverTCP(cfd, packet);
      }
      else if (mdp.d_qtype == QType::SOA) {
        bool ret = makeSOAPacket(mdp, packet);
        if (!ret) {
          close(cfd);
          continue;
        }
        sendPacketOverTCP(cfd, packet);
      }
      else if (mdp.d_qtype == QType::AXFR) {
        if (!handleAXFR(cfd, mdp)) {
          close(cfd);
          continue;
        }
      }
      else if (mdp.d_qtype == QType::IXFR) {
        /* RFC 1995 section 3:
         *  The IXFR query packet format is the same as that of a normal DNS
         *  query, but with the query type being IXFR and the authority section
         *  containing the SOA record of client's version of the zone.
         */
        shared_ptr<const SOARecordContent> clientSOA;
        for (auto &answer : mdp.d_answers) {
          // from dnsparser.hh:
          // typedef vector<pair<DNSRecord, uint16_t > > answers_t;
          if (answer.d_type == QType::SOA && answer.d_place == DNSResourceRecord::AUTHORITY) {
            clientSOA = getRR<SOARecordContent>(answer);
            if (clientSOA != nullptr) {
              break;
            }
          }
        } /* for (auto const &answer : mdp.d_answers) */

        if (clientSOA == nullptr) {
          g_log<<Logger::Warning<<prefix<<"IXFR request packet did not contain a SOA record in the AUTHORITY section"<<endl;
          close(cfd);
          continue;
        }

        if (!handleIXFR(cfd, mdp, clientSOA)) {
          close(cfd);
          continue;
        }
      } /* if (mdp.d_qtype == QType::IXFR) */

      shutdown(cfd, 2);
    } catch (const MOADNSException &mde) {
      g_log<<Logger::Warning<<prefix<<"Could not parse DNS packet from "<<saddr.toStringWithPort()<<": "<<mde.what()<<endl;
    } catch (runtime_error &e) {
      g_log<<Logger::Warning<<prefix<<"Could not write reply to "<<saddr.toStringWithPort()<<": "<<e.what()<<endl;
    }
    // bye!
    close(cfd);

    if (g_exiting) {
      break;
    }
  }
}

/* Parses the configuration file in configpath into config, adding defaults for
 * missing parameters (if applicable), returning true if the config file was
 * good, false otherwise. Will log all issues with the config
 */
static bool parseAndCheckConfig(const string& configpath, YAML::Node& config) {
  g_log<<Logger::Info<<"Loading configuration file from "<<configpath<<endl;
  try {
    config = YAML::LoadFile(configpath);
  } catch (const runtime_error &e) {
    g_log<<Logger::Error<<"Unable to load configuration file '"<<configpath<<"': "<<e.what()<<endl;
    return false;
  }

  bool retval = true;

  if (config["keep"]) {
    try {
      config["keep"].as<uint16_t>();
    } catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'keep' value: "<<e.what()<<endl;
      retval = false;
    }
  } else {
    config["keep"] = 20;
  }

  if (config["axfr-max-records"]) {
    try {
      config["axfr-max-records"].as<uint32_t>();
    } catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'axfr-max-records' value: "<<e.what()<<endl;
    }
  } else {
    config["axfr-max-records"] = 0;
  }

  if (config["axfr-timeout"]) {
    try {
      config["axfr-timeout"].as<uint16_t>();
    } catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'axfr-timeout' value: "<<e.what()<<endl;
    }
  } else {
    config["axfr-timeout"] = 20;
  }

  if (config["failed-soa-retry"]) {
    try {
      config["failed-soa-retry"].as<uint16_t>();
    } catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'failed-soa-retry' value: "<<e.what()<<endl;
    }
  } else {
    config["failed-soa-retry"] = 30;
  }

  if (config["tcp-in-threads"]) {
    try {
      config["tcp-in-threads"].as<uint16_t>();
    } catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'tcp-in-threads' value: "<<e.what()<<endl;
    }
  } else {
    config["tcp-in-threads"] = 10;
  }

  if (config["listen"]) {
    try {
      config["listen"].as<vector<ComboAddress>>();
    } catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'listen' value: "<<e.what()<<endl;
      retval = false;
    }
  } else {
    config["listen"].push_back("127.0.0.1:53");
    config["listen"].push_back("[::1]:53");
  }

  if (config["acl"]) {
    try {
      config["acl"].as<vector<string>>();
    } catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'acl' value: "<<e.what()<<endl;
      retval = false;
    }
  } else {
    config["acl"].push_back("127.0.0.0/8");
    config["acl"].push_back("::1/128");
  }

  if (config["work-dir"]) {
    try {
      config["work-dir"].as<string>();
    } catch(const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'work-dir' value: "<<e.what()<<endl;
      retval = false;
    }
  } else {
    char tmp[512];
    config["work-dir"] = getcwd(tmp, sizeof(tmp)) ? string(tmp) : "";;
  }

  if (config["uid"]) {
    try {
      config["uid"].as<string>();
    } catch(const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'uid' value: "<<e.what()<<endl;
      retval = false;
    }
  }

  if (config["gid"]) {
    try {
      config["gid"].as<string>();
    } catch(const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'gid' value: "<<e.what()<<endl;
      retval = false;
    }
  }

  if (config["domains"]) {
    if (config["domains"].size() == 0) {
      g_log<<Logger::Error<<"No domains configured"<<endl;
      retval = false;
    }
    for (auto const &domain : config["domains"]) {
      try {
        if (!domain["domain"]) {
          g_log<<Logger::Error<<"An entry in 'domains' is missing a 'domain' key!"<<endl;
          retval = false;
          continue;
        }
        domain["domain"].as<ZoneName>();
      } catch (const runtime_error &e) {
        g_log<<Logger::Error<<"Unable to read domain '"<<domain["domain"].as<string>()<<"': "<<e.what()<<endl;
      }
      try {
        if (!domain["master"]) {
          g_log << Logger::Error << "Domain '" << domain["domain"].as<string>() << "' has no primary configured!" << endl;
          retval = false;
          continue;
        }
        domain["master"].as<ComboAddress>();

        auto notifySource = domain["master"].as<ComboAddress>();

        g_notifySources.addMask(notifySource);
      } catch (const runtime_error &e) {
        g_log << Logger::Error << "Unable to read domain '" << domain["domain"].as<string>() << "' primary address: " << e.what() << endl;
        retval = false;
      }
      if (domain["max-soa-refresh"]) {
        try {
          domain["max-soa-refresh"].as<uint32_t>();
        } catch (const runtime_error &e) {
          g_log<<Logger::Error<<"Unable to read 'max-soa-refresh' value for domain '"<<domain["domain"].as<string>()<<"': "<<e.what()<<endl;
        }
      }
    }
  } else {
    g_log<<Logger::Error<<"No domains configured"<<endl;
    retval = false;
  }

  if (config["compress"]) {
    try {
      config["compress"].as<bool>();
    }
    catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'compress' value: "<<e.what()<<endl;
      retval = false;
    }
  }
  else {
    config["compress"] = false;
  }

  if (config["webserver-address"]) {
    try {
      config["webserver-address"].as<ComboAddress>();
    }
    catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'webserver-address' value: "<<e.what()<<endl;
      retval = false;
    }
  }

  if (config["webserver-acl"]) {
    try {
      config["webserver-acl"].as<vector<Netmask>>();
    }
    catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'webserver-acl' value: "<<e.what()<<endl;
      retval = false;
    }
  }

  if (config["webserver-loglevel"]) {
    try {
      config["webserver-loglevel"].as<string>();
    }
    catch (const runtime_error &e) {
      g_log<<Logger::Error<<"Unable to read 'webserver-loglevel' value: "<<e.what()<<endl;
      retval = false;
    }
  }

  return retval;
}

struct IXFRDistConfiguration
{
  set<int> listeningSockets;
  NetmaskGroup wsACL;
  ComboAddress wsAddr;
  std::string wsLogLevel{"normal"};
  std::string workDir;
  const struct passwd* userInfo{nullptr};
  uint32_t axfrMaxRecords{0};
  uint16_t keep{0};
  uint16_t axfrTimeout{0};
  uint16_t failedSOARetry{0};
  uint16_t tcpInThreads{0};
  uid_t uid{0};
  gid_t gid{0};
  bool shouldExit{false};
};

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static std::optional<IXFRDistConfiguration> parseConfiguration(int argc, char** argv, FDMultiplexer& fdm)
{
  IXFRDistConfiguration configuration;
  po::variables_map g_vm;
  std::string configPath;

  try {
    po::options_description desc("IXFR distribution tool");
    desc.add_options()
      ("help", "produce help message")
      ("version", "Display the version of ixfrdist")
      ("verbose", "Be verbose")
      ("debug", "Be even more verbose")
      ("config", po::value<string>()->default_value(SYSCONFDIR + string("/ixfrdist.yml")), "Configuration file to use")
      ;

    po::store(po::command_line_parser(argc, argv).options(desc).run(), g_vm);
    po::notify(g_vm);

    if (g_vm.count("help") > 0) {
      usage(desc);
      configuration.shouldExit = true;
      return configuration;
    }

    if (g_vm.count("version") > 0) {
      cout<<"ixfrdist "<<VERSION<<endl;
      configuration.shouldExit = true;
      return configuration;
    }

    configPath = g_vm["config"].as<string>();
  }
  catch (const po::error &e) {
    g_log<<Logger::Error<<e.what()<<". See `ixfrdist --help` for valid options"<<endl;
    return std::nullopt;
  }
  catch (const std::exception& exp) {
    g_log<<Logger::Error<<exp.what()<<". See `ixfrdist --help` for valid options"<<endl;
    return std::nullopt;
  }

  bool had_error = false;

  if (g_vm.count("verbose")) {
    g_log.setLoglevel(Logger::Info);
    g_log.toConsole(Logger::Info);
  }

  if (g_vm.count("debug") > 0) {
    g_log.setLoglevel(Logger::Debug);
    g_log.toConsole(Logger::Debug);
  }

  g_log<<Logger::Notice<<"IXFR distributor version "<<VERSION<<" starting up!"<<endl;

  try {
    YAML::Node config;
    if (!parseAndCheckConfig(configPath, config)) {
      // parseAndCheckConfig already logged whatever was wrong
      return std::nullopt;
    }

    /*  From hereon out, we known that all the values in config are valid. */

    for (auto const &domain : config["domains"]) {
      set<ComboAddress> s;
      s.insert(domain["master"].as<ComboAddress>());
      g_domainConfigs[domain["domain"].as<ZoneName>()].primaries = s;
      if (domain["max-soa-refresh"].IsDefined()) {
        g_domainConfigs[domain["domain"].as<ZoneName>()].maxSOARefresh = domain["max-soa-refresh"].as<uint32_t>();
      }
      if (domain["notify"].IsDefined()) {
        auto& listset = g_domainConfigs[domain["domain"].as<ZoneName>()].notify;
        if (domain["notify"].IsScalar()) {
          auto remote = domain["notify"].as<std::string>();
          try {
            listset.emplace(remote, 53);
          }
          catch (PDNSException& e) {
            g_log << Logger::Error << "Unparseable IP in notify directive " << remote << ". Error: " << e.reason << endl;
          }
        } else if (domain["notify"].IsSequence()) {
          for (const auto& entry: domain["notify"]) {
            auto remote = entry.as<std::string>();
            try {
              listset.emplace(remote, 53);
            }
            catch (PDNSException& e) {
              g_log << Logger::Error << "Unparseable IP in notify directive " << remote << ". Error: " << e.reason << endl;
            }
          }
        }
      }
      g_stats.registerDomain(domain["domain"].as<ZoneName>());
    }

    for (const auto &addr : config["acl"].as<vector<string>>()) {
      try {
        g_acl.addMask(addr);
      }
      catch (const std::exception& exp) {
        g_log<<Logger::Error<<exp.what()<<endl;
        had_error = true;
      }
      catch (const NetmaskException &e) {
        g_log<<Logger::Error<<e.reason<<endl;
        had_error = true;
      }
    }

    try {
      g_log<<Logger::Notice<<"ACL set to "<<g_acl.toString()<<"."<<endl;
    }
    catch (const std::exception& exp) {
      g_log<<Logger::Error<<"Error printing ACL: "<<exp.what()<<endl;
    }

    g_log<<Logger::Notice<<"NOTIFY accepted from "<<g_notifySources.toString()<<"."<<endl;

    if (config["compress"].IsDefined()) {
      g_compress = config["compress"].as<bool>();
      if (g_compress) {
        g_log<<Logger::Notice<<"Record compression is enabled."<<endl;
      }
    }

    for (const auto& addr : config["listen"].as<vector<ComboAddress>>()) {
      for (const auto& stype : {SOCK_DGRAM, SOCK_STREAM}) {
        try {
          int s = SSocket(addr.sin4.sin_family, stype, 0);
          setNonBlocking(s);
          setReuseAddr(s);
          if (addr.isIPv6()) {
            int one = 1;
            (void)setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
          }

          SBind(s, addr);
          if (stype == SOCK_STREAM) {
            SListen(s, 30); // TODO make this configurable
          }
          fdm.addReadFD(s, stype == SOCK_DGRAM ? handleUDPRequest : handleTCPRequest);
          configuration.listeningSockets.insert(s);
        }
        catch (const runtime_error& exp) {
          g_log<<Logger::Error<<exp.what()<<endl;
          had_error = true;
          continue;
        }
        catch (const PDNSException& exp) {
          g_log<<Logger::Error<<exp.reason<<endl;
          had_error = true;
          continue;
        }
      }
    }

    if (config["gid"].IsDefined()) {
      bool gidParsed = false;
      auto gid = config["gid"].as<string>();
      try {
        configuration.gid = pdns::checked_stoi<gid_t>(gid);
        gidParsed = true;
      }
      catch (const std::exception& e) {
        configuration.gid = 0;
      }
      if (!gidParsed) {
        //NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
        const struct group *gr = getgrnam(gid.c_str());
        if (gr == nullptr) {
          g_log<<Logger::Error<<"Can not determine group-id for gid "<<gid<<endl;
          had_error = true;
        } else {
          configuration.gid = gr->gr_gid;
        }
      }
    }

    if (config["webserver-address"].IsDefined()) {
      configuration.wsAddr = config["webserver-address"].as<ComboAddress>();

      try {
        configuration.wsACL.addMask("127.0.0.0/8");
        configuration.wsACL.addMask("::1/128");

        if (config["webserver-acl"].IsDefined()) {
          configuration.wsACL.clear();
          for (const auto &acl : config["webserver-acl"].as<vector<Netmask>>()) {
            configuration.wsACL.addMask(acl);
          }
        }
      }
      catch (const NetmaskException& ne) {
        g_log<<Logger::Error<<"Could not set the webserver ACL: "<<ne.reason<<endl;
        had_error = true;
      }
      catch (const std::exception& exp) {
        g_log<<Logger::Error<<"Could not set the webserver ACL: "<<exp.what()<<endl;
        had_error = true;
      }

      if (config["webserver-loglevel"]) {
        configuration.wsLogLevel = config["webserver-loglevel"].as<string>();
      }
    }

    if (config["uid"].IsDefined()) {
      bool uidParsed = false;
      auto uid = config["uid"].as<string>();
      try {
        configuration.uid = pdns::checked_stoi<uid_t>(uid);
        uidParsed = true;
      }
      catch (const std::exception& e) {
        configuration.uid = 0;
      }
      if (!uidParsed) {
        //NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
        const struct passwd *pw = getpwnam(uid.c_str());
        if (pw == nullptr) {
          g_log<<Logger::Error<<"Can not determine user-id for uid "<<uid<<endl;
          had_error = true;
        } else {
          configuration.uid = pw->pw_uid;
          uidParsed = true;
        }
        //NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
      }
      if (uidParsed) {
        configuration.userInfo = getpwuid(configuration.uid);
      }
    }

    configuration.workDir = config["work-dir"].as<string>();
    configuration.keep = config["keep"].as<uint16_t>();
    configuration.axfrTimeout = config["axfr-timeout"].as<uint16_t>();
    configuration.failedSOARetry = config["failed-soa-retry"].as<uint16_t>();
    configuration.axfrMaxRecords = config["axfr-max-records"].as<uint32_t>();
    configuration.tcpInThreads = config["tcp-in-threads"].as<uint16_t>();

    if (had_error) {
      return std::nullopt;
    }
    return configuration;
  }
  catch (const YAML::Exception& exp) {
    had_error = true;
    g_log<<Logger::Error<<"Got an exception while applying our configuration: "<<exp.msg<<endl;
    return std::nullopt;
  }
}

int main(int argc, char** argv) {
  bool had_error = false;
  std::optional<IXFRDistConfiguration> configuration{std::nullopt};
  std::unique_ptr<FDMultiplexer> fdm{nullptr};

  try {
    g_log.setLoglevel(Logger::Notice);
    g_log.toConsole(Logger::Notice);
    g_log.setPrefixed(true);
    g_log.disableSyslog(true);
    g_log.setTimestamps(false);

    fdm = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());
    if (!fdm) {
      g_log<<Logger::Error<<"Could not enable a multiplexer for the listen sockets!"<<endl;
      return EXIT_FAILURE;
    }

    configuration = parseConfiguration(argc, argv, *fdm);
    if (!configuration) {
      // We have already sent the errors to stderr, just die
      return EXIT_FAILURE;
    }

    if (configuration->shouldExit) {
      return EXIT_SUCCESS;
    }
  }
  catch (const YAML::Exception& exp) {
    had_error = true;
    g_log<<Logger::Error<<"Got an exception while processing our configuration: "<<exp.msg<<endl;
  }

  try {
    if (configuration->gid != 0) {
      g_log<<Logger::Notice<<"Dropping effective group-id to "<<configuration->gid<<endl;
      if (setgid(configuration->gid) < 0) {
        g_log<<Logger::Error<<"Could not set group id to "<<configuration->gid<<": "<<stringerror()<<endl;
        had_error = true;
      }
    }

    // It all starts here
    signal(SIGTERM, handleSignal);
    signal(SIGINT, handleSignal);
    //NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    signal(SIGPIPE, SIG_IGN);

    // Launch the webserver!
    try {
      std::thread(&IXFRDistWebServer::go, IXFRDistWebServer(configuration->wsAddr, configuration->wsACL, configuration->wsLogLevel)).detach();
    }
    catch (const std::exception& exp) {
      g_log<<Logger::Error<<"Unable to start webserver: "<<exp.what()<<endl;
      had_error = true;
    }
    catch (const PDNSException &e) {
      g_log<<Logger::Error<<"Unable to start webserver: "<<e.reason<<endl;
      had_error = true;
    }

    if (configuration->uid != 0) {
      if (configuration->userInfo == nullptr) {
        if (setgroups(0, nullptr) < 0) {
          g_log<<Logger::Error<<"Unable to drop supplementary gids: "<<stringerror()<<endl;
          had_error = true;
        }
      } else {
        if (initgroups(configuration->userInfo->pw_name, configuration->gid) < 0) {
          g_log<<Logger::Error<<"Unable to set supplementary groups: "<<stringerror()<<endl;
          had_error = true;
        }
      }

      g_log<<Logger::Notice<<"Dropping effective user-id to "<<configuration->uid<<endl;
      if (setuid(configuration->uid) < 0) {
        g_log<<Logger::Error<<"Could not set user id to "<<configuration->uid<<": "<<stringerror()<<endl;
        had_error = true;
      }
    }

    if (had_error) {
      return EXIT_FAILURE;
    }
  }
  catch (const YAML::Exception& exp) {
    had_error = true;
    g_log<<Logger::Error<<"Got an exception while applying our configuration: "<<exp.msg<<endl;
  }

  try {
    // Init the things we need
    reportAllTypes();

    std::thread ut(updateThread,
                   configuration->workDir,
                   configuration->keep,
                   configuration->axfrTimeout,
                   configuration->failedSOARetry,
                   configuration->axfrMaxRecords);
    std::thread communicator(communicatorThread);

    vector<std::thread> tcpHandlers;
    tcpHandlers.reserve(configuration->tcpInThreads);
    for (size_t i = 0; i < tcpHandlers.capacity(); ++i) {
      tcpHandlers.push_back(std::thread(tcpWorker, i));
    }

    struct timeval now;
    for (;;) {
      gettimeofday(&now, 0);
      fdm->run(&now);
      if (g_exiting) {
        g_log<<Logger::Debug<<"Closing listening sockets"<<endl;
        for (const int& fd : configuration->listeningSockets) {
          try {
            closesocket(fd);
          } catch (const PDNSException &e) {
            g_log<<Logger::Error<<e.reason<<endl;
          }
        }
        break;
      }
    }

    g_log<<Logger::Debug<<"Waiting for all threads to stop"<<endl;
    g_tcpHandlerCV.notify_all();
    ut.join();
    communicator.join();
    for (auto &t : tcpHandlers) {
      t.join();
    }
    g_log<<Logger::Notice<<"IXFR distributor stopped"<<endl;
  }
  catch (const YAML::Exception& exp) {
    had_error = true;
    g_log<<Logger::Error<<"Got an exception: "<<exp.msg<<endl;
  }

  return had_error ? EXIT_FAILURE : EXIT_SUCCESS;
}
