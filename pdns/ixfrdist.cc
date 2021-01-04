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
#include "ixfrdist.hh"
#include "axfr-retriever.hh"
#include "dns_random.hh"
#include "sstuff.hh"
#include "mplexer.hh"
#include "misc.hh"
#include "iputils.hh"
#include "logger.hh"
#include "ixfrdist-stats.hh"
#include "ixfrdist-web.hh"
#include "configuration.hh"
#include "pdns-yaml.hh"

/* BEGIN Needed because of deeper dependencies */
#include "arguments.hh"
#include "statbag.hh"
StatBag S;

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}
/* END Needed because of deeper dependencies */

// This contains the configuration for each domain
static ixfrdistDomainConfig g_domainConfigs;

// Map domains and their data
static std::map<DNSName, std::shared_ptr<ixfrinfo_t>> g_soas;
static std::mutex g_soas_mutex;

// Condition variable for TCP handling
static std::condition_variable g_tcpHandlerCV;
static std::queue<pair<int, ComboAddress>> g_tcpRequestFDs;
static std::mutex g_tcpRequestFDsMutex;

namespace po = boost::program_options;

static bool g_exiting = false;

static NetmaskGroup g_acl;
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

static void cleanUpDomain(const DNSName& domain, const uint16_t& keep, const string& workdir) {
  string dir = workdir + "/" + domain.toString();
  DIR *dp;
  dp = opendir(dir.c_str());
  if (dp == nullptr) {
    return;
  }
  vector<uint32_t> zoneVersions;
  struct dirent *d;
  while ((d = readdir(dp)) != nullptr) {
    if(!strcmp(d->d_name, ".") || !strcmp(d->d_name, "..")) {
      continue;
    }
    zoneVersions.push_back(std::stoi(d->d_name));
  }
  closedir(dp);
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
    std::lock_guard<std::mutex> guard(g_soas_mutex);
    for (auto iter = zoneVersions.cbegin(); iter != zoneVersions.cend() - keep; ++iter) {
      string fname = dir + "/" + std::to_string(*iter);
      g_log<<Logger::Debug<<"Removing "<<fname<<endl;
      unlink(fname.c_str());
    }
  }
}

static void getSOAFromRecords(const records_t& records, shared_ptr<SOARecordContent>& soa, uint32_t& soaTTL) {
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

static void makeIXFRDiff(const records_t& from, const records_t& to, std::shared_ptr<ixfrdiff_t>& diff, const shared_ptr<SOARecordContent>& fromSOA = nullptr, uint32_t fromSOATTL=0, const shared_ptr<SOARecordContent>& toSOA = nullptr, uint32_t toSOATTL = 0) {
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
static std::shared_ptr<ixfrinfo_t> getCurrentZoneInfo(const DNSName& domain)
{
  std::lock_guard<std::mutex> guard(g_soas_mutex);
  return g_soas[domain];
}

static void updateCurrentZoneInfo(const DNSName& domain, std::shared_ptr<ixfrinfo_t>& newInfo)
{
  std::lock_guard<std::mutex> guard(g_soas_mutex);
  g_soas[domain] = newInfo;
  g_stats.setSOASerial(domain, newInfo->soa->d_st.serial);
  // FIXME: also report zone size?
}

static void updateThread(const string& workdir, const uint16_t& keep, const uint16_t& axfrTimeout, const uint16_t& soaRetry, const uint32_t axfrMaxRecords) {
  setThreadName("ixfrdist/update");
  std::map<DNSName, time_t> lastCheck;

  // Initialize the serials we have
  for (const auto &domainConfig : g_domainConfigs) {
    DNSName domain = domainConfig.first;
    lastCheck[domain] = 0;
    string dir = workdir + "/" + domain.toString();
    try {
      g_log<<Logger::Info<<"Trying to initially load domain "<<domain<<" from disk"<<endl;
      auto serial = getSerialFromDir(dir);
      shared_ptr<SOARecordContent> soa;
      uint32_t soaTTL;
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

      DNSName domain = domainConfig.first;
      shared_ptr<SOARecordContent> current_soa;
      const auto& zoneInfo = getCurrentZoneInfo(domain);
      if (zoneInfo != nullptr) {
        current_soa = zoneInfo->soa;
      }

      auto& zoneLastCheck = lastCheck[domain];
      if ((current_soa != nullptr && now - zoneLastCheck < current_soa->d_st.refresh) || // Only check if we have waited `refresh` seconds
          (current_soa == nullptr && now - zoneLastCheck < soaRetry))  {                       // Or if we could not get an update at all still, every 30 seconds
        continue;
      }

      // TODO Keep track of 'down' masters
      set<ComboAddress>::const_iterator it(domainConfig.second.masters.begin());
      std::advance(it, dns_random(domainConfig.second.masters.size()));
      ComboAddress master = *it;

      string dir = workdir + "/" + domain.toString();
      g_log<<Logger::Info<<"Attempting to retrieve SOA Serial update for '"<<domain<<"' from '"<<master.toStringWithPort()<<"'"<<endl;
      shared_ptr<SOARecordContent> sr;
      try {
        zoneLastCheck = now;
        g_stats.incrementSOAChecks(domain);
        auto newSerial = getSerialFromMaster(master, domain, sr); // TODO TSIG
        if(current_soa != nullptr) {
          g_log<<Logger::Info<<"Got SOA Serial for "<<domain<<" from "<<master.toStringWithPort()<<": "<< newSerial<<", had Serial: "<<current_soa->d_st.serial;
          if (newSerial == current_soa->d_st.serial) {
            g_log<<Logger::Info<<", not updating."<<endl;
            continue;
          }
          g_log<<Logger::Info<<", will update."<<endl;
        }
      } catch (runtime_error &e) {
        g_log<<Logger::Warning<<"Unable to get SOA serial update for '"<<domain<<"' from master "<<master.toStringWithPort()<<": "<<e.what()<<endl;
        g_stats.incrementSOAChecksFailed(domain);
        continue;
      }
      // Now get the full zone!
      g_log<<Logger::Info<<"Attempting to receive full zonedata for '"<<domain<<"'"<<endl;
      ComboAddress local = master.isIPv4() ? ComboAddress("0.0.0.0") : ComboAddress("::");
      TSIGTriplet tt;

      // The *new* SOA
      shared_ptr<SOARecordContent> soa;
      uint32_t soaTTL = 0;
      records_t records;
      try {
        AXFRRetriever axfr(master, domain, tt, &local);
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
        ixfrInfo->soa = soa;
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

static bool checkQuery(const MOADNSParser& mdp, const ComboAddress& saddr, const bool udp = true, const string& logPrefix="") {
  vector<string> info_msg;

  g_log<<Logger::Debug<<logPrefix<<"Had "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" query from "<<saddr.toStringWithPort()<<endl;

  if (udp && mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::IXFR) {
    info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).getName() + " is not in {SOA,IXFR})");
  }

  if (!udp && mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::IXFR && mdp.d_qtype != QType::AXFR) {
    info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).getName() + " is not in {SOA,IXFR,AXFR})");
  }

  {
    if (g_domainConfigs.find(mdp.d_qname) == g_domainConfigs.end()) {
      info_msg.push_back("Domain name '" + mdp.d_qname.toLogString() + "' is not configured for distribution");
    }
    else {
      const auto zoneInfo = getCurrentZoneInfo(mdp.d_qname);
      if (zoneInfo == nullptr) {
        info_msg.push_back("Domain has not been transferred yet");
      }
    }
  }

  if (!info_msg.empty()) {
    g_log<<Logger::Warning<<logPrefix<<"Refusing "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" query from "<<saddr.toStringWithPort();
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
    return false;
  }

  return true;
}

/*
 * Returns a vector<uint8_t> that represents the full positive response to a SOA
 * query. QNAME is read from mdp.
 */
static bool makeSOAPacket(const MOADNSParser& mdp, vector<uint8_t>& packet) {

  auto zoneInfo = getCurrentZoneInfo(mdp.d_qname);
  if (zoneInfo == nullptr) {
    return false;
  }

  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;

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
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;
  pw.getHeader()->rcode = RCode::Refused;

  return true;
}

static vector<uint8_t> getSOAPacket(const MOADNSParser& mdp, const shared_ptr<SOARecordContent>& soa, uint32_t soaTTL) {
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
  record.d_content->toPacket(pw);
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

  g_stats.incrementAXFRinQueries(mdp.d_qname);

  auto zoneInfo = getCurrentZoneInfo(mdp.d_qname);
  if (zoneInfo == nullptr) {
    return false;
  }

  shared_ptr<SOARecordContent> soa = zoneInfo->soa;
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
static bool handleIXFR(int fd, const ComboAddress& destination, const MOADNSParser& mdp, const shared_ptr<SOARecordContent>& clientSOA) {
  vector<std::shared_ptr<ixfrdiff_t>> toSend;

  /* we get a shared pointer of the zone info that we can't modify, ever.
     A newer one may arise in the meantime, but this one will stay valid
     until we release it.
  */

  g_stats.incrementIXFRinQueries(mdp.d_qname);

  auto zoneInfo = getCurrentZoneInfo(mdp.d_qname);
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

  std::vector<std::vector<uint8_t>> packets;
  for (const auto& diff : toSend) {
    /* An IXFR packet's ANSWER section looks as follows:
     * SOA new_serial
     * SOA old_serial
     * ... removed records ...
     * SOA new_serial
     * ... added records ...
     * SOA new_serial
     */

    const auto newSOAPacket = getSOAPacket(mdp, diff->newSOA, diff->newSOATTL);
    const auto oldSOAPacket = getSOAPacket(mdp, diff->oldSOA, diff->oldSOATTL);

    if (!sendPacketOverTCP(fd, newSOAPacket)) {
      return false;
    }

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

    if (!sendPacketOverTCP(fd, newSOAPacket)) {
      return false;
    }
  }

  return true;
}

static bool allowedByACL(const ComboAddress& addr) {
  return g_acl.match(addr);
}

static void handleUDPRequest(int fd, boost::any&) {
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

  if (!allowedByACL(saddr)) {
    g_log<<Logger::Warning<<"UDP query from "<<saddr.toString()<<" is not allowed, dropping"<<endl;
    return;
  }

  MOADNSParser mdp(true, string(buf, res));
  vector<uint8_t> packet;
  if (checkQuery(mdp, saddr)) {
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
    g_stats.incrementSOAinQueries(mdp.d_qname); // FIXME: this also counts IXFR queries (but the response is the same as to a SOA query)
    makeSOAPacket(mdp, packet);
  } else {
    makeRefusedPacket(mdp, packet);
  }

  if(sendto(fd, &packet[0], packet.size(), 0, (struct sockaddr*) &saddr, fromlen) < 0) {
    auto savedErrno = errno;
    g_log<<Logger::Warning<<"Could not send reply for "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" to "<<saddr.toStringWithPort()<<": "<<strerror(savedErrno)<<endl;
  }
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

  if (!allowedByACL(saddr)) {
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
      res = readn2WithTimeout(cfd, &buf, toRead, 2);
      g_log<<Logger::Debug<<prefix<<"Had message of "<<std::to_string(toRead)<<" bytes from "<<saddr.toStringWithPort()<<endl;
    } catch (runtime_error &e) {
      g_log<<Logger::Warning<<prefix<<"Could not read message from "<<saddr.toStringWithPort()<<": "<<e.what()<<endl;
      close(cfd);
      continue;
    }

    try {
      MOADNSParser mdp(true, string(buf, res));

      if (!checkQuery(mdp, saddr, false, prefix)) {
        close(cfd);
        continue;
      }

      if (mdp.d_qtype == QType::SOA) {
        vector<uint8_t> packet;
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
        shared_ptr<SOARecordContent> clientSOA;
        for (auto &answer : mdp.d_answers) {
          // from dnsparser.hh:
          // typedef vector<pair<DNSRecord, uint16_t > > answers_t;
          if (answer.first.d_type == QType::SOA && answer.first.d_place == DNSResourceRecord::AUTHORITY) {
            clientSOA = getRR<SOARecordContent>(answer.first);
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

        if (!handleIXFR(cfd, saddr, mdp, clientSOA)) {
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

int main(int argc, char** argv) {
  g_log.setLoglevel(Logger::Notice);
  g_log.toConsole(Logger::Notice);
  g_log.setPrefixed(true);
  g_log.disableSyslog(true);
  g_log.setTimestamps(false);
  po::variables_map g_vm;
  try {
    po::options_description desc("IXFR distribution tool");
    desc.add_options()
      ("help", "produce help message")
      ("version", "Display the version of ixfrdist")
      ("verbose", "Be verbose")
      ("debug", "Be even more verbose")
      ("config", po::value<string>()->default_value(SYSCONFDIR + string("/ixfrdist.yml")), "Configuration file to use")
      ("check-config", "Check the configuration and exit")
      ("get-default-config", "Dumps the default configuration file to standard out")
      ;

    po::store(po::command_line_parser(argc, argv).options(desc).run(), g_vm);
    po::notify(g_vm);

    if (g_vm.count("help") > 0) {
      usage(desc);
      return EXIT_SUCCESS;
    }

    if (g_vm.count("version") > 0) {
      cout<<"ixfrdist "<<VERSION<<endl;
      return EXIT_SUCCESS;
    }
  } catch (po::error &e) {
    g_log<<Logger::Error<<e.what()<<". See `ixfrdist --help` for valid options"<<endl;
    return(EXIT_FAILURE);
  }

  if (g_vm.count("check-config")) {
    g_log.setLoglevel(Logger::Error);
    g_log.toConsole(Logger::Error);
  }

  if (g_vm.count("verbose")) {
    g_log.setLoglevel(Logger::Info);
    g_log.toConsole(Logger::Info);
  }

  if (g_vm.count("debug") > 0) {
    g_log.setLoglevel(Logger::Debug);
    g_log.toConsole(Logger::Debug);
  }

  auto keep = std::make_shared<uint16_t>(20);
  pdns::config::registerOption<uint16_t>("keep", false, "Amount of older copies/IXFR diffs to keep for every domain", keep);

  auto listen_addrs = std::make_shared<vector<ComboAddress>>();
  listen_addrs->push_back(ComboAddress("127.0.0.1:53"));
  listen_addrs->push_back(ComboAddress("[::1]:53"));
  pdns::config::registerOption<vector<ComboAddress>>("listen", false, R"(Listen addresses. ixfrdist will listen on both UDP and TCP.
When no port is specified, 53 is used. When specifying ports for IPv6, use the
"bracket" notation:

    listen:
      - '127.0.0.1'
      - '::1'
      - '192.0.2.3:5300'
      - '[2001:DB8:1234::334]:5353')", listen_addrs);

  // Set the defaults
  g_acl.addMask("127.0.0.0/8");
  g_acl.addMask("::1/128");
  pdns::config::registerOption("acl", pdns::config::configInfoFuncs{
    .check = [](const YAML::Node &n, const bool initial){ 
      if (n.IsNull()) { return; }
      n.as<NetmaskGroup>(); 
    },
    .defaults = []() { 
      static NetmaskGroup defaultNMG;
      defaultNMG.addMask("127.0.0.0/8");
      defaultNMG.addMask("::1/128");
      return YAML::Node(defaultNMG); 
     },
    .apply = [&](const YAML::Node &n, const bool initial) {
      if (!initial) {
        return;
      }
      if (n.IsNull()) { return; }
      g_acl = n.as<NetmaskGroup>();
      g_log<<Logger::Notice<<"ACL set to "<<g_acl.toString()<<"."<<endl;
    },
    .current = []() { return YAML::Node(g_acl); },
    .help = R"(Netmasks or IP addresses of hosts that are allowed to query ixfrdist.
Hosts do not need a netmask, and subnets can be negated with a '!'.

    acl:
      - '127.0.0.0/8'
      - '::1'
      - 192.0.2.0/24 # Allow this subnet
      - '!192.0.2.55' # but deny this specific address
      - '2001:DB8:ABCD::/48')"
  });

  uint16_t axfr_timeout = 20;
  uint32_t axfr_max_records = 0;
  pdns::config::registerOption("axfr", pdns::config::configInfoFuncs{
    .check = [&axfr_timeout, &axfr_max_records](const YAML::Node &n, const bool initial){
      if (n.IsNull()) { return; }
      static const set<string> axfrOpts({"timeout", "max-records"});
      if (!n.IsMap()) {
        throw runtime_error("'axfr' is not a map");
      }
      uint16_t timeout = axfr_timeout;
      uint32_t max_records = axfr_max_records;
      for (auto nit = n.begin(); nit != n.end(); nit++) {
        auto opt = nit->first.as<string>();
        if (axfrOpts.count(opt) == 0) {
          throw std::runtime_error("Unknown 'axfr' option '" + opt + "'");
        }
        if (opt == "timeout") {
          timeout = nit->second.as<uint16_t>();
        }
        if (opt == "max-records") {
          max_records = nit->second.as<uint32_t>();
        }
      }
      if (initial) {
        return;
      }
      if (timeout != axfr_timeout || max_records != axfr_max_records) {
        throw std::runtime_error("'axfr' cannot be changed at runtime");
      }
    },
    .defaults = [axfr_timeout, axfr_max_records]() {
      YAML::Node ret;
      ret["timeout"] = axfr_timeout;
      ret["max-records"] = axfr_max_records;
      return ret;
    },
    .apply = [&axfr_timeout, &axfr_max_records](const YAML::Node &n, const bool initial) {
      if (n.IsNull()) { return; }
      if (!initial) {
        return;
      }
      if (n["timeout"]) {
        axfr_timeout = n["timeout"].as<uint16_t>();
      }
      if (n["max-records"]) {
        axfr_max_records = n["max-records"].as<uint32_t>();
      }
    },
    .current = [&axfr_timeout, &axfr_max_records]() {
      YAML::Node ret;
      ret["timeout"] = axfr_timeout;
      ret["max-records"] = axfr_max_records;
      return ret;
    },
    .help = R"(This configures limits for the AXFR requests done by ixfrdist

'timeout' is the amount seconds an AXFR transaction requested by ixfrdist may take.
Increase this when the network to the authoritative servers is slow or the
domains are very large and you experience timeouts.

'max-records' is the maximum number of records allowed in a single zone transfer.
ixfrdist will abort the zone transfer from the master when more than this number of records have been
received. A value of 0 means unlimited)"
  });

  auto failedSOARetry = std::make_shared<uint16_t>(30);
  pdns::config::registerOption<uint16_t>("failed-soa-retry", false, "Time in seconds between retries of the SOA query for a zone we have never transferred.", failedSOARetry);

  auto tcpInThreads = std::make_shared<uint16_t>(10);
  pdns::config::registerOption<uint16_t>("tcp-in-threads", false, "Number of threads to spawn for TCP connections (AXFRs) from downstream hosts.", tcpInThreads);

  pdns::config::registerOption("domains", pdns::config::configInfoFuncs{
    .check = [](const YAML::Node &n, const bool initial) {
      if (n.IsNull()) { return; }
      auto cfg = n.as<ixfrdistDomainConfig>();
      if (!initial && cfg != g_domainConfigs) {
        throw std::runtime_error("'domains' can not be changed at runtime");
      }
    },
    .defaults = [](){ return YAML::Node(vector<string>()); },
    .apply = [](const YAML::Node &n, const bool initial) {
      if (!initial) {
        return;
      }
      if (n.IsNull()) { return; }
      g_domainConfigs = n.as<ixfrdistDomainConfig>();
      for (auto const &d : g_domainConfigs) {
        g_stats.registerDomain(d.first);
      }
    },
    .current = []() { return YAML::Node(g_domainConfigs); },
    .help = R"(The domains to redistribute, the 'master' and 'domains' keys are mandatory.
When no port is specified, 53 is used. When specifying ports for IPv6, use the
"bracket" notation:

   domains:
     - domain: example.com
       master: 192.0.2.15
     - domain: rpz.example
       master: [2001:DB8:a34:543::53]:5353)"
  });

  pdns::config::registerOption("compress", pdns::config::configInfoFuncs{
    .check = [](const YAML::Node &n, const bool initial) {
      if (n.IsNull()) { return; }
      if (n.IsScalar()) {
        n.as<bool>();
        return;
      }
      throw std::runtime_error("'compress' value is not a bool");
    },
    .defaults = [](){ return YAML::Node(false); },
    .apply = [](const YAML::Node &n, const bool initial) {
      if (!n.IsNull()) {
        g_compress = n.as<bool>();
      }
      g_log<<Logger::Notice<<"Record compression is "<<(g_compress ? "en" : "dis")<<"abled."<<endl;
    },
    .current = []() { return YAML::Node(g_compress); },
    .help = R"(Whether record compression should be enabled, leading to smaller answers
at the cost of an increased CPU and memory usage.)"
  });

  ComboAddress webserverListen;
  NetmaskGroup webserverACL;
  webserverACL.addMask("127.0.0.0/24");
  webserverACL.addMask("::1");
  string webserverLoglevel("normal");
  static const std::set<string> webserverConfigItems = {"listen", "acl", "loglevel"};
  static const std::set<string> webserverLoglevels = {"none", "detailed", "normal"};
  pdns::config::registerOption("webserver", pdns::config::configInfoFuncs{
    .check = [&webserverListen, &webserverACL, &webserverLoglevel](const YAML::Node &n, const bool initial) {
      if (n.IsNull()) { return; }
      if (!n.IsMap()) {
        throw std::runtime_error("'webserver' config is not a map");
      }
      ComboAddress listen;
      NetmaskGroup acl;
      string loglevel;
      for (auto nit = n.begin(); nit != n.end(); nit++) {
        auto opt = nit->first.as<string>();
        if (webserverConfigItems.count(opt) == 0) {
          throw std::runtime_error("Unknown 'webserver' option '" + opt + "'");
        }
        if (opt == "listen") {
          listen = nit->second.as<ComboAddress>();
        }
        if (opt == "acl") {
          acl = nit->second.as<NetmaskGroup>();
        }
        if (opt == "loglevel") {
          loglevel = nit->second.as<string>();
          if (webserverLoglevels.count(loglevel) != 1) {
            throw std::runtime_error(loglevel + " is not a valid webserver loglevel");
          }
        }
      }
      if (listen == ComboAddress()) {
        // We're not listening
        return;
      }
      if (initial) {
        // fine
        return;
      }
      if (loglevel != webserverLoglevel || listen != webserverListen) {
        // TODO compare NMG
        throw std::runtime_error("'webserver' settings can not be changed at runtime");
      }
    },
    .defaults = [](){ return YAML::Node(std::map<string, string>()); },
    .apply = [&webserverListen, &webserverACL, &webserverLoglevel](const YAML::Node &n, const bool initial) {
      if (!initial) {
        return;
      }
      if (n.IsNull()) { return; }
      for (auto nit = n.begin(); nit != n.end(); nit++) {
        auto opt = nit->first.as<string>();
        if (opt == "listen") {
          webserverListen = nit->second.as<ComboAddress>();
        }
        if (opt == "acl") {
          webserverACL = nit->second.as<NetmaskGroup>();
        }
        if (opt == "loglevel") {
          webserverLoglevel = nit->second.as<string>();
        }
      }
    },
    .current = [&webserverListen, &webserverACL, &webserverLoglevel]() {
      YAML::Node ret;
      ret["listen"] = webserverListen;
      ret["acl"] = webserverACL;
      ret["loglevel"] = webserverLoglevel;
      return ret;
    },
    .help = R"(Configuration for the webserver.
This is a map with 3 possible elements:
listen
  The IP address and port to listen on.
  When this is not set, the webserver is not started
acl
  The netmasks allowed to access the webserver. When unset, only 127.0.0.0/8, ::1/128 are allowed.
loglevel
  How much the webserver should log: 'none', 'normal' or 'detailed'.
  With 'none', nothing is logged except for errors
  With 'normal' (the default), one line per request is logged in the style of the common log format
  with 'detailed', the full requests and responses (including headers) are logged

Here's an example config:

  webserver:
    listen: 127.0.0.1:8080
    acl:
      - 127.0.0.0/8
      - ::1/128
    loglevel: detailed
    )"
  });

  char tmp[512];
  string workdir = getcwd(tmp, sizeof(tmp)) ? string(tmp) : "";
  pdns::config::registerOption("work-dir", pdns::config::configInfoFuncs{
    .check = [&workdir](const YAML::Node &n, const bool initial) {
      if (n.IsNull()) { return; }
      auto tmpWorkdir = n.as<string>();
      if (initial) {
        return;
      }
      if (tmpWorkdir != workdir) {
        throw std::runtime_error("'work-dir' can not be updated at runtime");
      }
    },
    .defaults = [](){ return YAML::Node(string()); },
    .apply = [&workdir](const YAML::Node &n, const bool initial) {
      if (n.IsNull()) { return; }
      if (!initial) {
        return;
      }
      workdir = n.as<string>();
    },
    .current = [&workdir]() { return YAML::Node(workdir); },
    .help = R"(The directory where the domain data is stored. When unset, the current
working directory is used. Note that this directory must be writable for the
user or group ixfrdist runs as. e.g
    work-dir: '/var/lib/ixfrdist')"
  });

  int newgid = -1;
  pdns::config::registerOption("gid", pdns::config::configInfoFuncs{
    .check = [&newgid](const YAML::Node &n, const bool initial) {
      if (n.IsNull()) { return; }
      auto gid = n.as<string>();
      if (gid.empty()) {
        return;
      }
      int parsedgid;
      if (!(parsedgid = atoi(gid.c_str()))) {
        struct group *gr = getgrnam(gid.c_str());
        if (gr == nullptr) {
          throw std::runtime_error("Can not determine group-id for gid " + gid);
        }
      }
      if (initial) {
        return;
      }
      if (parsedgid != newgid) {
        throw std::runtime_error("'gid' can not be updated at runtime");
      }
    },
    .defaults = [](){ return YAML::Node(""); },
    .apply = [&newgid](const YAML::Node &n, const bool initial) {
      if (n.IsNull()) { return; }
      if (!initial) {
        return;
      }
      auto gid = n.as<string>();
      if (gid.empty()) {
        return;
      }
      if (!(newgid = atoi(gid.c_str()))) {
        struct group *gr = getgrnam(gid.c_str());
        // This is safe 'check' verified this
        newgid = gr->gr_gid;
      }
    },
    .current = [&newgid]() {
      if (newgid == -1) {
        return YAML::Node("");
      }
      struct group* gr = getgrgid(newgid);
      if (gr != nullptr) {
        return YAML::Node(gr->gr_name);
      }
      return YAML::Node("");
    },
    .help = "Group to drop privileges to once all listen-sockets are bound. May be either a username or numerical ID."
  });

  int newuid = -1;
  pdns::config::registerOption("uid", pdns::config::configInfoFuncs{
    .check = [&newuid](const YAML::Node &n, const bool initial) {
      if (n.IsNull()) { return; }
      auto uid = n.as<string>();
      if (uid.empty()) {
        return;
      }
      int parseduid;
      if (!(parseduid = atoi(uid.c_str()))) {
        struct passwd *pw = getpwnam(uid.c_str());
        if (pw == nullptr) {
          throw std::runtime_error("Can not determine user-id for uid " + uid);
        }
      }
      if (initial) {
        return;
      }
      if (parseduid != newuid) {
        throw std::runtime_error("'uid' can not be updated at runtime");
      }
    },
    .defaults = [](){ return YAML::Node(""); },
    .apply = [&newuid](const YAML::Node &n, const bool initial) {
      if (n.IsNull()) { return; }
      if (!initial) {
        return;
      }
      auto uid = n.as<string>();
      if (uid.empty()) {
        return;
      }
      if (!(newuid = atoi(uid.c_str()))) {
        struct passwd *pw = getpwnam(uid.c_str());
        // This is safe 'check' verified this
        newuid = pw->pw_uid;
      }
    },
    .current = [&newuid]() {
      if (newuid == -1) {
        return YAML::Node("");
      }
      struct passwd* pw = getpwuid(newuid);
      if (pw != nullptr) {
        return YAML::Node(pw->pw_name);
      }
      return YAML::Node("");
    },
    .help = "User to drop privileges to once all listen-sockets are bound. May be either a username or numerical ID."
  });

  if (g_vm.count("get-default-config")) {
    cout<<pdns::config::dumpDefaults()<<endl;
    return EXIT_SUCCESS;
  }

  auto configpath = g_vm["config"].as<string>();
  g_log<<Logger::Info<<"Loading configuration file from "<<configpath<<endl;
  try {
    pdns::config::parseConfigFile(configpath);
  } catch (const runtime_error &e) {
    g_log<<Logger::Error<<"Unable to load configuration file '"<<configpath<<"': "<<e.what()<<endl;
    return EXIT_FAILURE;
  }

  if (g_vm.count("check-config")) {
    cout<<"Configuration file "<<configpath<<" successfully parsed"<<endl;
    return EXIT_SUCCESS;
  }

  g_log<<Logger::Notice<<"IXFR distributor version "<<VERSION<<" starting up!"<<endl;

  FDMultiplexer* fdm = FDMultiplexer::getMultiplexerSilent();
  if (fdm == nullptr) {
    g_log<<Logger::Error<<"Could not enable a multiplexer for the listen sockets!"<<endl;
    return EXIT_FAILURE;
  }

  set<int> allSockets;
  for (const auto& addr : *listen_addrs) {
    for (const auto& stype : {SOCK_DGRAM, SOCK_STREAM}) {
      try {
        int s = SSocket(addr.sin4.sin_family, stype, 0);
        setNonBlocking(s);
        setReuseAddr(s);
        SBind(s, addr);
        if (stype == SOCK_STREAM) {
          SListen(s, 30); // TODO make this configurable
        }
        fdm->addReadFD(s, stype == SOCK_DGRAM ? handleUDPRequest : handleTCPRequest);
        allSockets.insert(s);
      } catch(runtime_error &e) {
        g_log<<Logger::Error<<e.what()<<endl;
        return EXIT_FAILURE;
      }
    }
  }

  if (newgid != -1) {
    g_log<<Logger::Notice<<"Dropping effective group-id to "<<newgid<<endl;
    if (setgid(newgid) < 0) {
      g_log<<Logger::Error<<"Could not set group id to "<<newgid<<": "<<stringerror()<<endl;
      return EXIT_FAILURE;
    }
  }

  if (webserverListen != ComboAddress()) {
    // Launch the webserver!
    try {
      std::thread(&IXFRDistWebServer::go, IXFRDistWebServer(webserverListen, webserverACL, webserverLoglevel)).detach();
    } catch (const PDNSException &e) {
      g_log<<Logger::Error<<"Unable to start webserver: "<<e.reason<<endl;
      return EXIT_FAILURE;
    }
  }

  if (newuid != -1) {
    struct passwd *pw = getpwuid(newuid);
    if (pw == nullptr) {
      if (setgroups(0, nullptr) < 0) {
        g_log<<Logger::Error<<"Unable to drop supplementary gids: "<<stringerror()<<endl;
        return EXIT_FAILURE;
      }
    } else {
      if (initgroups(pw->pw_name, newgid) < 0) {
        g_log<<Logger::Error<<"Unable to set supplementary groups: "<<stringerror()<<endl;
        return EXIT_FAILURE;
      }
    }

    g_log<<Logger::Notice<<"Dropping effective user-id to "<<newuid<<endl;
    if (setuid(newuid) < 0) {
      g_log<<Logger::Error<<"Could not set user id to "<<newuid<<": "<<stringerror()<<endl;
      return EXIT_FAILURE;
    }
  }

  // It all starts here
  signal(SIGTERM, handleSignal);
  signal(SIGINT, handleSignal);
  signal(SIGPIPE, SIG_IGN);

  // Init the things we need
  reportAllTypes();

  dns_random_init();

  std::thread ut(updateThread,
      workdir,
      *keep,
      axfr_timeout,
      *failedSOARetry,
      axfr_max_records);

  vector<std::thread> tcpHandlers;
  tcpHandlers.reserve(*tcpInThreads);
  for (size_t i = 0; i < tcpHandlers.capacity(); ++i) {
    tcpHandlers.push_back(std::thread(tcpWorker, i));
  }

  struct timeval now;
  for(;;) {
    gettimeofday(&now, 0);
    fdm->run(&now);
    if (g_exiting) {
      g_log<<Logger::Debug<<"Closing listening sockets"<<endl;
      for (const int& fd : allSockets) {
        try {
          closesocket(fd);
        } catch(PDNSException &e) {
          g_log<<Logger::Error<<e.reason<<endl;
        }
      }
      break;
    }
  }
  g_log<<Logger::Debug<<"Waiting for all threads to stop"<<endl;
  g_tcpHandlerCV.notify_all();
  ut.join();
  for (auto &t : tcpHandlers) {
    t.join();
  }
  g_log<<Logger::Notice<<"IXFR distributor stopped"<<endl;
  return EXIT_SUCCESS;
}
