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
#include <sys/stat.h>
#include <mutex>
#include <thread>
#include <dirent.h>
#include "ixfr.hh"
#include "ixfrutils.hh"
#include "resolver.hh"
#include "dns_random.hh"
#include "sstuff.hh"
#include "mplexer.hh"
#include "misc.hh"
#include "iputils.hh"

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


// For all the listen-sockets
FDMultiplexer* g_fdm;

// The domains we support
set<DNSName> g_domains;

// Map domains to SOA Records and have a mutex to update it.
std::map<DNSName, shared_ptr<SOARecordContent>> g_soas;
std::mutex g_soas_mutex;

using namespace boost::multi_index;

namespace po = boost::program_options;
po::variables_map g_vm;
string g_workdir;
ComboAddress g_master;

bool g_verbose = false;
bool g_debug = false;

bool g_exiting = false;

#define KEEP_DEFAULT 20
uint16_t g_keep = KEEP_DEFAULT;

void handleSignal(int signum) {
  if (g_verbose) {
    cerr<<"[INFO] Got "<<strsignal(signum)<<" signal";
  }
  if (g_exiting) {
    if (g_verbose) {
      cerr<<", this is the second time we were asked to stop, forcefully exiting"<<endl;
    }
    exit(EXIT_FAILURE);
  }
  if (g_verbose) {
    cerr<<", stopping"<<endl;
  }
  g_exiting = true;
}

void usage(po::options_description &desc) {
  cerr << "Usage: ixfrdist [OPTION]... DOMAIN [DOMAIN]..."<<endl;
  cerr << desc << "\n";
}

// The compiler does not like using rfc1982LessThan in std::sort directly
bool sortSOA(uint32_t i, uint32_t j) {
  return rfc1982LessThan(i, j);
}

void cleanUpDomain(const DNSName& domain) {
  string dir = g_workdir + "/" + domain.toString();
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
  if (g_verbose) {
    cerr<<"[INFO] Found "<<zoneVersions.size()<<" versions of "<<domain<<", asked to keep "<<g_keep<<", ";
  }
  if (zoneVersions.size() <= g_keep) {
    if (g_verbose) {
      cerr<<"not cleaning up"<<endl;
    }
    return;
  }
  if (g_verbose) {
    cerr<<"cleaning up the oldest "<<zoneVersions.size() - g_keep<<endl;
  }

  // Sort the versions
  std::sort(zoneVersions.begin(), zoneVersions.end(), sortSOA);

  // And delete all the old ones
  {
    // Lock to ensure no one reads this.
    std::lock_guard<std::mutex> guard(g_soas_mutex);
    for (auto iter = zoneVersions.cbegin(); iter != zoneVersions.cend() - g_keep; ++iter) {
      string fname = dir + "/" + std::to_string(*iter);
      if (g_debug) {
        cerr<<"[DEBUG] Removing "<<fname<<endl;
      }
      unlink(fname.c_str());
    }
  }
}

void updateThread() {
  std::map<DNSName, time_t> lastCheck;

  // Initialize the serials we have
  for (const auto &domain : g_domains) {
    lastCheck[domain] = 0;
    string dir = g_workdir + "/" + domain.toString();
    try {
      auto serial = getSerialsFromDir(dir);
      shared_ptr<SOARecordContent> soa;
      {
        loadSOAFromDisk(domain, g_workdir + "/" + domain.toString() + "/" + std::to_string(serial), soa);
        std::lock_guard<std::mutex> guard(g_soas_mutex);
        if (soa != nullptr) {
          g_soas[domain] = soa;
        }
      }
      if (soa != nullptr) {
        // Initial cleanup
        cleanUpDomain(domain);
      }
    } catch (runtime_error &e) {
      // Most likely, the directory does not exist.
      cerr<<"[INFO] "<<e.what()<<", attempting to create"<<endl;
      // Attempt to create it, if _that_ fails, there is no hope
      if (mkdir(dir.c_str(), 0777) == -1 && errno != EEXIST) {
        cerr<<"[ERROR] Could not create '"<<dir<<"': "<<strerror(errno)<<endl;
        exit(EXIT_FAILURE);
      }
    }
  }


  if (g_verbose) {
    cerr<<"[INFO] Update Thread started"<<endl;
  }

  while (true) {
    if (g_exiting) {
      if (g_verbose) {
        cerr<<"[INFO] UpdateThread stopped"<<endl;
      }
      break;
    }
    time_t now = time(nullptr);
    for (const auto &domain : g_domains) {
      if ((g_soas.find(domain) != g_soas.end() && now - lastCheck[domain] < g_soas[domain]->d_st.refresh) || // Only check if we have waited `refresh` seconds
          (g_soas.find(domain) == g_soas.end() && now - lastCheck[domain] < 30))  {                          // Or if we could not get an update at all still, every 30 seconds
        continue;
      }
      string dir = g_workdir + "/" + domain.toString();
      if (g_verbose) {
        cerr<<"[INFO] Attempting to retrieve SOA Serial update for '"<<domain<<"' from '"<<g_master.toStringWithPort()<<"'"<<endl;
      }
      shared_ptr<SOARecordContent> sr;
      try {
        lastCheck[domain] = now;
        auto newSerial = getSerialFromMaster(g_master, domain, sr); // TODO TSIG
        if(g_soas.find(domain) != g_soas.end() && g_verbose) {
          cerr<<"[INFO] Got SOA Serial for "<<domain<<" from "<<g_master.toStringWithPort()<<": "<< newSerial<<", had Serial: "<<g_soas[domain]->d_st.serial;
          if (newSerial == g_soas[domain]->d_st.serial) {
            if (g_verbose) {
              cerr<<", not updating."<<endl;
            }
            continue;
          }
          cerr<<", will update."<<endl;
        }
      } catch (runtime_error &e) {
        cerr<<"[WARNING] Unable to get SOA serial update for '"<<domain<<"': "<<e.what()<<endl;
        continue;
      }
      // Now get the full zone!
      if (g_verbose) {
        cerr<<"[INFO] Attempting to receive full zonedata for '"<<domain<<"'"<<endl;
      }
      ComboAddress local = g_master.isIPv4() ? ComboAddress("0.0.0.0") : ComboAddress("::");
      TSIGTriplet tt;
      shared_ptr<SOARecordContent> soa;
      try {
        AXFRRetriever axfr(g_master, domain, tt, &local);
        unsigned int nrecords=0;
        Resolver::res_t nop;
        vector<DNSRecord> chunk;
        records_t records;
        while(axfr.getChunk(nop, &chunk)) {
          for(auto& dr : chunk) {
            if(dr.d_type == QType::TSIG)
              continue;
            dr.d_name.makeUsRelative(domain);
            records.insert(dr);
            nrecords++;
            if (dr.d_type == QType::SOA) {
              soa = getRR<SOARecordContent>(dr);
            }
          }
        }
        if (soa == nullptr) {
          cerr<<"[WARNING] No SOA was found in the AXFR of "<<domain<<endl;
          continue;
        }
        if (g_verbose) {
          cerr<<"[INFO] Retrieved all zone data for "<<domain<<". Received "<<nrecords<<" records."<<endl;
        }
        writeZoneToDisk(records, domain, dir);
        if (g_verbose) {
          cerr<<"[INFO] Wrote zonedata for "<<domain<<" with serial "<<soa->d_st.serial<<" to "<<dir<<endl;
        }
      } catch (ResolverException &e) {
        cerr<<"[WARNING] Could not retrieve AXFR for '"<<domain<<"': "<<e.reason<<endl;
      } catch (runtime_error &e) {
        cerr<<"[WARNING] Could not save zone '"<<domain<<"' to disk: "<<e.what()<<endl;
      }
      {
        std::lock_guard<std::mutex> guard(g_soas_mutex);
        g_soas[domain] = soa;
      }

      // Now clean up the directory
      cleanUpDomain(domain);
    } /* for (const auto &domain : domains) */
    sleep(1);
  } /* while (true) */
} /* updateThread */

bool checkQuery(const MOADNSParser& mdp, const ComboAddress& saddr, const bool udp = true) {
  vector<string> info_msg;

  if (g_debug) {
    cerr<<"[DEBUG] Had "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" query from "<<saddr.toStringWithPort()<<endl;
  }

  if (udp && mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::IXFR) {
    info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).getName() + " is not in {SOA,IXFR}");
  }

  if (!udp && mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::IXFR && mdp.d_qtype != QType::AXFR) {
    info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).getName() + " is not in {SOA,IXFR,AXFR}");
  }

  if (g_domains.find(mdp.d_qname) == g_domains.end()) {
    info_msg.push_back("Domain name '" + mdp.d_qname.toLogString() + "' is not configured for distribution");
  }

  if (g_soas.find(mdp.d_qname) == g_soas.end()) {
    info_msg.push_back("Domain has not been transferred yet");
  }

  if (!info_msg.empty()) {
    cerr<<"[WARNING] Ignoring "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" query from "<<saddr.toStringWithPort();
    if (g_verbose) {
      cerr<<": ";
      bool first = true;
      for (const auto& s : info_msg) {
        if (!first) {
          cerr<<", ";
          first = false;
        }
        cerr<<s;
      }
    }
    cerr<<endl;
    return false;
  }

  return true;
}

/*
 * Returns a vector<uint8_t> that represents the full response to a SOA
 * query. QNAME is read from mdp.
 */
bool makeSOAPacket(const MOADNSParser& mdp, vector<uint8_t>& packet) {
  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;

  pw.startRecord(mdp.d_qname, QType::SOA);
  g_soas[mdp.d_qname]->toPacket(pw);
  pw.commit();

  return true;
}

vector<uint8_t> getSOAPacket(const MOADNSParser& mdp, const shared_ptr<SOARecordContent>& soa) {
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;

  // Add the first SOA
  pw.startRecord(mdp.d_qname, QType::SOA);
  soa->toPacket(pw);
  pw.commit();
  return packet;
}

bool makeAXFRPackets(const MOADNSParser& mdp, vector<vector<uint8_t>>& packets) {
  string dir = g_workdir + "/" + mdp.d_qname.toString();
  auto serial = getSerialsFromDir(dir);
  string fname = dir + "/" + std::to_string(serial);
  // Use the SOA from the file, the one in g_soas _may_ have changed
  shared_ptr<SOARecordContent> soa;
  loadSOAFromDisk(mdp.d_qname, fname, soa);
  if (soa == nullptr) {
    // :(
    cerr<<"[WARNING] Could not retrieve SOA record from "<<fname<<" for AXFR"<<endl;
    return false;
  }
  records_t records;
  loadZoneFromDisk(records, fname, mdp.d_qname);
  if (records.empty()) {
    cerr<<"[WARNING] Could not load zone from "<<fname<<" for AXFR"<<endl;
    return false;
  }

  // Initial SOA
  packets.push_back(getSOAPacket(mdp, soa));

  for (auto const &record : records) {
    if (record.d_type == QType::SOA) {
      continue;
    }
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
    pw.getHeader()->id = mdp.d_header.id;
    pw.getHeader()->rd = mdp.d_header.rd;
    pw.getHeader()->qr = 1;
    pw.startRecord(record.d_name + mdp.d_qname, record.d_type);
    record.d_content->toPacket(pw);
    pw.commit();
    packets.push_back(packet);
  }

  // Final SOA
  packets.push_back(getSOAPacket(mdp, soa));

  return true;
}

void makeXFRPacketsFromDNSRecords(const MOADNSParser& mdp, const vector<DNSRecord>& records, vector<vector<uint8_t>>& packets) {
  for(const auto& r : records) {
    if (r.d_type == QType::SOA) {
      continue;
    }
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
    pw.getHeader()->id = mdp.d_header.id;
    pw.getHeader()->rd = mdp.d_header.rd;
    pw.getHeader()->qr = 1;
    pw.startRecord(r.d_name + mdp.d_qname, r.d_type);
    r.d_content->toPacket(pw);
    pw.commit();
    packets.push_back(packet);
  }
}

/* Produces an IXFR if one can be made according to the rules in RFC 1995 and
 * creates a SOA or AXFR packet when required by the RFC.
 */
bool makeIXFRPackets(const MOADNSParser& mdp, const shared_ptr<SOARecordContent>& clientSOA, vector<vector<uint8_t>>& packets) {
  string dir = g_workdir + "/" + mdp.d_qname.toString();
  // Get the new SOA only once, so it will not change under our noses from the
  // updateThread.
  uint32_t newSerial = g_soas[mdp.d_qname]->d_st.serial;

  if (rfc1982LessThan(newSerial, clientSOA->d_st.serial)){
    /* RFC 1995 Section 2
     *    If an IXFR query with the same or newer version number than that of
     *    the server is received, it is replied to with a single SOA record of
     *    the server's current version, just as in AXFR.
     */
    vector<uint8_t> packet;
    bool ret = makeSOAPacket(mdp, packet);
    if (ret) {
      packets.push_back(packet);
    }
    return ret;
  }

  // Let's see if we have the old zone
  string oldZoneFname = dir + "/" + std::to_string(clientSOA->d_st.serial);
  string newZoneFname = dir + "/" + std::to_string(newSerial);
  records_t oldRecords, newRecords;
  shared_ptr<SOARecordContent> newSOA;
  {
    // Make sure the update thread does not clean this in front of our feet
    std::lock_guard<std::mutex> guard(g_soas_mutex);

    // Check if we can actually make an IXFR
    struct stat s;
    if (stat(oldZoneFname.c_str(), &s) == -1) {
      if (errno == ENOENT) {
        if (g_verbose) {
          cerr<<"[INFO] IXFR for "<<mdp.d_qname<<" not possible: no zone data with serial "<<clientSOA->d_st.serial<<", sending out AXFR"<<endl;
        }
        return makeAXFRPackets(mdp, packets);
      }
      cerr<<"[WARNING] Could not determine existence of "<<oldZoneFname<<" for IXFR: "<<strerror(errno)<<endl;
      return false;
    }

    loadSOAFromDisk(mdp.d_qname, newZoneFname, newSOA);

    if (newSOA == nullptr) {
      // :(
      cerr<<"[WARNING] Could not retrieve SOA record from "<<newZoneFname<<" for IXFR"<<endl;
      return false;
    }

    loadZoneFromDisk(oldRecords, oldZoneFname, mdp.d_qname);
    loadZoneFromDisk(newRecords, newZoneFname, mdp.d_qname);
  }

  if (oldRecords.empty() || newRecords.empty()) {
    if (oldRecords.empty()) {
      cerr<<"[WARNING] Unable to load zone from "<<oldZoneFname<<endl;
    }
    if (newRecords.empty()) {
      cerr<<"[WARNING] Unable to load zone from "<<newZoneFname<<endl;
    }
    return false;
  }

  /* An IXFR packet's ANSWER section looks as follows:
   * SOA new_serial
   * SOA old_serial
   * ... removed records ...
   * SOA new_serial
   * ... added records ...
   * SOA new_serial
   */

  packets.push_back(getSOAPacket(mdp, newSOA));
  packets.push_back(getSOAPacket(mdp, clientSOA));

  // Removed records
  vector<DNSRecord> diff;
  set_difference(oldRecords.cbegin(), oldRecords.cend(), newRecords.cbegin(), newRecords.cend(), back_inserter(diff), oldRecords.value_comp());
  makeXFRPacketsFromDNSRecords(mdp, diff, packets);

  // Added records
  packets.push_back(getSOAPacket(mdp, newSOA));

  diff.clear();

  set_difference(newRecords.cbegin(), newRecords.cend(), oldRecords.cbegin(), oldRecords.cend(), back_inserter(diff), oldRecords.value_comp());
  makeXFRPacketsFromDNSRecords(mdp, diff, packets);

  // Final SOA
  packets.push_back(getSOAPacket(mdp, newSOA));

  return true;
}

void handleUDPRequest(int fd, boost::any&) {
  // TODO make the buffer-size configurable
  char buf[4096];
  ComboAddress saddr;
  socklen_t fromlen = sizeof(saddr);
  int res = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*) &saddr, &fromlen);

  if (res == 0) {
    cerr<<"[WARNING] Got an empty message from "<<saddr.toStringWithPort()<<endl;
    return;
  }

  if(res < 0) {
    auto savedErrno = errno;
    cerr<<"[WARNING] Could not read message from "<<saddr.toStringWithPort()<<": "<<strerror(savedErrno)<<endl;
    return;
  }

  if (saddr == ComboAddress("0.0.0.0", 0)) {
    cerr<<"[WARNING] Could not determine source of message"<<endl;
    return;
  }

  MOADNSParser mdp(true, string(buf, res));
  if (!checkQuery(mdp, saddr)) {
    return;
  }

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
  vector<uint8_t> packet;
  makeSOAPacket(mdp, packet);
  if(sendto(fd, &packet[0], packet.size(), 0, (struct sockaddr*) &saddr, fromlen) < 0) {
    auto savedErrno = errno;
    cerr<<"[WARNING] Could not send reply for "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" to "<<saddr.toStringWithPort()<<": "<<strerror(savedErrno)<<endl;
  }
  return;
}

void handleTCPRequest(int fd, boost::any&) {
  ComboAddress saddr;
  int cfd = 0;

  try {
    cfd = SAccept(fd, saddr);
    setBlocking(cfd);
  } catch(runtime_error &e) {
    cerr<<"[ERROR] "<<e.what()<<endl;
    return;
  }

  if (saddr == ComboAddress("0.0.0.0", 0)) {
    cerr<<"[WARNING] Could not determine source of message"<<endl;
    return;
  }

  char buf[4096];
  // Discard the first 2 bytes (qlen)
  int res;
  res = recv(cfd, &buf, 2, 0);
  if (res != 2) {
    if (res == 0) { // Connection is closed
      close(cfd);
      return;
    }
    if (res == -1) {
      auto savedErrno = errno;
      cerr<<"[WARNING] Could not read message from "<<saddr.toStringWithPort()<<": "<<strerror(savedErrno)<<endl;
      close(cfd);
      return;
    }
  }

  res = recv(cfd, &buf, sizeof(buf), 0);

  if (res == -1) {
    auto savedErrno = errno;
    cerr<<"[WARNING] Could not read message from "<<saddr.toStringWithPort()<<": "<<strerror(savedErrno)<<endl;
    close(cfd);
    return;
  }

  if (res == 0) { // Connection is closed
    close(cfd);
    return;
  }

  try {
    MOADNSParser mdp(true, string(buf, res));

    if (!checkQuery(mdp, saddr, false)) {
      close(cfd);
      return;
    }

    vector<vector<uint8_t>> packets;
    if (mdp.d_qtype == QType::SOA) {
    vector<uint8_t> packet;
      bool ret = makeSOAPacket(mdp, packet);
      if (!ret) {
        close(cfd);
        return;
      }
      packets.push_back(packet);
    }

    if (mdp.d_qtype == QType::AXFR) {
      if (!makeAXFRPackets(mdp, packets)) {
        close(cfd);
        return;
      }
    }

    if (mdp.d_qtype == QType::IXFR) {
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
        cerr<<"[WARNING] IXFR request packet did not contain a SOA record in the AUTHORITY section"<<endl;
        close(cfd);
        return;
      }

      if (!makeIXFRPackets(mdp, clientSOA, packets)) {
        close(cfd);
        return;
      }
    } /* if (mdp.d_qtype == QType::IXFR) */

    for (const auto& packet : packets) {
      char buf[2];
      buf[0]=packet.size()/256;
      buf[1]=packet.size()%256;

      int send = writen2(cfd, buf, 2);
      send += writen2(cfd, &packet[0], packet.size());
    }
    shutdown(cfd, 2);
  } catch (MOADNSException &e) {
    cerr<<"[WARNING] Could not parse DNS packet from "<<saddr.toStringWithPort()<<": "<<e.what()<<endl;
  } catch (runtime_error &e) {
    cerr<<"[WARNING] Could not write reply to "<<saddr.toStringWithPort()<<": "<<e.what()<<endl;
  }
  // bye!
  close(cfd);
}

int main(int argc, char** argv) {
  try {
    po::options_description desc("IXFR distribution tool");
    desc.add_options()
      ("help", "produce help message")
      ("version", "Display the version of ixfrdist")
      ("verbose", "Be verbose")
      ("debug", "Be even more verbose")
      ("listen-address", po::value< vector< string>>(), "IP Address(es) to listen on")
      ("server-address", po::value<string>()->default_value("127.0.0.1:5300"), "server address")
      ("work-dir", po::value<string>()->default_value("."), "Directory for storing AXFR and IXFR data")
      ("keep", po::value<uint16_t>()->default_value(KEEP_DEFAULT), "Number of old zone versions to retain")
      ;
    po::options_description alloptions;
    po::options_description hidden("hidden options");
    hidden.add_options()
      ("domains", po::value< vector<string> >(), "domains");

    alloptions.add(desc).add(hidden);
    po::positional_options_description p;
    p.add("domains", -1);

    po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
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
    cerr<<"[ERROR] "<<e.what()<<". See `ixfrdist --help` for valid options"<<endl;
    return(EXIT_FAILURE);
  }

  bool had_error = false;

  if (g_vm.count("verbose") > 0 || g_vm.count("debug") > 0) {
    g_verbose = true;
  }

  if (g_vm.count("debug") > 0) {
    g_debug = true;
  }

  if (g_vm.count("keep") > 0) {
    g_keep = g_vm["keep"].as<uint16_t>();
  }

  vector<ComboAddress> listen_addresses = {ComboAddress("127.0.0.1:53")};

  if (g_vm.count("listen-address") > 0) {
    listen_addresses.clear();
    for (const auto &addr : g_vm["listen-address"].as< vector< string> >()) {
      try {
        listen_addresses.push_back(ComboAddress(addr, 53));
      } catch(PDNSException &e) {
        cerr<<"[ERROR] listen-address '"<<addr<<"' is not an IP address: "<<e.reason<<endl;
        had_error = true;
      }
    }
  }

  try {
    g_master = ComboAddress(g_vm["server-address"].as<string>(), 53);
  } catch(PDNSException &e) {
    cerr<<"[ERROR] server-address '"<<g_vm["server-address"].as<string>()<<"' is not an IP address: "<<e.reason<<endl;
    had_error = true;
  }

  if (!g_vm.count("domains")) {
    cerr<<"[ERROR] No domain(s) specified!"<<endl;
    had_error = true;
  } else {
    for (const auto &domain : g_vm["domains"].as<vector<string>>()) {
      try {
        g_domains.insert(DNSName(domain));
      } catch (PDNSException &e) {
        cerr<<"[ERROR] '"<<domain<<"' is not a valid domain name: "<<e.reason<<endl;
        had_error = true;
      }
    }
  }

  g_fdm = FDMultiplexer::getMultiplexerSilent();
  if (g_fdm == nullptr) {
    cerr<<"[ERROR] Could not enable a multiplexer for the listen sockets!"<<endl;
    return EXIT_FAILURE;
  }

  set<int> allSockets;
  for (const auto& addr : listen_addresses) {
    for (const auto& stype : {SOCK_DGRAM, SOCK_STREAM}) {
      try {
        int s = SSocket(addr.sin4.sin_family, stype, 0);
        setNonBlocking(s);
        setReuseAddr(s);
        SBind(s, addr);
        if (stype == SOCK_STREAM) {
          SListen(s, 30); // TODO make this configurable
        }
        g_fdm->addReadFD(s, stype == SOCK_DGRAM ? handleUDPRequest : handleTCPRequest);
        allSockets.insert(s);
      } catch(runtime_error &e) {
        cerr<<"[ERROR] "<<e.what()<<endl;
        had_error = true;
        continue;
      }
    }
  }

  g_workdir = g_vm["work-dir"].as<string>();

  if (had_error) {
    // We have already sent the errors to stderr, just die
    return EXIT_FAILURE;
  }

  // It all starts here
  signal(SIGTERM, handleSignal);
  signal(SIGINT, handleSignal);
  signal(SIGSTOP, handleSignal);

  // Init the things we need
  reportAllTypes();

  // TODO read from urandom (perhaps getrandom(2)?
  dns_random_init("0123456789abcdef");

  cout<<"[INFO] IXFR distributor starting up!"<<endl;

  std::thread ut(updateThread);

  struct timeval now;
  for(;;) {
    gettimeofday(&now, 0);
    g_fdm->run(&now);
    if (g_exiting) {
      if (g_verbose) {
        cerr<<"[INFO] Shutting down!"<<endl;
      }
      for (const int& fd : allSockets) {
        try {
          closesocket(fd);
        } catch(PDNSException &e) {
          cerr<<"[ERROR] "<<e.reason<<endl;
        }
      }
      break;
    }
  }
  ut.join();
  if (g_verbose) {
    cerr<<"[INFO] IXFR distributor stopped"<<endl;
  }
  return EXIT_SUCCESS;
}
