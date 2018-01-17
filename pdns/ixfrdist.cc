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
#include "ixfr.hh"
#include "ixfrutils.hh"
#include "resolver.hh"
#include "dns_random.hh"
#include "sstuff.hh"
#include "mplexer.hh"


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
SelectFDMultiplexer g_fdm;

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

void usage(po::options_description &desc) {
  cerr << "Usage: ixfrdist [OPTION]... DOMAIN [DOMAIN]..."<<endl;
  cerr << desc << "\n";
}

void* updateThread(void*) {
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
    } catch (runtime_error &e) {
      // Most likely, the directory does not exist.
      cerr<<"[INFO] "<<e.what()<<", attempting to create"<<endl;
      // Attempt to create it, if _that_ fails, there is no hope
      if (mkdir(dir.c_str(), 0777) == -1) {
        cerr<<"[ERROR] Could not create '"<<dir<<"': "<<strerror(errno)<<endl;
        exit(EXIT_FAILURE);
      }
    }
  }

  if (g_verbose) {
    cerr<<"[INFO] Update Thread started"<<endl;
  }

  while (true) {
    time_t now = time(nullptr);
    for (const auto &domain : g_domains) {
      string dir = g_workdir + "/" + domain.toString();
      if (now - lastCheck[domain] < 30) { // YOLO 30 seconds
        continue;
      }
      if (g_verbose) {
        cerr<<"[INFO] Attempting to retrieve SOA Serial update for '"<<domain<<"' from '"<<g_master.toStringWithPort()<<"'"<<endl;
      }
      shared_ptr<SOARecordContent> sr;
      try {
        auto newSerial = getSerialFromMaster(g_master, domain, sr); // TODO TSIG
        if(g_soas.find(domain) != g_soas.end() && g_verbose) {
          cerr<<"[INFO]   Got SOA Serial: "<< newSerial<<", had Serial: "<<g_soas[domain]->d_st.serial<<endl;
        }
        if (g_soas.find(domain) != g_soas.end() && newSerial == g_soas[domain]->d_st.serial) {
          if (g_verbose) {
            cerr<<"[INFO]   Not updating."<<endl;
          }
          continue;
        }
      } catch (runtime_error &e) {
        cerr<<"[WARNING] Unable to get SOA serial update for '"<<domain<<"': "<<e.what()<<endl;
        continue;
      }
      // Now get the full zone!
      if (g_verbose) {
        cerr<<"[INFO] Attempting to receive full zonedata for '"<<domain<<"'"<<endl;
      }
      ComboAddress local = g_master.sin4.sin_family == AF_INET ? ComboAddress("0.0.0.0") : ComboAddress("::");
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
        if (g_verbose) {
          cerr<<"[INFO]    Done! Received "<<nrecords<<" records. Attempting to write to disk!"<<endl;
        }
        writeZoneToDisk(records, domain, dir);
        if (g_verbose) {
          cerr<<"[INFO]    Done!"<<endl;
        }
      } catch (ResolverException &e) {
        cerr<<"[WARNING] Could not retrieve AXFR for '"<<domain<<"': "<<e.reason<<endl;
      } catch (runtime_error &e) {
        cerr<<"[WARNING] Could not save zone '"<<domain<<"' to disk: "<<e.what()<<endl;
      }
      lastCheck[domain] = now;
      {
        std::lock_guard<std::mutex> guard(g_soas_mutex);
        if (soa != nullptr) {
          g_soas[domain] = soa;
        }
      }
    } /* for (const auto &domain : domains) */
    sleep(10);
  } /* while (true) */
} /* updateThread */

bool checkQuery(const MOADNSParser& mdp, const ComboAddress& saddr, const bool udp = true) {
  vector<string> info_msg;

  if (g_debug) {
    cerr<<"[DEBUG] Had "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" query from "<<saddr.toStringWithPort()<<endl;
  }

  if (udp && mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::IXFR) {
    info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).getName() + " is not in {SOA,IXFR}.");
  }

  if (!udp && mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::IXFR && mdp.d_qtype != QType::AXFR) {
    info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).getName() + " is not in {SOA,IXFR,AXFR}.");
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
      cerr<<":";
      for (const auto& s : info_msg) {
        cerr<<endl<<"    "<<s;
      }
    }
    cerr<<endl;
    return false;
  }

  return true;
}

vector<uint8_t> makeSOAPacket(const MOADNSParser& mdp) {
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;

  pw.startRecord(mdp.d_qname, QType::SOA);
  g_soas[mdp.d_qname]->toPacket(pw);
  pw.commit();

  return packet;
}


void handleUDPRequest(int fd, boost::any&) {
  // TODO make the buffer-size configurable
  char buf[4096];
  ComboAddress saddr;
  socklen_t fromlen;
  int res = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*) &saddr, &fromlen);

  if (res == 0) {
    cerr<<"[WARNING] Got an empty message from "<<saddr.toStringWithPort()<<endl;
    return;
  }

  // TODO better error handling/logging
  if(res < 0) {
    cerr<<"[WARNING] Could not read message from "<<saddr.toStringWithPort()<<": "<<strerror(errno)<<endl;
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

  // Let's not complicate this with IXFR over UDP (and looking if we need to truncate etc).
  // Just send the current SOA and let the client try over TCP
  auto packet = makeSOAPacket(mdp);
  if(sendto(fd, &packet[0], packet.size(), 0, (struct sockaddr*) &saddr, fromlen) < 0) {
    cerr<<"[WARNING] Could not send reply for "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" to "<<saddr.toStringWithPort()<<": "<<strerror(errno)<<endl;
  }
  return;
}

void handleTCPRequest(int fd, boost::any&) {
  ComboAddress saddr;
  socklen_t socklen;

  int cfd = accept(fd, (sockaddr*) &saddr, &socklen);

  if (cfd == -1) {
    cerr<<"Accepting connection from "<<saddr.toStringWithPort()<<" failed: "<<strerror(errno)<<endl;
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
      cerr<<"[WARNING] Could not read message from "<<saddr.toStringWithPort()<<": "<<strerror(errno)<<endl;
      close(cfd);
      return;
    }
  }

  res = recv(cfd, &buf, sizeof(buf), 0);

  if (res == -1) {
    cerr<<"[WARNING] Could not read message from "<<saddr.toStringWithPort()<<": "<<strerror(errno)<<endl;
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

    vector<uint8_t> packet;
    if (mdp.d_qtype == QType::SOA) {
      packet = makeSOAPacket(mdp);
    }

    char buf[2];
    buf[0]=packet.size()/256;
    buf[1]=packet.size()%256;

    int send = writen2(cfd, buf, 2);
    send += writen2(cfd, &packet[0], packet.size());
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
  po::options_description desc("IXFR distribution tool");
  desc.add_options()
    ("help", "produce help message")
    ("version", "Display the version of ixfrdist")
    ("verbose", "Be verbose")
    ("debug", "Be even more verbose")
    ("listen-address", po::value< vector< string>>(), "IP Address(es) to listen on")
    ("server-address", po::value<string>()->default_value("127.0.0.1:5300"), "server address")
    ("work-dir", po::value<string>()->default_value("."), "Directory for storing AXFR and IXFR data")
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

  if (g_vm.count("verbose") > 0 || g_vm.count("debug") > 0) {
    g_verbose = true;
  }

  if (g_vm.count("debug") > 0) {
    g_debug = true;
  }

  bool had_error = false;

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
  }

  for (const auto &domain : g_vm["domains"].as<vector<string>>()) {
    try {
      g_domains.insert(DNSName(domain));
    } catch (PDNSException &e) {
      cerr<<"[ERROR] '"<<domain<<"' is not a valid domain name: "<<e.reason<<endl;
      had_error = true;
    }
  }

  for (const auto addr : listen_addresses) {
    // Create UDP socket
    int s = socket(addr.sin4.sin_family, SOCK_DGRAM, 0);
    if (s < 0) {
      cerr<<"[ERROR] Unable to create socket: "<<strerror(errno)<<endl;
      had_error = true;
      continue;
    }

    setNonBlocking(s);

    if (bind(s, (sockaddr*) &addr, addr.getSocklen()) < 0) {
      cerr<<"[ERROR] Unable to bind to "<<addr.toStringWithPort()<<": "<<strerror(errno)<<endl;
      had_error = true;
      continue;
    }

    g_fdm.addReadFD(s, handleUDPRequest);

    // Create TCP socket
    int t = socket(addr.sin4.sin_family, SOCK_STREAM, 0);

    if (t < 0) {
      cerr<<"[ERROR] Unable to create socket: "<<strerror(errno)<<endl;
      had_error = true;
      continue;
    }

    setNonBlocking(t);

    if (bind(t, (sockaddr*) &addr, addr.getSocklen()) < 0) {
      cerr<<"[ERROR] Unable to bind to "<<addr.toStringWithPort()<<": "<<strerror(errno)<<endl;
      had_error = true;
    }

    // TODO Make backlog configurable?
    if (listen(t, 30) < 0) {
      cerr<<"[ERROR] Unable to listen on "<<addr.toStringWithPort()<<": "<<strerror(errno)<<endl;
      had_error = true;
      continue;
    }

    g_fdm.addReadFD(t, handleTCPRequest);
  }

  g_workdir = g_vm["work-dir"].as<string>();

  if (had_error) {
    // We have already sent the errors to stderr, just die
    return EXIT_FAILURE;
  }

  // It all starts here
  // Init the things we need
  reportAllTypes();

  // TODO read from urandom (perhaps getrandom(2)?
  dns_random_init("0123456789abcdef");

  pthread_t qtid;

  cout<<"[INFO] IXFR distributor starting up!"<<endl;

  pthread_create(&qtid, 0, updateThread, 0);

  struct timeval now;
  for(;;) {
    gettimeofday(&now, 0);
    g_fdm.run(&now);
  }
}
