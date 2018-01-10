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

void updateThread() {
  std::map<DNSName, uint32_t> serials;
  std::map<DNSName, time_t> lastCheck;

  // Initialize the serials we have
  for (const auto &domain : g_domains) {
    lastCheck[domain] = 0;
    string dir = g_workdir + "/" + domain.toString();
    try {
      serials[domain] = getSerialsFromDir(dir);
    } catch (runtime_error &e) {
      // Most likely, the directory does not exist.
      cerr<<"[INFO] "<<e.what()<<", attempting to create"<<endl;
      // Attempt to create it, if _that_ fails, there is no hope
      if (mkdir(dir.c_str(), 0777) == -1) {
        cerr<<"[Error] Could not create '"<<dir<<"': "<<strerror(errno)<<endl;
        exit(EXIT_FAILURE);
      }
    }
  }

  while (true) {
    time_t now = time(nullptr);
    for (const auto &domain : g_domains) {
      string dir = g_workdir + "/" + domain.toString();
      if (now - lastCheck[domain] < 30) { // YOLO 30 seconds
          continue;
      }
      if (serials.find(domain) != serials.end() && serials[domain] != 0) {
        if (g_verbose) {
          cerr<<"[INFO] Attempting to retrieve SOA Serial update for '"<<domain<<"' from '"<<g_master.toStringWithPort()<<"'"<<endl;
        }
        shared_ptr<SOARecordContent> sr;
        try {
          auto newSerial = getSerialFromMaster(g_master, domain, sr); // TODO TSIG
          if (g_verbose) {
            cerr<<"[INFO]   Got SOA Serial: "<< newSerial<<", had Serial: "<<serials[domain]<<endl;
          }
          if (newSerial == serials[domain]) {
            if (g_verbose) {
              cerr<<"[INFO]   Not updating."<<endl;
            }
            continue;
          }
        } catch (runtime_error &e) {
          cerr<<"[WARNING] Unable to get SOA serial update for '"<<domain<<"': "<<e.what()<<endl;
          continue;
        }
      }
      // Now get the full zone!
      if (g_verbose) {
        cerr<<"[INFO] Attempting to receive full zonedata for '"<<domain<<"'"<<endl;
      }
      ComboAddress local = g_master.sin4.sin_family == AF_INET ? ComboAddress("0.0.0.0") : ComboAddress("::");
      TSIGTriplet tt;
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
          }
        }
        if (g_verbose) {
          cerr<<"[INFO]   Done! Received "<<nrecords<<" records. Attempting to write to disk!"<<endl;
        }
        writeZoneToDisk(records, domain, dir);
        if (g_verbose) {
          cerr<<"[INFO]   Done!"<<endl;
        }
      } catch (ResolverException &e) {
        cerr<<"[WARNING] Could not retrieve AXFR for '"<<domain<<"': "<<e.reason<<endl;
      } catch (runtime_error &e) {
        cerr<<"[WARNING] Could not save zone '"<<domain<<"' to disk: "<<e.what()<<endl;
      }
      serials[domain] = getSerialsFromDir(dir);
      lastCheck[domain] = now;
    } /* for (const auto &domain : domains) */
    sleep(10);
  } /* while (true) */
} /* updateThread */

void handleUDPRequest(int fd, boost::any&) {
  // TODO make the buffer-size configurable
  char buf[4096];
  struct sockaddr saddr;
  socklen_t fromlen;
  int res = recvfrom(fd, buf, sizeof(buf), 0, &saddr, &fromlen);
  ComboAddress from(&saddr, fromlen);

  if (res == 0) {
    cerr<<"[Warning] Got an empty message from "<<from.toStringWithPort()<<endl;
    return;
  }

  // TODO better error handling/logging
  if(res < 0) {
    cerr<<"[Warning] Could not read message from "<<from.toStringWithPort()<<": "<<strerror(errno)<<endl;
    return;
  }

  MOADNSParser mdp(true, string(buf, res));
  vector<string> info_msg;

  if (g_debug) {
    cerr<<"[Debug] Had "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" query from "<<from.toStringWithPort()<<endl;
  }

  if (mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::AXFR && mdp.d_qtype != QType::IXFR) {
    info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).getName() + " is not in {SOA,AXFR,IXFR}.");
  }

  if (g_domains.find(mdp.d_qname) == g_domains.end()) {
    info_msg.push_back("Domain name '" + mdp.d_qname.toLogString() + "' is not configured for distribution");
  }

  if (!info_msg.empty()) {
    cerr<<"[Warning] Ignoring "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" query from "<<from.toStringWithPort();
    if (g_verbose) {
      cerr<<":";
      for (const auto& s : info_msg) {
        cerr<<endl<<"    "<<s;
      }
    }
    cerr<<endl;
    return;
  }
}

void handleTCPRequest(int fd, boost::any&) {
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
        cerr<<"[Error] listen-address '"<<addr<<"' is not an IP address: "<<e.reason<<endl;
        had_error = true;
      }
    }
  }

  try {
    g_master = ComboAddress(g_vm["server-address"].as<string>(), 53);
  } catch(PDNSException &e) {
    cerr<<"[Error] server-address '"<<g_vm["server-address"].as<string>()<<"' is not an IP address: "<<e.reason<<endl;
    had_error = true;
  }

  if (!g_vm.count("domains")) {
    cerr<<"[Error] No domain(s) specified!"<<endl;
    had_error = true;
  }

  for (const auto &domain : g_vm["domains"].as<vector<string>>()) {
    try {
      g_domains.insert(DNSName(domain));
    } catch (PDNSException &e) {
      cerr<<"[Error] '"<<domain<<"' is not a valid domain name: "<<e.reason<<endl;
      had_error = true;
    }
  }

  for (const auto addr : listen_addresses) {
    // Create UDP socket
    int s = socket(addr.sin4.sin_family, SOCK_DGRAM, 0);
    if (s < 0) {
      cerr<<"[Error] Unable to create socket: "<<strerror(errno)<<endl;
      had_error = true;
      continue;
    }

    setNonBlocking(s);

    if (bind(s, (sockaddr*) &addr, addr.getSocklen()) < 0) {
      cerr<<"[Error] Unable to bind to "<<addr.toStringWithPort()<<": "<<strerror(errno)<<endl;
      had_error = true;
      continue;
    }

    g_fdm.addReadFD(s, handleUDPRequest);

    // Create TCP socket
    int t = socket(addr.sin4.sin_family, SOCK_STREAM, 0);

    if (t < 0) {
      cerr<<"[Error] Unable to create socket: "<<strerror(errno)<<endl;
      had_error = true;
      continue;
    }

    setNonBlocking(t);

    if (bind(t, (sockaddr*) &addr, addr.getSocklen()) < 0) {
      cerr<<"[Error] Unable to bind to "<<addr.toStringWithPort()<<": "<<strerror(errno)<<endl;
      had_error = true;
    }

    // TODO Make backlog configurable?
    if (listen(t, 30) < 0) {
      cerr<<"[Error] Unable to listen on "<<addr.toStringWithPort()<<": "<<strerror(errno)<<endl;
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

  // Updater thread (TODO: actually thread it :))
  // TODO use mplexer?
  // updateThread();

  // start loop
  cout<<"IXFR distributor starting up!"<<endl;
  struct timeval now;
  for(;;) {
    gettimeofday(&now, 0);
    g_fdm.run(&now);
  }
}
