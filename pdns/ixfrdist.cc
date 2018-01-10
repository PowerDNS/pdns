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

using namespace boost::multi_index;

namespace po = boost::program_options;
po::variables_map g_vm;
string g_workdir;
ComboAddress g_master;
bool g_verbose = false;

void usage(po::options_description &desc) {
  cerr << "Usage: ixfrdist [OPTION]... DOMAIN [DOMAIN]..."<<endl;
  cerr << desc << "\n";
}

void updateThread(const vector<DNSName> &domains) {
  std::map<DNSName, uint32_t> serials;
  std::map<DNSName, time_t> lastCheck;

  // Initialize the serials we have
  for (const auto &domain : domains) {
    lastCheck[domain] = 0;
    string dir = g_workdir + "/" + domain.toString();
    try {
      serials[domain] = getSerialsFromDir(dir);
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

  while (true) {
    time_t now = time(nullptr);
    for (const auto &domain : domains) {
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

int main(int argc, char** argv) {
  po::options_description desc("IXFR distribution tool");
  desc.add_options()
    ("help", "produce help message")
    ("version", "Display the version of ixfrdist")
    ("verbose", "Be verbose")
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

  if (g_vm.count("help")) {
    usage(desc);
    return EXIT_SUCCESS;
  }

  if (g_vm.count("version")) {
    cout<<"ixfrdist "<<VERSION<<endl;
    return EXIT_SUCCESS;
  }

  if (g_vm.count("verbose")) {
    g_verbose = true;
  }

  bool had_error = false;

  vector<ComboAddress> listen_addresses = {ComboAddress("127.0.0.1:53")};

  if (g_vm.count("listen-address")) {
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

  vector<DNSName> domains;

  for (const auto &domain : g_vm["domains"].as<vector<string>>()) {
    try {
      domains.push_back(DNSName(domain));
    } catch (PDNSException &e) {
      cerr<<"[Error] '"<<domain<<"' is not a valid domain name: "<<e.reason<<endl;
      had_error = true;
    }
  }

  g_workdir = g_vm["work-dir"].as<string>();

  if (had_error) {
    // We have already sent the errors to stderr, just die
    return EXIT_FAILURE;
  }

  // It all starts here
  // Init the things we need
  reportAllTypes();
  dns_random_init("0123456789abcdef");

  // Updater thread (TODO: actually thread it :))
  updateThread(domains);
}
