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
#include "arguments.hh"
#include "base64.hh"
#include <sys/types.h>
#include <dirent.h>

#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "base32.hh"
#include "dnssecinfra.hh"

#include "dns_random.hh"
#include "gss_context.hh"
#include "zoneparser-tng.hh"
#include <boost/multi_index_container.hpp>
#include <boost/program_options.hpp>
#include "resolver.hh"
#include <fstream>
#include "ixfr.hh"
using namespace boost::multi_index;
StatBag S;

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}

namespace po = boost::program_options;
po::variables_map g_vm;

void usage(po::options_description &desc) {
  cerr << "Usage: ixfrdist [OPTION]... DOMAIN [DOMAIN]..."<<endl;
  cerr << desc << "\n";
}

int main(int argc, char** argv) {
  po::options_description desc("IXFR distribution tool");
  desc.add_options()
    ("help", "produce help message")
    ("version", "Display the version of ixfrdist")
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
    ComboAddress serverAddress = ComboAddress(g_vm["server-address"].as<string>(), 53);
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
  if (had_error) {
    // We have already sent the errors to stderr, just die
    return EXIT_FAILURE;
  }
}
