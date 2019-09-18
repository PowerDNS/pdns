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
#include <bitset>
#include "dnsparser.hh"
#include "dns_random.hh"
#include "iputils.hh"
#include <boost/program_options.hpp>

#include <boost/format.hpp>
#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

#include "mplexer.hh"
#include "statbag.hh"
#include "arguments.hh"
#include "version.hh"
#include "namespaces.hh"
using namespace ::boost::multi_index;
#include "namespaces.hh"

namespace po = boost::program_options;
po::variables_map g_vm;

StatBag S;
ArgvMap &arg()
{
  static ArgvMap arg;
  return arg;
}

void usage() {
  cerr<<"Syntax: pdns_notify IP_ADDRESS/HOSTNAME[:PORT] DOMAIN"<<endl;
}

int main(int argc, char** argv)
try
{
  set<ComboAddress> addrs;
  ::arg().set("rng")="auto";
  ::arg().set("entropy-source")="/dev/urandom";

  for(int n=1 ; n < argc; ++n) {
    if ((string) argv[n] == "--help") {
      usage();
      return EXIT_SUCCESS;
    }

    if ((string) argv[n] == "--version") {
      cerr<<"notify "<<VERSION<<endl;
      return EXIT_SUCCESS;
    }
  }

  if(argc!=3) {
    usage();
    exit(1);
  }

  int sock = -1;

 // ComboAddress local("127.0.0.1", (int)0);
//  if(::bind(sock, (struct sockaddr*) &local, local.getSocklen()) < 0) 
//    throw runtime_error("Failed to bind local socket to address "+local.toString()+": "+stringerror());

  try {
     addrs.emplace(ComboAddress{argv[1], 53});
  } catch (PDNSException &ex) {
     /* needs resolving, maybe */
     struct addrinfo *info;
     vector<string> parts;
     boost::split(parts, argv[1], [](char c){return c == ':';});
     if (parts.size() == 1)
       parts.push_back("domain");
     else if (parts.size() != 2)
       throw runtime_error("Invalid hostname:port syntax");
     if (getaddrinfo(parts[0].c_str(), parts[1].c_str(), NULL, &info) < 0)
       throw runtime_error("Cannot resolve '" + string(argv[1]) +"'");
     for(auto ptr = info; ptr != NULL; ptr = ptr->ai_next)
       addrs.emplace(ComboAddress{ptr->ai_addr, ptr->ai_addrlen});
  }

  for(const auto &addr: addrs) {
    if (sock > -1)
      (void)close(sock);
    sock = socket(addr.sin4.sin_family, SOCK_DGRAM, 0);
    if(sock < 0)
      throw runtime_error("Creating socket for incoming packets: "+stringerror());
    if(connect(sock, (struct sockaddr*)&addr, addr.getSocklen()) < 0) {
      cerr<<"Failed to connect to address "+addr.toStringWithPort()+": "+stringerror()<<endl;
      continue;
    }
    vector<uint8_t> outpacket;
    DNSPacketWriter pw(outpacket, DNSName(argv[2]), QType::SOA, 1, Opcode::Notify);
    pw.getHeader()->id = dns_random_uint16();

    if(send(sock, &outpacket[0], outpacket.size(), 0) < 0) {
      cerr<<"Unable to send notify to "<<addr.toStringWithPort()<<": "+stringerror()<<endl;
      continue;
    }

    char buffer[1500];
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    fd_set errfds;
    FD_ZERO(&errfds);
    FD_SET(sock, &errfds);
    int len;
    struct timeval tv;
    bool timeout = true;

    for(int tries=0; tries<60; tries++) {
      tv.tv_sec = 1;
      tv.tv_usec = 0;
      if ((len = select(sock+1, &rfds, nullptr, &errfds, &tv)) > 0) {
        len = recv(sock, buffer, sizeof(buffer), 0);
        timeout = false;
        break;
      }
    }

    if(len < 0) {
      cerr<<"Unable to receive notification response from "<<addr.toStringWithPort()<<": "+stringerror()<<endl;
      continue;
    } else if (timeout) {
      cerr<<"Unable to receive notification response from "<<addr.toStringWithPort()<<": Timed out"<<endl;
      continue;
    } else if (len == 0) {
      cerr<<"Unable to receive notification response from "<<addr.toStringWithPort()<<": EOF"<<endl;
      continue;
    }

    string packet(buffer, len);
    MOADNSParser mdp(false, packet);

    if (mdp.d_header.rcode == 0)
      cerr<<"Successfully notified "<<addr.toStringWithPort()<<endl;
    else
      cerr<<"Received notification response with error from "<<addr.toStringWithPort()<<": "<<RCode::to_s(mdp.d_header.rcode)<<endl;
    cerr<<"For: '"<<mdp.d_qname<<"'"<<endl;
  }
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

