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

#include <fstream>

#include "iputils.hh"
#include "misc.hh"
#include "dns.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"

#include "statbag.hh"
StatBag S;

static void usage()
{
  cerr<<"This program reads DNS queries from a PCAP file and outputs them in the calidns format."<<endl;
  cerr<<"Usage: dnspcap2calidns PCAPFILE OUTFILE"<<endl;
}

int main(int argc, char **argv)
{
  try {
    for(int n=1 ; n < argc; ++n) {
      if ((string) argv[n] == "--help") {
        usage();
        return EXIT_SUCCESS;
      }

      if ((string) argv[n] == "--version") {
        cerr<<"dnspcap2calidns "<<VERSION<<endl;
        return EXIT_SUCCESS;
      }
    }

    if(argc < 3) {
      usage();
      exit(EXIT_FAILURE);
    }


    PcapPacketReader pr(argv[1]);
    ofstream fp(argv[2]);

    if (!fp) {
      cerr<<"Error opening output file "<<argv[2]<<": "<<stringerror()<<endl;
      exit(EXIT_FAILURE);
    }

    try {
      while (pr.getUDPPacket()) {
        if (pr.d_len < sizeof(dnsheader)) {
          continue;
        }

        const dnsheader* dh=reinterpret_cast<const dnsheader*>(pr.d_payload);
        if (!dh->qdcount) {
          continue;
        }

        if (!dh->rd) {
          continue;
        }

        if (dh->qr) {
          continue;
        }

        uint16_t qtype, qclass;
        DNSName qname;
        try {
          qname=DNSName(reinterpret_cast<const char*>(pr.d_payload), pr.d_len, sizeof(dnsheader), false, &qtype, &qclass);
        }
        catch(const std::exception& e) {
          cerr<<"Error while parsing qname: "<<e.what()<<endl;
          continue;
        }

        const ComboAddress requestor = pr.getSource();

        fp << qname << " " << QType(qtype).getName() << " " << requestor.toString() << endl;
      }
    }
    catch (const std::exception& e) {
      cerr<<"Error while parsing the PCAP file: "<<e.what()<<endl;
      fp.close();
      exit(EXIT_FAILURE);
    }

    fp.flush();
    fp.close();
  }
  catch(const std::exception& e) {
    cerr<<"Error opening PCAP file: "<<e.what()<<endl;
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
