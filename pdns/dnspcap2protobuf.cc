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
#include <boost/uuid/uuid.hpp>

#include "iputils.hh"
#include "misc.hh"
#include "dns.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"
#include "protozero.hh"
#include "uuid-utils.hh"

#include "statbag.hh"
StatBag S;

static void usage()
{
  cerr<<"This program reads DNS queries and responses from a PCAP file and stores them into our protobuf format."<<endl;
  cerr<<"Usage: dnspcap2protobuf PCAPFILE OUTFILE"<<endl;
}

int main(int argc, char **argv)
try {
  for(int n=1 ; n < argc; ++n) {
    if ((string) argv[n] == "--help") {
      usage();
      return EXIT_SUCCESS;
    }

    if ((string) argv[n] == "--version") {
      cerr<<"dnspcap2protobuf "<<VERSION<<endl;
      return EXIT_SUCCESS;
    }
  }

  if(argc < 3) {
    usage();
    exit(EXIT_FAILURE);
  }


  PcapPacketReader pr(argv[1]);

  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(argv[2], "w"), fclose);
  if (!fp) {
    cerr<<"Error opening output file "<<argv[2]<<": "<<stringerror()<<endl;
    exit(EXIT_FAILURE);
  }

  int ind=0;
  if(argc==4)
    ind=atoi(argv[3]);

  std::map<uint16_t,std::pair<boost::uuids::uuid,struct timeval> > ids;
  std::string pbBuffer;
  try {
    while (pr.getUDPPacket()) {
      const dnsheader* dh=(dnsheader*)pr.d_payload;
      if (!dh->qdcount)
        continue;

      if (pr.d_len < sizeof(dnsheader))
        continue;

      if(!dh->rd)
        continue;

      uint16_t qtype, qclass;
      DNSName qname;
      try {
        qname=DNSName((const char*)pr.d_payload, pr.d_len, sizeof(dnsheader), false, &qtype, &qclass);
      }
      catch(const std::exception& e) {
        cerr<<"Error while parsing qname: "<<e.what()<<endl;
        continue;
      }

      boost::uuids::uuid uniqueId;
      struct timeval queryTime = { 0, 0 };
      bool hasQueryTime = false;
      if (!dh->qr) {
        queryTime.tv_sec = pr.d_pheader.ts.tv_sec;
        queryTime.tv_usec = pr.d_pheader.ts.tv_usec;
        uniqueId = getUniqueID();
        ids[dh->id] = {uniqueId, queryTime};
      }
      else {
        const auto& it = ids.find(dh->id);
        if (it != ids.end()) {
          uniqueId = it->second.first;
          queryTime = it->second.second;
          hasQueryTime = true;
        }
        else {
          uniqueId = getUniqueID();
        }
      }

      const ComboAddress requestor = dh->qr ? pr.getDest() : pr.getSource();
      const ComboAddress responder = dh->qr ? pr.getSource() : pr.getDest();
      *((char*)&requestor.sin4.sin_addr.s_addr)|=ind;
      *((char*)&responder.sin4.sin_addr.s_addr)|=ind;

      pbBuffer.clear();
      pdns::ProtoZero::Message pbMessage(pbBuffer);
      pbMessage.setType(dh->qr ? pdns::ProtoZero::Message::MessageType::DNSResponseType : pdns::ProtoZero::Message::MessageType::DNSQueryType);
      pbMessage.setRequest(uniqueId, requestor, responder, qname, qtype, qclass, dh->id, pdns::ProtoZero::Message::TransportProtocol::UDP, pr.d_len);
      pbMessage.setTime(pr.d_pheader.ts.tv_sec, pr.d_pheader.ts.tv_usec);

      if (dh->qr) {
        pbMessage.startResponse();
        pbMessage.setResponseCode(dh->rcode);
        if (hasQueryTime) {
          pbMessage.setQueryTime(queryTime.tv_sec, queryTime.tv_usec);
        }

        try {
          pbMessage.addRRsFromPacket((const char*) dh, pr.d_len, true);
        }
        catch (const std::exception& e)
        {
          cerr<<"Error parsing response records: "<<e.what()<<endl;
        }
        catch(const PDNSException& e)
        {
          cerr<<"Error parsing response records: "<<e.reason<<endl;
        }
      }

      uint16_t mlen = htons(pbBuffer.length());
      fwrite(&mlen, 1, sizeof(mlen), fp.get());
      fwrite(pbBuffer.c_str(), 1, pbBuffer.length(), fp.get());
    }
  }
  catch (const std::exception& e) {
    cerr<<"Error while parsing the PCAP file: "<<e.what()<<endl;
    exit(EXIT_FAILURE);
  }
}
catch(const std::exception& e) {
  cerr<<"Error opening PCAP file: "<<e.what()<<endl;
  exit(EXIT_FAILURE);
}
