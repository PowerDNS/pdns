#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include "iputils.hh"
#include "misc.hh"
#include "dns.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"
#include "protobuf.hh"

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

  FILE* fp = fopen(argv[2], "w");
  if (!fp) {
    cerr<<"Error opening output file "<<argv[2]<<": "<<strerror(errno)<<endl;
    exit(EXIT_FAILURE);
  }

  int ind=0;
  if(argc==4)
    ind=atoi(argv[3]);

  std::map<uint16_t,std::pair<boost::uuids::uuid,struct timeval> > ids;
  boost::uuids::random_generator uuidGenerator;
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
        uniqueId = uuidGenerator();
        ids[dh->id] = std::make_pair(uniqueId, queryTime);
      }
      else {
        const auto& it = ids.find(dh->id);
        if (it != ids.end()) {
          uniqueId = it->second.first;
          queryTime = it->second.second;
          hasQueryTime = true;
        }
        else {
          uniqueId = uuidGenerator();
        }
      }

      const ComboAddress requestor = dh->qr ? pr.getDest() : pr.getSource();
      const ComboAddress responder = dh->qr ? pr.getSource() : pr.getDest();
      *((char*)&requestor.sin4.sin_addr.s_addr)|=ind;
      *((char*)&responder.sin4.sin_addr.s_addr)|=ind;

      DNSProtoBufMessage message(dh->qr ? DNSProtoBufMessage::DNSProtoBufMessageType::Response : DNSProtoBufMessage::DNSProtoBufMessageType::Query, uniqueId, &requestor, &responder, qname, qtype, qclass, dh->id, false, pr.d_len);
      message.setTime(pr.d_pheader.ts.tv_sec, pr.d_pheader.ts.tv_usec);

      if (dh->qr) {
        message.setResponseCode(dh->rcode);
        if (hasQueryTime) {
          message.setQueryTime(queryTime.tv_sec, queryTime.tv_usec);
        }

        try {
          message.addRRsFromPacket((const char*) dh, pr.d_len);
        }
        catch(std::exception& e)
        {
          cerr<<"Error parsing response records: "<<e.what()<<endl;
        }
        catch(const PDNSException& e)
        {
          cerr<<"Error parsing response records: "<<e.reason<<endl;
        }
      }

      std::string str;
      message.serialize(str);

      uint16_t mlen = htons(str.length());
      fwrite(&mlen, 1, sizeof(mlen), fp);
      fwrite(str.c_str(), 1, str.length(), fp);
    }
  }
  catch (const std::exception& e) {
    cerr<<"Error while parsing the PCAP file: "<<e.what()<<endl;
    fclose(fp);
    exit(EXIT_FAILURE);
  }

  fclose(fp);
}
catch(const std::exception& e) {
  cerr<<"Error opening PCAP file: "<<e.what()<<endl;
  exit(EXIT_FAILURE);
}
