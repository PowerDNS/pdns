#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include "dnsmessage.pb.h"
#include "iputils.hh"
#include "misc.hh"
#include "dns.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"

#include "statbag.hh"
StatBag S;

static void addRRs(const char* packet, const size_t len, PBDNSMessage_DNSResponse* response)
try
{
  if (len < sizeof(struct dnsheader))
    return;

  const struct dnsheader* dh = (const struct dnsheader*) packet;

  if (ntohs(dh->ancount) == 0)
    return;

  if (ntohs(dh->qdcount) == 0)
    return;

  vector<uint8_t> content(len - sizeof(dnsheader));
  copy(packet + sizeof(dnsheader), packet + len, content.begin());
  PacketReader pr(content);

  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);
  uint16_t rrtype;
  uint16_t rrclass;
  string blob;
  struct dnsrecordheader ah;

  rrname = pr.getName();
  rrtype = pr.get16BitInt();
  rrclass = pr.get16BitInt();

  /* consume remaining qd if any */
  if (qdcount > 1) {
    for(idx = 1; idx < qdcount; idx++) {
      rrname = pr.getName();
      rrtype = pr.get16BitInt();
      rrclass = pr.get16BitInt();
      (void) rrtype;
      (void) rrclass;
    }
  }

  /* parse AN */
  for (idx = 0; idx < ancount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pr.xfrBlob(blob);
    if (ah.d_type == QType::A || ah.d_type == QType::AAAA) {
      PBDNSMessage_DNSResponse_DNSRR* rr = response->add_rrs();
      if (rr) {
        rr->set_name(rrname.toString());
        rr->set_type(ah.d_type);
        rr->set_class_(ah.d_class);
        rr->set_ttl(ah.d_ttl);
        rr->set_rdata(blob.c_str(), blob.length());
      }
    }
  }
}
catch(const std::exception& e)
{
  cerr<<"Error parsing response records: "<<e.what()<<endl;
}
catch(const PDNSException& e)
{
  cerr<<"Error parsing response records: "<<e.reason<<endl;
}

void usage()
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

  std::map<uint16_t,boost::uuids::uuid> ids;
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

      PBDNSMessage message;
      message.set_timesec(pr.d_pheader.ts.tv_sec);
      message.set_timeusec(pr.d_pheader.ts.tv_usec);
      message.set_id(ntohs(dh->id));
      message.set_type(dh->qr ? PBDNSMessage_Type_DNSResponseType : PBDNSMessage_Type_DNSQueryType);
      const ComboAddress requestor = dh->qr ? pr.getDest() : pr.getSource();
      const ComboAddress responder = dh->qr ? pr.getSource() : pr.getDest();

      *((char*)&requestor.sin4.sin_addr.s_addr)|=ind;
      *((char*)&responder.sin4.sin_addr.s_addr)|=ind;
      message.set_socketfamily(requestor.sin4.sin_family == AF_INET ? PBDNSMessage_SocketFamily_INET : PBDNSMessage_SocketFamily_INET6);
      // we handle UDP packets only for now
      message.set_socketprotocol(PBDNSMessage_SocketProtocol_UDP);
      if (requestor.sin4.sin_family == AF_INET) {
        message.set_from(&requestor.sin4.sin_addr.s_addr, sizeof(requestor.sin4.sin_addr.s_addr));
      }
      else if (requestor.sin4.sin_family == AF_INET6) {
        message.set_from(&requestor.sin6.sin6_addr.s6_addr, sizeof(requestor.sin6.sin6_addr.s6_addr));
      }
      if (responder.sin4.sin_family == AF_INET) {
        message.set_to(&responder.sin4.sin_addr.s_addr, sizeof(responder.sin4.sin_addr.s_addr));
      }
      else if (responder.sin4.sin_family == AF_INET6) {
        message.set_to(&responder.sin6.sin6_addr.s6_addr, sizeof(responder.sin6.sin6_addr.s6_addr));
      }
      message.set_inbytes(pr.d_len);

      PBDNSMessage_DNSQuestion* question = message.mutable_question();
      PBDNSMessage_DNSResponse* response = message.mutable_response();

      if (!dh->qr) {
        boost::uuids::uuid uniqueId = uuidGenerator();
        ids[dh->id] = uniqueId;
        std::string* messageId = message.mutable_messageid();
        messageId->resize(uniqueId.size());
        std::copy(uniqueId.begin(), uniqueId.end(), messageId->begin());
      }
      else {
        const auto& it = ids.find(dh->id);
        if (it != ids.end()) {
          std::string* messageId = message.mutable_messageid();
          messageId->resize(it->second.size());
          std::copy(it->second.begin(), it->second.end(), messageId->begin());
        }

        response->set_rcode(dh->rcode);
        addRRs((const char*) dh, pr.d_len, response);
      }

      question->set_qname(qname.toString());
      question->set_qtype(qtype);
      question->set_qclass(qclass);

      std::string str;
      //cerr<<message.DebugString()<<endl;
      message.SerializeToString(&str);
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
