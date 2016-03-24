#include "dnsmessage.pb.h"
#include "iputils.hh"
#include "misc.hh"
#include "dns.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"

#include "statbag.hh"
StatBag S;

static void addRRs(const char* packet, const size_t len, PBDNSMessage_DNSResponse& response)
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
      PBDNSMessage_DNSResponse_DNSRR* rr = response.add_rrs();
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

int main(int argc, char **argv)
{
  if(argc != 3) {
    cerr<<"This program reads DNS queries and responses from a PCAP file and stores them into our protobuf format."<<endl;
    cerr<<"Usage: "<<argv[0]<<" <PCAP file> <out file>"<<endl;
    exit(EXIT_FAILURE);
  }

  PcapPacketReader pr(argv[1]);

  FILE* fp = fopen(argv[2], "w");
  if (!fp) {
    cerr<<"Error opening output file "<<argv[2]<<": "<<strerror(errno)<<endl;
    exit(EXIT_FAILURE);
  }

  while (pr.getUDPPacket()) {
    const dnsheader* dh=(dnsheader*)pr.d_payload;
    if (!dh->qdcount)
      continue;

    if (pr.d_len < sizeof(dnsheader))
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
    const ComboAddress source = pr.getSource();
    const ComboAddress dest = pr.getDest();
    message.set_socketfamily(source.sin4.sin_family == AF_INET ? PBDNSMessage_SocketFamily_INET : PBDNSMessage_SocketFamily_INET6);
    // we handle UDP packets only for now
    message.set_socketprotocol(PBDNSMessage_SocketProtocol_UDP);
    if (source.sin4.sin_family == AF_INET) {
      message.set_from(&source.sin4.sin_addr.s_addr, sizeof(source.sin4.sin_addr.s_addr));
    }
    else if (source.sin4.sin_family == AF_INET6) {
      message.set_from(&source.sin6.sin6_addr.s6_addr, sizeof(source.sin6.sin6_addr.s6_addr));
    }
    if (dest.sin4.sin_family == AF_INET) {
      message.set_to(&dest.sin4.sin_addr.s_addr, sizeof(dest.sin4.sin_addr.s_addr));
    }
    else if (dest.sin4.sin_family == AF_INET6) {
      message.set_to(&dest.sin6.sin6_addr.s6_addr, sizeof(dest.sin6.sin6_addr.s6_addr));
    }
    message.set_inbytes(pr.d_len);

    PBDNSMessage_DNSQuestion question;
    PBDNSMessage_DNSResponse response;
    if (!dh->qr) {
      question.set_qname(qname.toString());
      question.set_qtype(qtype);
      question.set_qclass(qclass);
      message.set_allocated_question(&question);
    }
    else {
      response.set_rcode(dh->rcode);
      addRRs((const char*) dh, pr.d_len, response);
      message.set_allocated_response(&response);
    }

    std::string str;
    message.SerializeToString(&str);
    uint16_t mlen = str.length();
    fwrite(&mlen, 1, sizeof(mlen), fp);
    fwrite(str.c_str(), 1, str.length(), fp);
    if (!dh->qr) {
      message.release_question();
    }
    else {
      message.release_response();
    }
  }
  fclose(fp);
}
