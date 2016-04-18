
#include "config.h"

#include "dnsdist.hh"
#include "gettime.hh"

#include "dnsparser.hh"
#include "dnsdist-protobuf.hh"

#ifdef HAVE_PROTOBUF
#include "dnsmessage.pb.h"

static void protobufFillMessage(PBDNSMessage& message, const DNSQuestion& dq)
{
  std::string* messageId = message.mutable_messageid();
  messageId->resize(dq.uniqueId.size());
  std::copy(dq.uniqueId.begin(), dq.uniqueId.end(), messageId->begin());

  message.set_socketfamily(dq.remote->sin4.sin_family == AF_INET ? PBDNSMessage_SocketFamily_INET : PBDNSMessage_SocketFamily_INET6);
  message.set_socketprotocol(dq.tcp ? PBDNSMessage_SocketProtocol_TCP : PBDNSMessage_SocketProtocol_UDP);
  if (dq.local->sin4.sin_family == AF_INET) {
    message.set_to(&dq.local->sin4.sin_addr.s_addr, sizeof(dq.local->sin4.sin_addr.s_addr));
  }
  else if (dq.local->sin4.sin_family == AF_INET6) {
    message.set_to(&dq.local->sin6.sin6_addr.s6_addr, sizeof(dq.local->sin6.sin6_addr.s6_addr));
  }
  if (dq.remote->sin4.sin_family == AF_INET) {
    message.set_from(&dq.remote->sin4.sin_addr.s_addr, sizeof(dq.remote->sin4.sin_addr.s_addr));
  }
  else if (dq.remote->sin4.sin_family == AF_INET6) {
    message.set_from(&dq.remote->sin6.sin6_addr.s6_addr, sizeof(dq.remote->sin6.sin6_addr.s6_addr));
  }

  message.set_inbytes(dq.len);

  struct timespec ts;
  gettime(&ts, true);
  message.set_timesec(ts.tv_sec);
  message.set_timeusec(ts.tv_nsec / 1000);
  message.set_id(ntohs(dq.dh->id));

  PBDNSMessage_DNSQuestion* question = message.mutable_question();
  question->set_qname(dq.qname->toString());
  question->set_qtype(dq.qtype);
  question->set_qclass(dq.qclass);
}

void protobufMessageFromQuestion(const DNSQuestion& dq, std::string& data)
{
  PBDNSMessage message;
  message.set_type(PBDNSMessage_Type_DNSQueryType);
  protobufFillMessage(message, dq);
//  cerr <<message.DebugString()<<endl;
  message.SerializeToString(&data);
}

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

void protobufMessageFromResponse(const DNSQuestion& dr, std::string& data)
{
  PBDNSMessage message;
  message.set_type(PBDNSMessage_Type_DNSResponseType);
  protobufFillMessage(message, dr);

  PBDNSMessage_DNSResponse response;
  response.set_rcode(dr.dh->rcode);
  addRRs((const char*) dr.dh, dr.len, response);
  message.set_allocated_response(&response);

//  cerr <<message.DebugString()<<endl;
  message.SerializeToString(&data);
  message.release_response();
}
#endif /* HAVE_PROTOBUF */
