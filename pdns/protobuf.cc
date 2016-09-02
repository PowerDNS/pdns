
#include "protobuf.hh"
#include "dnsparser.hh"
#include "gettime.hh"

DNSProtoBufMessage::DNSProtoBufMessage(DNSProtoBufMessageType type)
{
#ifdef HAVE_PROTOBUF
  d_message.set_type(type == DNSProtoBufMessage::DNSProtoBufMessageType::Query ? PBDNSMessage_Type_DNSQueryType : PBDNSMessage_Type_DNSResponseType);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setQuestion(const DNSName& qname, uint16_t qtype, uint16_t qclass)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage_DNSQuestion* question = d_message.mutable_question();
  if (question) {
    question->set_qname(qname.toString());
    question->set_qtype(qtype);
    question->set_qclass(qclass);
  }
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setBytes(size_t bytes)
{
#ifdef HAVE_PROTOBUF
  d_message.set_inbytes(bytes);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setResponseCode(uint8_t rcode)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage_DNSResponse* response = d_message.mutable_response();
  if (response) {
    response->set_rcode(rcode);
  }
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setTime(time_t sec, uint32_t usec)
{
#ifdef HAVE_PROTOBUF
  d_message.set_timesec(sec);
  d_message.set_timeusec(usec);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setQueryTime(time_t sec, uint32_t usec)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage_DNSResponse* response = d_message.mutable_response();
  if (response) {
    response->set_querytimesec(sec);
    response->set_querytimeusec(usec);
  }
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setEDNSSubnet(const Netmask& subnet, uint8_t mask)
{
#ifdef HAVE_PROTOBUF
  if (!subnet.empty()) {
    ComboAddress ca(subnet.getNetwork());
    ca.truncate(mask);
    if (ca.sin4.sin_family == AF_INET) {
      d_message.set_originalrequestorsubnet(&ca.sin4.sin_addr.s_addr, sizeof(ca.sin4.sin_addr.s_addr));
    }
    else if (ca.sin4.sin_family == AF_INET6) {
      d_message.set_originalrequestorsubnet(&ca.sin6.sin6_addr.s6_addr, sizeof(ca.sin6.sin6_addr.s6_addr));
    }
  }
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::addRRsFromPacket(const char* packet, const size_t len)
{
#ifdef HAVE_PROTOBUF
  if (len < sizeof(struct dnsheader))
    return;

  const struct dnsheader* dh = (const struct dnsheader*) packet;

  if (ntohs(dh->ancount) == 0)
    return;

  if (ntohs(dh->qdcount) == 0)
    return;

  PBDNSMessage_DNSResponse* response = d_message.mutable_response();
  if (!response)
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
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setRequestor(const std::string& requestor)
{
#ifdef HAVE_PROTOBUF
  d_message.set_from(requestor);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setRequestor(const ComboAddress& requestor)
{
#ifdef HAVE_PROTOBUF
  if (requestor.sin4.sin_family == AF_INET) {
    d_message.set_from(&requestor.sin4.sin_addr.s_addr, sizeof(requestor.sin4.sin_addr.s_addr));
  }
  else if (requestor.sin4.sin_family == AF_INET6) {
    d_message.set_from(&requestor.sin6.sin6_addr.s6_addr, sizeof(requestor.sin6.sin6_addr.s6_addr));
  }
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setResponder(const std::string& responder)
{
#ifdef HAVE_PROTOBUF
  d_message.set_from(responder);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setResponder(const ComboAddress& responder)
{
#ifdef HAVE_PROTOBUF
  if (responder.sin4.sin_family == AF_INET) {
    d_message.set_from(&responder.sin4.sin_addr.s_addr, sizeof(responder.sin4.sin_addr.s_addr));
  }
  else if (responder.sin4.sin_family == AF_INET6) {
    d_message.set_from(&responder.sin6.sin6_addr.s6_addr, sizeof(responder.sin6.sin6_addr.s6_addr));
  }
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::serialize(std::string& data) const
{
#ifdef HAVE_PROTOBUF
  d_message.SerializeToString(&data);
#endif /* HAVE_PROTOBUF */
}

std::string DNSProtoBufMessage::toDebugString() const
{
#ifdef HAVE_PROTOBUF
  return d_message.DebugString();
#else
  return std::string();
#endif /* HAVE_PROTOBUF */
}

#ifdef HAVE_PROTOBUF

void DNSProtoBufMessage::setUUID(const boost::uuids::uuid& uuid)
{
  std::string* messageId = d_message.mutable_messageid();
  messageId->resize(uuid.size());
  std::copy(uuid.begin(), uuid.end(), messageId->begin());
}

void DNSProtoBufMessage::update(const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, bool isTCP, uint16_t id)
{
  struct timespec ts;
  gettime(&ts, true);
  setTime(ts.tv_sec, ts.tv_nsec / 1000);

  setUUID(uuid);
  d_message.set_id(ntohs(id));

  d_message.set_socketfamily((requestor && requestor->sin4.sin_family == AF_INET) ? PBDNSMessage_SocketFamily_INET : PBDNSMessage_SocketFamily_INET6);
  d_message.set_socketprotocol(isTCP ? PBDNSMessage_SocketProtocol_TCP : PBDNSMessage_SocketProtocol_UDP);

  if (responder) {
    setResponder(*responder);
  }
  if (requestor) {
    setRequestor(*requestor);
  }
}


DNSProtoBufMessage::DNSProtoBufMessage(DNSProtoBufMessageType type, const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* to, const DNSName& domain, int qtype, uint16_t qclass, uint16_t qid, bool isTCP, size_t bytes)
{
  update(uuid, requestor, to, isTCP, qid);

  d_message.set_type(type == DNSProtoBufMessage::DNSProtoBufMessageType::Query ? PBDNSMessage_Type_DNSQueryType : PBDNSMessage_Type_DNSResponseType);

  setBytes(bytes);
  setQuestion(domain, qtype, qclass);
}

#endif /* HAVE_PROTOBUF */
