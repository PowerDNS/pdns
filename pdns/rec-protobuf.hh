#pragma once

#include "protobuf.hh"

#include "dnsrecords.hh"

class RecProtoBufMessage: public DNSProtoBufMessage
{
public:
  RecProtoBufMessage(): DNSProtoBufMessage()
  {
  }

  RecProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type): DNSProtoBufMessage(type)
  {
  }

#ifdef HAVE_PROTOBUF
  RecProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type, const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, const DNSName& domain, int qtype, uint16_t qclass, uint16_t qid, bool isTCP, size_t bytes): DNSProtoBufMessage(type, uuid, requestor, responder, domain, qtype, qclass, qid, isTCP, bytes)
  {
  }
#endif /* HAVE_PROTOBUF */

  void addRRs(const std::vector<DNSRecord>& records);
  void addRR(const DNSRecord& record);
  void setAppliedPolicy(const std::string& policy);
  void setPolicyTags(const std::vector<std::string>& policyTags);

};
