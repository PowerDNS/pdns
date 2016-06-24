
#include "config.h"
#include "rec-protobuf.hh"

void RecProtoBufMessage::addRR(const DNSRecord& record)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage_DNSResponse* response = d_message.mutable_response();
  if (!response) {
    return;
  }

  if (record.d_place != DNSResourceRecord::ANSWER ||
      record.d_class != QClass::IN ||
      (record.d_type != QType::A &&
       record.d_type != QType::AAAA &&
       record.d_type != QType::CNAME)) {
    return;
  }

   PBDNSMessage_DNSResponse_DNSRR* pbRR = response->add_rrs();
   if (!pbRR) {
     return;
   }

   pbRR->set_name(record.d_name.toString());
   pbRR->set_type(record.d_type);
   pbRR->set_class_(record.d_class);
   pbRR->set_ttl(record.d_ttl);
   if (record.d_type == QType::A) {
     const ARecordContent& arc = dynamic_cast<const ARecordContent&>(*(record.d_content));
     ComboAddress data = arc.getCA();
     pbRR->set_rdata(&data.sin4.sin_addr.s_addr, sizeof(data.sin4.sin_addr.s_addr));
   }
   else if (record.d_type == QType::AAAA) {
     const AAAARecordContent& arc = dynamic_cast<const AAAARecordContent&>(*(record.d_content));
     ComboAddress data = arc.getCA();
     pbRR->set_rdata(&data.sin6.sin6_addr.s6_addr, sizeof(data.sin6.sin6_addr.s6_addr));
   } else if (record.d_type == QType::CNAME) {
     const CNAMERecordContent& crc = dynamic_cast<const CNAMERecordContent&>(*(record.d_content));
     DNSName data = crc.getTarget();
     pbRR->set_rdata(data.toString());
   }
#endif /* HAVE_PROTOBUF */
}

void RecProtoBufMessage::addRRs(const std::vector<DNSRecord>& records)
{
  for (const auto& record : records) {
    addRR(record);
  }
}

void RecProtoBufMessage::setAppliedPolicy(const std::string& policy)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage_DNSResponse* response = d_message.mutable_response();
  if (response && !policy.empty()) {
    response->set_appliedpolicy(policy);
  }
#endif /* HAVE_PROTOBUF */
}

void RecProtoBufMessage::setPolicyTags(const std::vector<std::string>& policyTags)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage_DNSResponse* response = d_message.mutable_response();
  if (response) {
    for (const auto& tag : policyTags) {
      response->add_tags(tag);
    }
  }
#endif /* HAVE_PROTOBUF */
}
