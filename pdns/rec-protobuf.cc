
#include "config.h"
#include "rec-protobuf.hh"

#ifdef NOD_ENABLED
void RecProtoBufMessage::setNOD(bool nod)
{
#ifdef HAVE_PROTOBUF
  d_message.set_newlyobserveddomain(nod);
#endif /* HAVE_PROTOBUF */  
}

void RecProtoBufMessage::clearUDR() 
{
#ifdef HAVE_PROTOBUF
  auto response = d_message.mutable_response();
  const int count = response->rrs_size();
  for (int idx = 0; idx < count; idx++) {
    auto rr = response->mutable_rrs(idx);
    rr->set_udr(false);
  }
#endif /* HAVE_PROTOBUF */
}
#endif /* NOD_ENABLED */

#ifdef NOD_ENABLED
void RecProtoBufMessage::addRR(const DNSRecord& record, const std::set<uint16_t>& exportTypes, bool udr)
#else
void RecProtoBufMessage::addRR(const DNSRecord& record, const std::set<uint16_t>& exportTypes)
#endif /* NOD_ENABLED */
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage_DNSResponse* response = d_message.mutable_response();
  if (!response) {
    return;
  }

  if (record.d_place != DNSResourceRecord::ANSWER || record.d_class != QClass::IN) {
    return;
  }

  if (exportTypes.count(record.d_type) == 0) {
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
#ifdef NOD_ENABLED
  pbRR->set_udr(udr);
#endif

  switch(record.d_type) {
  case QType::A:
  {
    const auto& content = dynamic_cast<const ARecordContent&>(*(record.d_content));
    ComboAddress data = content.getCA();
    pbRR->set_rdata(&data.sin4.sin_addr.s_addr, sizeof(data.sin4.sin_addr.s_addr));
    break;
  }
  case QType::AAAA:
  {
    const auto& content = dynamic_cast<const AAAARecordContent&>(*(record.d_content));
    ComboAddress data = content.getCA();
    pbRR->set_rdata(&data.sin6.sin6_addr.s6_addr, sizeof(data.sin6.sin6_addr.s6_addr));
    break;
  }
  case QType::CNAME:
  {
    const auto& content = dynamic_cast<const CNAMERecordContent&>(*(record.d_content));
    pbRR->set_rdata(content.getTarget().toString());
    break;
  }
  case QType::TXT:
  {
    const auto& content = dynamic_cast<const TXTRecordContent&>(*(record.d_content));
    pbRR->set_rdata(content.d_text);
    break;
  }
  case QType::NS:
  {
    const auto& content = dynamic_cast<const NSRecordContent&>(*(record.d_content));
    pbRR->set_rdata(content.getNS().toString());
    break;
  }
  case QType::PTR:
  {
    const auto& content = dynamic_cast<const PTRRecordContent&>(*(record.d_content));
    pbRR->set_rdata(content.getContent().toString());
    break;
  }
  case QType::MX:
  {
    const auto& content = dynamic_cast<const MXRecordContent&>(*(record.d_content));
    pbRR->set_rdata(content.d_mxname.toString());
    break;
  }
  case QType::SPF:
  {
    const auto& content = dynamic_cast<const SPFRecordContent&>(*(record.d_content));
    pbRR->set_rdata(content.getText());
    break;
  }
  case QType::SRV:
  {
    const auto& content = dynamic_cast<const SRVRecordContent&>(*(record.d_content));
    pbRR->set_rdata(content.d_target.toString());
    break;
  }
  default:
    break;
  }
#endif /* HAVE_PROTOBUF */
}

void RecProtoBufMessage::addRRs(const std::vector<DNSRecord>& records, const std::set<uint16_t>& exportTypes)
{
  for (const auto& record : records) {
    addRR(record, exportTypes);
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

void RecProtoBufMessage::setAppliedPolicyType(const DNSFilterEngine::PolicyType& type)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage_DNSResponse* response = d_message.mutable_response();
  if (response) {
    switch(type) {
    case DNSFilterEngine::PolicyType::None:
      response->set_appliedpolicytype(PBDNSMessage_PolicyType_UNKNOWN);
      break;
    case DNSFilterEngine::PolicyType::QName:
      response->set_appliedpolicytype(PBDNSMessage_PolicyType_QNAME);
      break;
    case DNSFilterEngine::PolicyType::ClientIP:
      response->set_appliedpolicytype(PBDNSMessage_PolicyType_CLIENTIP);
      break;
    case DNSFilterEngine::PolicyType::ResponseIP:
      response->set_appliedpolicytype(PBDNSMessage_PolicyType_RESPONSEIP);
      break;
    case DNSFilterEngine::PolicyType::NSDName:
      response->set_appliedpolicytype(PBDNSMessage_PolicyType_NSDNAME);
      break;
    case DNSFilterEngine::PolicyType::NSIP:
      response->set_appliedpolicytype(PBDNSMessage_PolicyType_NSIP);
      break;
    default:
      throw std::runtime_error("Unsupported protobuf policy type");
    }
  }
#endif /* HAVE_PROTOBUF */
}

void RecProtoBufMessage::setPolicyTags(const std::unordered_set<std::string>& policyTags)
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

void RecProtoBufMessage::addPolicyTag(const std::string& policyTag)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage_DNSResponse* response = d_message.mutable_response();
  if (response) {
    response->add_tags(policyTag);
  }
#endif
}

void RecProtoBufMessage::removePolicyTag(const std::string& policyTag)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage_DNSResponse* response = d_message.mutable_response();
  if (response) {
    const int count = response->tags_size();
    int keep = 0;
    for (int idx = 0; idx < count; ++idx) {
      auto tagp = response->mutable_tags(idx);
      if (tagp->compare(policyTag) == 0) {        
      }
      else {
        if (keep < idx) {
          response->mutable_tags()->SwapElements(idx, keep);
        }
        ++keep;
      }
    }
    response->mutable_tags()->DeleteSubrange(keep, count - keep);
  }  
#endif
}

std::string RecProtoBufMessage::getAppliedPolicy() const
{
  std::string result;
#ifdef HAVE_PROTOBUF
  const PBDNSMessage_DNSResponse& response = d_message.response();
  result = response.appliedpolicy();
#endif /* HAVE_PROTOBUF */
  return result;
}

std::vector<std::string> RecProtoBufMessage::getPolicyTags() const
{
  std::vector<std::string> result;
#ifdef HAVE_PROTOBUF
  const PBDNSMessage_DNSResponse& response = d_message.response();
  const int count = response.tags_size();
  for (int idx = 0; idx < count; idx++) {
    result.push_back(response.tags(idx));
  }
#endif /* HAVE_PROTOBUF */
  return result;
}
