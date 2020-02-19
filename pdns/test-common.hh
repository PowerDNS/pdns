
#include "dnsrecords.hh"
#include "iputils.hh"

static inline std::shared_ptr<DNSRecordContent> getRecordContent(uint16_t type, const std::string& content)
{
  std::shared_ptr<DNSRecordContent> result = nullptr;

  if (type == QType::NS) {
    result = std::make_shared<NSRecordContent>(DNSName(content));
  }
  else if (type == QType::A) {
    result = std::make_shared<ARecordContent>(ComboAddress(content));
  }
  else if (type == QType::AAAA) {
    result = std::make_shared<AAAARecordContent>(ComboAddress(content));
  }
  else if (type == QType::CNAME) {
    result = std::make_shared<CNAMERecordContent>(DNSName(content));
  }
  else if (type == QType::OPT) {
    result = std::make_shared<OPTRecordContent>();
  }
  else {
    result = DNSRecordContent::mastermake(type, QClass::IN, content);
  }

  return result;
}

static inline void addRecordToList(std::vector<DNSRecord>& records, const DNSName& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place = DNSResourceRecord::ANSWER, uint32_t ttl = 3600)
{
  DNSRecord rec;
  rec.d_place = place;
  rec.d_name = name;
  rec.d_type = type;
  rec.d_ttl = ttl;

  rec.d_content = getRecordContent(type, content);

  records.push_back(rec);
}
