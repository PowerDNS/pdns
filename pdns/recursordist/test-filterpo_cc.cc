
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include "dnsrecords.hh"
#include "filterpo.hh"

BOOST_AUTO_TEST_CASE(test_filter_policies_basic) {
  DNSFilterEngine dfe;

  std::string zoneName("Unit test policy 0");
  auto zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName(zoneName);
  BOOST_CHECK_EQUAL(*(zone->getName()), zoneName);
  zone->setDomain(DNSName("powerdns.com."));
  BOOST_CHECK_EQUAL(zone->getDomain(), DNSName("powerdns.com."));
  zone->setSerial(42);
  BOOST_CHECK_EQUAL(zone->getSerial(), 42);
  zone->setRefresh(99);
  BOOST_CHECK_EQUAL(zone->getRefresh(), 99);

  const ComboAddress nsIP("192.0.2.1");
  const DNSName nsName("ns.bad.wolf.");
  const ComboAddress clientIP("192.0.2.128");
  const DNSName blockedName("blocked.");
  const ComboAddress responseIP("192.0.2.254");
  BOOST_CHECK_EQUAL(zone->size(), 0);
  zone->addClientTrigger(Netmask(clientIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::ClientIP));
  BOOST_CHECK_EQUAL(zone->size(), 1);
  zone->addQNameTrigger(blockedName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::QName));
  BOOST_CHECK_EQUAL(zone->size(), 2);
  zone->addNSIPTrigger(Netmask(nsIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::NSIP));
  BOOST_CHECK_EQUAL(zone->size(), 3);
  zone->addNSTrigger(nsName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::NSDName));
  BOOST_CHECK_EQUAL(zone->size(), 4);
  zone->addResponseTrigger(Netmask(responseIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::ResponseIP));
  BOOST_CHECK_EQUAL(zone->size(), 5);

  size_t zoneIdx = dfe.addZone(zone);

  BOOST_CHECK_EQUAL(dfe.size(), 1);
  BOOST_CHECK(dfe.getZone(zoneName) == zone);
  BOOST_CHECK(dfe.getZone(zoneIdx) == zone);

  dfe.setZone(zoneIdx, zone);

  BOOST_CHECK_EQUAL(dfe.size(), 1);
  BOOST_CHECK(dfe.getZone(zoneName) == zone);
  BOOST_CHECK(dfe.getZone(zoneIdx) == zone);

  {
    /* blocked NS name */
    const auto matchingPolicy = dfe.getProcessingPolicy(nsName, std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::NSDName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findNSPolicy(nsName, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
  }

  {
    /* allowed NS name */
    const auto matchingPolicy = dfe.getProcessingPolicy(DNSName("ns.bad.rabbit."), std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findNSPolicy(DNSName("ns.bad.rabbit."), zonePolicy) == false);
  }

  {
    /* blocked NS IP */
    const auto matchingPolicy = dfe.getProcessingPolicy(nsIP, std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::NSIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findNSIPPolicy(nsIP, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
  }

  {
    /* allowed NS IP */
    const auto matchingPolicy = dfe.getProcessingPolicy(ComboAddress("192.0.2.142"), std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findNSIPPolicy(ComboAddress("192.0.2.142"), zonePolicy) == false);
  }

  {
    /* blocked qname */
    const auto matchingPolicy = dfe.getQueryPolicy(blockedName, ComboAddress("192.0.2.142"), std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findQNamePolicy(blockedName, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
  }

  {
    /* blocked client IP */
    const auto matchingPolicy = dfe.getQueryPolicy(DNSName("totally.legit."), clientIP, std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ClientIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findClientPolicy(clientIP, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
  }

  {
    /* not blocked */
    const auto matchingPolicy = dfe.getQueryPolicy(DNSName("totally.legit."), ComboAddress("192.0.2.142"), std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findClientPolicy(ComboAddress("192.0.2.142"), zonePolicy) == false);
    BOOST_CHECK(zone->findQNamePolicy(DNSName("totally.legit."), zonePolicy) == false);
  }

  {
    /* blocked A */
    DNSRecord dr;
    dr.d_type = QType::A;
    dr.d_content = DNSRecordContent::mastermake(QType::A, QClass::IN, responseIP.toString());
    const auto matchingPolicy = dfe.getPostPolicy({ dr }, std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ResponseIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findResponsePolicy(responseIP, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
  }

  {
    /* allowed A */
    DNSRecord dr;
    dr.d_type = QType::A;
    dr.d_content = DNSRecordContent::mastermake(QType::A, QClass::IN, "192.0.2.142");
    const auto matchingPolicy = dfe.getPostPolicy({ dr }, std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findResponsePolicy(ComboAddress("192.0.2.142"), zonePolicy) == false);
  }

  BOOST_CHECK_EQUAL(zone->size(), 5);
  zone->rmClientTrigger(Netmask(clientIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::ClientIP));
  BOOST_CHECK_EQUAL(zone->size(), 4);
  zone->rmQNameTrigger(blockedName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::QName));
  BOOST_CHECK_EQUAL(zone->size(), 3);
  zone->rmNSIPTrigger(Netmask(nsIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::NSIP));
  BOOST_CHECK_EQUAL(zone->size(), 2);
  zone->rmNSTrigger(nsName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::NSDName));
  BOOST_CHECK_EQUAL(zone->size(), 1);
  zone->rmResponseTrigger(Netmask(responseIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::ResponseIP));
  BOOST_CHECK_EQUAL(zone->size(), 0);

  /* DNSFilterEngine::clear() calls clear() on all zones, but keeps the zones */
  dfe.clear();
  BOOST_CHECK_EQUAL(dfe.size(), 1);
  BOOST_CHECK(dfe.getZone(zoneName) == zone);
  BOOST_CHECK(dfe.getZone(zoneIdx) == zone);
}

BOOST_AUTO_TEST_CASE(test_filter_policies_local_data) {
  DNSFilterEngine dfe;

  std::string zoneName("Unit test policy local data");
  auto zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName(zoneName);

  const DNSName bad1("bad1.example.com.");
  const DNSName bad2("bad2.example.com.");

  zone->addQNameTrigger(bad1, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, { DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "garden.example.net.") } ));
  BOOST_CHECK_EQUAL(zone->size(), 1);

  zone->addQNameTrigger(bad2, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, { DNSRecordContent::mastermake(QType::A, QClass::IN, "192.0.2.1") } ));
  BOOST_CHECK_EQUAL(zone->size(), 2);

  zone->addQNameTrigger(bad2, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, { DNSRecordContent::mastermake(QType::A, QClass::IN, "192.0.2.2") } ));
  BOOST_CHECK_EQUAL(zone->size(), 2);

  zone->addQNameTrigger(bad2, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, { DNSRecordContent::mastermake(QType::MX, QClass::IN, "10 garden-mail.example.net.") } ));
  BOOST_CHECK_EQUAL(zone->size(), 2);

  dfe.addZone(zone);

  {
    /* exact type does not exist, but we have a CNAME */
    const auto matchingPolicy = dfe.getQueryPolicy(bad1, ComboAddress("192.0.2.142"), std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad1, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = std::dynamic_pointer_cast<CNAMERecordContent>(record.d_content);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden.example.net.");
  }

  {
    /* exact type exists */
    const auto matchingPolicy = dfe.getQueryPolicy(bad2, ComboAddress("192.0.2.142"), std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);

    {
      auto records = matchingPolicy.getCustomRecords(bad2, QType::A);
      BOOST_REQUIRE_EQUAL(records.size(), 2);
      {
        const auto& record = records.at(0);
        BOOST_CHECK(record.d_type == QType::A);
        BOOST_CHECK(record.d_class == QClass::IN);
        auto content = std::dynamic_pointer_cast<ARecordContent>(record.d_content);
        BOOST_CHECK(content != nullptr);
        BOOST_CHECK_EQUAL(content->getCA().toString(), "192.0.2.1");
      }
      {
        const auto& record = records.at(1);
        BOOST_CHECK(record.d_type == QType::A);
        BOOST_CHECK(record.d_class == QClass::IN);
        auto content = std::dynamic_pointer_cast<ARecordContent>(record.d_content);
        BOOST_CHECK(content != nullptr);
        BOOST_CHECK_EQUAL(content->getCA().toString(), "192.0.2.2");
      }
    }

    {
      auto records = matchingPolicy.getCustomRecords(bad2, QType::MX);
      BOOST_CHECK_EQUAL(records.size(), 1);
      const auto& record = records.at(0);
      BOOST_CHECK(record.d_type == QType::MX);
      BOOST_CHECK(record.d_class == QClass::IN);
      auto content = std::dynamic_pointer_cast<MXRecordContent>(record.d_content);
      BOOST_CHECK(content != nullptr);
      BOOST_CHECK_EQUAL(content->d_mxname.toString(), "garden-mail.example.net.");
    }

    {
      /* the name exists but there is no CNAME nor matching type, so NODATA */
      auto records = matchingPolicy.getCustomRecords(bad2, QType::AAAA);
      BOOST_CHECK_EQUAL(records.size(), 0);
    }
  }

  /* remove only one entry, one of the A local records */
  zone->rmQNameTrigger(bad2, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, { DNSRecordContent::mastermake(QType::A, QClass::IN, "192.0.2.1") } ));
  BOOST_CHECK_EQUAL(zone->size(), 2);

  {
    /* exact type exists */
    const auto matchingPolicy = dfe.getQueryPolicy(bad2, ComboAddress("192.0.2.142"), std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);

    {
      auto records = matchingPolicy.getCustomRecords(bad2, QType::A);
      BOOST_REQUIRE_EQUAL(records.size(), 1);
      {
        const auto& record = records.at(0);
        BOOST_CHECK(record.d_type == QType::A);
        BOOST_CHECK(record.d_class == QClass::IN);
        auto content = std::dynamic_pointer_cast<ARecordContent>(record.d_content);
        BOOST_CHECK(content != nullptr);
        BOOST_CHECK_EQUAL(content->getCA().toString(), "192.0.2.2");
      }
    }

    {
      auto records = matchingPolicy.getCustomRecords(bad2, QType::MX);
      BOOST_CHECK_EQUAL(records.size(), 1);
      const auto& record = records.at(0);
      BOOST_CHECK(record.d_type == QType::MX);
      BOOST_CHECK(record.d_class == QClass::IN);
      auto content = std::dynamic_pointer_cast<MXRecordContent>(record.d_content);
      BOOST_CHECK(content != nullptr);
      BOOST_CHECK_EQUAL(content->d_mxname.toString(), "garden-mail.example.net.");
    }

    {
      /* the name exists but there is no CNAME nor matching type, so NODATA */
      auto records = matchingPolicy.getCustomRecords(bad2, QType::AAAA);
      BOOST_CHECK_EQUAL(records.size(), 0);
    }
  }
}

BOOST_AUTO_TEST_CASE(test_multiple_filter_policies) {
  DNSFilterEngine dfe;

  auto zone1 = std::make_shared<DNSFilterEngine::Zone>();
  zone1->setName("Unit test policy 0");

  auto zone2 = std::make_shared<DNSFilterEngine::Zone>();
  zone2->setName("Unit test policy 1");

  const DNSName bad("bad.example.com.");

  zone1->addQNameTrigger(bad, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, { DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "garden1.example.net.") } ));
  zone2->addQNameTrigger(bad, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, { DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "garden2.example.net.") } ));

  dfe.addZone(zone1);
  dfe.addZone(zone2);

  {
    /* zone 1 should match first */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, ComboAddress("192.0.2.142"), std::unordered_map<std::string,bool>());
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = std::dynamic_pointer_cast<CNAMERecordContent>(record.d_content);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden1.example.net.");
  }

  {
    /* zone 1 should still match if zone 2 has been disabled */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, ComboAddress("192.0.2.142"), { { *(zone2->getName()), true } });
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = std::dynamic_pointer_cast<CNAMERecordContent>(record.d_content);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden1.example.net.");
  }

  {
    /* if zone 1 is disabled, zone 2 should match */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, ComboAddress("192.0.2.142"), { { *(zone1->getName()), true } });
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = std::dynamic_pointer_cast<CNAMERecordContent>(record.d_content);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden2.example.net.");
  }

  {
    /* if both zones are disabled, we should not match */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, ComboAddress("192.0.2.142"), { { *(zone1->getName()), true }, { *(zone2->getName()), true } });
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
  }

}
