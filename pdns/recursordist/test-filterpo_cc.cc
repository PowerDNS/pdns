
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include "dnsrecords.hh"
#include "filterpo.hh"

BOOST_AUTO_TEST_CASE(test_filter_policies_basic)
{
  DNSFilterEngine dfe;

  std::string zoneName("Unit test policy 0");
  auto zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName(zoneName);
  BOOST_CHECK_EQUAL(zone->getName(), zoneName);
  zone->setDomain(DNSName("powerdns.com."));
  BOOST_CHECK_EQUAL(zone->getDomain(), DNSName("powerdns.com."));
  zone->setSerial(42);
  BOOST_CHECK_EQUAL(zone->getSerial(), 42U);
  zone->setRefresh(99);
  BOOST_CHECK_EQUAL(zone->getRefresh(), 99U);

  const ComboAddress nsIP("192.0.2.1");
  const DNSName nsName("ns.bad.wolf.");
  const DNSName nsWildcardName("*.wildcard.wolf.");
  const ComboAddress clientIP("192.0.2.128");
  const DNSName blockedName("blocked.");
  const DNSName blockedWildcardName("*.wildcard-blocked.");
  const ComboAddress responseIP("192.0.2.254");
  BOOST_CHECK_EQUAL(zone->size(), 0U);
  zone->addClientTrigger(Netmask(clientIP, 31), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::ClientIP));
  BOOST_CHECK_EQUAL(zone->size(), 1U);
  zone->addQNameTrigger(blockedName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::QName));
  BOOST_CHECK_EQUAL(zone->size(), 2U);
  zone->addQNameTrigger(blockedWildcardName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::QName));
  BOOST_CHECK_EQUAL(zone->size(), 3U);
  zone->addNSIPTrigger(Netmask(nsIP, 31), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::NSIP));
  BOOST_CHECK_EQUAL(zone->size(), 4U);
  zone->addNSTrigger(nsName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::NSDName));
  BOOST_CHECK_EQUAL(zone->size(), 5U);
  zone->addNSTrigger(nsWildcardName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::NSDName));
  BOOST_CHECK_EQUAL(zone->size(), 6U);
  zone->addResponseTrigger(Netmask(responseIP, 31), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::ResponseIP));
  BOOST_CHECK_EQUAL(zone->size(), 7U);

  size_t zoneIdx = dfe.addZone(zone);

  BOOST_CHECK_EQUAL(dfe.size(), 1U);
  BOOST_CHECK(dfe.getZone(zoneName) == zone);
  BOOST_CHECK(dfe.getZone(zoneIdx) == zone);

  dfe.setZone(zoneIdx, zone);

  BOOST_CHECK_EQUAL(dfe.size(), 1U);
  BOOST_CHECK(dfe.getZone(zoneName) == zone);
  BOOST_CHECK(dfe.getZone(zoneIdx) == zone);

  {
    /* blocked NS name */
    auto matchingPolicy = dfe.getProcessingPolicy(nsName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::NSDName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);

    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findExactNSPolicy(nsName, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);

    /* but a subdomain should not be blocked (not a wildcard, and this is not suffix domain matching */
    matchingPolicy = dfe.getProcessingPolicy(DNSName("sub") + nsName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    BOOST_CHECK(zone->findExactNSPolicy(DNSName("sub") + nsName, zonePolicy) == false);
  }

  {
    /* blocked NS name via wildcard */
    const auto matchingPolicy = dfe.getProcessingPolicy(DNSName("sub.sub.wildcard.wolf."), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::NSDName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    BOOST_CHECK_EQUAL(matchingPolicy.d_trigger, DNSName("*.wildcard.wolf.rpz-nsdname"));
    BOOST_CHECK_EQUAL(matchingPolicy.d_hit, "sub.sub.wildcard.wolf");

    /* looking for wildcard.wolf. should not match *.wildcard-blocked. */
    const auto notMatchingPolicy = dfe.getProcessingPolicy(DNSName("wildcard.wolf."), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(notMatchingPolicy.d_type == DNSFilterEngine::PolicyType::None);

    /* a direct lookup would not match */
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findExactNSPolicy(DNSName("sub.sub.wildcard.wolf."), zonePolicy) == false);
    /* except if we look exactly for the wildcard */
    BOOST_CHECK(zone->findExactNSPolicy(nsWildcardName, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
    BOOST_CHECK_EQUAL(zonePolicy.d_trigger, DNSName("*.wildcard.wolf.rpz-nsdname"));
    BOOST_CHECK_EQUAL(zonePolicy.d_hit, nsWildcardName.toStringNoDot());
  }

  {
    /* allowed NS name */
    const auto matchingPolicy = dfe.getProcessingPolicy(DNSName("ns.bad.rabbit."), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findExactNSPolicy(DNSName("ns.bad.rabbit."), zonePolicy) == false);
  }

  {
    /* blocked NS IP */
    const auto matchingPolicy = dfe.getProcessingPolicy(nsIP, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::NSIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findNSIPPolicy(nsIP, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
    BOOST_CHECK_EQUAL(zonePolicy.d_trigger, DNSName("31.0.2.0.192.rpz-nsip"));
    BOOST_CHECK_EQUAL(zonePolicy.d_hit, nsIP.toString());
  }

  {
    /* allowed NS IP */
    const auto matchingPolicy = dfe.getProcessingPolicy(ComboAddress("192.0.2.142"), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findNSIPPolicy(ComboAddress("192.0.2.142"), zonePolicy) == false);
  }

  {
    /* blocked qname */
    auto matchingPolicy = dfe.getQueryPolicy(blockedName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findExactQNamePolicy(blockedName, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
    BOOST_CHECK_EQUAL(zonePolicy.d_trigger, blockedName);
    BOOST_CHECK_EQUAL(zonePolicy.d_hit, blockedName.toStringNoDot());

    /* but a subdomain should not be blocked (not a wildcard, and this is not suffix domain matching */
    matchingPolicy = dfe.getQueryPolicy(DNSName("sub") + blockedName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    BOOST_CHECK(zone->findExactQNamePolicy(DNSName("sub") + blockedName, zonePolicy) == false);
  }

  {
    /* blocked NS name via wildcard */
    const auto matchingPolicy = dfe.getQueryPolicy(DNSName("sub.sub.wildcard-blocked."), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    BOOST_CHECK_EQUAL(matchingPolicy.d_trigger, blockedWildcardName);
    BOOST_CHECK_EQUAL(matchingPolicy.d_hit, "sub.sub.wildcard-blocked");

    /* looking for wildcard-blocked. should not match *.wildcard-blocked. */
    const auto notMatchingPolicy = dfe.getQueryPolicy(DNSName("wildcard-blocked."), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(notMatchingPolicy.d_type == DNSFilterEngine::PolicyType::None);

    /* a direct lookup would not match */
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findExactQNamePolicy(DNSName("sub.sub.wildcard-blocked."), zonePolicy) == false);
    /* except if we look exactly for the wildcard */
    BOOST_CHECK(zone->findExactQNamePolicy(blockedWildcardName, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
    BOOST_CHECK_EQUAL(zonePolicy.d_trigger, blockedWildcardName);
    BOOST_CHECK_EQUAL(zonePolicy.d_hit, blockedWildcardName.toStringNoDot());
  }

  {
    /* blocked client IP */
    const auto matchingPolicy = dfe.getClientPolicy(clientIP, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ClientIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findClientPolicy(clientIP, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
    BOOST_CHECK_EQUAL(zonePolicy.d_trigger, DNSName("31.128.2.0.192.rpz-client-ip"));
    BOOST_CHECK_EQUAL(zonePolicy.d_hit, clientIP.toString());
  }

  {
    /* not blocked */
    const auto matchingPolicy = dfe.getClientPolicy(ComboAddress("192.0.2.142"), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findClientPolicy(ComboAddress("192.0.2.142"), zonePolicy) == false);
    BOOST_CHECK(zone->findExactQNamePolicy(DNSName("totally.legit."), zonePolicy) == false);
  }

  {
    /* blocked A */
    DNSRecord dr;
    dr.d_type = QType::A;
    dr.setContent(DNSRecordContent::mastermake(QType::A, QClass::IN, responseIP.toString()));
    const auto matchingPolicy = dfe.getPostPolicy({dr}, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ResponseIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findResponsePolicy(responseIP, zonePolicy));
    BOOST_CHECK(zonePolicy == matchingPolicy);
    BOOST_CHECK_EQUAL(zonePolicy.d_trigger, DNSName("31.254.2.0.192.rpz-ip"));
    BOOST_CHECK_EQUAL(zonePolicy.d_hit, responseIP.toString());
  }

  {
    /* allowed A */
    DNSRecord dr;
    dr.d_type = QType::A;
    dr.setContent(DNSRecordContent::mastermake(QType::A, QClass::IN, "192.0.2.142"));
    const auto matchingPolicy = dfe.getPostPolicy({dr}, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    DNSFilterEngine::Policy zonePolicy;
    BOOST_CHECK(zone->findResponsePolicy(ComboAddress("192.0.2.142"), zonePolicy) == false);
  }

  BOOST_CHECK_EQUAL(zone->size(), 7U);
  zone->rmClientTrigger(Netmask(clientIP, 31), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::ClientIP));
  BOOST_CHECK_EQUAL(zone->size(), 6U);
  zone->rmQNameTrigger(blockedName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::QName));
  BOOST_CHECK_EQUAL(zone->size(), 5U);
  zone->rmQNameTrigger(blockedWildcardName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::QName));
  BOOST_CHECK_EQUAL(zone->size(), 4U);
  zone->rmNSIPTrigger(Netmask(nsIP, 31), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::NSIP));
  BOOST_CHECK_EQUAL(zone->size(), 3U);
  zone->rmNSTrigger(nsName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::NSDName));
  BOOST_CHECK_EQUAL(zone->size(), 2U);
  zone->rmNSTrigger(nsWildcardName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::NSDName));
  BOOST_CHECK_EQUAL(zone->size(), 1U);
  zone->rmResponseTrigger(Netmask(responseIP, 31), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop, DNSFilterEngine::PolicyType::ResponseIP));
  BOOST_CHECK_EQUAL(zone->size(), 0U);

  /* DNSFilterEngine::clear() calls clear() on all zones, but keeps the zones */
  dfe.clear();
  BOOST_CHECK_EQUAL(dfe.size(), 1U);
  BOOST_CHECK(dfe.getZone(zoneName) == zone);
  BOOST_CHECK(dfe.getZone(zoneIdx) == zone);
}

BOOST_AUTO_TEST_CASE(test_filter_policies_wildcard_with_enc)
{
  DNSFilterEngine dfe;

  std::string zoneName("Unit test policy wc");
  auto zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName(zoneName);
  zone->setDomain(DNSName("powerdns.com."));
  zone->setSerial(42);
  zone->setRefresh(99);

  zone->addQNameTrigger(DNSName("bcbsks.com.102.112.2o7.net."),
                        DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::NoAction,
                                                DNSFilterEngine::PolicyType::QName));
  zone->addQNameTrigger(DNSName("2o7.net."),
                        DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop,
                                                DNSFilterEngine::PolicyType::QName));
  zone->addQNameTrigger(DNSName("*.2o7.net."),
                        DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Drop,
                                                DNSFilterEngine::PolicyType::QName));

  dfe.addZone(zone);

  ComboAddress address("192.0.2.142");

  {
    const DNSName tstName("bcbsks.com.102.112.2o7.net.");
    auto matchingPolicy = dfe.getQueryPolicy(tstName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction);
  }

  {
    const DNSName tstName("2o7.net.");
    auto matchingPolicy = dfe.getQueryPolicy(tstName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
  }

  // Once fixed the BOOST_WARN should becomes BOOST_CHECK
  const string m("Please fix issue #8231");

  {
    const DNSName tstName("112.2o7.net.");
    auto matchingPolicy = dfe.getQueryPolicy(tstName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_WARN_MESSAGE(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None, m);
    BOOST_WARN_MESSAGE(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction, m);
  }

  {
    const DNSName tstName("102.112.2o7.net.");
    auto matchingPolicy = dfe.getQueryPolicy(tstName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_WARN_MESSAGE(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None, m);
    BOOST_WARN_MESSAGE(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction, m);
  }

  {
    const DNSName tstName("com.112.2o7.net.");
    auto matchingPolicy = dfe.getQueryPolicy(tstName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_WARN_MESSAGE(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None, m);
    BOOST_WARN_MESSAGE(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction, m);
  }

  {
    const DNSName tstName("wcmatch.2o7.net.");
    auto matchingPolicy = dfe.getQueryPolicy(tstName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Drop);
  }
}

BOOST_AUTO_TEST_CASE(test_filter_policies_local_data)
{
  DNSFilterEngine dfe;

  std::string zoneName("Unit test policy local data");
  auto zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName(zoneName);

  const DNSName bad1("bad1.example.com.");
  const DNSName bad2("bad2.example.com.");

  zone->addQNameTrigger(bad1, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "garden.example.net.")}));
  BOOST_CHECK_EQUAL(zone->size(), 1U);

  zone->addQNameTrigger(bad2, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "192.0.2.1")}));
  BOOST_CHECK_EQUAL(zone->size(), 2U);

  zone->addQNameTrigger(bad2, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "192.0.2.2")}));
  BOOST_CHECK_EQUAL(zone->size(), 2U);

  zone->addQNameTrigger(bad2, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::MX, QClass::IN, "10 garden-mail.example.net.")}));
  BOOST_CHECK_EQUAL(zone->size(), 2U);

  dfe.addZone(zone);

  {
    /* exact type does not exist, but we have a CNAME */
    const auto matchingPolicy = dfe.getQueryPolicy(bad1, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad1, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden.example.net.");
  }

  {
    /* exact type exists */
    const auto matchingPolicy = dfe.getQueryPolicy(bad2, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);

    {
      auto records = matchingPolicy.getCustomRecords(bad2, QType::A);
      BOOST_REQUIRE_EQUAL(records.size(), 2U);
      {
        const auto& record = records.at(0);
        BOOST_CHECK(record.d_type == QType::A);
        BOOST_CHECK(record.d_class == QClass::IN);
        auto content = getRR<ARecordContent>(record);
        BOOST_CHECK(content != nullptr);
        BOOST_CHECK_EQUAL(content->getCA().toString(), "192.0.2.1");
      }
      {
        const auto& record = records.at(1);
        BOOST_CHECK(record.d_type == QType::A);
        BOOST_CHECK(record.d_class == QClass::IN);
        auto content = getRR<ARecordContent>(record);
        BOOST_CHECK(content != nullptr);
        BOOST_CHECK_EQUAL(content->getCA().toString(), "192.0.2.2");
      }
    }

    {
      auto records = matchingPolicy.getCustomRecords(bad2, QType::MX);
      BOOST_CHECK_EQUAL(records.size(), 1U);
      const auto& record = records.at(0);
      BOOST_CHECK(record.d_type == QType::MX);
      BOOST_CHECK(record.d_class == QClass::IN);
      auto content = getRR<MXRecordContent>(record);
      BOOST_CHECK(content != nullptr);
      BOOST_CHECK_EQUAL(content->d_mxname.toString(), "garden-mail.example.net.");
    }

    {
      /* the name exists but there is no CNAME nor matching type, so NODATA */
      auto records = matchingPolicy.getCustomRecords(bad2, QType::AAAA);
      BOOST_CHECK_EQUAL(records.size(), 0U);
    }
  }

  /* remove only one entry, one of the A local records */
  zone->rmQNameTrigger(bad2, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "192.0.2.1")}));
  BOOST_CHECK_EQUAL(zone->size(), 2U);

  {
    /* exact type exists */
    const auto matchingPolicy = dfe.getQueryPolicy(bad2, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);

    {
      auto records = matchingPolicy.getCustomRecords(bad2, QType::A);
      BOOST_REQUIRE_EQUAL(records.size(), 1U);
      {
        const auto& record = records.at(0);
        BOOST_CHECK(record.d_type == QType::A);
        BOOST_CHECK(record.d_class == QClass::IN);
        auto content = getRR<ARecordContent>(record);
        BOOST_CHECK(content != nullptr);
        BOOST_CHECK_EQUAL(content->getCA().toString(), "192.0.2.2");
      }
    }

    {
      auto records = matchingPolicy.getCustomRecords(bad2, QType::MX);
      BOOST_CHECK_EQUAL(records.size(), 1U);
      const auto& record = records.at(0);
      BOOST_CHECK(record.d_type == QType::MX);
      BOOST_CHECK(record.d_class == QClass::IN);
      auto content = getRR<MXRecordContent>(record);
      BOOST_CHECK(content != nullptr);
      BOOST_CHECK_EQUAL(content->d_mxname.toString(), "garden-mail.example.net.");
    }

    {
      /* the name exists but there is no CNAME nor matching type, so NODATA */
      auto records = matchingPolicy.getCustomRecords(bad2, QType::AAAA);
      BOOST_CHECK_EQUAL(records.size(), 0U);
    }
  }
}

BOOST_AUTO_TEST_CASE(test_filter_policies_local_data_netmask)
{
  DNSFilterEngine dfe;

  std::string zoneName("Unit test policy local data using netmasks");
  auto zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName(zoneName);

  const DNSName name("foo.example.com");
  const Netmask nm1("192.168.1.0/24");

  zone->addClientTrigger(nm1, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "1.2.3.4")}));
  zone->addClientTrigger(nm1, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "1.2.3.5")}));
  zone->addClientTrigger(nm1, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::AAAA, QClass::IN, "::1234")}));
  BOOST_CHECK_EQUAL(zone->size(), 1U);

  dfe.addZone(zone);

  { // A query should match two records
    const auto matchingPolicy = dfe.getClientPolicy(ComboAddress("192.168.1.1"), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ClientIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(DNSName(), QType::A);
    BOOST_CHECK_EQUAL(records.size(), 2U);
    const auto& record1 = records.at(0);
    BOOST_CHECK(record1.d_type == QType::A);
    BOOST_CHECK(record1.d_class == QClass::IN);
    auto content1 = getRR<ARecordContent>(record1);
    BOOST_CHECK(content1 != nullptr);
    BOOST_CHECK_EQUAL(content1->getCA().toString(), "1.2.3.4");

    const auto& record2 = records.at(1);
    BOOST_CHECK(record2.d_type == QType::A);
    BOOST_CHECK(record2.d_class == QClass::IN);
    auto content2 = getRR<ARecordContent>(record2);
    BOOST_CHECK(content2 != nullptr);
    BOOST_CHECK_EQUAL(content2->getCA().toString(), "1.2.3.5");
  }

  { // AAAA query should match 1 record
    const auto matchingPolicy = dfe.getClientPolicy(ComboAddress("192.168.1.1"), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ClientIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(DNSName(), QType::AAAA);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record1 = records.at(0);
    BOOST_CHECK(record1.d_type == QType::AAAA);
    BOOST_CHECK(record1.d_class == QClass::IN);
    auto content1 = getRR<AAAARecordContent>(record1);
    BOOST_CHECK(content1 != nullptr);
    BOOST_CHECK_EQUAL(content1->getCA().toString(), "::1234");
  }

  // Try to zap 1 nonexisting record
  zone->rmClientTrigger(nm1, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "1.1.1.1")}));

  // Zap a record using a wider netmask
  zone->rmClientTrigger(Netmask("192.168.0.0/16"), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "1.2.3.4")}));

  // Zap a record using a narrow netmask
  zone->rmClientTrigger(Netmask("192.168.1.1/32"), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "1.2.3.4")}));

  // Zap 1 existing record
  zone->rmClientTrigger(nm1, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "1.2.3.5")}));

  { // A query should match one record now
    const auto matchingPolicy = dfe.getClientPolicy(ComboAddress("192.168.1.1"), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ClientIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(DNSName(), QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record1 = records.at(0);
    BOOST_CHECK(record1.d_type == QType::A);
    BOOST_CHECK(record1.d_class == QClass::IN);
    auto content1 = getRR<ARecordContent>(record1);
    BOOST_CHECK(content1 != nullptr);
    BOOST_CHECK_EQUAL(content1->getCA().toString(), "1.2.3.4");
  }
  { // AAAA query should still match one record
    const auto matchingPolicy = dfe.getClientPolicy(ComboAddress("192.168.1.1"), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ClientIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(DNSName(), QType::AAAA);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record1 = records.at(0);
    BOOST_CHECK(record1.d_type == QType::AAAA);
    BOOST_CHECK(record1.d_class == QClass::IN);
    auto content1 = getRR<AAAARecordContent>(record1);
    BOOST_CHECK(content1 != nullptr);
    BOOST_CHECK_EQUAL(content1->getCA().toString(), "::1234");
  }

  // Zap one more A record
  zone->rmClientTrigger(nm1, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "1.2.3.4")}));

  // Zap now nonexisting record
  zone->rmClientTrigger(nm1, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::A, QClass::IN, "1.2.3.4")}));

  { // AAAA query should still match one record
    const auto matchingPolicy = dfe.getClientPolicy(ComboAddress("192.168.1.1"), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ClientIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(DNSName(), QType::AAAA);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record1 = records.at(0);
    BOOST_CHECK(record1.d_type == QType::AAAA);
    BOOST_CHECK(record1.d_class == QClass::IN);
    auto content1 = getRR<AAAARecordContent>(record1);
    BOOST_CHECK(content1 != nullptr);
    BOOST_CHECK_EQUAL(content1->getCA().toString(), "::1234");
  }

  // Zap AAAA record
  zone->rmClientTrigger(nm1, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::AAAA, QClass::IN, "::1234")}));

  { // there should be no match left
    const auto matchingPolicy = dfe.getClientPolicy(ComboAddress("192.168.1.1"), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction);
  }
}

BOOST_AUTO_TEST_CASE(test_multiple_filter_policies)
{
  DNSFilterEngine dfe;

  auto zone1 = std::make_shared<DNSFilterEngine::Zone>();
  zone1->setName("Unit test policy 0");

  auto zone2 = std::make_shared<DNSFilterEngine::Zone>();
  zone2->setName("Unit test policy 1");

  const DNSName bad("bad.example.com.");
  const DNSName badWildcard("*.bad-wildcard.example.com.");
  const DNSName badUnderWildcard("sub.bad-wildcard.example.com.");

  zone1->addQNameTrigger(bad, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "garden1a.example.net.")}));
  zone2->addQNameTrigger(bad, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "garden2a.example.net.")}));
  zone1->addQNameTrigger(badWildcard, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "garden1b.example.net.")}));
  zone2->addQNameTrigger(badUnderWildcard, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "garden2b.example.net.")}));

  dfe.addZone(zone1);
  dfe.addZone(zone2);

  {
    /* zone 1 should match first */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden1a.example.net.");
  }

  {
    /* zone 2 has an exact match for badUnderWildcard, but the wildcard from the first zone should match first */
    const auto matchingPolicy = dfe.getQueryPolicy(badUnderWildcard, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(badUnderWildcard, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden1b.example.net.");
  }

  {
    /* zone 1 should still match if zone 2 has been disabled */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, {{zone2->getName(), true}}, DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden1a.example.net.");
  }

  {
    /* if zone 1 is disabled, zone 2 should match */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, {{zone1->getName(), true}}, DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden2a.example.net.");
  }

  {
    /* if both zones are disabled, we should not match */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, {{zone1->getName(), true}, {zone2->getName(), true}}, DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
  }
}

BOOST_AUTO_TEST_CASE(test_multiple_filter_policies_order)
{
  DNSFilterEngine dfe;

  auto zone1 = std::make_shared<DNSFilterEngine::Zone>();
  zone1->setName("Unit test policy 0");

  auto zone2 = std::make_shared<DNSFilterEngine::Zone>();
  zone2->setName("Unit test policy 1");

  const ComboAddress clientIP("192.0.2.128");
  const DNSName bad("bad.example.com.");
  const ComboAddress nsIP("192.0.2.1");
  const DNSName nsName("ns.bad.wolf.");
  const ComboAddress responseIP("192.0.2.254");

  zone1->addClientTrigger(Netmask(clientIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "client1a.example.net.")}));
  zone1->addQNameTrigger(bad, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "garden1a.example.net.")}));
  zone1->addNSIPTrigger(Netmask(nsIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::NSIP, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "nsip1a.example.net.")}));
  zone1->addNSTrigger(nsName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::NSDName, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "nsname1a.example.net.")}));
  zone1->addResponseTrigger(Netmask(responseIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ResponseIP, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "response1a.example.net.")}));

  zone2->addClientTrigger(Netmask(clientIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ClientIP, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "client2a.example.net.")}));
  zone2->addQNameTrigger(bad, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::QName, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "garden2a.example.net.")}));
  zone2->addNSIPTrigger(Netmask(nsIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::NSIP, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "nsip2a.example.net.")}));
  zone2->addNSTrigger(nsName, DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::NSDName, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "nsname2a.example.net.")}));
  zone2->addResponseTrigger(Netmask(responseIP, 32), DNSFilterEngine::Policy(DNSFilterEngine::PolicyKind::Custom, DNSFilterEngine::PolicyType::ResponseIP, 0, nullptr, {DNSRecordContent::mastermake(QType::CNAME, QClass::IN, "response2a.example.net.")}));

  dfe.addZone(zone1);
  dfe.addZone(zone2);
  BOOST_CHECK_EQUAL(zone1->getPriority(), 0);
  BOOST_CHECK_EQUAL(zone2->getPriority(), 1);

  {
    /* client IP should match before qname */
    const auto matchingPolicy = dfe.getClientPolicy(ComboAddress("192.0.2.128"), std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ClientIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "client1a.example.net.");
  }

  {
    /* client IP and qname should match, but zone 1 is disabled and zone2's priority is too high */
    const auto matchingPolicy = dfe.getClientPolicy(ComboAddress("192.0.2.128"), {{zone1->getName(), true}}, 1);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction);
  }

  {
    /* zone 1 should match first */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden1a.example.net.");
  }

  {
    /* zone 1 should still match if we require a priority < 1 */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, std::unordered_map<std::string, bool>(), 1);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden1a.example.net.");
  }

  {
    /* nothing should match if we require a priority < 0 */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, std::unordered_map<std::string, bool>(), 0);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction);
  }

  {
    /* if we disable zone 1, zone 2 should match */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, {{zone1->getName(), true}}, DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::QName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "garden2a.example.net.");
  }

  {
    /* if we disable zone 1, zone 2 should match, except if we require a priority < 1 */
    const auto matchingPolicy = dfe.getQueryPolicy(bad, {{zone1->getName(), true}}, 1);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction);
  }

  {
    /* blocked NS name */
    auto matchingPolicy = dfe.getProcessingPolicy(nsName, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::NSDName);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "nsname1a.example.net.");
  }

  {
    /* blocked NS name, except policy 1 is disabled and policy2's priority is too high */
    auto matchingPolicy = dfe.getProcessingPolicy(nsName, {{zone1->getName(), true}}, 1);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction);
  }

  {
    /* blocked NS IP */
    const auto matchingPolicy = dfe.getProcessingPolicy(nsIP, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::NSIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "nsip1a.example.net.");
  }

  {
    /* blocked NS ip, except policy 1 is disabled and policy2's priority is too high */
    auto matchingPolicy = dfe.getProcessingPolicy(nsIP, {{zone1->getName(), true}}, 1);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction);
  }

  {
    /* blocked A in the response */
    DNSRecord dr;
    dr.d_type = QType::A;
    dr.setContent(DNSRecordContent::mastermake(QType::A, QClass::IN, responseIP.toString()));
    const auto matchingPolicy = dfe.getPostPolicy({dr}, std::unordered_map<std::string, bool>(), DNSFilterEngine::maximumPriority);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::ResponseIP);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom);
    auto records = matchingPolicy.getCustomRecords(bad, QType::A);
    BOOST_CHECK_EQUAL(records.size(), 1U);
    const auto& record = records.at(0);
    BOOST_CHECK(record.d_type == QType::CNAME);
    BOOST_CHECK(record.d_class == QClass::IN);
    auto content = getRR<CNAMERecordContent>(record);
    BOOST_CHECK(content != nullptr);
    BOOST_CHECK_EQUAL(content->getTarget().toString(), "response1a.example.net.");
  }

  {
    /* blocked A in the response, except 1 is disabled and 2's priority is too high */
    DNSRecord dr;
    dr.d_type = QType::A;
    dr.setContent(DNSRecordContent::mastermake(QType::A, QClass::IN, responseIP.toString()));
    const auto matchingPolicy = dfe.getPostPolicy({dr}, {{zone1->getName(), true}}, 1);
    BOOST_CHECK(matchingPolicy.d_type == DNSFilterEngine::PolicyType::None);
    BOOST_CHECK(matchingPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction);
  }
}

BOOST_AUTO_TEST_CASE(test_mask_to_rpz)
{
  BOOST_CHECK_EQUAL(DNSFilterEngine::Zone::maskToRPZ(Netmask("::2/127")).toString(), "127.2.zz.");
  BOOST_CHECK_EQUAL(DNSFilterEngine::Zone::maskToRPZ(Netmask("1::2/127")).toString(), "127.2.zz.1.");
  BOOST_CHECK_EQUAL(DNSFilterEngine::Zone::maskToRPZ(Netmask("2::/127")).toString(), "127.zz.2.");
  BOOST_CHECK_EQUAL(DNSFilterEngine::Zone::maskToRPZ(Netmask("1abc:2::/127")).toString(), "127.zz.2.1abc.");
  BOOST_CHECK_EQUAL(DNSFilterEngine::Zone::maskToRPZ(Netmask("1:2:3:4:5:6:7::/127")).toString(), "127.0.7.6.5.4.3.2.1.");
  BOOST_CHECK_EQUAL(DNSFilterEngine::Zone::maskToRPZ(Netmask("1:2:3:4:5:6::/127")).toString(), "127.zz.6.5.4.3.2.1.");
  BOOST_CHECK_EQUAL(DNSFilterEngine::Zone::maskToRPZ(Netmask("1:0:0:0:2:0:0:0/127")).toString(), "127.zz.2.0.0.0.1.");
  BOOST_CHECK_EQUAL(DNSFilterEngine::Zone::maskToRPZ(Netmask("1:0:0:2:0:0:0:0/127")).toString(), "127.zz.2.0.0.1.");
  BOOST_CHECK_EQUAL(DNSFilterEngine::Zone::maskToRPZ(Netmask("1:0:0:0:0:2:0:0/127")).toString(), "127.0.0.2.zz.1.");
}
