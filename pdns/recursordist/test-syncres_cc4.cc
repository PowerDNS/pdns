#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc4)

BOOST_AUTO_TEST_CASE(test_auth_zone_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("nodata.powerdns.com.");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<ARecordContent>(ComboAddress("192.0.2.1")));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    queriesCount++;

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_nx)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("nx.powerdns.com.");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("powerdns.com.");
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    queriesCount++;

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_delegation)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("www.test.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.2");
  const DNSName ns("ns1.test.powerdns.com.");
  const ComboAddress nsAddr("192.0.2.1");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("test.powerdns.com.");
  dr.d_type = QType::NS;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<NSRecordContent>(ns));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = ns;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<ARecordContent>(nsAddr));
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  testkeysset_t keys;
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::RSASHA512, DNSSEC::DIGEST_SHA384, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  /* make sure that the signature inception and validity times are computed
     based on the SyncRes time, not the current one, in case the function
     takes too long. */
  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;
    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys, domain == DNSName("com.") || domain == authZone, fixedNow);
    }

    if (address == ComboAddress(nsAddr.toString(), 53) && domain == target) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  sr->setDNSSECValidationRequested(true);
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_delegation_point)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("test.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.2");
  const DNSName ns("ns1.test.powerdns.com.");
  const ComboAddress nsAddr("192.0.2.1");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("test.powerdns.com.");
  dr.d_type = QType::NS;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<NSRecordContent>(ns));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = ns;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<ARecordContent>(nsAddr));
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (address == ComboAddress(nsAddr.toString(), 53) && domain == target) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_wildcard)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("test.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.2");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("*.powerdns.com.");
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<ARecordContent>(targetAddr));
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    queriesCount++;

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_wildcard_with_ent)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("test.powerdns.com.");
  const ComboAddress targetAddr1("192.0.2.1");
  const ComboAddress targetAddr2("192.0.2.2");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("abc.xyz.test.powerdns.com.");
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<ARecordContent>(targetAddr1));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("*.powerdns.com.");
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<ARecordContent>(targetAddr2));
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    queriesCount++;

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);

  // WARN below should be changed to CHECK once the issue is fixed.
  const string m("Please fix issue #8312");
  BOOST_WARN_MESSAGE(ret[0].d_type == QType::SOA, m);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_wildcard_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("test.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.2");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("*.powerdns.com.");
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<ARecordContent>(targetAddr));
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    queriesCount++;

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_cache_only)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("powerdns.com.");
  const ComboAddress addr("192.0.2.5");

  SyncRes::AuthDomain ad;
  ad.d_name = target;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<ARecordContent>(addr));
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[target] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;
    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, domain, QType::A, "192.0.2.42");
    return LWResult::Result::Success;
  });

  /* simulate a no-RD query */
  sr->setCacheOnly();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig)
{
  initSR();

  auto dcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.setKey(std::move(dcke), 256);

  sortedRecords_t recordcontents;
  recordcontents.insert(getRecordContent(QType::A, "192.0.2.1"));

  DNSName qname("powerdns.com.");

  time_t now = time(nullptr);
  RRSIGRecordContent rrc;
  /* this RRSIG is valid for the current second only */
  computeRRSIG(dpk, qname, qname, QType::A, 600, 0, rrc, recordcontents, boost::none, now);

  skeyset_t keyset;
  keyset.insert(std::make_shared<DNSKEYRecordContent>(dpk.getDNSKEY()));

  std::vector<std::shared_ptr<const RRSIGRecordContent>> sigs;
  sigs.push_back(std::make_shared<RRSIGRecordContent>(rrc));

  pdns::validation::ValidationContext validationContext;
  BOOST_CHECK(validateWithKeySet(now, qname, recordcontents, sigs, keyset, std::nullopt, validationContext) == vState::Secure);
  BOOST_CHECK_EQUAL(validationContext.d_validationsCounter, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_future)
{
  initSR();

  auto dcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.setKey(std::move(dcke), 256);

  sortedRecords_t recordcontents;
  recordcontents.insert(getRecordContent(QType::A, "192.0.2.1"));

  DNSName qname("powerdns.com.");

  time_t inception = 0xf0000000U;
  auto validity = 0xffffffffU;
  RRSIGRecordContent rrc;
  computeRRSIG(dpk, qname, qname, QType::A, 600, validity, rrc, recordcontents, boost::none, inception, 0);

  skeyset_t keyset;
  keyset.insert(std::make_shared<DNSKEYRecordContent>(dpk.getDNSKEY()));

  std::vector<std::shared_ptr<const RRSIGRecordContent>> sigs;
  sigs.push_back(std::make_shared<RRSIGRecordContent>(rrc));

  pdns::validation::ValidationContext validationContext;
  time_t now = 0xe0000000;
  // Case 1:  current time before inception
  BOOST_CHECK(validateWithKeySet(now, qname, recordcontents, sigs, keyset, std::nullopt, validationContext) == vState::BogusSignatureNotYetValid);
  BOOST_CHECK_EQUAL(validationContext.d_validationsCounter, 0U);

  // Case 2: we're in Jan 1970
  now = 1; // Both inception and expiry are in the past (1969)
  BOOST_CHECK(validateWithKeySet(now, qname, recordcontents, sigs, keyset, std::nullopt, validationContext) == vState::BogusSignatureExpired);
  BOOST_CHECK_EQUAL(validationContext.d_validationsCounter, 0U);

  // Case 3: we're in 2038
  now = 0xffff0001; // should be ok, we're inside validity
  BOOST_CHECK(validateWithKeySet(now, qname, recordcontents, sigs, keyset, std::nullopt, validationContext) == vState::Secure);
  BOOST_CHECK_EQUAL(validationContext.d_validationsCounter, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_extreme_timestamps)
{
  initSR();

  auto dcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.setKey(std::move(dcke), 256);

  sortedRecords_t recordcontents;
  recordcontents.insert(getRecordContent(QType::A, "192.0.2.1"));

  DNSName qname("powerdns.com.");

  time_t inception = 0U; // Interpreted as jan 1st 1970, until it is more than 68 years in the past
  auto validity = 0xffffffffU; // Will be interpreted as end of 1969, as is more than 68 years in the future (until it isn't)
  RRSIGRecordContent rrc;
  computeRRSIG(dpk, qname, qname, QType::A, 600, validity, rrc, recordcontents, boost::none, inception, 0);

  skeyset_t keyset;
  keyset.insert(std::make_shared<DNSKEYRecordContent>(dpk.getDNSKEY()));

  std::vector<std::shared_ptr<const RRSIGRecordContent>> sigs;
  sigs.push_back(std::make_shared<RRSIGRecordContent>(rrc));

  pdns::validation::ValidationContext validationContext;
  time_t now = time(nullptr);
  // Case 1: interpretion depends on current time, test below will start to fail around 1970 + 68 = 2038 as it wil be interpeted as the 3rd case
  BOOST_CHECK(validateWithKeySet(now, qname, recordcontents, sigs, keyset, std::nullopt, validationContext) == vState::BogusSignatureExpired);
  BOOST_CHECK_EQUAL(validationContext.d_validationsCounter, 0U);

  // Case 2: we're in Jan 1970
  now = 1; // sig inception is OK, but expiry is in 1969: not valid
  BOOST_CHECK(validateWithKeySet(now, qname, recordcontents, sigs, keyset, std::nullopt, validationContext) == vState::BogusSignatureExpired);
  BOOST_CHECK_EQUAL(validationContext.d_validationsCounter, 0U);

  // Case 3: we're in 2038
  now = 0xffff0000; // inception (0) wil be interpreted as being in the future
  BOOST_CHECK(validateWithKeySet(now, qname, recordcontents, sigs, keyset, std::nullopt, validationContext) == vState::BogusSignatureNotYetValid);
  BOOST_CHECK_EQUAL(validationContext.d_validationsCounter, 0U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_root_validation_csk)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_root_validation_ksk_zsk)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t zskeys;
  testkeysset_t kskeys;

  /* Generate key material for "." */
  auto dckeZ = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dckeZ->create(dckeZ->getBits());
  DNSSECPrivateKey ksk;
  ksk.setKey(std::move(dckeZ), 257);
  DSRecordContent kskds = makeDSFromDNSKey(target, ksk.getDNSKEY(), DNSSEC::DIGEST_SHA256);

  auto dckeK = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dckeK->create(dckeK->getBits());
  DNSSECPrivateKey zsk;
  zsk.setKey(std::move(dckeK), 256);
  DSRecordContent zskds = makeDSFromDNSKey(target, zsk.getDNSKEY(), DNSSEC::DIGEST_SHA256);

  kskeys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(ksk, kskds);
  zskeys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(zsk, zskds);

  /* Set the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(kskds);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(zskeys, res->d_records, domain, 300);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(kskeys, domain, 300, res->d_records);
      addDNSKEY(zskeys, domain, 300, res->d_records);
      addRRSIG(kskeys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_no_dnskey)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      /* No DNSKEY */

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusMissingNegativeIndication);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusMissingNegativeIndication);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_dnskey_without_zone_flag)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  /* Generate key material for "." */
  auto dcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey csk;
  csk.setKey(std::move(dcke), 0);
  DSRecordContent dsContent = makeDSFromDNSKey(target, csk.getDNSKEY(), DNSSEC::DIGEST_SHA256);

  keys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(csk, dsContent);

  /* Set the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(dsContent);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300);
      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoZoneKeyBitSet);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoZoneKeyBitSet);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_dnskey_revoked)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  /* Generate key material for "." */
  auto dcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey csk;
  csk.setKey(std::move(dcke), 257 | 128);
  DSRecordContent dsContent = makeDSFromDNSKey(target, csk.getDNSKEY(), DNSSEC::DIGEST_SHA256);

  keys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(csk, dsContent);

  /* Set the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(dsContent);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300);
      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusRevokedDNSKEY);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusRevokedDNSKEY);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_dnskey_doesnt_match_ds)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target(".");
  testkeysset_t dskeys;
  testkeysset_t keys;

  /* Generate key material for "." */
  auto dckeDS = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dckeDS->create(dckeDS->getBits());
  DNSSECPrivateKey dskey;
  dskey.setKey(std::move(dckeDS), 257);
  DSRecordContent drc = makeDSFromDNSKey(target, dskey.getDNSKEY(), DNSSEC::DIGEST_SHA256);

  auto dcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.setKey(std::move(dcke), 256);
  DSRecordContent seconddrc = makeDSFromDNSKey(target, dpk.getDNSKEY(), DNSSEC::DIGEST_SHA256);

  dskeys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(dskey, drc);
  keys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(dpk, seconddrc);

  /* Set the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(drc);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  /* === with validation enabled === */
  sr->setDNSSECValidationRequested(true);
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidDNSKEY);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidDNSKEY);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* === first without validation, then with (just-in-time validation) === */
  /* clear the caches */
  g_recCache = std::make_unique<MemRecursorCache>();
  g_negCache = std::make_unique<NegCache>();
  sr->setDNSSECValidationRequested(false);
  primeHints();

  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 3U);

  /* now we ask for the DNSKEYs (still without validation) */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DNSKEY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  /* 1 SOA + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache WITH validation */
  sr->setDNSSECValidationRequested(true);
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidDNSKEY);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_too_many_dss)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  g_maxDSsToConsider = 1;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  /* generate more DSs for the zone than we are willing to consider: only the last one will be used to generate DNSKEY records */
  for (size_t idx = 0; idx < (g_maxDSsToConsider + 10U); idx++) {
    generateKeyMaterial(g_rootdnsname, DNSSEC::RSASHA512, DNSSEC::DIGEST_SHA384, keys, luaconfsCopy.dsAnchors);
  }
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    else if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  /* === with validation enabled === */
  sr->setDNSSECValidationRequested(true);
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidDNSKEY);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidDNSKEY);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  g_maxDNSKEYsToConsider = 0;
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_too_many_dnskeys)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target(".");
  testkeysset_t dskeys;
  testkeysset_t keys;

  DNSKEYRecordContent dnskeyRecordContent;
  dnskeyRecordContent.d_algorithm = 13;
  /* Generate key material for "." */
  auto dckeDS = DNSCryptoKeyEngine::makeFromISCString(dnskeyRecordContent, R"PKEY(Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Ovj4pzrSh0U6aEVoKaPFhK1D4NMG0xrymj9+6TpwC8o=)PKEY");
  DNSSECPrivateKey dskey;
  dskey.setKey(std::move(dckeDS), 257);
  assert(dskey.getTag() == 31337);
  DSRecordContent drc = makeDSFromDNSKey(target, dskey.getDNSKEY(), DNSSEC::DIGEST_SHA256);
  dskeys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(dskey, drc);

  /* Different key, same tag */
  auto dcke = DNSCryptoKeyEngine::makeFromISCString(dnskeyRecordContent, R"PKEY(Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: n7SRA4n6NejhZBWQOhjTaICYSpkTl6plJn1ATFG23FI=)PKEY");
  DNSSECPrivateKey dpk;
  dpk.setKey(std::move(dcke), 256);
  assert(dpk.getTag() == dskey.getTag());
  DSRecordContent uselessdrc = makeDSFromDNSKey(target, dpk.getDNSKEY(), DNSSEC::DIGEST_SHA256);
  keys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(dpk, uselessdrc);

  /* Set the root DS (one of them!) */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(drc);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys, dskeys](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(dskeys, res->d_records, domain, 300);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    else if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addDNSKEY(dskeys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);
      addRRSIG(dskeys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  g_maxDNSKEYsToConsider = 1;

  /* === with validation enabled === */
  sr->setDNSSECValidationRequested(true);
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidDNSKEY);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidDNSKEY);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  g_maxDNSKEYsToConsider = 0;
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_too_many_dnskeys_while_checking_signature)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target(".");
  testkeysset_t dskeys;
  testkeysset_t keys;
  testkeysset_t otherkeys;

  DNSKEYRecordContent dnskeyRecordContent;
  dnskeyRecordContent.d_algorithm = 13;
  /* Generate key material for "." */
  auto dckeDS = DNSCryptoKeyEngine::makeFromISCString(dnskeyRecordContent, R"PKEY(Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Ovj4pzrSh0U6aEVoKaPFhK1D4NMG0xrymj9+6TpwC8o=)PKEY");
  DNSSECPrivateKey dskey;
  dskey.setKey(std::move(dckeDS), 257);
  assert(dskey.getTag() == 31337);
  DSRecordContent drc = makeDSFromDNSKey(target, dskey.getDNSKEY(), DNSSEC::DIGEST_SHA256);
  dskeys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(dskey, drc);

  /* Different key, same tag */
  auto dcke = DNSCryptoKeyEngine::makeFromISCString(dnskeyRecordContent, R"PKEY(Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: pTaMJcvNrPIIiQiHGvCLZZASroyQpUwew5FvCgjHNsk=)PKEY");
  DNSSECPrivateKey dpk;
  // why 258, you may ask? We need this record to be sorted AFTER the other one in a sortedRecords_t
  // so that the validation of the DNSKEY rrset succeeds
  dpk.setKey(std::move(dcke), 258);
  assert(dpk.getTag() == dskey.getTag());
  DSRecordContent uselessdrc = makeDSFromDNSKey(target, dpk.getDNSKEY(), DNSSEC::DIGEST_SHA256);
  keys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(dpk, uselessdrc);

  /* Set the root DSs (only one of them) */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(drc);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys, dskeys](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300);
      addRRSIG(dskeys, res->d_records, domain, 300);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    else if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(dskeys, domain, 300, res->d_records);
      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(dskeys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  g_maxDNSKEYsToConsider = 1;

  /* === with validation enabled === */
  sr->setDNSSECValidationRequested(true);
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 15U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 15U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  g_maxDNSKEYsToConsider = 0;
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_rrsig_signed_with_unknown_dnskey)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;
  testkeysset_t rrsigkeys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  auto dckeRRSIG = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dckeRRSIG->create(dckeRRSIG->getBits());
  DNSSECPrivateKey rrsigkey;
  rrsigkey.setKey(std::move(dckeRRSIG), 257);
  DSRecordContent rrsigds = makeDSFromDNSKey(target, rrsigkey.getDNSKEY(), DNSSEC::DIGEST_SHA256);

  rrsigkeys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(rrsigkey, rrsigds);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(rrsigkeys, res->d_records, domain, 300);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(rrsigkeys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_no_rrsig)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 86400);
      }

      /* No RRSIG */

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  SyncRes::s_maxcachettl = 86400;
  SyncRes::s_maxbogusttl = 3600;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  /* 13 NS + 0 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 13U);
  /* no RRSIG so no query for DNSKEYs */
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 13U);
  /* check that we capped the TTL to max-cache-bogus-ttl */
  for (const auto& record : ret) {
    BOOST_CHECK_LE(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_no_rrsig_noaa)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      /* We are not setting AA! */
      setLWResult(res, 0, false, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 86400);
      }

      /* No RRSIG */

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  SyncRes::s_maxcachettl = 86400;
  SyncRes::s_maxbogusttl = 3600;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  /* 13 NS + 0 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 13U);
  /* no RRSIG so no query for DNSKEYs */
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 13U);
  /* check that we capped the TTL to max-cache-bogus-ttl */
  for (const auto& record : ret) {
    BOOST_CHECK_LE(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_unknown_ds_algorithm)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  /* Generate key material for "." */
  auto dcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey dpk;
  /* Fake algorithm number (private) */
  dpk.setKey(std::move(dcke), 256, 253);

  DSRecordContent drc = makeDSFromDNSKey(target, dpk.getDNSKEY(), DNSSEC::DIGEST_SHA256);
  keys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(dpk, drc);
  /* Fake algorithm number (private) */
  drc.d_algorithm = 253;

  /* Set the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(drc);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  /* no supported DS so no query for DNSKEYs */
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_unknown_ds_digest)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  /* Generate key material for "." */
  auto dcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.setKey(std::move(dcke), 256);
  DSRecordContent drc = makeDSFromDNSKey(target, dpk.getDNSKEY(), DNSSEC::DIGEST_SHA256);
  /* Fake digest number (reserved) */
  drc.d_digesttype = 0;

  keys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(dpk, drc);

  /* Set the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(drc);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  /* no supported DS so no query for DNSKEYs */
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_bad_sig)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::RSASHA512, DNSSEC::DIGEST_SHA384, keys, luaconfsCopy.dsAnchors);

  g_luaconfs.setState(luaconfsCopy);
  /* make sure that the signature inception and validity times are computed
     based on the SyncRes time, not the current one, in case the function
     takes too long. */
  const time_t fixedNow = sr->getNow().tv_sec;

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300, true, boost::none, boost::none, fixedNow);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, fixedNow);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_too_many_sigs)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::RSASHA512, DNSSEC::DIGEST_SHA384, keys, luaconfsCopy.dsAnchors);

  g_luaconfs.setState(luaconfsCopy);
  /* make sure that the signature inception and validity times are computed
     based on the SyncRes time, not the current one, in case the function
     takes too long. */
  const time_t fixedNow = sr->getNow().tv_sec;

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys, fixedNow](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300, 1, boost::none, boost::none, fixedNow);
      addRRSIG(keys, res->d_records, domain, 300, 2, boost::none, boost::none, fixedNow);
      addRRSIG(keys, res->d_records, domain, 300, 0, boost::none, boost::none, fixedNow);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    else if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, fixedNow);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  g_maxRRSIGsPerRecordToConsider = 2;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 16U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 16U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  g_maxRRSIGsPerRecordToConsider = 0;
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_too_many_sig_validations)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::RSASHA512, DNSSEC::DIGEST_SHA384, keys, luaconfsCopy.dsAnchors);

  g_luaconfs.setState(luaconfsCopy);
  /* make sure that the signature inception and validity times are computed
     based on the SyncRes time, not the current one, in case the function
     takes too long. */
  const time_t fixedNow = sr->getNow().tv_sec;

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys, fixedNow](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      addRRSIG(keys, res->d_records, domain, 300, true, boost::none, boost::none, fixedNow);
      addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, fixedNow);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    else if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, fixedNow);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  SyncRes::s_maxvalidationsperq = 1U;

  vector<DNSRecord> ret;
  BOOST_REQUIRE_THROW(sr->beginResolve(target, QType(QType::NS), QClass::IN, ret), ImmediateServFailException);

  SyncRes::s_maxvalidationsperq = 0U;
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_bad_algo)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::RSASHA512, DNSSEC::DIGEST_SHA384, keys, luaconfsCopy.dsAnchors);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target && type == QType::NS) {

      setLWResult(res, 0, true, false, true);
      char addr[] = "a.root-servers.net.";
      for (char idx = 'a'; idx <= 'm'; idx++) {
        addr[0] = idx;
        addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
      }

      /* FORCE WRONG ALGO */
      addRRSIG(keys, res->d_records, domain, 300, false, DNSSEC::RSASHA256);

      addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_unsigned_ds)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::RSASHA512, DNSSEC::DIGEST_SHA384, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys) == LWResult::Result::Timeout) {
        return LWResult::Result::Timeout;
      }

      if (type == QType::DS && domain == target) {
        /* remove the last record, which is the DS's RRSIG */
        res->d_records.pop_back();
      }

      return LWResult::Result::Success;
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
      /* Include the DS but omit the RRSIG*/
      addDS(DNSName("com."), 300, res->d_records, keys);
      addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, RCode::NoError, true, false, true);
      addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
      addRRSIG(keys, res->d_records, auth, 300);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 3U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 3U);

  /* now we ask directly for the DS */
  ret.clear();
  res = sr->beginResolve(DNSName("com."), QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_unsigned_ds_direct)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::RSASHA512, DNSSEC::DIGEST_SHA384, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys) == LWResult::Result::Timeout) {
        return LWResult::Result::Timeout;
      }

      if (type == QType::DS && domain == target) {
        /* remove the last record, which is the DS's RRSIG */
        res->d_records.pop_back();
      }

      return LWResult::Result::Success;
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
      /* Include the DS but omit the RRSIG*/
      addDS(DNSName("com."), 300, res->d_records, keys);
      addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("com."), QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_SUITE_END()
