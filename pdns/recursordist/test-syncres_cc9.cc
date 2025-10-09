#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc9)

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cname_cache_secure)
{
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Secure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  const DNSName cnameTarget("cname-com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
    }
    {
      if (domain == target && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::CNAME, cnameTarget.toString());
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
      }
      if (domain == cnameTarget && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cname_cache_insecure)
{
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Insecure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  const DNSName cnameTarget("cname-com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
    }
    {
      if (domain == target && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::CNAME, cnameTarget.toString());
        addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
        return LWResult::Result::Success;
      }
      if (domain == cnameTarget && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cname_cache_bogus)
{
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Bogus.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  const DNSName cnameTarget("cname-com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
    }
    {
      if (domain == target && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::CNAME, cnameTarget.toString(), DNSResourceRecord::ANSWER, 86400);
        addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
        /* no RRSIG */
        return LWResult::Result::Success;
      }
      if (domain == cnameTarget && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
        /* no RRSIG */
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  SyncRes::s_maxbogusttl = 60;
  SyncRes::s_maxnegttl = 3600;

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, 86400U);
  }
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  /* check that we correctly capped the TTD for a Bogus record after
     just-in-time validation */
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  ret.clear();
  /* and a third time to make sure that the validation status (and TTL!)
     was properly updated in the cache */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_additional_without_rrsig)
{
  /*
    We get a record from a secure zone in the additional section, without
    the corresponding RRSIG. The record should not be marked as authoritative
    and should be correctly validated.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  const DNSName addTarget("nsX.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == addTarget) {
        DNSName auth(domain);
        /* no DS for com, auth will be . */
        auth.chopOff();
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, false);
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
    }
    {
      if (domain == target && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.1");
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, addTarget, QType::A, "192.0.2.42", DNSResourceRecord::ADDITIONAL);
        /* no RRSIG for the additional record */
        return LWResult::Result::Success;
      }
      if (domain == addTarget && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, addTarget, QType::A, "192.0.2.42");
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  /* first query for target/A, will pick up the additional record as non-auth / unvalidated */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::RRSIG || record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  ret.clear();
  /* ask for the additional record directly, we should not use
     the non-auth one and issue a new query, properly validated */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(addTarget, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::RRSIG || record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_negcache_secure)
{
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is negatively cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Secure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    auth.chopOff();

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }
    {
      setLWResult(res, RCode::NoError, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      addRRSIG(keys, res->d_records, domain, 300);
      addNSECRecordToLW(domain, DNSName("z."), {QType::NSEC, QType::RRSIG}, 600, res->d_records);
      addRRSIG(keys, res->d_records, domain, 1, false, boost::none, boost::none, fixedNow);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
  /* check that the entry has been negatively cached */
  NegCache::NegCacheEntry ne;
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);
  BOOST_REQUIRE_EQUAL(g_negCache->get(target, QType(QType::A), sr->getNow(), ne), true);
  BOOST_CHECK_EQUAL(ne.d_validationState, vState::Indeterminate);
  BOOST_CHECK_EQUAL(ne.authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.authoritySOA.signatures.size(), 1U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.signatures.size(), 1U);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);
  BOOST_REQUIRE_EQUAL(g_negCache->get(target, QType(QType::A), sr->getNow(), ne), true);
  BOOST_CHECK_EQUAL(ne.d_validationState, vState::Secure);
  BOOST_CHECK_EQUAL(ne.authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.authoritySOA.signatures.size(), 1U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.signatures.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_negcache_secure_ds)
{
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is negatively cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Secure.
    The difference with test_dnssec_validation_from_negcache_secure is
    that have one more level here, so we are going to look for the proof
    that the DS does not exist for the last level. Since there is no cut,
    we should accept the fact that the NSEC denies DS and NS both.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("www.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == target) {
        /* there is no cut */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_negcache_insecure)
{
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is negatively cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Insecure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    auth.chopOff();

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }
    {
      setLWResult(res, RCode::NoError, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
  /* check that the entry has not been negatively cached */
  NegCache::NegCacheEntry ne;
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);
  BOOST_REQUIRE_EQUAL(g_negCache->get(target, QType(QType::A), sr->getNow(), ne), true);
  BOOST_CHECK_EQUAL(ne.d_validationState, vState::Indeterminate);
  BOOST_CHECK_EQUAL(ne.authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.authoritySOA.signatures.size(), 0U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.records.size(), 0U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.signatures.size(), 0U);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
  BOOST_REQUIRE_EQUAL(g_negCache->get(target, QType(QType::A), sr->getNow(), ne), true);
  BOOST_CHECK_EQUAL(ne.d_validationState, vState::Insecure);
  BOOST_CHECK_EQUAL(ne.authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.authoritySOA.signatures.size(), 0U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.records.size(), 0U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.signatures.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_negcache_bogus)
{
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is negatively cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Bogus.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    auth.chopOff();

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }
    {
      setLWResult(res, RCode::NoError, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 86400);
      addRRSIG(keys, res->d_records, domain, 86400);
      /* no denial */
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  SyncRes::s_maxbogusttl = 60;
  SyncRes::s_maxnegttl = 3600;
  const auto now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    if (record.d_type == QType::SOA) {
      BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxnegttl);
    }
  }
  BOOST_CHECK_EQUAL(queriesCount, 1U);
  NegCache::NegCacheEntry ne;
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);
  BOOST_REQUIRE_EQUAL(g_negCache->get(target, QType(QType::A), sr->getNow(), ne), true);
  BOOST_CHECK_EQUAL(ne.d_validationState, vState::Indeterminate);
  BOOST_CHECK_EQUAL(ne.authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.authoritySOA.signatures.size(), 1U);
  BOOST_CHECK_EQUAL(ne.d_ttd, now + SyncRes::s_maxnegttl);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.records.size(), 0U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.signatures.size(), 0U);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusInvalidDenial);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);
  BOOST_REQUIRE_EQUAL(g_negCache->get(target, QType(QType::A), sr->getNow(), ne), true);
  BOOST_CHECK_EQUAL(ne.d_validationState, vState::BogusInvalidDenial);
  BOOST_CHECK_EQUAL(ne.authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.authoritySOA.signatures.size(), 1U);
  BOOST_CHECK_EQUAL(ne.d_ttd, now + SyncRes::s_maxbogusttl);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.records.size(), 0U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.signatures.size(), 0U);

  ret.clear();
  /* third one _does_ not require validation, we just check that
     the cache (status and TTL) has been correctly updated */
  sr->setDNSSECValidationRequested(false);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusInvalidDenial);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);
  BOOST_REQUIRE_EQUAL(g_negCache->get(target, QType(QType::A), sr->getNow(), ne), true);
  BOOST_CHECK_EQUAL(ne.d_validationState, vState::BogusInvalidDenial);
  BOOST_CHECK_EQUAL(ne.authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.authoritySOA.signatures.size(), 1U);
  BOOST_CHECK_EQUAL(ne.d_ttd, now + SyncRes::s_maxbogusttl);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.records.size(), 0U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.signatures.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_lowercase_outgoing)
{
  g_lowercaseOutgoing = true;
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  vector<DNSName> sentOutQnames;

  const DNSName target("WWW.POWERDNS.COM");
  const DNSName cname("WWW.PowerDNS.org");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    sentOutQnames.push_back(domain);

    if (isRootServer(address)) {
      if (domain == target) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (domain == cname) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.org.", QType::NS, "pdns-public-ns1.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.org.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
    }
    else if (address == ComboAddress("192.0.2.1:53")) {
      if (domain == target) {
        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::CNAME, cname.toString());
        return LWResult::Result::Success;
      }
    }
    else if (address == ComboAddress("192.0.2.2:53")) {
      if (domain == cname) {
        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "127.0.0.1");
        return LWResult::Result::Success;
      }
    }
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);

  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(ret[0].getContent()->getZoneRepresentation(), cname.toString());

  BOOST_REQUIRE_EQUAL(sentOutQnames.size(), 4U);
  BOOST_CHECK_EQUAL(sentOutQnames[0].toString(), target.makeLowerCase().toString());
  BOOST_CHECK_EQUAL(sentOutQnames[1].toString(), target.makeLowerCase().toString());
  BOOST_CHECK_EQUAL(sentOutQnames[2].toString(), cname.makeLowerCase().toString());
  BOOST_CHECK_EQUAL(sentOutQnames[3].toString(), cname.makeLowerCase().toString());

  g_lowercaseOutgoing = false;
}

BOOST_AUTO_TEST_CASE(test_getDSRecords_multialgo)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys, keys2;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  // As testkeysset_t only contains one DSRecordContent, create another one with a different hash algo
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA1, keys2);
  // But add the existing root key otherwise no RRSIG can be created
  auto rootkey = keys.find(g_rootdnsname);
  keys2.insert(*rootkey);

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    DNSName auth = domain;
    auth.chopOff();
    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == target) {
        if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys2) != LWResult::Result::Success) {
          return LWResult::Result::Timeout;
        }
      }
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }
    return LWResult::Result::Timeout;
  });

  dsset_t dsSet;
  auto state = sr->getDSRecords(target, dsSet, false, 0, "", false);
  BOOST_CHECK_EQUAL(state, vState::Secure);
  BOOST_REQUIRE_EQUAL(dsSet.size(), 1U);
  for (const auto& dsRecord : dsSet) {
    BOOST_CHECK_EQUAL(dsRecord.d_digesttype, DNSSEC::DIGEST_SHA256);
  }
}

BOOST_AUTO_TEST_CASE(test_getDSRecords_multialgo_all_sha)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys, keys2, keys3;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  // As testkeysset_t only contains one DSRecordContent, create another one with a different hash algo
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA1, keys2);
  // But add the existing root key otherwise no RRSIG can be created
  auto rootkey = keys.find(g_rootdnsname);
  keys2.insert(*rootkey);

  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA384, keys3);
  // But add the existing root key otherwise no RRSIG can be created
  keys3.insert(*rootkey);

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    DNSName auth = domain;
    auth.chopOff();
    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == target) {
        if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys2) != LWResult::Result::Success) {
          return LWResult::Result::Timeout;
        }
        if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys3) != LWResult::Result::Success) {
          return LWResult::Result::Timeout;
        }
      }
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }
    return LWResult::Result::Timeout;
  });

  dsset_t dsSet;
  auto state = sr->getDSRecords(target, dsSet, false, 0, "", false);
  BOOST_CHECK_EQUAL(state, vState::Secure);
  BOOST_REQUIRE_EQUAL(dsSet.size(), 2U);
  for (const auto& dsRecord : dsSet) {
    BOOST_CHECK(dsRecord.d_digesttype == DNSSEC::DIGEST_SHA384 || dsRecord.d_digesttype == DNSSEC::DIGEST_SHA256);
  }
}

BOOST_AUTO_TEST_CASE(test_getDSRecords_multialgo_two_highest)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys, keys2, keys3;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  // As testkeysset_t only contains one DSRecordContent, create another one with a different hash algo
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys2);
  // But add the existing root key otherwise no RRSIG can be created
  auto rootkey = keys.find(g_rootdnsname);
  keys2.insert(*rootkey);

  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA1, keys3);
  // But add the existing root key otherwise no RRSIG can be created
  keys3.insert(*rootkey);

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    DNSName auth = domain;
    auth.chopOff();
    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == target) {
        if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys2) != LWResult::Result::Success) {
          return LWResult::Result::Timeout;
        }
        if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys3) != LWResult::Result::Success) {
          return LWResult::Result::Timeout;
        }
      }
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }
    return LWResult::Result::Timeout;
  });

  dsset_t dsSet;
  auto state = sr->getDSRecords(target, dsSet, false, 0, "", false);
  BOOST_CHECK_EQUAL(state, vState::Secure);
  BOOST_REQUIRE_EQUAL(dsSet.size(), 2U);
  for (const auto& dsRecord : dsSet) {
    BOOST_CHECK_EQUAL(dsRecord.d_digesttype, DNSSEC::DIGEST_SHA256);
  }
}

BOOST_AUTO_TEST_CASE(test_cname_plus_authority_ns_ttl)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cname.powerdns.com.");
  const DNSName cnameTarget("cname-target.powerdns.com");
  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, DNSName("powerdns.com"), QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 42);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53")) {
      if (domain == target) {
        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
        addRecordToLW(res, cnameTarget, QType::A, "192.0.2.2");
        addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, DNSName("a.gtld-servers.net."), QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (domain == cnameTarget) {
        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[1].d_name, cnameTarget);

  /* check that the NS in authority has not replaced the one in the cache
     with auth=0 (or at least has not raised the TTL since it could otherwise
     be used to create a never-ending ghost zone even after the NS have been
     changed in the parent.
  */
  const ComboAddress who;
  vector<DNSRecord> cached;
  bool wasAuth = false;

  auto ttl = g_recCache->get(now, DNSName("powerdns.com."), QType(QType::NS), MemRecursorCache::None, &cached, who, boost::none, nullptr, nullptr, nullptr, nullptr, &wasAuth);
  BOOST_REQUIRE_GE(ttl, 1);
  BOOST_REQUIRE_LE(ttl, 42);
  BOOST_CHECK_EQUAL(cached.size(), 1U);
  BOOST_CHECK_EQUAL(wasAuth, false);

  cached.clear();

  /* Also check that the the part in additional is still not auth */
  BOOST_REQUIRE_GE(g_recCache->get(now, DNSName("a.gtld-servers.net."), QType(QType::A), MemRecursorCache::None, &cached, who, boost::none, nullptr, nullptr, nullptr, nullptr, &wasAuth), -1);
  BOOST_CHECK_EQUAL(cached.size(), 1U);
  BOOST_CHECK_EQUAL(wasAuth, false);
}

BOOST_AUTO_TEST_CASE(test_bogus_does_not_replace_secure_in_the_cache)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();

  testkeysset_t keys;
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == DNSName("cname.powerdns.com.")) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false /* no cut */);
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
      addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
      addRRSIG(keys, res->d_records, DNSName("com."), 300);
      addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    {
      setLWResult(res, 0, true, false, true);
      if (domain == DNSName("powerdns.com.") && type == QType::A) {
        addRecordToLW(res, domain, QType::A, "192.0.2.1");
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        addRecordToLW(res, domain, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
      }
      else if (domain == DNSName("powerdns.com.") && type == QType::AAAA) {
        addRecordToLW(res, domain, QType::AAAA, "2001:db8::1");
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        addRecordToLW(res, domain, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY);
        /* no RRSIG this time! */
      }

      return LWResult::Result::Success;
    }
  });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 2U);

  const ComboAddress who;
  vector<DNSRecord> cached;
  bool wasAuth = false;
  vState retrievedState = vState::Insecure;
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("powerdns.com."), QType(QType::SOA), MemRecursorCache::RequireAuth, &cached, who, boost::none, nullptr, nullptr, nullptr, &retrievedState, &wasAuth), 0);
  BOOST_CHECK_EQUAL(vStateToString(retrievedState), vStateToString(vState::Secure));
  BOOST_CHECK_EQUAL(wasAuth, true);

  ret.clear();
  res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);

  cached.clear();
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("powerdns.com."), QType(QType::SOA), MemRecursorCache::RequireAuth, &cached, who, boost::none, nullptr, nullptr, nullptr, &retrievedState, &wasAuth), 0);
  BOOST_CHECK_EQUAL(vStateToString(retrievedState), vStateToString(vState::Secure));
  BOOST_CHECK_EQUAL(wasAuth, true);
}

BOOST_AUTO_TEST_CASE(test_records_sanitization_general)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("sanitization.powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, domain, QType::A, "192.0.2.1");
    /* should be scrubbed because it doesn't match the QType */
    addRecordToLW(res, domain, QType::AAAA, "2001:db8::1");
    /* should be scrubbed because the DNAME is not relevant to the qname */
    addRecordToLW(res, DNSName("not-sanitization.powerdns.com."), QType::DNAME, "not-sanitization.powerdns.net.");
    /* should be scrubbed because a MX has no reason to show up in AUTHORITY */
    addRecordToLW(res, domain, QType::MX, "10 mx.powerdns.com.", DNSResourceRecord::AUTHORITY);
    /* should be scrubbed because the SOA name is not relevant to the qname */
    addRecordToLW(res, DNSName("not-sanitization.powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY);
    /* should be scrubbed because types other than A or AAAA are not really supposed to show up in ADDITIONAL */
    addRecordToLW(res, domain, QType::TXT, "TXT", DNSResourceRecord::ADDITIONAL);
    /* should be scrubbed because it doesn't match any of the accepted names in this answer (mostly 'domain') */
    addRecordToLW(res, DNSName("powerdns.com."), QType::AAAA, "2001:db8::1", DNSResourceRecord::ADDITIONAL);
    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);

  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_CHECK_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  cached.clear();
  BOOST_CHECK_LT(g_recCache->get(now, target, QType(QType::AAAA), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_CHECK_EQUAL(g_recCache->get(now, DNSName("not-sanitization.powerdns.com."), QType(QType::DNAME), MemRecursorCache::RequireAuth, &cached, who), -1);
  BOOST_CHECK_LT(g_recCache->get(now, target, QType(QType::MX), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_CHECK_EQUAL(g_recCache->get(now, DNSName("not-sanitization.powerdns.com."), QType(QType::SOA), MemRecursorCache::RequireAuth, &cached, who), -1);
  BOOST_CHECK_LT(g_recCache->get(now, target, QType(QType::TXT), MemRecursorCache::None, &cached, who), 0);
  BOOST_CHECK_EQUAL(g_recCache->get(now, DNSName("powerdns.com."), QType(QType::AAAA), MemRecursorCache::None, &cached, who), -1);
}

BOOST_AUTO_TEST_CASE(test_records_sanitization_keep_relevant_additional_aaaa)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("sanitization.powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, domain, QType::A, "192.0.2.1");
    addRecordToLW(res, domain, QType::AAAA, "2001:db8::1", DNSResourceRecord::ADDITIONAL);
    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);

  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_CHECK_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  cached.clear();
  /* not auth since it was in the additional section */
  BOOST_CHECK_LT(g_recCache->get(now, target, QType(QType::AAAA), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_CHECK_GT(g_recCache->get(now, target, QType(QType::AAAA), MemRecursorCache::None, &cached, who), 0);
}

BOOST_AUTO_TEST_CASE(test_records_sanitization_keep_glue)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("sanitization-glue.powerdns.com.");

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "powerdns.com.", QType::DS, "1 8 2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAA", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53") || address == ComboAddress("192.0.2.3:53") || address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("[2001:DB8::3]:53")) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.4");
      addRecordToLW(res, "powerdns.com.", QType::DS, "2 8 2 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB BBBBBBBB", DNSResourceRecord::AUTHORITY);
      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
  });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 3U);

  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_CHECK_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  cached.clear();

  BOOST_CHECK_GT(g_recCache->get(now, DNSName("com."), QType(QType::NS), MemRecursorCache::None, &cached, who), 0);
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("a.gtld-servers.net."), QType(QType::A), MemRecursorCache::None, &cached, who), 0);
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("a.gtld-servers.net."), QType(QType::AAAA), MemRecursorCache::None, &cached, who), 0);
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("powerdns.com."), QType(QType::NS), MemRecursorCache::None, &cached, who), 0);
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("pdns-public-ns1.powerdns.com."), QType(QType::A), MemRecursorCache::None, &cached, who), 0);
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("pdns-public-ns1.powerdns.com."), QType(QType::AAAA), MemRecursorCache::None, &cached, who), 0);
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("pdns-public-ns2.powerdns.com."), QType(QType::A), MemRecursorCache::None, &cached, who), 0);
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("pdns-public-ns2.powerdns.com."), QType(QType::AAAA), MemRecursorCache::None, &cached, who), 0);

  cached.clear();
  /* check that we accepted the DS from the parent, and not from the child zone */
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("powerdns.com."), QType(QType::DS), MemRecursorCache::None, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_CHECK_EQUAL(cached.at(0).getContent()->getZoneRepresentation(), "1 8 2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

BOOST_AUTO_TEST_CASE(test_records_sanitization_scrubs_ns_nxd)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("sanitization-ns-nxd.powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    setLWResult(res, RCode::NXDomain, true, false, true);
    addRecordToLW(res, "powerdns.com.", QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, "powerdns.com.", QType::NS, "spoofed.ns.", DNSResourceRecord::AUTHORITY, 172800);
    addRecordToLW(res, "spoofed.ns.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
    addRecordToLW(res, "spoofed.ns.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("powerdns.com."), QType(QType::SOA), MemRecursorCache::RequireAuth, &cached, who), 0);
  cached.clear();

  BOOST_CHECK_LT(g_recCache->get(now, DNSName("powerdns.com."), QType(QType::NS), MemRecursorCache::None, &cached, who), 0);
  BOOST_CHECK_LT(g_recCache->get(now, DNSName("spoofed.ns."), QType(QType::A), MemRecursorCache::None, &cached, who), 0);
  BOOST_CHECK_LT(g_recCache->get(now, DNSName("spoofed.ns."), QType(QType::AAAA), MemRecursorCache::None, &cached, who), 0);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_referral_on_ds_query_insecure)
{
  /*
    The server at ds-ignorant.com sends a referral to the child zone
    on a ds-ignorant.com DS query. ds-ignorant.com is unsigned,
    signed.ds-ignorant.com is somehow signed, but no TA.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("signed.ds-ignorant.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("signed.ds-ignorant.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain.isPartOf(DNSName("signed.ds-ignorant.com.")) && address == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "signed.ds-ignorant.com.", QType::NS, "ns.signed.ds-ignorant.com.", DNSResourceRecord::AUTHORITY, 3600);
      addRecordToLW(res, "ns.signed.ds-ignorant.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (type == QType::DNSKEY || (type == QType::DS && domain != target)) {
      DNSName auth(domain);
      auth.chopOff();
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, false);
    }
    {
      if (domain.isPartOf(DNSName("ds-ignorant.com.")) && isRootServer(address)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "ds-ignorant.com.", QType::NS, "ns.ds-ignorant.com.", DNSResourceRecord::AUTHORITY, 3600);
        /* no DS, insecure */
        addNSECRecordToLW(DNSName("ds-ignorant.com."), DNSName("ds-ignorant1.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "ns.ds-ignorant.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (domain == target) {
        if (type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::A, "192.0.2.200");
          addRRSIG(keys, res->d_records, domain, 300);
          return LWResult::Result::Success;
        }
        if (type == QType::DS) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "signed.ds-ignorant.com. admin\\.signed.ds-ignorant.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, domain, 300);
          addNSECRecordToLW(domain, DNSName("z.signed.ds-ignorant.com."), {QType::A, QType::SOA, QType::NSEC}, 600, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK(ret.at(1).d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK(ret.at(1).d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_referral_on_ds_query_secure)
{
  /*
    The server at ds-ignorant.com sends a referral to the child zone
    on a ds-ignorant.com DS query. ds-ignorant.com is signed,
    signed.ds-ignorant.com as well.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("signed.ds-ignorant.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("ds-ignorant.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("signed.ds-ignorant.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain.isPartOf(DNSName("signed.ds-ignorant.com.")) && address == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "signed.ds-ignorant.com.", QType::NS, "ns.signed.ds-ignorant.com.", DNSResourceRecord::AUTHORITY, 3600);
      addRecordToLW(res, "ns.signed.ds-ignorant.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (type == QType::DNSKEY || (type == QType::DS && domain != target)) {
      DNSName auth(domain);
      auth.chopOff();
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, false);
    }
    else {
      if (domain.isPartOf(DNSName("ds-ignorant.com.")) && isRootServer(address)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "ds-ignorant.com.", QType::NS, "ns.ds-ignorant.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("ds-ignorant.com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "ns.ds-ignorant.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (domain == target) {
        if (type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::A, "192.0.2.200");
          addRRSIG(keys, res->d_records, domain, 300);
          return LWResult::Result::Success;
        }
        if (type == QType::DS) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "signed.ds-ignorant.com. admin\\.signed.ds-ignorant.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, domain, 300);
          addNSECRecordToLW(domain, DNSName("z.signed.ds-ignorant.com."), {QType::A, QType::SOA, QType::NSEC}, 600, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusMissingNegativeIndication);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK(ret.at(1).d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusMissingNegativeIndication);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK(ret.at(1).d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_SUITE_END()
