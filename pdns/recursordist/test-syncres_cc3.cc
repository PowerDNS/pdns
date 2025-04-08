#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc3)

BOOST_AUTO_TEST_CASE(test_cache_auth)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* the auth server is sending the same answer in answer and additional,
     check that we only return one result, and we only cache one too. */
  const DNSName target("cache-auth.powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);
    addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 10);

    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_REQUIRE_EQUAL(QType(ret.at(0).d_type).toString(), QType(QType::A).toString());
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret.at(0))->getCA().toString(), ComboAddress("192.0.2.2").toString());

  /* check that we correctly cached only the answer entry, not the additional one */
  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_EQUAL(QType(cached.at(0).d_type).toString(), QType(QType::A).toString());
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(cached.at(0))->getCA().toString(), ComboAddress("192.0.2.2").toString());
}

BOOST_AUTO_TEST_CASE(test_unauth_any)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53")) {
      if (type == QType::A) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        addRecordToLW(res, domain, QType::A, "192.0.2.43");
        return LWResult::Result::Success;
      }
      if (type == QType::AAAA) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::AAAA, "::1");
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 2U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  ret.clear();
  MemRecursorCache::s_maxRRSetSize = 2;
  BOOST_CHECK_THROW(sr->beginResolve(target, QType(QType::ANY), QClass::IN, ret), ImmediateServFailException);

  MemRecursorCache::s_limitQTypeAny = false;
  ret.clear();
  res = sr->beginResolve(target, QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 3U);
}

static void test_no_data_f(bool qmin)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  if (qmin)
    sr->setQNameMinimization();

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback(
    [&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */,
        struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */,
        LWResult* res, bool* /* chained */) {
      setLWResult(res, 0, true, false, true);
      return LWResult::Result::Success;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_no_data)
{
  test_no_data_f(false);
}

BOOST_AUTO_TEST_CASE(test_no_data_qmin)
{
  test_no_data_f(true);
}

BOOST_AUTO_TEST_CASE(test_extra_answers)
{
  // Test extra records in the answer section
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");
  const DNSName target2("www2.powerdns.com."); // in bailiwick, but not asked for
  const DNSName target3("www.random.net."); // out of bailiwick and not asked for

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }

    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);
    addRecordToLW(res, target2, QType::A, "192.0.2.3", DNSResourceRecord::ANSWER, 10);
    addRecordToLW(res, target3, QType::A, "192.0.2.4", DNSResourceRecord::ANSWER, 10);

    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;

  // we should only see a single record for the question we asked
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_REQUIRE_EQUAL(QType(ret.at(0).d_type).toString(), QType(QType::A).toString());
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret.at(0))->getCA().toString(), ComboAddress("192.0.2.2").toString());

  // Also check the cache
  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_EQUAL(QType(cached.at(0).d_type).toString(), QType(QType::A).toString());
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(cached.at(0))->getCA().toString(), ComboAddress("192.0.2.2").toString());

  // The cache should not have an authoritative record for the extra in-bailiwick record
  BOOST_REQUIRE_LE(g_recCache->get(now, target2, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);

  // And the out-of-bailiwick record should not be there
  BOOST_REQUIRE_LE(g_recCache->get(now, target3, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
}

BOOST_AUTO_TEST_CASE(test_dnssec_extra_answers)
{
  // Test extra records in the answer section
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.powerdns.com.");
  const DNSName target2("www2.powerdns.com."); // in bailiwick, but not asked for
  const DNSName target3("www.random.net."); // out of bailiwick and not asked for
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com"), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
    }
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRRSIG(keys, res->d_records, DNSName("."), 300);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }

    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);
    addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
    addRecordToLW(res, target2, QType::A, "192.0.2.3", DNSResourceRecord::ANSWER, 10);
    addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
    addRecordToLW(res, target3, QType::A, "192.0.2.4", DNSResourceRecord::ANSWER, 10);

    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;

  // we should only see a single record for the question we asked
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(QType(ret.at(0).d_type).toString(), QType(QType::A).toString());
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret.at(0))->getCA().toString(), ComboAddress("192.0.2.2").toString());

  // Also check the cache
  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_EQUAL(QType(cached.at(0).d_type).toString(), QType(QType::A).toString());
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(cached.at(0))->getCA().toString(), ComboAddress("192.0.2.2").toString());

  // The cache should not have an authoritative record for the extra in-bailiwick record
  BOOST_REQUIRE_LE(g_recCache->get(now, target2, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);

  // And the out-of-bailiwick record should not be there
  BOOST_REQUIRE_LE(g_recCache->get(now, target3, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
}

BOOST_AUTO_TEST_CASE(test_skip_opt_any)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, domain, QType::A, "192.0.2.42");
    addRecordToLW(res, domain, QType::ANY, "\\# 0");
    addRecordToLW(res, domain, QType::OPT, "");
    return LWResult::Result::Success;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_nodata_nsec_nodnssec)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
    /* the NSEC and RRSIG contents are complete garbage, please ignore them */
    addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
    return LWResult::Result::Success;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_nodata_nsec_dnssec)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
    /* the NSEC and RRSIG contents are complete garbage, please ignore them */
    addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
    return LWResult::Result::Success;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 4U);
}

BOOST_AUTO_TEST_CASE(test_nx_nsec_nodnssec)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    setLWResult(res, RCode::NXDomain, true, false, true);
    addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
    /* the NSEC and RRSIG contents are complete garbage, please ignore them */
    addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
    return LWResult::Result::Success;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_nx_nsec_dnssec)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    setLWResult(res, RCode::NXDomain, true, false, true);
    addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
    /* the NSEC and RRSIG contents are complete garbage, please ignore them */
    addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
    return LWResult::Result::Success;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 4U);
}

BOOST_AUTO_TEST_CASE(test_qclass_none)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* apart from special names and QClass::ANY, anything else than QClass::IN should be rejected right away */
  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    queriesCount++;
    return LWResult::Result::Timeout;
  });

  const DNSName target("powerdns.com.");
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::NONE, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_answer_no_aa)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    setLWResult(res, 0, false, false, true);
    addRecordToLW(res, domain, QType::A, "192.0.2.1");
    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  /* check that the record in the answer section has not been cached */
  const ComboAddress who;
  vector<DNSRecord> cached;
  vector<std::shared_ptr<const RRSIGRecordContent>> signatures;
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::None, &cached, who, boost::none, &signatures), 0);
}

BOOST_AUTO_TEST_CASE(test_special_types)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* {A,I}XFR, RRSIG and NSEC3 should be rejected right away */
  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    cerr << "asyncresolve called to ask " << address.toStringWithPort() << " about " << domain.toString() << " / " << QType(type).toString() << " over " << (doTCP ? "TCP" : "UDP") << " (rd: " << sendRDQuery << ", EDNS0 level: " << EDNS0Level << ")" << endl;
    queriesCount++;
    return LWResult::Result::Timeout;
  });

  const DNSName target("powerdns.com.");
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::AXFR), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  res = sr->beginResolve(target, QType(QType::IXFR), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  res = sr->beginResolve(target, QType(QType::RRSIG), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  res = sr->beginResolve(target, QType(QType::NSEC3), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_special_names)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* special names should be handled internally */

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    queriesCount++;
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("1.0.0.127.in-addr.arpa."), QType(QType::PTR), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("1.0.0.127.in-addr.arpa."), QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."), QType(QType::PTR), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."), QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("localhost."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toString(), "127.0.0.1");
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("localhost."), QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::AAAA);
  BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(ret[0])->getCA().toString(), "::1");
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("localhost."), QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& rec : ret) {
    BOOST_REQUIRE((rec.d_type == QType::A) || rec.d_type == QType::AAAA);
    if (rec.d_type == QType::A) {
      BOOST_CHECK_EQUAL(getRR<ARecordContent>(rec)->getCA().toString(), "127.0.0.1");
    }
    else {
      BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(rec)->getCA().toString(), "::1");
    }
  }
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("version.bind."), QType(QType::TXT), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("version.bind."), QType(QType::ANY), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("version.pdns."), QType(QType::TXT), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("version.pdns."), QType(QType::ANY), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("id.server."), QType(QType::TXT), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests Server ID\"");
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(DNSName("id.server."), QType(QType::ANY), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests Server ID\"");
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_nameserver_ipv4_rpz)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, false, true, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ns) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  DNSFilterEngine::Policy pol;
  pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
  std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName("Unit test policy 0");
  zone->addNSIPTrigger(Netmask(ns, 32), std::move(pol));
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.clearZones();
  luaconfsCopy.dfe.addZone(zone);
  g_luaconfs.setState(luaconfsCopy);

  vector<DNSRecord> ret;
  BOOST_CHECK_THROW(sr->beginResolve(target, QType(QType::A), QClass::IN, ret), PolicyHitException);
}

BOOST_AUTO_TEST_CASE(test_nameserver_ipv6_rpz)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("[2001:DB8::42]:53");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ns) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  DNSFilterEngine::Policy pol;
  pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
  std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName("Unit test policy 0");
  zone->addNSIPTrigger(Netmask(ns, 128), std::move(pol));
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.clearZones();
  luaconfsCopy.dfe.addZone(zone);
  g_luaconfs.setState(luaconfsCopy);

  vector<DNSRecord> ret;
  BOOST_CHECK_THROW(sr->beginResolve(target, QType(QType::A), QClass::IN, ret), PolicyHitException);
}

BOOST_AUTO_TEST_CASE(test_nameserver_name_rpz)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const DNSName nsName("ns1.powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, nsName.toString(), DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, nsName, QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ns) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  DNSFilterEngine::Policy pol;
  pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
  std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName("Unit test policy 0");
  zone->addNSTrigger(nsName, std::move(pol));
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.clearZones();
  luaconfsCopy.dfe.addZone(zone);
  g_luaconfs.setState(luaconfsCopy);

  vector<DNSRecord> ret;
  BOOST_CHECK_THROW(sr->beginResolve(target, QType(QType::A), QClass::IN, ret), PolicyHitException);
}

BOOST_AUTO_TEST_CASE(test_nameserver_name_rpz_disabled)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const DNSName nsName("ns1.powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, nsName.toString(), DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, nsName, QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ns) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  DNSFilterEngine::Policy pol;
  pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
  std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName("Unit test policy 0");
  zone->addNSIPTrigger(Netmask(ns, 128), DNSFilterEngine::Policy(pol));
  zone->addNSTrigger(nsName, std::move(pol));
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.clearZones();
  luaconfsCopy.dfe.addZone(zone);
  g_luaconfs.setState(luaconfsCopy);

  /* RPZ is disabled for this query, we should not be blocked */
  sr->setWantsRPZ(false);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_nord)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = false;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[target] = ad;

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool sendRDQuery, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    ++queriesCount;
    if (address == forwardedNS) {
      BOOST_CHECK_EQUAL(sendRDQuery, false);

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  BOOST_CHECK_EQUAL(queriesCount, 0U);
  /* simulate a no-RD query */
  sr->setCacheOnly();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  /* simulate a RD query */
  sr->setCacheOnly(false);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* simulate a no-RD query */
  sr->setCacheOnly();

  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_rd)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  size_t queriesCount = 0;
  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[target] = ad;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool sendRDQuery, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (address == forwardedNS) {
      BOOST_CHECK_EQUAL(sendRDQuery, true);

      /* set AA=0, we are a recursor */
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* now make sure we can resolve from the cache (see #6340
     where the entries were added to the cache but not retrieved,
     because the recursor doesn't set the AA bit and we require
     it. We fixed it by not requiring the AA bit for forward-recurse
     answers. */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_nord)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[target] = ad;

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool sendRDQuery, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    ++queriesCount;
    if (address == forwardedNS) {
      BOOST_CHECK_EQUAL(sendRDQuery, true);

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  BOOST_CHECK_EQUAL(queriesCount, 0U);
  /* simulate a no-RD query */
  sr->setCacheOnly();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  /* simulate a RD query */
  sr->setCacheOnly(false);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* simulate a no-RD query */
  sr->setCacheOnly();

  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[target] = ad;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool sendRDQuery, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (address == forwardedNS) {
      BOOST_CHECK_EQUAL(sendRDQuery, true);

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd_dnssec)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* signed */
  const DNSName target("test.");
  /* unsigned */
  const DNSName cnameTarget("cname.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  const ComboAddress forwardedNS("192.0.2.42:53");
  size_t queriesCount = 0;

  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[g_rootdnsname] = ad;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool sendRDQuery, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    BOOST_CHECK_EQUAL(sendRDQuery, true);

    if (address != forwardedNS) {
      return LWResult::Result::Timeout;
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys);
    }

    if (domain == target && type == QType::A) {

      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, target, QType::CNAME, cnameTarget.toString());
      addRRSIG(keys, res->d_records, domain, 300);
      addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");

      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_nord_dnssec)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* signed */
  const DNSName parent("test.");
  const DNSName target1("a.test.");
  const DNSName target2("b.test.");

  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("test."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  const ComboAddress forwardedNS("192.0.2.42:53");
  size_t queriesCount = 0;
  size_t DSforParentCount = 0;

  SyncRes::AuthDomain ad;
  ad.d_rdForward = false;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[DNSName("test.")] = ad;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool sendRDQuery, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    BOOST_CHECK_EQUAL(sendRDQuery, false);

    if (type == QType::DS && domain == parent) {
      DSforParentCount++;
    }
    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != parent && domain.isPartOf(parent)) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false /* no cut / delegation */);
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, parent, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 42);
      addRRSIG(keys, res->d_records, g_rootdnsname, 300);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
    }

    if (address != forwardedNS) {
      return LWResult::Result::Timeout;
    }

    if (domain == target1 && type == QType::A) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target1, QType::A, "192.0.2.1");
      addRRSIG(keys, res->d_records, parent, 300);

      return LWResult::Result::Success;
    }
    if (domain == target2 && type == QType::A) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target2, QType::A, "192.0.2.2");
      addRRSIG(keys, res->d_records, parent, 300);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
  BOOST_CHECK_EQUAL(DSforParentCount, 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
  BOOST_CHECK_EQUAL(DSforParentCount, 1U);

  /* new target should not cause a DS query for test. */
  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
  BOOST_CHECK_EQUAL(DSforParentCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd_dnssec_bogus)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* signed */
  const DNSName target("test.");
  /* signed */
  const DNSName cnameTarget("cname.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(cnameTarget, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  const ComboAddress forwardedNS("192.0.2.42:53");
  size_t queriesCount = 0;

  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[g_rootdnsname] = ad;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool sendRDQuery, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    BOOST_CHECK_EQUAL(sendRDQuery, true);

    if (address != forwardedNS) {
      return LWResult::Result::Timeout;
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys);
    }

    if (domain == target && type == QType::A) {

      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, target, QType::CNAME, cnameTarget.toString());
      addRRSIG(keys, res->d_records, domain, 300);
      addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
      /* no RRSIG in a signed zone, Bogus ! */

      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd_dnssec_nodata_bogus)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  const ComboAddress forwardedNS("192.0.2.42:53");
  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[g_rootdnsname] = ad;

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool sendRDQuery, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    BOOST_CHECK_EQUAL(sendRDQuery, true);

    if (address != forwardedNS) {
      return LWResult::Result::Timeout;
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }

    setLWResult(res, 0, false, false, true);
    return LWResult::Result::Success;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusMissingNegativeIndication);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* com|NS, powerdns.com|NS, powerdns.com|A */
  BOOST_CHECK_EQUAL(queriesCount, 3U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusMissingNegativeIndication);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* we don't store empty results */
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd_dnssec_cname_wildcard_expanded)
{
  std::unique_ptr<SyncRes> testSR;
  initSR(testSR, true);

  setDNSSECValidation(testSR, DNSSECMode::ValidateAll);

  primeHints();
  /* unsigned */
  const DNSName target("test.");
  /* signed */
  const DNSName cnameTarget("cname.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(cnameTarget, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  const ComboAddress forwardedNS("192.0.2.42:53");
  size_t queriesCount = 0;

  SyncRes::AuthDomain authDomain;
  authDomain.d_rdForward = true;
  authDomain.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[g_rootdnsname] = authDomain;

  testSR->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool sendRDQuery, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    BOOST_CHECK_EQUAL(sendRDQuery, true);

    if (address != forwardedNS) {
      return LWResult::Result::Timeout;
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys);
    }

    if (domain == target && type == QType::A) {

      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, target, QType::CNAME, cnameTarget.toString());
      addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
      /* the RRSIG proves that the cnameTarget was expanded from a wildcard */
      addRRSIG(keys, res->d_records, cnameTarget, 300, false, boost::none, DNSName("*"));
      /* we need to add the proof that this name does not exist, so the wildcard may apply */
      addNSECRecordToLW(DNSName("cnamd."), DNSName("cnamf."), {QType::A, QType::NSEC, QType::RRSIG}, 60, res->d_records);
      addRRSIG(keys, res->d_records, cnameTarget, 300);

      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = testSR->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(testSR->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 5U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = testSR->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(testSR->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 5U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_oob)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("test.xx.");
  const ComboAddress targetAddr("127.0.0.1");
  const DNSName authZone("test.xx");

  SyncRes::AuthDomain ad;
  DNSRecord dr;

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::A;
  dr.d_ttl = 1800;
  dr.setContent(std::make_shared<ARecordContent>(targetAddr));
  ad.d_records.insert(dr);

  (*SyncRes::t_sstorage.domainmap)[authZone] = ad;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    queriesCount++;
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);

  /* a second time, to check that the OOB flag is set when the query cache is used */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);

  /* a third time, to check that the validation is disabled when the OOB flag is set */
  ret.clear();
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_oob_cname)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("cname.test.xx.");
  const DNSName targetCname("cname-target.test.xx.");
  const ComboAddress targetCnameAddr("127.0.0.1");
  const DNSName authZone("test.xx");

  SyncRes::AuthDomain ad;
  DNSRecord dr;

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::CNAME;
  dr.d_ttl = 1800;
  dr.setContent(std::make_shared<CNAMERecordContent>(targetCname));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = targetCname;
  dr.d_type = QType::A;
  dr.d_ttl = 1800;
  dr.setContent(std::make_shared<ARecordContent>(targetCnameAddr));
  ad.d_records.insert(dr);

  (*SyncRes::t_sstorage.domainmap)[authZone] = ad;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    queriesCount++;
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);

  /* a second time, to check that the OOB flag is set when the query cache is used */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);

  /* a third time, to check that the validation is disabled when the OOB flag is set */
  ret.clear();
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
}

BOOST_AUTO_TEST_CASE(test_auth_cname_to_oob_target)
{
  std::unique_ptr<SyncRes> resolver;
  initSR(resolver, false, false);

  resolver->setQNameMinimization();
  primeHints();

  size_t queriesCount = 0;
  const DNSName target("cname.example.com.");
  const DNSName existingname("existing.test.xx.");
  const DNSName target1Cname("cname1.example.com.");
  const DNSName authZone("test.xx");

  SyncRes::AuthDomain authDomain;

  DNSRecord record;
  record.d_place = DNSResourceRecord::ANSWER;
  record.d_name = existingname;
  record.d_type = QType::A;
  record.d_ttl = 1800;
  record.setContent(std::make_shared<ARecordContent>("127.0.0.1"));
  authDomain.d_records.insert(record);

  (*SyncRes::t_sstorage.domainmap)[authZone] = authDomain;

  resolver->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;
    if (isRootServer(address) || domain == DNSName("com") || domain == DNSName("example.com")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (domain == target) {
      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::CNAME, target1Cname.toString());
      return LWResult::Result::Success;
    }
    if (domain == target1Cname) {
      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::CNAME, existingname.toString());
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = resolver->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::Indeterminate);

  /* a second time, from the cache */
  ret.clear();
  res = resolver->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::Indeterminate);
}

BOOST_AUTO_TEST_CASE(test_auth_cname_to_non_existent_oob_target)
{
  std::unique_ptr<SyncRes> resolver;
  initSR(resolver, false, false);

  resolver->setQNameMinimization();
  primeHints();

  const DNSName target("cname.example.com.");
  const DNSName existingname("existing.test.xx.");
  const DNSName target1Cname("cname1.example.com.");
  const DNSName target2Cname("cname-target.test.xx.");
  const DNSName authZone("test.xx");

  SyncRes::AuthDomain authDomain;

  DNSRecord record;
  record.d_place = DNSResourceRecord::ANSWER;
  record.d_name = existingname;
  record.d_type = QType::A;
  record.d_ttl = 1800;
  record.setContent(std::make_shared<ARecordContent>("127.0.0.1"));
  authDomain.d_records.insert(record);

  (*SyncRes::t_sstorage.domainmap)[authZone] = authDomain;

  resolver->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address) || domain == DNSName("com") || domain == DNSName("example.com")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (domain == target) {
      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::CNAME, target1Cname.toString());
      return LWResult::Result::Success;
    }
    if (domain == target1Cname) {
      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::CNAME, target2Cname.toString());
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = resolver->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 3);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::Indeterminate);

  /* a second time, from the cache */
  ret.clear();
  res = resolver->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 3);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::Indeterminate);
}

BOOST_AUTO_TEST_CASE(test_auth_zone)
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

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;
    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, domain, QType::A, "192.0.2.42");
    return LWResult::Result::Success;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_cname_lead_to_oob)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("powerdns.com.");
  const DNSName authZone("internal.powerdns.com.");
  const ComboAddress addr("192.0.2.5");

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
  dr.d_name = authZone;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<ARecordContent>(addr));
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == target) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::CNAME, authZone.toString(), DNSResourceRecord::ANSWER, 3600);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(getRR<CNAMERecordContent>(ret[0])->getTarget().toString(), authZone.toString());
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[1])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_oob_lead_to_outgoing_queryb)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("powerdns.com.");
  const DNSName externalCNAME("www.open-xchange.com.");
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
  dr.d_type = QType::CNAME;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<CNAMERecordContent>(externalCNAME));
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[target] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (domain == externalCNAME) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, externalCNAME, QType::A, addr.toString(), DNSResourceRecord::ANSWER, 3600);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(getRR<CNAMERecordContent>(ret[0])->getTarget().toString(), externalCNAME.toString());
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[1])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_ds)
{
  // #10189
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("powerdns.corp");
  const ComboAddress addr("192.0.2.5");

  SyncRes::AuthDomain ad;
  ad.d_name = target;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.corp. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
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

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;
    if (type != QType::DS) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return LWResult::Result::Success;
    }
    else {
      setLWResult(res, RCode::NXDomain, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "a.root-servers.net. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      return LWResult::Result::Success;
    }
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 0U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_SUITE_END()
