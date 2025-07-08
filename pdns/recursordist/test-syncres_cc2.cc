#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"
#include "taskqueue.hh"
#include "rec-taskqueue.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc2)

static void do_test_referral_depth(bool limited)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queries = 0;
  const DNSName target("www.powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queries++;

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);

      if (domain == DNSName("www.powerdns.com.")) {
        addRecordToLW(res, domain, QType::NS, "ns.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      }
      else if (domain == DNSName("ns.powerdns.com.")) {
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
      }
      else if (domain == DNSName("ns1.powerdns.org.")) {
        addRecordToLW(res, domain, QType::NS, "ns2.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
      }
      else if (domain == DNSName("ns2.powerdns.org.")) {
        addRecordToLW(res, domain, QType::NS, "ns3.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
      }
      else if (domain == DNSName("ns3.powerdns.org.")) {
        addRecordToLW(res, domain, QType::NS, "ns4.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "ns4.powerdns.org.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      }

      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, true, false, false);
      if (domain == DNSName("www.powerdns.com.")) {
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }
      else {
        addRecordToLW(res, domain, QType::A, "192.0.2.1");
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  if (limited) {
    /* Set the maximum depth low */
    SyncRes::s_maxdepth = 3;
    try {
      vector<DNSRecord> ret;
      sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
      BOOST_CHECK(false);
    }
    catch (const ImmediateServFailException& e) {
      BOOST_CHECK(e.reason.find("max-recursion-depth") != string::npos);
    }
  }
  else {
    // Check if the setup with high limit is OK.
    SyncRes::s_maxdepth = 50;
    try {
      vector<DNSRecord> ret;
      int rcode = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
      BOOST_CHECK_EQUAL(rcode, RCode::NoError);
      BOOST_REQUIRE_EQUAL(ret.size(), 1U);
      BOOST_CHECK_EQUAL(ret[0].d_name, target);
      BOOST_REQUIRE(ret[0].d_type == QType::A);
      BOOST_CHECK(getRR<ARecordContent>(ret[0])->getCA() == ComboAddress("192.0.2.2"));
    }
    catch (const ImmediateServFailException& e) {
      BOOST_CHECK(false);
    }
  }
}

BOOST_AUTO_TEST_CASE(test_referral_depth)
{
  // Test with limit
  do_test_referral_depth(true);
}

BOOST_AUTO_TEST_CASE(test_referral_depth_ok)
{
  // Test with default limit
  do_test_referral_depth(false);
}

BOOST_AUTO_TEST_CASE(test_glueless_referral_loop)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  // We only do v4, this avoids "beenthere" non-deterministic behaviour. If we do both v4 and v6, there are multiple IPs
  // per (root) nameserver, and the "beenthere" loop detection is influenced by the particular address family selected.
  // To see the non-deterministic behaviour, uncomment the line below (you'll be seeing around 21-24 queries).
  // See #9565
  SyncRes::s_doIPv6 = false;

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("powerdns.org.");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesToNS++;

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);

      if (domain.isPartOf(DNSName("com."))) {
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      }
      else if (domain.isPartOf(DNSName("org."))) {
        addRecordToLW(res, "org.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      }
      else {
        setLWResult(res, RCode::NXDomain, false, false, true);
        return LWResult::Result::Success;
      }

      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      if (domain.isPartOf(target1)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "ns2.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        return LWResult::Result::Success;
      }
      if (domain.isPartOf(target2)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.org.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.org.", QType::NS, "ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        return LWResult::Result::Success;
      }
      setLWResult(res, RCode::NXDomain, false, false, true);
      return LWResult::Result::Success;
    }
    else {
      return LWResult::Result::Timeout;
    }
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesToNS, 16U);
}

BOOST_AUTO_TEST_CASE(test_glueless_referral_loop_with_nonresolving)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  // We only do v4, this avoids "beenthere" non-deterministic behaviour. If we do both v4 and v6, there are multiple IPs
  // per (root) nameserver, and the "beenthere" loop detection is influenced by the particular address family selected.
  // To see the non-deterministic behaviour, uncomment the line below (you'll be seeing around 21-24 queries).
  // See #9565
  SyncRes::s_doIPv6 = false;

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("powerdns.org.");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesToNS++;

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);

      if (domain.isPartOf(DNSName("com."))) {
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      }
      else if (domain.isPartOf(DNSName("org."))) {
        addRecordToLW(res, "org.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      }
      else {
        setLWResult(res, RCode::NXDomain, false, false, true);
        return LWResult::Result::Success;
      }

      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      if (domain.isPartOf(target1)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "ns2.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        return LWResult::Result::Success;
      }
      if (domain.isPartOf(target2)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.org.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.org.", QType::NS, "ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        return LWResult::Result::Success;
      }
      setLWResult(res, RCode::NXDomain, false, false, true);
      return LWResult::Result::Success;
    }
    else {
      return LWResult::Result::Timeout;
    }
  });

  SyncRes::s_nonresolvingnsmaxfails = 1;
  SyncRes::s_nonresolvingnsthrottletime = 60;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  // queriesToNS count varies due to shuffling
  // But all NS from above should be recorded as failing
  BOOST_CHECK_EQUAL(SyncRes::getNonResolvingNSSize(), 4U);
}

BOOST_AUTO_TEST_CASE(test_glueless_referral_with_non_resolving)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  size_t queryCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);

      if (domain.isPartOf(DNSName("com."))) {
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      }
      else if (domain.isPartOf(DNSName("org."))) {
        addRecordToLW(res, "org.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      }
      else {
        setLWResult(res, RCode::NXDomain, false, false, true);
        return LWResult::Result::Success;
      }

      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      if (domain == target) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        return LWResult::Result::Success;
      }
      if (domain == DNSName("pdns-public-ns1.powerdns.org.")) {
        queryCount++;
        setLWResult(res, 0, true, false, true);
        if (queryCount > 8) {
          addRecordToLW(res, "pdns-public-ns1.powerdns.org.", QType::A, "192.0.2.2");
          addRecordToLW(res, "pdns-public-ns1.powerdns.org.", QType::AAAA, "2001:DB8::2");
        }
        return LWResult::Result::Success;
      }
      else if (domain == DNSName("pdns-public-ns2.powerdns.org.")) {
        queryCount++;
        setLWResult(res, 0, true, false, true);
        if (queryCount > 8) {
          addRecordToLW(res, "pdns-public-ns2.powerdns.org.", QType::A, "192.0.2.3");
          addRecordToLW(res, "pdns-public-ns2.powerdns.org.", QType::AAAA, "2001:DB8::3");
        }
        return LWResult::Result::Success;
      }

      setLWResult(res, RCode::NXDomain, false, false, true);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53") || address == ComboAddress("192.0.2.3:53") || address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("[2001:DB8::3]:53")) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.4");
      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
  });

  SyncRes::s_nonresolvingnsmaxfails = 10;
  SyncRes::s_nonresolvingnsthrottletime = 60;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(SyncRes::getNonResolvingNSSize(), 2U);

  // Again, should not change anything
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  //BOOST_CHECK(ret[0].d_type == QType::A);
  //BOOST_CHECK_EQUAL(ret[0].d_name, target);

  BOOST_CHECK_EQUAL(SyncRes::getNonResolvingNSSize(), 2U);

  // Again, but now things should start working because of the queryCounter getting high enough
  // and one entry remains in the non-resolving cache
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(SyncRes::getNonResolvingNSSize(), 1U);
}

BOOST_AUTO_TEST_CASE(test_cname_qperq)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queries = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queries++;

    if (isRootServer(address)) {

      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53")) {

      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::CNAME, std::to_string(queries) + "-cname.powerdns.com");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  /* Set the maximum number of questions very low */
  SyncRes::s_maxqperq = 5;

  try {
    vector<DNSRecord> ret;
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch (const ImmediateServFailException& e) {
    BOOST_CHECK_EQUAL(queries, SyncRes::s_maxqperq);
  }
}

BOOST_AUTO_TEST_CASE(test_throttled_server)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("throttled.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {

      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ns) {

      queriesToNS++;

      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::A, "192.0.2.2");

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  /* mark ns as down */
  time_t now = sr->getNow().tv_sec;
  SyncRes::doThrottle(now, ns, SyncRes::s_serverdownthrottletime, 10000, SyncRes::ThrottleReason::Timeout);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  /* we should not have sent any queries to ns */
  BOOST_CHECK_EQUAL(queriesToNS, 0U);
}

BOOST_AUTO_TEST_CASE(test_throttled_server_count)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const ComboAddress ns("192.0.2.1:53");

  const size_t blocks = 10;
  /* mark ns as down for 'blocks' queries */
  time_t now = sr->getNow().tv_sec;
  SyncRes::doThrottle(now, ns, SyncRes::s_serverdownthrottletime, blocks, SyncRes::ThrottleReason::Timeout);

  for (size_t idx = 0; idx < blocks; idx++) {
    BOOST_CHECK(SyncRes::isThrottled(now, ns));
  }

  /* we have been throttled 'blocks' times, we should not be throttled anymore */
  BOOST_CHECK(!SyncRes::isThrottled(now, ns));
}

BOOST_AUTO_TEST_CASE(test_throttled_server_time)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const ComboAddress ns("192.0.2.1:53");

  const size_t seconds = 1;
  /* mark ns as down for 'seconds' seconds */
  time_t now = sr->getNow().tv_sec;
  SyncRes::doThrottle(now, ns, seconds, 10000, SyncRes::ThrottleReason::Timeout);

  BOOST_CHECK(SyncRes::isThrottled(now, ns));

  /* we should not be throttled anymore */
  BOOST_CHECK(!SyncRes::isThrottled(now + 2, ns));
}

BOOST_AUTO_TEST_CASE(test_dont_query_server)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("throttled.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {

      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ns) {

      queriesToNS++;

      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::A, "192.0.2.2");

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  /* prevent querying this NS */
  SyncRes::addDontQuery(Netmask(ns));

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  /* we should not have sent any queries to ns */
  BOOST_CHECK_EQUAL(queriesToNS, 0U);
}

BOOST_AUTO_TEST_CASE(test_root_nx_trust)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("notpowerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (isRootServer(address)) {

      if (domain == target1) {
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
      }
      else {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      }

      return LWResult::Result::Success;
    }
    if (address == ns) {

      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::A, "192.0.2.2");

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  SyncRes::s_maxnegttl = 3600;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  /* one for target1 and one for the entire TLD */
  BOOST_CHECK_EQUAL(g_negCache->size(), 2U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_LE(ret[0].d_ttl, SyncRes::s_maxnegttl);
  /* one for target1 and one for the entire TLD */
  BOOST_CHECK_EQUAL(g_negCache->size(), 2U);

  /* we should have sent only one query */
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_root_nx_trust_specific)
{
  std::unique_ptr<SyncRes> sr;
  initSR();
  initSR(sr, true, false);

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("notpowerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  /* This time the root denies target1 with a "com." SOA instead of a "." one.
     We should add target1 to the negcache, but not "com.". */

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (isRootServer(address)) {

      if (domain == target1) {
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, "com.", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
      }
      else {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      }

      return LWResult::Result::Success;
    }
    if (address == ns) {

      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::A, "192.0.2.2");

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  /* even with root-nx-trust on and a NX answer from the root,
     we should not have cached the entire TLD this time. */
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(ret[0].d_name, target2);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK(getRR<ARecordContent>(ret[0])->getCA() == ComboAddress("192.0.2.2"));

  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_root_nx_dont_trust)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("notpowerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (isRootServer(address)) {

      if (domain == target1) {
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
      }
      else {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      }

      return LWResult::Result::Success;
    }
    if (address == ns) {

      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::A, "192.0.2.2");

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  SyncRes::s_rootNXTrust = false;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  /* one for target1 */
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  /* one for target1 */
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  /* we should have sent three queries */
  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_rfc8020_nothing_underneath)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  SyncRes::s_hardenNXD = SyncRes::HardenNXD::Yes;

  primeHints();

  const DNSName target1("www.powerdns.com."); // will be denied
  const DNSName target2("foo.www.powerdns.com.");
  const DNSName target3("bar.www.powerdns.com.");
  const DNSName target4("quux.bar.www.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "ns1.powerdns.com.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ns) {
      setLWResult(res, RCode::NXDomain, true, false, false);
      addRecordToLW(res, "powerdns.com.", QType::SOA, "ns1.powerdns.com. hostmaster.powerdns.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target3, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target4, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  // Now test without RFC 8020 to see the cache and query count grow
  SyncRes::s_hardenNXD = SyncRes::HardenNXD::No;

  // Already cached
  ret.clear();
  res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  // New query
  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 3U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 2U);

  ret.clear();
  res = sr->beginResolve(target3, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 3U);

  ret.clear();
  res = sr->beginResolve(target4, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 4U);

  // reset
  SyncRes::s_hardenNXD = SyncRes::HardenNXD::DNSSEC;
}

BOOST_AUTO_TEST_CASE(test_rfc8020_nothing_underneath_dnssec)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();

  const DNSName parent1("com.");
  const DNSName parent2("powerdns.com.");
  const DNSName target1("www.powerdns.com."); // will be denied
  const DNSName target2("foo.www.powerdns.com.");
  const DNSName target3("bar.www.powerdns.com.");
  const DNSName target4("quux.bar.www.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(parent1, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(parent2, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    if (domain == target1 || domain == target2 || domain == target3 || domain == target4) {
      auth = DNSName("powerdns.com.");
    }
    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && (domain == target1 || domain == target2 || domain == target3 || domain == target4)) {
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, auth, 300);
        addNSECRecordToLW(DNSName("wwa.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }
    {
      if (isRootServer(address)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.1:53")) {
        if (domain == DNSName("com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
          addRRSIG(keys, res->d_records, domain, 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          addRRSIG(keys, res->d_records, domain, 300);
        }
        else {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, auth, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(auth, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        if (type == QType::NS) {
          setLWResult(res, 0, true, false, true);
          if (domain == DNSName("powerdns.com.")) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
        }
        else {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, auth, 300);
          addNSECRecordToLW(DNSName("wwa.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
          addRRSIG(keys, res->d_records, auth, 300);
          /* add wildcard denial */
          addNSECRecordToLW(DNSName("powerdns.com."), DNSName("a.powerdns.com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
          addRRSIG(keys, res->d_records, auth, 300);
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_CHECK_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_CHECK_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target3, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_CHECK_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target4, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_CHECK_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  // Now test without RFC 8020 to see the cache and query count grow
  SyncRes::s_hardenNXD = SyncRes::HardenNXD::No;

  // Already cached
  ret.clear();
  res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_CHECK_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  // New query
  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_CHECK_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 2U);

  ret.clear();
  res = sr->beginResolve(target3, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_CHECK_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 3U);

  ret.clear();
  res = sr->beginResolve(target4, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_CHECK_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 4U);

  // reset
  SyncRes::s_hardenNXD = SyncRes::HardenNXD::DNSSEC;
}

BOOST_AUTO_TEST_CASE(test_rfc8020_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  SyncRes::s_hardenNXD = SyncRes::HardenNXD::Yes;

  primeHints();

  const DNSName target1("www.powerdns.com."); // TXT record will be denied
  const DNSName target2("bar.www.powerdns.com."); // will be NXD, but the www. NODATA should not interfere with 8020 processing
  const DNSName target3("quux.bar.www.powerdns.com."); // will be NXD, but will not yield a query
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "ns1.powerdns.com.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ns) {
      if (domain == target1) { // NODATA for TXT, NOERROR for A
        if (type == QType::TXT) {
          setLWResult(res, RCode::NoError, true);
          addRecordToLW(res, "powerdns.com.", QType::SOA, "ns1.powerdns.com. hostmaster.powerdns.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          return LWResult::Result::Success;
        }
        if (type == QType::A) {
          setLWResult(res, RCode::NoError, true);
          addRecordToLW(res, domain, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
          return LWResult::Result::Success;
        }
      }
      if (domain == target2 || domain == target3) {
        setLWResult(res, RCode::NXDomain, true);
        addRecordToLW(res, "powerdns.com.", QType::SOA, "ns1.powerdns.com. hostmaster.powerdns.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        return LWResult::Result::Success;
      }
    }
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::TXT), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 3U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 2U);

  ret.clear();
  res = sr->beginResolve(target3, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 2U);
}

BOOST_AUTO_TEST_CASE(test_rfc8020_nodata_bis)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  SyncRes::s_hardenNXD = SyncRes::HardenNXD::Yes;

  primeHints();

  const DNSName target1("www.powerdns.com."); // TXT record will be denied
  const DNSName target2("bar.www.powerdns.com."); // will be NXD, but the www. NODATA should not interfere with 8020 processing
  const DNSName target3("quux.bar.www.powerdns.com."); // will be NXD, but will not yield a query
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "ns1.powerdns.com.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ns) {
      if (domain == target1) { // NODATA for TXT, NOERROR for A
        if (type == QType::TXT) {
          setLWResult(res, RCode::NoError, true);
          addRecordToLW(res, "powerdns.com.", QType::SOA, "ns1.powerdns.com. hostmaster.powerdns.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          return LWResult::Result::Success;
        }
        if (type == QType::A) {
          setLWResult(res, RCode::NoError, true);
          addRecordToLW(res, domain, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
          return LWResult::Result::Success;
        }
      }
      if (domain == target2 || domain == target3) {
        setLWResult(res, RCode::NXDomain, true);
        addRecordToLW(res, "powerdns.com.", QType::SOA, "ns1.powerdns.com. hostmaster.powerdns.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        return LWResult::Result::Success;
      }
    }
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::TXT), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 3U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::TXT), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 2U);

  ret.clear();
  res = sr->beginResolve(target3, QType(QType::TXT), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 2U);
}

BOOST_AUTO_TEST_CASE(test_dont_skip_negcache_for_variable_response)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");
  const DNSName cnameTarget("cname.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.setSource(Netmask("192.0.2.128/32"));
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& srcmask, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    BOOST_REQUIRE(srcmask);
    BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

      srcmask = boost::none;

      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53")) {
      if (domain == target) {
        /* Type 2 NXDOMAIN (rfc2308 section-2.1) */
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
        addRecordToLW(res, "powerdns.com", QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      }
      else if (domain == cnameTarget) {
        /* we shouldn't get there since the Type NXDOMAIN should have been enough,
             but we might if we still chase the CNAME. */
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, "powerdns.com", QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      }

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_limit_allowed)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.setSource(Netmask("192.0.2.128/32"));
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::s_ecsipv4cachelimit = 24;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& srcmask, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    BOOST_REQUIRE(srcmask);
    BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, target, QType::A, "192.0.2.1");

    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  /* should have been cached */
  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_limit_no_ttl_limit_allowed)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.setSource(Netmask("192.0.2.128/32"));
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::s_ecsipv4cachelimit = 16;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& srcmask, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    BOOST_REQUIRE(srcmask);
    BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, target, QType::A, "192.0.2.1");

    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  /* should have been cached because /24 is more specific than /16 but TTL limit is nof effective */
  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_ttllimit_allowed)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.setSource(Netmask("192.0.2.128/32"));
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::s_ecscachelimitttl = 30;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& srcmask, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    BOOST_REQUIRE(srcmask);
    BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, target, QType::A, "192.0.2.1");

    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  /* should have been cached */
  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_ttllimit_and_scope_allowed)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.setSource(Netmask("192.0.2.128/32"));
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::s_ecscachelimitttl = 100;
  SyncRes::s_ecsipv4cachelimit = 24;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& srcmask, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    BOOST_REQUIRE(srcmask);
    BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, target, QType::A, "192.0.2.1");

    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  /* should have been cached */
  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_ttllimit_notallowed)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.setSource(Netmask("192.0.2.128/32"));
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::s_ecscachelimitttl = 100;
  SyncRes::s_ecsipv4cachelimit = 16;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& srcmask, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    BOOST_REQUIRE(srcmask);
    BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

    setLWResult(res, 0, true, false, true);
    addRecordToLW(res, target, QType::A, "192.0.2.1");

    return LWResult::Result::Success;
  });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  /* should have NOT been cached because TTL of 60 is too small and /24 is more specific than /16 */
  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_LT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_ns_speed)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  BOOST_CHECK_EQUAL(SyncRes::getNSSpeedsSize(), 0U);

  primeHints();

  const DNSName target("powerdns.com.");

  std::map<ComboAddress, uint64_t> nsCounts;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, domain, QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, domain, QType::NS, "pdns-public-ns3.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);

      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "pdns-public-ns3.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "pdns-public-ns3.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    {
      nsCounts[address]++;

      if (address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("192.0.2.2:53")) {
        BOOST_CHECK_LT(nsCounts.size(), 3U);

        /* let's time out on pdns-public-ns2.powerdns.com. */
        return LWResult::Result::Timeout;
      }
      if (address == ComboAddress("192.0.2.1:53")) {
        BOOST_CHECK_EQUAL(nsCounts.size(), 3U);

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.254");
        return LWResult::Result::Success;
      }

      return LWResult::Result::Timeout;
    }

    return LWResult::Result::Timeout;
  });

  struct timeval now = sr->getNow();

  /* make pdns-public-ns2.powerdns.com. the fastest NS, with its IPv6 address faster than the IPV4 one,
     then pdns-public-ns1.powerdns.com. on IPv4 */
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns1.powerdns.com."), ComboAddress("192.0.2.1:53"), 100, now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns1.powerdns.com."), ComboAddress("[2001:DB8::1]:53"), 10000, now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns2.powerdns.com."), ComboAddress("192.0.2.2:53"), 10, now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns2.powerdns.com."), ComboAddress("[2001:DB8::2]:53"), 1, now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns3.powerdns.com."), ComboAddress("192.0.2.3:53"), 10000, now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns3.powerdns.com."), ComboAddress("[2001:DB8::3]:53"), 10000, now);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(nsCounts.size(), 3U);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("192.0.2.1:53")], 1U);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("192.0.2.2:53")], 1U);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("[2001:DB8::2]:53")], 1U);

  // read PB representation back and forth, compare using the text dump
  std::string temp1{"/tmp/speedDump1XXXXXX"};
  std::string temp2{"/tmp/speedDump2XXXXXX"};
  auto fd1 = FDWrapper(mkstemp(temp1.data()));
  auto fd2 = FDWrapper(mkstemp(temp2.data()));
  auto count = SyncRes::doDumpNSSpeeds(fd1);
  fd1.reset();
  std::string pbDump;
  auto records = SyncRes::getNSSpeedTable(0, pbDump);
  BOOST_CHECK_EQUAL(records, count);

  SyncRes::clearNSSpeeds();
  BOOST_CHECK_EQUAL(SyncRes::getNSSpeedsSize(), 0U);

  // Put PB dump back
  count = SyncRes::putIntoNSSpeedTable(pbDump);
  BOOST_CHECK_EQUAL(records, count);
  count = SyncRes::doDumpNSSpeeds(fd2);
  fd2.reset();
  BOOST_CHECK_EQUAL(records, count);

  // NS speed table is a hashed unique table, which not neccesarily stable wrt recreation
  // So we read the lines, sort them and compare
  std::ifstream file1(temp1);
  std::ifstream file2(temp2);
  std::vector<std::string> lines1;
  std::vector<std::string> lines2;
  while (file1.good()) {
    std::string line;
    std::getline(file1, line);
    lines1.emplace_back(line);
  }
  while (file2.good()) {
    std::string line;
    std::getline(file2, line);
    lines2.emplace_back(line);
  }
  unlink(temp1.data());
  unlink(temp2.data());
  std::sort(lines1.begin(), lines1.end());
  std::sort(lines2.begin(), lines2.end());
  BOOST_CHECK(lines1 == lines2);
}

BOOST_AUTO_TEST_CASE(test_flawed_nsset)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);

      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.254");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  /* we populate the cache with a flawed NSset, i.e. there is a NS entry but no corresponding glue */
  time_t now = sr->getNow().tv_sec;
  std::vector<DNSRecord> records;
  std::vector<shared_ptr<const RRSIGRecordContent>> sigs;
  addRecordToList(records, target, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, now + 3600);

  g_recCache->replace(now, target, QType(QType::NS), records, sigs, {}, true, g_rootdnsname, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_completely_flawed_nsset)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (isRootServer(address) && domain == target) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, domain, QType::NS, "pdns-public-ns3.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      return LWResult::Result::Success;
    }
    if (domain == DNSName("pdns-public-ns2.powerdns.com.") || domain == DNSName("pdns-public-ns3.powerdns.com.")) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  /* one query to get NSs, then A and AAAA for each NS */
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_completely_flawed_big_nsset)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (isRootServer(address) && domain == target) {
      setLWResult(res, 0, false, false, true);
      // 20 NS records
      for (int i = 0; i < 20; i++) {
        string n = string("pdns-public-ns") + std::to_string(i) + string(".powerdns.com.");
        addRecordToLW(res, domain, QType::NS, n, DNSResourceRecord::AUTHORITY, 172800);
      }
      return LWResult::Result::Success;
    }
    if (domain.toString().length() > 14 && domain.toString().substr(0, 14) == "pdns-public-ns") {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  try {
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(0);
  }
  catch (const ImmediateServFailException& ex) {
    BOOST_CHECK_EQUAL(ret.size(), 0U);
    // one query to get NSs, then A and AAAA for each NS, 5th NS hits the limit
    // limit is reduced to 5, because zone publishes many (20) NS
    BOOST_CHECK_EQUAL(queriesCount, 11U);
  }
}

BOOST_AUTO_TEST_CASE(test_cache_hit)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    return LWResult::Result::Timeout;
  });

  /* we populate the cache with everything we need */
  time_t now = sr->getNow().tv_sec;
  std::vector<DNSRecord> records;
  std::vector<shared_ptr<const RRSIGRecordContent>> sigs;

  addRecordToList(records, target, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, now + 3600);
  g_recCache->replace(now, target, QType(QType::A), records, sigs, {}, true, g_rootdnsname, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_no_rd)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  size_t queriesCount = 0;

  sr->setCacheOnly();

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* /* res */, bool* /* chained */) {
    queriesCount++;
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_cache_min_max_ttl)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cachettl.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {

      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 7200);
      return LWResult::Result::Success;
    }
    if (address == ns) {

      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  const time_t now = sr->getNow().tv_sec;
  SyncRes::s_minimumTTL = 60;
  SyncRes::s_maxcachettl = 3600;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(ret[0].d_ttl, SyncRes::s_minimumTTL);

  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_EQUAL((cached[0].d_ttl - now), SyncRes::s_minimumTTL);

  cached.clear();
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::NS), MemRecursorCache::None, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_LE((cached[0].d_ttl - now), SyncRes::s_maxcachettl);
}

BOOST_AUTO_TEST_CASE(test_cache_min_max_ecs_ttl)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cacheecsttl.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  EDNSSubnetOpts incomingECS;
  incomingECS.setSource(Netmask("192.0.2.128/32"));
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::addEDNSDomain(target);

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& srcmask, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    BOOST_REQUIRE(srcmask);
    BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

    if (isRootServer(address)) {

      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 20);
      srcmask = boost::none;

      return LWResult::Result::Success;
    }
    if (address == ns) {

      setLWResult(res, 0, true, false, false);
      addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  const time_t now = sr->getNow().tv_sec;
  SyncRes::s_minimumTTL = 60;
  SyncRes::s_minimumECSTTL = 120;
  SyncRes::s_maxcachettl = 3600;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(ret[0].d_ttl, SyncRes::s_minimumECSTTL);

  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_EQUAL((cached[0].d_ttl - now), SyncRes::s_minimumECSTTL);

  cached.clear();
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::NS), MemRecursorCache::None, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_LE((cached[0].d_ttl - now), SyncRes::s_maxcachettl);

  cached.clear();
  BOOST_REQUIRE_GT(g_recCache->get(now, DNSName("a.gtld-servers.net."), QType(QType::A), MemRecursorCache::None, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_LE((cached[0].d_ttl - now), SyncRes::s_minimumTTL);
}

BOOST_AUTO_TEST_CASE(test_cache_expired_ttl)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);

      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.2");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  /* we populate the cache with entries that expired 60s ago*/
  const time_t now = sr->getNow().tv_sec;

  std::vector<DNSRecord> records;
  std::vector<shared_ptr<const RRSIGRecordContent>> sigs;
  addRecordToList(records, target, QType::A, "192.0.2.42", DNSResourceRecord::ANSWER, now - 60);

  g_recCache->replace(now - 3600, target, QType(QType::A), records, sigs, {}, true, g_rootdnsname, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toStringWithPort(), ComboAddress("192.0.2.2").toStringWithPort());
}

BOOST_AUTO_TEST_CASE(test_cache_almost_expired_ttl)
{

  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  SyncRes::s_refresh_ttlperc = 50;
  primeHints();

  const DNSName target("powerdns.com.");

  auto callback = [&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);

      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.2");
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  };
  sr->setAsyncCallback(callback);

  /* we populate the cache with an 60s TTL entry that is 31s old*/
  const time_t now = sr->getNow().tv_sec;

  std::vector<DNSRecord> records;
  std::vector<shared_ptr<const RRSIGRecordContent>> sigs;
  addRecordToList(records, target, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, now + 29);

  g_recCache->replace(now - 30, target, QType(QType::A), records, sigs, {}, true, g_rootdnsname, boost::optional<Netmask>(), boost::none, vState::Indeterminate, boost::none, false, now - 31);

  /* Same for the NS record */
  std::vector<DNSRecord> ns;
  addRecordToList(ns, target, QType::NS, "pdns-public-ns1.powerdns.com", DNSResourceRecord::ANSWER, now + 29);
  g_recCache->replace(now - 30, target, QType::NS, ns, sigs, {}, false, target, boost::optional<Netmask>(), boost::none, vState::Indeterminate, boost::none, false, now - 31);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toStringWithPort(), ComboAddress("192.0.2.2").toStringWithPort());
  auto ttl = ret[0].d_ttl;
  BOOST_CHECK_EQUAL(ttl, 29U);

  // One task should be submitted
  BOOST_REQUIRE_EQUAL(getTaskSize(), 1U);

  auto task = taskQueuePop();

  // Refresh the almost expired record, its NS records also gets updated
  sr->setRefreshAlmostExpired(task.d_refreshMode);
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toStringWithPort(), ComboAddress("192.0.2.2").toStringWithPort());
  ttl = ret[0].d_ttl;
  BOOST_CHECK_EQUAL(ttl, 60U);

  // Also check if NS record was updated
  ret.clear();
  BOOST_REQUIRE_GT(g_recCache->get(now, target, QType(QType::NS), MemRecursorCache::None, &ret, ComboAddress()), 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_REQUIRE(ret[0].d_type == QType::NS);
  BOOST_CHECK_EQUAL(getRR<NSRecordContent>(ret[0])->getNS(), DNSName("pdns-public-ns1.powerdns.com."));
  ttl = ret[0].d_ttl - now;
  BOOST_CHECK_EQUAL(ttl, std::min(SyncRes::s_maxcachettl, 172800U));

  // ATM we are not testing the almost expiry of root infra records, it would require quite some cache massage...
}

BOOST_AUTO_TEST_SUITE_END()
