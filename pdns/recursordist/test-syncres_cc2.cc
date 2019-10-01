#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc2)

BOOST_AUTO_TEST_CASE(test_referral_depth) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queries = 0;
  const DNSName target("www.powerdns.com.");

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queries++;

      if (isRootServer(ip)) {
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
        }
        else if (domain == DNSName("ns4.powerdns.org.")) {
          addRecordToLW(res, domain, QType::NS, "ns5.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, domain, QType::A, "192.0.2.1", DNSResourceRecord::AUTHORITY, 172800);
        }

        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  /* Set the maximum depth low */
  SyncRes::s_maxdepth = 10;

  try {
    vector<DNSRecord> ret;
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch(const ImmediateServFailException& e) {
  }
}

BOOST_AUTO_TEST_CASE(test_cname_qperq) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queries = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queries++;

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::CNAME, std::to_string(queries) + "-cname.powerdns.com");
        return 1;
      }

      return 0;
    });

  /* Set the maximum number of questions very low */
  SyncRes::s_maxqperq = 5;

  try {
    vector<DNSRecord> ret;
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch(const ImmediateServFailException& e) {
    BOOST_CHECK_EQUAL(queries, SyncRes::s_maxqperq);
  }
}

BOOST_AUTO_TEST_CASE(test_throttled_server) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("throttled.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([target,ns,&queriesToNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        queriesToNS++;

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        return 1;
      }

      return 0;
    });

  /* mark ns as down */
  time_t now = sr->getNow().tv_sec;
  SyncRes::doThrottle(now, ns, SyncRes::s_serverdownthrottletime, 10000);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  /* we should not have sent any queries to ns */
  BOOST_CHECK_EQUAL(queriesToNS, 0U);
}

BOOST_AUTO_TEST_CASE(test_throttled_server_count) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const ComboAddress ns("192.0.2.1:53");

  const size_t blocks = 10;
  /* mark ns as down for 'blocks' queries */
  time_t now = sr->getNow().tv_sec;
  SyncRes::doThrottle(now, ns, SyncRes::s_serverdownthrottletime, blocks);

  for (size_t idx = 0; idx < blocks; idx++) {
    BOOST_CHECK(SyncRes::isThrottled(now, ns));
  }

  /* we have been throttled 'blocks' times, we should not be throttled anymore */
  BOOST_CHECK(!SyncRes::isThrottled(now, ns));
}

BOOST_AUTO_TEST_CASE(test_throttled_server_time) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const ComboAddress ns("192.0.2.1:53");

  const size_t seconds = 1;
  /* mark ns as down for 'seconds' seconds */
  time_t now = sr->getNow().tv_sec;
  SyncRes::doThrottle(now, ns, seconds, 10000);

  BOOST_CHECK(SyncRes::isThrottled(now, ns));

  /* we should not be throttled anymore */
  BOOST_CHECK(!SyncRes::isThrottled(now + 2, ns));
}

BOOST_AUTO_TEST_CASE(test_dont_query_server) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("throttled.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([target,ns,&queriesToNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        queriesToNS++;

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        return 1;
      }

      return 0;
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

BOOST_AUTO_TEST_CASE(test_root_nx_trust) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("notpowerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([target1, target2, ns, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip)) {

        if (domain == target1) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        }

        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        return 1;
      }

      return 0;
    });

  SyncRes::s_maxnegttl = 3600;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  /* one for target1 and one for the entire TLD */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 2U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_LE(ret[0].d_ttl, SyncRes::s_maxnegttl);
  /* one for target1 and one for the entire TLD */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 2U);

  /* we should have sent only one query */
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_root_nx_trust_specific) {
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

  sr->setAsyncCallback([target1, target2, ns, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip)) {

        if (domain == target1) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, "com.", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        }

        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  /* even with root-nx-trust on and a NX answer from the root,
     we should not have cached the entire TLD this time. */
  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(ret[0].d_name, target2);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK(getRR<ARecordContent>(ret[0])->getCA() == ComboAddress("192.0.2.2"));

  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1U);

  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_root_nx_dont_trust) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("notpowerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([target1, target2, ns, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip)) {

        if (domain == target1) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        }

        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        return 1;
      }

      return 0;
    });

  SyncRes::s_rootNXTrust = false;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  /* one for target1 */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  /* one for target1 */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1U);

  /* we should have sent three queries */
  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_rfc8020_nothing_underneath) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target1("www.powerdns.com."); // will be denied
  const DNSName target2("foo.www.powerdns.com.");
  const DNSName target3("bar.www.powerdns.com.");
  const DNSName target4("quux.bar.www.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([ns, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {
        setLWResult(res, RCode::NXDomain, true, false, false);
        addRecordToLW(res, "powerdns.com.", QType::SOA, "ns1.powerdns.com. hostmaster.powerdns.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 2);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 2);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  ret.clear();
  res = sr->beginResolve(target3, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 2);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  ret.clear();
  res = sr->beginResolve(target4, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 2);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  // Now test without RFC 8020 to see the cache and query count grow
  SyncRes::s_hardenNXD = false;

  // Already cached
  ret.clear();
  res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 2);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  // New query
  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 3);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 2);

  ret.clear();
  res = sr->beginResolve(target3, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 4);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 3);

  ret.clear();
  res = sr->beginResolve(target4, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 5);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 4);

  // reset
  SyncRes::s_hardenNXD = true;
}

BOOST_AUTO_TEST_CASE(test_rfc8020_nodata) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target1("www.powerdns.com."); // TXT record will be denied
  const DNSName target2("bar.www.powerdns.com."); // will be NXD, but the www. NODATA should not interfere with 8020 processing
  const DNSName target3("quux.bar.www.powerdns.com."); // will be NXD, but will not yield a query
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([ns, target1, target2, target3, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {
        if (domain == target1) { // NODATA for TXT, NOERROR for A
          if (type == QType::TXT) {
            setLWResult(res, RCode::NoError, true);
            addRecordToLW(res, "powerdns.com.", QType::SOA, "ns1.powerdns.com. hostmaster.powerdns.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
            return 1;
          }
          if (type == QType::A) {
            setLWResult(res, RCode::NoError, true);
            addRecordToLW(res, domain, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
            return 1;
          }
        }
        if (domain == target2 || domain == target3) {
          setLWResult(res, RCode::NXDomain, true);
          addRecordToLW(res, "powerdns.com.", QType::SOA, "ns1.powerdns.com. hostmaster.powerdns.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          return 1;
        }
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::TXT), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 2);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  ret.clear();
  res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 3);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 4);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 2);

  ret.clear();
  res = sr->beginResolve(target3, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 4);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 2);
}

BOOST_AUTO_TEST_CASE(test_rfc8020_nodata_bis) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target1("www.powerdns.com."); // TXT record will be denied
  const DNSName target2("bar.www.powerdns.com."); // will be NXD, but the www. NODATA should not interfere with 8020 processing
  const DNSName target3("quux.bar.www.powerdns.com."); // will be NXD, but will not yield a query
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([ns, target1, target2, target3, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {
        if (domain == target1) { // NODATA for TXT, NOERROR for A
          if (type == QType::TXT) {
            setLWResult(res, RCode::NoError, true);
            addRecordToLW(res, "powerdns.com.", QType::SOA, "ns1.powerdns.com. hostmaster.powerdns.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
            return 1;
          }
          if (type == QType::A) {
            setLWResult(res, RCode::NoError, true);
            addRecordToLW(res, domain, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
            return 1;
          }
        }
        if (domain == target2 || domain == target3) {
          setLWResult(res, RCode::NXDomain, true);
          addRecordToLW(res, "powerdns.com.", QType::SOA, "ns1.powerdns.com. hostmaster.powerdns.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          return 1;
        }
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::TXT), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 2);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  ret.clear();
  res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 3);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::TXT), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 4);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 2);

  ret.clear();
  res = sr->beginResolve(target3, QType(QType::TXT), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 4);
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 2);
}

BOOST_AUTO_TEST_CASE(test_skip_negcache_for_variable_response) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");
  const DNSName cnameTarget("cname.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([target,cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

        srcmask = boost::none;

        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {
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

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  /* no negative cache entry because the response was variable */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 0U);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_limit_allowed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::s_ecsipv4cachelimit = 24;

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.1");

      return 1;
    });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  /* should have been cached */
  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_limit_no_ttl_limit_allowed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::s_ecsipv4cachelimit = 16;

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.1");

      return 1;
    });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);

  /* should have been cached because /24 is more specific than /16 but TTL limit is nof effective */
  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_ttllimit_allowed) {
    std::unique_ptr<SyncRes> sr;
    initSR(sr);

    primeHints();

    const DNSName target("www.powerdns.com.");

    SyncRes::addEDNSDomain(DNSName("powerdns.com."));

    EDNSSubnetOpts incomingECS;
    incomingECS.source = Netmask("192.0.2.128/32");
    sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
    SyncRes::s_ecscachelimitttl = 30;

    sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.1");

      return 1;
    });

    const time_t now = sr->getNow().tv_sec;
    vector<DNSRecord> ret;
    int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK_EQUAL(res, RCode::NoError);
    BOOST_CHECK_EQUAL(ret.size(), 1U);

    /* should have been cached */
    const ComboAddress who("192.0.2.128");
    vector<DNSRecord> cached;
    BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
    BOOST_REQUIRE_EQUAL(cached.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_ttllimit_and_scope_allowed) {
    std::unique_ptr<SyncRes> sr;
    initSR(sr);

    primeHints();

    const DNSName target("www.powerdns.com.");

    SyncRes::addEDNSDomain(DNSName("powerdns.com."));

    EDNSSubnetOpts incomingECS;
    incomingECS.source = Netmask("192.0.2.128/32");
    sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
    SyncRes::s_ecscachelimitttl = 100;
    SyncRes::s_ecsipv4cachelimit = 24;

    sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.1");

      return 1;
    });

    const time_t now = sr->getNow().tv_sec;
    vector<DNSRecord> ret;
    int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK_EQUAL(res, RCode::NoError);
    BOOST_CHECK_EQUAL(ret.size(), 1U);

    /* should have been cached */
    const ComboAddress who("192.0.2.128");
    vector<DNSRecord> cached;
    BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
    BOOST_REQUIRE_EQUAL(cached.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_ttllimit_notallowed) {
    std::unique_ptr<SyncRes> sr;
    initSR(sr);

    primeHints();

    const DNSName target("www.powerdns.com.");

    SyncRes::addEDNSDomain(DNSName("powerdns.com."));

    EDNSSubnetOpts incomingECS;
    incomingECS.source = Netmask("192.0.2.128/32");
    sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
    SyncRes::s_ecscachelimitttl = 100;
    SyncRes::s_ecsipv4cachelimit = 16;

    sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.1");

      return 1;
    });

    const time_t now = sr->getNow().tv_sec;
    vector<DNSRecord> ret;
    int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK_EQUAL(res, RCode::NoError);
    BOOST_CHECK_EQUAL(ret.size(), 1U);

    /* should have NOT been cached because TTL of 60 is too small and /24 is more specific than /16 */
    const ComboAddress who("192.0.2.128");
    vector<DNSRecord> cached;
    BOOST_REQUIRE_LT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
    BOOST_REQUIRE_EQUAL(cached.size(), 0U);
}


BOOST_AUTO_TEST_CASE(test_ns_speed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  std::map<ComboAddress, uint64_t> nsCounts;

  sr->setAsyncCallback([target,&nsCounts](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
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

        return 1;
      } else {
        nsCounts[ip]++;

        if (ip == ComboAddress("[2001:DB8::2]:53") || ip == ComboAddress("192.0.2.2:53")) {
          BOOST_CHECK_LT(nsCounts.size(), 3U);

          /* let's time out on pdns-public-ns2.powerdns.com. */
          return 0;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
          BOOST_CHECK_EQUAL(nsCounts.size(), 3U);

          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, "192.0.2.254");
          return 1;
        }

        return 0;
      }

      return 0;
    });

  struct timeval now = sr->getNow();

  /* make pdns-public-ns2.powerdns.com. the fastest NS, with its IPv6 address faster than the IPV4 one,
     then pdns-public-ns1.powerdns.com. on IPv4 */
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns1.powerdns.com."), ComboAddress("192.0.2.1:53"), 100, &now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns1.powerdns.com."), ComboAddress("[2001:DB8::1]:53"), 10000, &now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns2.powerdns.com."), ComboAddress("192.0.2.2:53"), 10, &now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns2.powerdns.com."), ComboAddress("[2001:DB8::2]:53"), 1, &now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns3.powerdns.com."), ComboAddress("192.0.2.3:53"), 10000, &now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns3.powerdns.com."), ComboAddress("[2001:DB8::3]:53"), 10000, &now);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(nsCounts.size(), 3U);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("192.0.2.1:53")], 1U);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("192.0.2.2:53")], 1U);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("[2001:DB8::2]:53")], 1U);
}

BOOST_AUTO_TEST_CASE(test_flawed_nsset) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);

        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.254");
        return 1;
      }

      return 0;
    });

  /* we populate the cache with a flawed NSset, i.e. there is a NS entry but no corresponding glue */
  time_t now = sr->getNow().tv_sec;
  std::vector<DNSRecord> records;
  std::vector<shared_ptr<RRSIGRecordContent> > sigs;
  addRecordToList(records, target, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, now + 3600);

  t_RC->replace(now, target, QType(QType::NS), records, sigs, vector<std::shared_ptr<DNSRecord>>(), true, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_completely_flawed_nsset) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount,target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip) && domain == target) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns3.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        return 1;
      } else if (domain == DNSName("pdns-public-ns2.powerdns.com.") || domain == DNSName("pdns-public-ns3.powerdns.com.")){
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  /* one query to get NSs, then A and AAAA for each NS */
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_cache_hit) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      return 0;
    });

  /* we populate the cache with eveything we need */
  time_t now = sr->getNow().tv_sec;
  std::vector<DNSRecord> records;
  std::vector<shared_ptr<RRSIGRecordContent> > sigs;

  addRecordToList(records, target, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, now + 3600);
  t_RC->replace(now, target , QType(QType::A), records, sigs, vector<std::shared_ptr<DNSRecord>>(), true, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_no_rd) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  size_t queriesCount = 0;

  sr->setCacheOnly();

  sr->setAsyncCallback([target,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_cache_min_max_ttl) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cachettl.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 7200);
        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);

        return 1;
      }

      return 0;
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
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_EQUAL((cached[0].d_ttl - now), SyncRes::s_minimumTTL);

  cached.clear();
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::NS), false, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_LE((cached[0].d_ttl - now), SyncRes::s_maxcachettl);
}

BOOST_AUTO_TEST_CASE(test_cache_min_max_ecs_ttl) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cacheecsttl.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::addEDNSDomain(target);

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 20);
        srcmask = boost::none;

        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);

        return 1;
      }

      return 0;
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
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_EQUAL((cached[0].d_ttl - now), SyncRes::s_minimumECSTTL);

  cached.clear();
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::NS), false, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_LE((cached[0].d_ttl - now), SyncRes::s_maxcachettl);

  cached.clear();
  BOOST_REQUIRE_GT(t_RC->get(now, DNSName("a.gtld-servers.net."), QType(QType::A), false, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_LE((cached[0].d_ttl - now), SyncRes::s_minimumTTL);
}

BOOST_AUTO_TEST_CASE(test_cache_expired_ttl) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);

        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  /* we populate the cache with entries that expired 60s ago*/
  const time_t now = sr->getNow().tv_sec;

  std::vector<DNSRecord> records;
  std::vector<shared_ptr<RRSIGRecordContent> > sigs;
  addRecordToList(records, target, QType::A, "192.0.2.42", DNSResourceRecord::ANSWER, now - 60);

  t_RC->replace(now - 3600, target, QType(QType::A), records, sigs, vector<std::shared_ptr<DNSRecord>>(), true, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toStringWithPort(), ComboAddress("192.0.2.2").toStringWithPort());
}

BOOST_AUTO_TEST_SUITE_END()
