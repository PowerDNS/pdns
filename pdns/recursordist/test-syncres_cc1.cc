#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc1)

BOOST_AUTO_TEST_CASE(test_root_primed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("a.root-servers.net.");

  /* we are primed, we should be able to resolve A a.root-servers.net. without any query */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::AAAA);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_root_primed_ns) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();
  const DNSName target(".");

  /* we are primed, but we should not be able to NS . without any query
   because the . NS entry is not stored as authoritative */

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (domain == target && type == QType::NS) {

        setLWResult(res, 0, true, false, true);
        char addr[] = "a.root-servers.net.";
        for (char idx = 'a'; idx <= 'm'; idx++) {
          addr[0] = idx;
          addRecordToLW(res, g_rootdnsname, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
        }

        addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 13U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_root_not_primed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (domain == g_rootdnsname && type == QType::NS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, g_rootdnsname, QType::NS, "a.root-servers.net.", DNSResourceRecord::ANSWER, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      }

      return 0;
    });

  /* we are not primed yet, so SyncRes will have to call primeHints()
     then call getRootNS(), for which at least one of the root servers needs to answer */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("."), QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_root_not_primed_and_no_response) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  std::set<ComboAddress> downServers;

  /* we are not primed yet, so SyncRes will have to call primeHints()
     then call getRootNS(), for which at least one of the root servers needs to answer.
     None will, so it should ServFail.
  */
  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      downServers.insert(ip);
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("."), QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK(downServers.size() > 0);
  /* we explicitly refuse to mark the root servers down */
  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 0U);
  }
}

static void test_edns_formerr_fallback_f(bool sample) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  if (sample) {
    sr->setQNameMinimization();
  }
  ComboAddress noEDNSServer;
  size_t queriesWithEDNS = 0;
  size_t queriesWithoutEDNS = 0;

  sr->setAsyncCallback([&queriesWithEDNS, &queriesWithoutEDNS, &noEDNSServer, sample](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      if (EDNS0Level != 0) {
        queriesWithEDNS++;
        noEDNSServer = ip;

        setLWResult(res, RCode::FormErr);
        return 1;
      }

      queriesWithoutEDNS++;

      if (domain == DNSName("powerdns.com") && type == QType::A && !doTCP) {
        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.1");
        return 1;
      }

      return sample ? basicRecordsForQnameMinimization(res, domain, type) : 0;
    });

  primeHints();

  /* fake that the root NS doesn't handle EDNS, check that we fallback */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesWithEDNS, sample ? 3U : 1U);
  BOOST_CHECK_EQUAL(queriesWithoutEDNS, sample ? 4U : 1U);
  BOOST_CHECK_EQUAL(SyncRes::getEDNSStatusesSize(), sample ? 3U : 1U);
  BOOST_CHECK_EQUAL(SyncRes::getEDNSStatus(noEDNSServer), SyncRes::EDNSStatus::NOEDNS);
}

BOOST_AUTO_TEST_CASE(test_edns_formerr_fallback) {
  test_edns_formerr_fallback_f(false);
}

BOOST_AUTO_TEST_CASE(test_edns_formerr_fallback_qmin) {
  // DISABLED UNTIL QNAME MINIMIZATON IS THERE
  return;
  test_edns_formerr_fallback_f(true);
}

BOOST_AUTO_TEST_CASE(test_edns_formerr_but_edns_enabled) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  /* in this test, the auth answers with FormErr to an EDNS-enabled
     query, but the response does contain EDNS so we should not mark
     it as EDNS ignorant or intolerant.
  */
  size_t queriesWithEDNS = 0;
  size_t queriesWithoutEDNS = 0;
  std::set<ComboAddress> usedServers;

  sr->setAsyncCallback([&queriesWithEDNS, &queriesWithoutEDNS, &usedServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (EDNS0Level > 0) {
        queriesWithEDNS++;
      }
      else {
        queriesWithoutEDNS++;
      }
      usedServers.insert(ip);

      if (type == QType::DNAME) {
        setLWResult(res, RCode::FormErr);
        if (EDNS0Level > 0) {
          res->d_haveEDNS = true;
        }
        return 1;
      }

      return 0;
    });

  primeHints();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::DNAME), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesWithEDNS, 26U);
  BOOST_CHECK_EQUAL(queriesWithoutEDNS, 0U);
  BOOST_CHECK_EQUAL(SyncRes::getEDNSStatusesSize(), 26U);
  BOOST_CHECK_EQUAL(usedServers.size(), 26U);
  for (const auto& server : usedServers) {
    BOOST_CHECK_EQUAL(SyncRes::getEDNSStatus(server), SyncRes::EDNSStatus::EDNSOK);
  }
}

BOOST_AUTO_TEST_CASE(test_meta_types) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  static const std::set<uint16_t> invalidTypes = { 128, QType::AXFR, QType::IXFR, QType::RRSIG, QType::NSEC3, QType::OPT, QType::TSIG, QType::TKEY, QType::MAILA, QType::MAILB, 65535 };

  for (const auto qtype : invalidTypes) {
    size_t queriesCount = 0;

    sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      return 0;
    });

    primeHints();

    vector<DNSRecord> ret;
    int res = sr->beginResolve(DNSName("powerdns.com."), QType(qtype), QClass::IN, ret);
    BOOST_CHECK_EQUAL(res, -1);
    BOOST_CHECK_EQUAL(ret.size(), 0U);
    BOOST_CHECK_EQUAL(queriesCount, 0U);
  }
}

BOOST_AUTO_TEST_CASE(test_tc_fallback_to_tcp) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  sr->setAsyncCallback([](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      if (!doTCP) {
        setLWResult(res, 0, false, true, false);
        return 1;
      }
      if (domain == DNSName("powerdns.com") && type == QType::A && doTCP) {
        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.1");
        return 1;
      }

      return 0;
    });

  primeHints();

  /* fake that the NS truncates every request over UDP, we should fallback to TCP */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
}

BOOST_AUTO_TEST_CASE(test_tc_over_tcp) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  size_t tcpQueriesCount = 0;

  sr->setAsyncCallback([&tcpQueriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      if (!doTCP) {
        setLWResult(res, 0, true, true, false);
        return 1;
      }

      /* first TCP query is answered with a TC response */
      tcpQueriesCount++;
      if (tcpQueriesCount == 1) {
        setLWResult(res, 0, true, true, false);
      }
      else {
        setLWResult(res, 0, true, false, false);
      }

      addRecordToLW(res, domain, QType::A, "192.0.2.1");
      return 1;
    });

  primeHints();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(tcpQueriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_all_nss_down) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return 1;
      }
      else {
        downServers.insert(ip);
        return 0;
      }
    });

  DNSName target("powerdns.com.");

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(downServers.size(), 4U);

  time_t now = sr->getNow().tv_sec;
  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 1U);
    BOOST_CHECK(SyncRes::isThrottled(now, server, target, QType::A));
  }
}

BOOST_AUTO_TEST_CASE(test_all_nss_network_error) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return 1;
      }
      else {
        downServers.insert(ip);
        return 0;
      }
    });

  /* exact same test than the previous one, except instead of a time out we fake a network error */
  DNSName target("powerdns.com.");

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(downServers.size(), 4U);

  time_t now = sr->getNow().tv_sec;
  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 1U);
    BOOST_CHECK(SyncRes::isThrottled(now, server, target, QType::A));
  }
}

BOOST_AUTO_TEST_CASE(test_only_one_ns_up_resolving_itself_with_glue) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  DNSName target("www.powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        if (domain == target) {
          addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
          addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        }
        else if (domain == DNSName("pdns-public-ns2.powerdns.net.")) {
          addRecordToLW(res, "powerdns.net.", QType::NS, "pdns-public-ns2.powerdns.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "powerdns.net.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "pdns-public-ns2.powerdns.net.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
          addRecordToLW(res, "pdns-public-ns2.powerdns.net.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        }
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.3:53")) {
        setLWResult(res, 0, true, false, true);
        if (domain == DNSName("pdns-public-ns2.powerdns.net.")) {
          if (type == QType::A) {
            addRecordToLW(res, "pdns-public-ns2.powerdns.net.", QType::A, "192.0.2.3");
          }
          else if (type == QType::AAAA) {
            addRecordToLW(res, "pdns-public-ns2.powerdns.net.", QType::AAAA, "2001:DB8::3");
          }
        }
        else if (domain == target) {
          if (type == QType::A) {
            addRecordToLW(res, domain, QType::A, "192.0.2.1");
          }
          else if (type == QType::AAAA) {
            addRecordToLW(res, domain, QType::AAAA, "2001:DB8::1");
          }
        }
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_os_limit_errors) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return 1;
      }
      else {
        if (downServers.size() < 3) {
          /* only the last one will answer */
          downServers.insert(ip);
          return -2;
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, "powerdns.com.", QType::A, "192.0.2.42");
          return 1;
        }
      }
    });

  DNSName target("powerdns.com.");

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(downServers.size(), 3U);

  /* Error is reported as "OS limit error" (-2) so the servers should _NOT_ be marked down */
  time_t now = sr->getNow().tv_sec;
  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 0U);
    BOOST_CHECK(!SyncRes::isThrottled(now, server, target, QType::A));
  }
}

BOOST_AUTO_TEST_CASE(test_glued_referral) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      /* this will cause issue with qname minimization if we ever implement it */
      if (domain != target) {
        return 0;
      }

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.2:53") || ip == ComboAddress("192.0.2.3:53") || ip == ComboAddress("[2001:DB8::2]:53") || ip == ComboAddress("[2001:DB8::3]:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.4");
        return 1;
      }
      else {
        return 0;
      }
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_glueless_referral) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);

        if (domain.isPartOf(DNSName("com."))) {
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        } else if (domain.isPartOf(DNSName("org."))) {
          addRecordToLW(res, "org.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        }
        else {
          setLWResult(res, RCode::NXDomain, false, false, true);
          return 1;
        }

        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        if (domain == target) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
          return 1;
        }
        else if (domain == DNSName("pdns-public-ns1.powerdns.org.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, "pdns-public-ns1.powerdns.org.", QType::A, "192.0.2.2");
          addRecordToLW(res, "pdns-public-ns1.powerdns.org.", QType::AAAA, "2001:DB8::2");
          return 1;
        }
        else if (domain == DNSName("pdns-public-ns2.powerdns.org.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, "pdns-public-ns2.powerdns.org.", QType::A, "192.0.2.3");
          addRecordToLW(res, "pdns-public-ns2.powerdns.org.", QType::AAAA, "2001:DB8::3");
          return 1;
        }

        setLWResult(res, RCode::NXDomain, false, false, true);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.2:53") || ip == ComboAddress("192.0.2.3:53") || ip == ComboAddress("[2001:DB8::2]:53") || ip == ComboAddress("[2001:DB8::3]:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.4");
        return 1;
      }
      else {
        return 0;
      }
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_edns_subnet_by_domain) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSDomain(target);

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

        /* this one did not use the ECS info */
        srcmask = boost::none;

        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        /* this one did, but only up to a precision of /16, not the full /24 */
        srcmask = Netmask("192.0.0.0/16");

        return 1;
      }

      return 0;
    });

  SyncRes::s_ecsqueries = 0;
  SyncRes::s_ecsresponses = 0;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(SyncRes::s_ecsqueries, 2U);
  BOOST_CHECK_EQUAL(SyncRes::s_ecsresponses, 1U);
  for (const auto& entry : SyncRes::s_ecsResponsesBySubnetSize4) {
    BOOST_CHECK_EQUAL(entry.second, entry.first == 15 ? 1U : 0U);
  }
  for (const auto& entry : SyncRes::s_ecsResponsesBySubnetSize6) {
    BOOST_CHECK_EQUAL(entry.second, 0U);
  }
}

BOOST_AUTO_TEST_CASE(test_edns_subnet_by_addr) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSRemoteSubnet("192.0.2.1/32");

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("2001:DB8::FF/128");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        BOOST_REQUIRE(srcmask);
        BOOST_CHECK_EQUAL(srcmask->toString(), "2001:db8::/56");

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  SyncRes::s_ecsqueries = 0;
  SyncRes::s_ecsresponses = 0;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(SyncRes::s_ecsqueries, 1U);
  BOOST_CHECK_EQUAL(SyncRes::s_ecsresponses, 1U);
  for (const auto& entry : SyncRes::s_ecsResponsesBySubnetSize4) {
    BOOST_CHECK_EQUAL(entry.second, 0u);
  }
  for (const auto& entry : SyncRes::s_ecsResponsesBySubnetSize6) {
    BOOST_CHECK_EQUAL(entry.second, entry.first == 55 ? 1U : 0U);
  }
}

BOOST_AUTO_TEST_CASE(test_ecs_use_requestor) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSRemoteSubnet("192.0.2.1/32");
  // No incoming ECS data
  sr->setQuerySource(ComboAddress("192.0.2.127"), boost::none);

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        BOOST_REQUIRE(srcmask);
        BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_ecs_use_scope_zero) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSRemoteSubnet("192.0.2.1/32");
  SyncRes::clearEDNSLocalSubnets();
  SyncRes::addEDNSLocalSubnet("192.0.2.254/32");
  // No incoming ECS data, Requestor IP not in ecs-add-for
  sr->setQuerySource(ComboAddress("192.0.2.127"), boost::none);

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        BOOST_REQUIRE(srcmask);
        BOOST_CHECK_EQUAL(srcmask->toString(), "127.0.0.1/32");

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_ecs_honor_incoming_mask) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSRemoteSubnet("192.0.2.1/32");
  SyncRes::clearEDNSLocalSubnets();
  SyncRes::addEDNSLocalSubnet("192.0.2.254/32");
  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.0.0/16");
  sr->setQuerySource(ComboAddress("192.0.2.127"), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        BOOST_REQUIRE(srcmask);
        BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.0.0/16");

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_ecs_honor_incoming_mask_zero) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSRemoteSubnet("192.0.2.1/32");
  SyncRes::clearEDNSLocalSubnets();
  SyncRes::addEDNSLocalSubnet("192.0.2.254/32");
  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("0.0.0.0/0");
  sr->setQuerySource(ComboAddress("192.0.2.127"), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        BOOST_REQUIRE(srcmask);
        BOOST_CHECK_EQUAL(srcmask->toString(), "127.0.0.1/32");

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_following_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cname.powerdns.com.");
  const DNSName cnameTarget("cname-target.powerdns.com");

  sr->setAsyncCallback([target, cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
          return 1;
        }
        else if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
        }

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[1].d_name, cnameTarget);
}

BOOST_AUTO_TEST_CASE(test_cname_nxdomain) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cname.powerdns.com.");
  const DNSName cnameTarget("cname-target.powerdns.com");

  sr->setAsyncCallback([target, cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        if (domain == target) {
          setLWResult(res, RCode::NXDomain, true, false, false);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
          addRecordToLW(res, "powerdns.com.", QType::SOA, "a.powerdns.com. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        } else if (domain == cnameTarget) {
          setLWResult(res, RCode::NXDomain, true, false, false);
          addRecordToLW(res, "powerdns.com.", QType::SOA, "a.powerdns.com. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          return 1;
        }

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[1].d_type == QType::SOA);

  /* a second time, to check the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[1].d_type == QType::SOA);
}

BOOST_AUTO_TEST_CASE(test_included_poisonous_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* In this test we directly get the NS server for cname.powerdns.com.,
     and we don't know whether it's also authoritative for
     cname-target.powerdns.com or powerdns.com, so we shouldn't accept
     the additional A record for cname-target.powerdns.com. */
  const DNSName target("cname.powerdns.com.");
  const DNSName cnameTarget("cname-target.powerdns.com");

  sr->setAsyncCallback([target, cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);

        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL);
          return 1;
        } else if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.3");
          return 1;
        }

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_REQUIRE(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(getRR<CNAMERecordContent>(ret[0])->getTarget(), cnameTarget);
  BOOST_REQUIRE(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[1].d_name, cnameTarget);
  BOOST_CHECK(getRR<ARecordContent>(ret[1])->getCA() == ComboAddress("192.0.2.3"));
}

BOOST_AUTO_TEST_CASE(test_cname_loop) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t count = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&count](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      count++;

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::CNAME, domain.toString());
          return 1;
        }

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_GT(ret.size(), 0U);
  BOOST_CHECK_EQUAL(count, 2U);
}

BOOST_AUTO_TEST_CASE(test_cname_depth) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t depth = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&depth](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::CNAME, std::to_string(depth) + "-cname.powerdns.com");
        depth++;
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), depth);
  /* we have an arbitrary limit at 10 when following a CNAME chain */
  BOOST_CHECK_EQUAL(depth, 10U + 2U);
}

BOOST_AUTO_TEST_CASE(test_time_limit) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queries = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queries++;

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        /* Pretend that this query took 2000 ms */
        res->d_usec = 2000;

        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  /* Set the maximum time to 1 ms */
  SyncRes::s_maxtotusec = 1000;

  try {
    vector<DNSRecord> ret;
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch(const ImmediateServFailException& e) {
  }
  BOOST_CHECK_EQUAL(queries, 1U);
}

BOOST_AUTO_TEST_CASE(test_dname_processing) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName dnameOwner("powerdns.com");
  const DNSName dnameTarget("powerdns.net");

  const DNSName target("dname.powerdns.com.");
  const DNSName cnameTarget("dname.powerdns.net");

  const DNSName uncachedTarget("dname-uncached.powerdns.com.");
  const DNSName uncachedCNAMETarget("dname-uncached.powerdns.net.");

  const DNSName synthCNAME("cname-uncached.powerdns.com.");
  const DNSName synthCNAMETarget("cname-uncached.powerdns.net.");

  size_t queries = 0;

  sr->setAsyncCallback([dnameOwner, dnameTarget, target, cnameTarget, uncachedTarget, uncachedCNAMETarget, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queries++;

      if (isRootServer(ip)) {
        if (domain.isPartOf(dnameOwner)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameOwner, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        if (domain.isPartOf(dnameTarget)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameTarget, QType::NS, "b.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "b.gtld-servers.net.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, dnameOwner, QType::DNAME, dnameTarget.toString());
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
        }
        if (domain == uncachedCNAMETarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.3");
        }
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);

  BOOST_CHECK_EQUAL(queries, 4u);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[1].d_name, target);

  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[2].d_name, cnameTarget);

  // Now check the cache
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);

  BOOST_CHECK_EQUAL(queries, 4U);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[1].d_name, target);

  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[2].d_name, cnameTarget);

  // Check if we correctly return a synthesizd CNAME, should send out just 1 more query
  ret.clear();
  res = sr->beginResolve(uncachedTarget, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(queries, 5U);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_REQUIRE(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[1].d_name, uncachedTarget);
  BOOST_CHECK_EQUAL(getRR<CNAMERecordContent>(ret[1])->getTarget(), uncachedCNAMETarget);

  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[2].d_name, uncachedCNAMETarget);

  // Check if we correctly return the DNAME from cache when asked
  ret.clear();
  res = sr->beginResolve(dnameOwner, QType(QType::DNAME), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(queries, 5U);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  // Check if we correctly return the synthesized CNAME from cache when asked
  ret.clear();
  res = sr->beginResolve(synthCNAME, QType(QType::CNAME), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(queries, 5U);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_REQUIRE(ret[1].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_name == synthCNAME);
  BOOST_CHECK_EQUAL(getRR<CNAMERecordContent>(ret[1])->getTarget(), synthCNAMETarget);
}

BOOST_AUTO_TEST_CASE(test_dname_dnssec_secure) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();

  const DNSName dnameOwner("powerdns");
  const DNSName dnameTarget("example");

  const DNSName target("dname.powerdns");
  const DNSName cnameTarget("dname.example");

  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(dnameOwner, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(dnameTarget, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queries = 0;

  sr->setAsyncCallback([dnameOwner, dnameTarget, target, cnameTarget, keys, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queries++;
      /* We don't use the genericDSAndDNSKEYHandler here, as it would deny names existing at the wrong level of the tree, due to the way computeZoneCuts works
       * As such, we need to do some more work to make the answers correct.
       */

      if (isRootServer(ip)) {
        if (domain.countLabels() == 0 && type == QType::DNSKEY) { // .|DNSKEY
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
        if (domain.countLabels() == 1 && type == QType::DS) { // powerdns|DS or example|DS
          setLWResult(res, 0, true, false, true);
          addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
        // For the rest, delegate!
        if (domain.isPartOf(dnameOwner)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameOwner, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addDS(dnameOwner, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        if (domain.isPartOf(dnameTarget)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameTarget, QType::NS, "b.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addDS(dnameTarget, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "b.gtld-servers.net.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain.countLabels() == 1 && type == QType::DNSKEY) { // powerdns|DNSKEY
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        if (domain == target && type == QType::DS) { // dname.powerdns|DS
          return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
        }
        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, dnameOwner, QType::DNAME, dnameTarget.toString());
          addRRSIG(keys, res->d_records, dnameOwner, 300);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString()); // CNAME from a DNAME is not signed
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain.countLabels() == 1 && type == QType::DNSKEY) { // example|DNSKEY
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        if (domain == cnameTarget && type == QType::DS) { // dname.example|DS
          return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
        }
        if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
          addRRSIG(keys, res->d_records, dnameTarget, 300);
        }
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 5U); /* DNAME + RRSIG(DNAME) + CNAME + A + RRSIG(A) */

  BOOST_CHECK_EQUAL(queries, 11U);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_REQUIRE(ret[1].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[1].d_name, dnameOwner);

  BOOST_CHECK(ret[2].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[2].d_name, target);

  BOOST_CHECK(ret[3].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[3].d_name, cnameTarget);

  BOOST_CHECK(ret[4].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[4].d_name, cnameTarget);

  // And the cache
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 5U); /* DNAME + RRSIG(DNAME) + CNAME + A + RRSIG(A) */

  BOOST_CHECK_EQUAL(queries, 11U);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[1].d_name, dnameOwner);

  BOOST_CHECK(ret[2].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[2].d_name, target);

  BOOST_CHECK(ret[3].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[3].d_name, cnameTarget);

  BOOST_CHECK(ret[4].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[4].d_name, cnameTarget);

}

BOOST_AUTO_TEST_CASE(test_dname_dnssec_insecure) {
  /*
   * The DNAME itself is signed, but the final A record is not
   */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();

  const DNSName dnameOwner("powerdns");
  const DNSName dnameTarget("example");

  const DNSName target("dname.powerdns");
  const DNSName cnameTarget("dname.example");

  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(dnameOwner, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queries = 0;

  sr->setAsyncCallback([dnameOwner, dnameTarget, target, cnameTarget, keys, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queries++;

      if (isRootServer(ip)) {
        if (domain.countLabels() == 0 && type == QType::DNSKEY) { // .|DNSKEY
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
        if (domain == dnameOwner && type == QType::DS) { // powerdns|DS
          setLWResult(res, 0, true, false, true);
          addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
        if (domain == dnameTarget && type == QType::DS) { // example|DS
          return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys);
        }
        // For the rest, delegate!
        if (domain.isPartOf(dnameOwner)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameOwner, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addDS(dnameOwner, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        if (domain.isPartOf(dnameTarget)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameTarget, QType::NS, "b.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addDS(dnameTarget, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "b.gtld-servers.net.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain.countLabels() == 1 && type == QType::DNSKEY) { // powerdns|DNSKEY
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        if (domain == target && type == QType::DS) { // dname.powerdns|DS
          return genericDSAndDNSKEYHandler(res, domain, dnameOwner, type, keys, false);
        }
        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, dnameOwner, QType::DNAME, dnameTarget.toString());
          addRRSIG(keys, res->d_records, dnameOwner, 300);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString()); // CNAME from a DNAME is not signed
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == target && type == QType::DS) { // dname.example|DS
          return genericDSAndDNSKEYHandler(res, domain, dnameTarget, type, keys, false);
        }
        if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
        }
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U); /* DNAME + RRSIG(DNAME) + CNAME + A */

  BOOST_CHECK_EQUAL(queries, 9U);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[1].d_name, dnameOwner);

  BOOST_CHECK(ret[2].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[2].d_name, target);

  BOOST_CHECK(ret[3].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[3].d_name, cnameTarget);

  // And the cache
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U); /* DNAME + RRSIG(DNAME) + CNAME + A */

  BOOST_CHECK_EQUAL(queries, 9U);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[1].d_name, dnameOwner);

  BOOST_CHECK(ret[2].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[2].d_name, target);

  BOOST_CHECK(ret[3].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[3].d_name, cnameTarget);
}

BOOST_AUTO_TEST_CASE(test_dname_processing_no_CNAME) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName dnameOwner("powerdns.com");
  const DNSName dnameTarget("powerdns.net");

  const DNSName target("dname.powerdns.com.");
  const DNSName cnameTarget("dname.powerdns.net");

  size_t queries = 0;

  sr->setAsyncCallback([dnameOwner, dnameTarget, target, cnameTarget, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queries++;

      if (isRootServer(ip)) {
        if (domain.isPartOf(dnameOwner)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameOwner, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        if (domain.isPartOf(dnameTarget)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameTarget, QType::NS, "b.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "b.gtld-servers.net.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, dnameOwner, QType::DNAME, dnameTarget.toString());
          // No CNAME, recursor should synth
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
        }
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);

  BOOST_CHECK_EQUAL(queries, 4U);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[1].d_name, target);

  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[2].d_name, cnameTarget);

  // Now check the cache
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);

  BOOST_CHECK_EQUAL(queries, 4U);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[1].d_name, target);

  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[2].d_name, cnameTarget);
}

/*
// cerr<<"asyncresolve called to ask "<<ip.toStringWithPort()<<" about "<<domain.toString()<<" / "<<QType(type).getName()<<" over "<<(doTCP ? "TCP" : "UDP")<<" (rd: "<<sendRDQuery<<", EDNS0 level: "<<EDNS0Level<<")"<<endl;

- check out of band support

- check preoutquery

*/
BOOST_AUTO_TEST_SUITE_END()
