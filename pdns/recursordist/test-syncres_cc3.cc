#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc3)

BOOST_AUTO_TEST_CASE(test_cache_auth) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* the auth server is sending the same answer in answer and additional,
     check that we only return one result, and we only cache one too. */
  const DNSName target("cache-auth.powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);
      addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 10);

      return 1;
    });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_REQUIRE_EQUAL(QType(ret.at(0).d_type).getName(), QType(QType::A).getName());
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret.at(0))->getCA().toString(), ComboAddress("192.0.2.2").toString());

  /* check that we correctly cached only the answer entry, not the additional one */
  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_EQUAL(QType(cached.at(0).d_type).getName(), QType(QType::A).getName());
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(cached.at(0))->getCA().toString(), ComboAddress("192.0.2.2").toString());
}

BOOST_AUTO_TEST_CASE(test_delegation_only) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* Thanks, Verisign */
  SyncRes::addDelegationOnly(DNSName("com."));
  SyncRes::addDelegationOnly(DNSName("net."));

  const DNSName target("nx-powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_unauth_any) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

static void test_no_data_f(bool qmin) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  if (qmin)
    sr->setQNameMinimization();

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback(
    [target](const ComboAddress &ip, const DNSName &domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level,
             struct timeval *now, boost::optional <Netmask> &srcmask, boost::optional<const ResolveContext &> context,
             LWResult *res, bool *chained) {

      setLWResult(res, 0, true, false, true);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_no_data) {
  test_no_data_f(false);
}

BOOST_AUTO_TEST_CASE(test_no_data_qmin) {
  test_no_data_f(true);
}

BOOST_AUTO_TEST_CASE(test_skip_opt_any) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      addRecordToLW(res, domain, QType::ANY, "0 0");
      addRecordToLW(res, domain, QType::OPT, "");
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_nodata_nsec_nodnssec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_nodata_nsec_dnssec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 4U);
}

BOOST_AUTO_TEST_CASE(test_nx_nsec_nodnssec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, RCode::NXDomain, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_nx_nsec_dnssec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, RCode::NXDomain, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 4U);
}

BOOST_AUTO_TEST_CASE(test_qclass_none) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* apart from special names and QClass::ANY, anything else than QClass::IN should be rejected right away */
  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      return 0;
    });

  const DNSName target("powerdns.com.");
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::NONE, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_answer_no_aa) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.1");
      return 1;
    });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);

  /* check that the record in the answer section has not been cached */
  const ComboAddress who;
  vector<DNSRecord> cached;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  BOOST_REQUIRE_EQUAL(t_RC->get(now, target, QType(QType::A), false, &cached, who, &signatures), -1);
}

BOOST_AUTO_TEST_CASE(test_special_types) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* {A,I}XFR, RRSIG and NSEC3 should be rejected right away */
  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      cerr<<"asyncresolve called to ask "<<ip.toStringWithPort()<<" about "<<domain.toString()<<" / "<<QType(type).getName()<<" over "<<(doTCP ? "TCP" : "UDP")<<" (rd: "<<sendRDQuery<<", EDNS0 level: "<<EDNS0Level<<")"<<endl;
      queriesCount++;
      return 0;
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

BOOST_AUTO_TEST_CASE(test_special_names) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* special names should be handled internally */

  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      return 0;
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

BOOST_AUTO_TEST_CASE(test_nameserver_ipv4_rpz) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, false, true, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
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
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -2);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_nameserver_ipv6_rpz) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("[2001:DB8::42]:53");

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
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
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -2);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_nameserver_name_rpz) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const DNSName nsName("ns1.powerdns.com.");

  sr->setAsyncCallback([target,ns,nsName](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, nsName.toString(), DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, nsName, QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
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
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -2);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_nameserver_name_rpz_disabled) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const DNSName nsName("ns1.powerdns.com.");

  sr->setAsyncCallback([target,ns,nsName](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, nsName.toString(), DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, nsName, QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
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

BOOST_AUTO_TEST_CASE(test_forward_zone_nord) {
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

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (ip == forwardedNS) {
        BOOST_CHECK_EQUAL(sendRDQuery, false);

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  /* simulate a no-RD query */
  sr->setCacheOnly();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_rd) {
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

  sr->setAsyncCallback([forwardedNS, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (ip == forwardedNS) {
        BOOST_CHECK_EQUAL(sendRDQuery, true);

        /* set AA=0, we are a recursor */
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
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

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_nord) {
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

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (ip == forwardedNS) {
        BOOST_CHECK_EQUAL(sendRDQuery, false);

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  /* simulate a no-RD query */
  sr->setCacheOnly();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd) {
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

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (ip == forwardedNS) {
        BOOST_CHECK_EQUAL(sendRDQuery, true);

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd_dnssec) {
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

  sr->setAsyncCallback([target,cnameTarget,keys,forwardedNS,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      BOOST_CHECK_EQUAL(sendRDQuery, true);

      if (ip != forwardedNS) {
        return 0;
      }

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys);
      }

      if (domain == target && type == QType::A) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, target, QType::CNAME, cnameTarget.toString());
        addRRSIG(keys, res->d_records, domain, 300);
        addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");

        return 1;
      }
      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd_dnssec_bogus) {
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

  sr->setAsyncCallback([target,cnameTarget,keys,forwardedNS,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      BOOST_CHECK_EQUAL(sendRDQuery, true);

      if (ip != forwardedNS) {
        return 0;
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

        return 1;
      }
      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd_dnssec_nodata_bogus) {
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

  sr->setAsyncCallback([target,forwardedNS,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      BOOST_CHECK_EQUAL(sendRDQuery, true);

      if (ip != forwardedNS) {
        return 0;
      }

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
      else {

        setLWResult(res, 0, false, false, true);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* com|NS, powerdns.com|NS, powerdns.com|A */
  BOOST_CHECK_EQUAL(queriesCount, 3U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* we don't store empty results */
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_oob) {
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
  dr.d_content = std::make_shared<ARecordContent>(targetAddr);
  ad.d_records.insert(dr);

  (*SyncRes::t_sstorage.domainmap)[authZone] = ad;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
        queriesCount++;
        return 0;
      });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);

  /* a second time, to check that the OOB flag is set when the query cache is used */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);

  /* a third time, to check that the validation is disabled when the OOB flag is set */
  ret.clear();
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_oob_cname) {
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
  dr.d_content = std::make_shared<CNAMERecordContent>(targetCname);
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = targetCname;
  dr.d_type = QType::A;
  dr.d_ttl = 1800;
  dr.d_content = std::make_shared<ARecordContent>(targetCnameAddr);
  ad.d_records.insert(dr);

  (*SyncRes::t_sstorage.domainmap)[authZone] = ad;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
        queriesCount++;
        return 0;
      });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);

  /* a second time, to check that the OOB flag is set when the query cache is used */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0U);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);

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
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
}

BOOST_AUTO_TEST_CASE(test_auth_zone) {
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
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<ARecordContent>(addr);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[target] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return 1;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 0U);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_cname_lead_to_oob) {
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
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<ARecordContent>(addr);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount,target,authZone](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (domain == target) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::CNAME, authZone.toString(), DNSResourceRecord::ANSWER, 3600);
        return 1;
      }

      return 0;
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

BOOST_AUTO_TEST_CASE(test_auth_zone_oob_lead_to_outgoing_queryb) {
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
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::CNAME;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<CNAMERecordContent>(externalCNAME);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[target] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount,externalCNAME,addr](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (domain == externalCNAME) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, externalCNAME, QType::A, addr.toString(), DNSResourceRecord::ANSWER, 3600);
        return 1;
      }

      return 0;
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

BOOST_AUTO_TEST_SUITE_END()
