#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc10)
BOOST_AUTO_TEST_CASE(test_outgoing_v4_only)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  SyncRes::s_doIPv6 = false;
  primeHints();
  bool v6Hit = false;
  bool v4Hit = false;
  int queries = 0;

  const DNSName target("powerdns.com.");
  sr->setAsyncCallback([target, &v4Hit, &v6Hit, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queries++;
    if (isRootServer(ip)) {
      setLWResult(res, 0, false, false, true);
      v4Hit |= ip.isIPv4();
      v6Hit |= ip.isIPv6();

      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "ns1.powerdns.com.", QType::AAAA, "2001:DB8:1::53", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return 1;
    }
    else if (ip == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, true, false, false);
      v4Hit |= true;
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }
      return 1;
    }
    else if (ip == ComboAddress("[2001:DB8:1::53]:53")) {
      setLWResult(res, 0, true, false, false);
      v6Hit |= true;
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }
      return 1;
    }
    return 0;
  });

  vector<DNSRecord> ret;
  int rcode;
  rcode = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_REQUIRE_EQUAL(queries, 2);
  BOOST_REQUIRE_EQUAL(v4Hit, true);
  BOOST_REQUIRE_EQUAL(v6Hit, false);
  BOOST_CHECK_EQUAL(rcode, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_outgoing_v4_only_no_A_in_delegation)
{
  // The name is not resolvable, as there's no A glue for an in-bailiwick NS
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  SyncRes::s_doIPv6 = false;
  primeHints();
  int queries = 0;

  const DNSName target("powerdns.com.");
  sr->setAsyncCallback([target, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queries++;
    if (isRootServer(ip)) {
      setLWResult(res, 0, false, false, true);

      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "ns1.powerdns.com.", QType::AAAA, "2001:DB8:1::53", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return 1;
    }
    else if (ip == ComboAddress("[2001:DB8:1::53]:53")) {
      setLWResult(res, 0, true, false, false);
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }
      return 1;
    }
    return 0;
  });

  vector<DNSRecord> ret;
  int rcode;
  rcode = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_REQUIRE_EQUAL(queries, 14); // We keep trying all parent nameservers, this is wrong!
  BOOST_CHECK_EQUAL(rcode, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_outgoing_v6_only_no_AAAA_in_delegation)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  SyncRes::s_doIPv4 = false;
  SyncRes::s_doIPv6 = true;
  primeHints();
  int queries = 0;

  const DNSName target("powerdns.com.");
  sr->setAsyncCallback([target, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queries++;
    if (isRootServer(ip)) {
      setLWResult(res, 0, false, false, true);
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return 1;
    }
    else if (ip == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, true, false, false);
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }
      return 1;
    }
    return 0;
  });

  vector<DNSRecord> ret;
  int rcode;
  rcode = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_REQUIRE_EQUAL(queries, 14); // The recursor tries all parent nameservers... this needs to be fixed
  BOOST_CHECK_EQUAL(rcode, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
