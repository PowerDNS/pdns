#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "aggressive_nsec.hh"
#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(aggressive_nsec_cc)

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_nxdomain)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>();

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we are lucky enough that our hashes will cover g.powerdns.com. as well */
  const DNSName target1("b.powerdns.com.");
  const DNSName target2("g.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target1, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC3 */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false, boost::none, true);
      }
      else if (domain == DNSName("com.")) {
        /* no cut */
        return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys, false);
      }
      else if (domain == DNSName("powerdns.com.")) {
        return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys);
      }
      else {
        /* cut */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain == target1) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          /* no data */
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* no record for this name */
          /* first the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* then the next closer */
          addNSEC3UnhashedRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG, QType::NSEC}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* no wildcard */
          addNSEC3NarrowRecordToLW(DNSName("*.powerdns.com."), DNSName("powerdns.com."), {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

#if 0
BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>();

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target1("a.powerdns.com.");
  const DNSName target2("b.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target1, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC3 */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false, boost::none, true);
      }
      else if (domain == DNSName("com.")) {
        /* no cut */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        /* cut */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain == target1) {
          setLWResult(res, 0, true, false, true);
          /* no data */
          addRecordToLW(res, DNSName("com."), QType::SOA, "com. com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* no record for this name */
          /* first the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("com."), DNSName("com."), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* then the next closer */
          addNSEC3NarrowRecordToLW(domain, DNSName("com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* a wildcard matches but has no record for this type */
          addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
