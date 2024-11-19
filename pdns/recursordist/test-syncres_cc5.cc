#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc5)

BOOST_AUTO_TEST_CASE(test_dnssec_secure_various_algos)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::RSASHA512, DNSSECKeeper::DIGEST_SHA384, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA384, DNSSECKeeper::DIGEST_SHA384, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  /* make sure that the signature inception and validity times are computed
     based on the SyncRes time, not the current one, in case the function
     takes too long. */

  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    if (domain == target) {
      auth = DNSName("powerdns.com.");
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, true, fixedNow);
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
      addDS(DNSName("com."), 300, res->d_records, keys);
      addRRSIG(keys, res->d_records, DNSName("."), 300, false, boost::none, boost::none, fixedNow);
      addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.1:53")) {
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
        addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, domain, 300);
      }
      else {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, auth, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(auth, 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("com."), 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.2:53")) {
      if (type == QType::NS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, auth, 300);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

static void testFixedPointInTime(time_t fixedNow)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true, false, fixedNow);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints(fixedNow);
  const DNSName target("powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::RSASHA512, DNSSECKeeper::DIGEST_SHA384, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA384, DNSSECKeeper::DIGEST_SHA384, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    if (domain == target) {
      auth = DNSName("powerdns.com.");
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, true, fixedNow);
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
      addDS(DNSName("com."), 300, res->d_records, keys);
      addRRSIG(keys, res->d_records, DNSName("."), 300, false, boost::none, boost::none, fixedNow);
      addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.1:53")) {
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
        addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, fixedNow);
      }
      else {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, auth, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(auth, 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("com."), 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.2:53")) {
      if (type == QType::NS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_various_algos1970)
{
  /* validity period in ye olde times */
  const time_t fixedNow = 1800;
  testFixedPointInTime(fixedNow);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_various_algos2038)
{
  /* validity period contains the wrapping point in 2038 */
  const time_t fixedNow = INT_MAX - 1800;
  testFixedPointInTime(fixedNow);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_various_algos2041)
{
  /* validity period completely after 2038 but not wrapping uint32_t*/
  const time_t fixedNow = time_t(INT_MAX) + 100000000;
  testFixedPointInTime(fixedNow);
}

#if 0
// Currently fails see validate.cc:isRRSIGNotExpired() and isRRSIGIncepted()
BOOST_AUTO_TEST_CASE(test_dnssec_secure_various_algos2106)
{
  /* validity period beyond 2106 uint32_t wrapping point */
  const time_t fixedNow = 2 * time_t(INT_MAX);
  testFixedPointInTime(fixedNow);
}
#endif

BOOST_AUTO_TEST_CASE(test_dnssec_secure_a_then_ns)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    if (domain == target) {
      auth = DNSName("powerdns.com.");
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }

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
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        addRRSIG(keys, res->d_records, auth, 300);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, auth, 300);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, auth, 300);
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* this time we ask for the NS that should be in the cache, to check
     the validation status */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_a_then_ns)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    if (domain == target) {
      auth = DNSName("powerdns.com.");
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }

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
        /* no DS */
        addNSECRecordToLW(domain, DNSName("z.powerdns.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.2:53")) {
      if (type == QType::NS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* this time we ask for the NS that should be in the cache, to check
     the validation status */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_with_nta)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  /* Add a NTA for "powerdns.com" */
  luaconfsCopy.negAnchors[target] = "NTA for PowerDNS.com";

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    if (domain == target) {
      auth = DNSName("powerdns.com.");
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }

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
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        addRRSIG(keys, res->d_records, auth, 300);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, auth, 300);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, auth, 300);
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* Should be insecure because of the NTA */
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* Should be insecure because of the NTA */
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_with_nta)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  /* Add a NTA for "powerdns.com" */
  luaconfsCopy.negAnchors[target] = "NTA for PowerDNS.com";

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      return LWResult::Result::Success;
    }
    {
      if (isRootServer(address)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.1:53")) {
        if (domain == DNSName("com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        }
        else {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        if (type == QType::NS) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        else {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  /* There is TA for root but no DS/DNSKEY/RRSIG, should be Bogus, but.. */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* Should be insecure because of the NTA */
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 3U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
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
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(domain, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        if (type == QType::NS) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, domain, 300);
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), {QType::NS, QType::DNSKEY}, 600, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nxdomain_nsec)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("nx.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    if (domain == target) {
      auth = DNSName("powerdns.com.");
    }
    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, auth, 300);
        addNSECRecordToLW(DNSName("nw.powerdns.com."), DNSName("ny.powerdns.com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
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
          else {
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addNSECRecordToLW(DNSName("nx.powerdns.com."), DNSName("nz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
        }
        else {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, auth, 300);
          addNSECRecordToLW(DNSName("nw.powerdns.com."), DNSName("ny.powerdns.com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
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
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec_wildcard)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
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
          addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        if (type == QType::NS) {
          if (domain == DNSName("powerdns.com.")) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
          else {
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
        }
        else {
          addRecordToLW(res, domain, QType::A, "192.0.2.42", DNSResourceRecord::ANSWER, 600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
          /* we need to add the proof that this name does not exist, so the wildcard may apply */
          addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 60, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  for (const auto& rec : ret) {
    /* check that we applied the lowest TTL, here this is from the NSEC proving that the exact name did not exist */
    BOOST_CHECK_LE(rec.d_ttl, 60U);
  }
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec_wildcard_proof_before_rrsig)
{
  /* this tests makes sure that we correctly detect that we need to gather
     wildcard proof (since the answer is expanded from a wildcard, we need
     to prove that the target name does not exist) even though the RRSIG which
     allows us to detect that the answer is an expanded wildcard (from the label
     count field of the RRSIG) comes _after_ the NSEC
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
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
          addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        if (type == QType::NS) {
          if (domain == DNSName("powerdns.com.")) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
          else {
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
        }
        else {
          addRecordToLW(res, domain, QType::A, "192.0.2.42", DNSResourceRecord::ANSWER, 600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
          /* we need to add the proof that this name does not exist, so the wildcard may apply */
          addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 60, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          /* now this is the important part! We are swapping the first RRSIG and the NSEC, to make sure we still gather the NSEC proof that the
             exact name does not exist even though we have not seen the RRSIG whose label count is smaller than the target name yet */
          std::swap(res->d_records.at(1), res->d_records.at(3));
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  for (const auto& rec : ret) {
    /* check that we applied the lowest TTL, here this is from the NSEC proving that the exact name did not exist */
    BOOST_CHECK_LE(rec.d_ttl, 60U);
  }
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec_wildcard_proof_cname)
{
  /* this tests makes sure that we correctly detect that we need to gather
     wildcard proof (since the answer is expanded from a wildcard, we need
     to prove that the target name does not exist) even though the answer is
     a CNAME
  */
  std::unique_ptr<SyncRes> resolver;
  initSR(resolver, true);

  setDNSSECValidation(resolver, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.powerdns.com.");
  const DNSName alias("alias.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  resolver->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
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
        addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53")) {
      setLWResult(res, 0, true, false, true);
      if (type == QType::NS) {
        if (domain == DNSName("powerdns.com.")) {
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        }
        else {
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        }
      }
      else if (domain == target) {
        addRecordToLW(res, domain, QType::CNAME, "alias.powerdns.com", DNSResourceRecord::ANSWER, 600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
        /* we need to add the proof that this name does not exist, so the wildcard may apply,
           and we are NOT including it */
      }
      else if (domain == alias) {
        addRecordToLW(res, alias, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = resolver->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::BogusInvalidDenial);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* again, to test the cache */
  ret.clear();
  res = resolver->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::BogusInvalidDenial);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec_nodata_nowildcard)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        DNSName auth("com.");
        setLWResult(res, 0, true, false, true);

        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC denying the DS AND the existence of a cut (no NS) */
        addNSECRecordToLW(domain, DNSName("z") + domain, {QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
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
        setLWResult(res, 0, true, false, true);
        /* no data */
        addRecordToLW(res, DNSName("com."), QType::SOA, "com. com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* no record for this name */
        addNSECRecordToLW(DNSName("wwv.com."), DNSName("wwx.com."), {QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* a wildcard matches but has no record for this type */
        addNSECRecordToLW(DNSName("*.com."), DNSName("com."), {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_nodata_nowildcard)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        DNSName auth("com.");
        setLWResult(res, 0, true, false, true);

        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC3 denying the DS AND the existence of a cut (no NS) */
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("com."), auth, "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        /* then the next closer */
        addNSEC3NarrowRecordToLW(domain, DNSName("com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        /* a wildcard matches but has no record for this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
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

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_too_many_nsec3s)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        DNSName auth("com.");
        setLWResult(res, 0, true, false, true);

        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC3 denying the DS AND the existence of a cut (no NS) */
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("com."), auth, "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        /* then the next closer */
        addNSEC3NarrowRecordToLW(domain, DNSName("com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        /* a wildcard matches but has no record for this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.1:53")) {
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

    return LWResult::Result::Timeout;
  });

  /* we allow at most 2 NSEC3s, but we need at least 3 of them to
     get a valid denial so we will go Bogus */
  g_maxNSEC3sPerRecordToConsider = 2;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusInvalidDenial);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  g_maxNSEC3sPerRecordToConsider = 0;
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_too_many_nsec3s_per_query)
{
  SyncRes::s_maxnsec3iterationsperq = 20;
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        DNSName auth("com.");
        setLWResult(res, 0, true, false, true);

        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC3 denying the DS AND the existence of a cut (no NS) */
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("com."), auth, "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        /* then the next closer */
        addNSEC3NarrowRecordToLW(domain, DNSName("com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        /* a wildcard matches but has no record for this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.1:53")) {
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

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  BOOST_CHECK_THROW(sr->beginResolve(target, QType(QType::A), QClass::IN, ret), pdns::validation::TooManySEC3IterationsException);

  SyncRes::s_maxnsec3iterationsperq = 0;
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_nodata_nowildcard_duplicated_nsec3)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        DNSName auth("com.");
        setLWResult(res, 0, true, false, true);

        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC3 denying the DS AND the existence of a cut (no NS) */
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("com."), auth, "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        /* then the next closer */
        addNSEC3NarrowRecordToLW(domain, DNSName("com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        /* a wildcard matches but has no record for this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
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
      // The code below introduces duplicate NSEC3 records
      if (address == ComboAddress("192.0.2.1:53")) {
        setLWResult(res, 0, true, false, true);
        /* no data */
        addRecordToLW(res, DNSName("com."), QType::SOA, "com. com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* no record for this name */
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("com."), DNSName("com."), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* !! we duplicate the NSEC3 on purpose, to check deduplication. The RRSIG will have been computed for a RRSET containing only one NSEC3 and should not be valid. */
        addNSEC3UnhashedRecordToLW(DNSName("com."), DNSName("com."), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records);
        /* then the next closer */
        addNSEC3NarrowRecordToLW(domain, DNSName("com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* a wildcard matches but has no record for this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  /* the duplicated NSEC3 have not been dedupped */
  BOOST_REQUIRE_EQUAL(ret.size(), 9U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  /* the duplicated NSEC3 have not been dedupped */
  BOOST_REQUIRE_EQUAL(ret.size(), 9U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_nodata_nowildcard_too_many_iterations)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        DNSName auth("com.");
        setLWResult(res, 0, true, false, true);

        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC3 denying the DS AND the existence of a cut (no NS) */
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("com."), auth, "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records, g_maxNSEC3Iterations + 100);
        addRRSIG(keys, res->d_records, auth, 300);
        /* then the next closer */
        addNSEC3NarrowRecordToLW(domain, DNSName("com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records, g_maxNSEC3Iterations + 100);
        addRRSIG(keys, res->d_records, auth, 300);
        /* a wildcard matches but has no record for this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records, g_maxNSEC3Iterations + 100);
        addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
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
        setLWResult(res, 0, true, false, true);
        /* no data */
        addRecordToLW(res, DNSName("com."), QType::SOA, "com. com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* no record for this name */
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("com."), DNSName("com."), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records, g_maxNSEC3Iterations + 100);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* then the next closer */
        addNSEC3NarrowRecordToLW(domain, DNSName("com."), {QType::RRSIG, QType::NSEC}, 600, res->d_records, g_maxNSEC3Iterations + 100);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* a wildcard matches but has no record for this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records, g_maxNSEC3Iterations + 100);
        addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  /* we are generating NSEC3 with more iterations than we allow, so we should go Insecure */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_wildcard)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.sub.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain.isPartOf(DNSName("sub.powerdns.com"))) {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        if (domain == DNSName("sub.powerdns.com")) {
          addNSECRecordToLW(DNSName("sub.powerdns.com."), DNSName("sud.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        }
        else if (domain == target) {
          addNSECRecordToLW(DNSName("www.sub.powerdns.com."), DNSName("wwz.sub.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        }
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
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
          addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        if (type == QType::NS) {
          if (domain == DNSName("powerdns.com.")) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
          else {
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
        }
        else {
          addRecordToLW(res, domain, QType::A, "192.0.2.42", DNSResourceRecord::ANSWER, 600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
          /* we need to add the proof that this name does not exist, so the wildcard may apply */
          /* first the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* then the next closer */
          addNSEC3NarrowRecordToLW(DNSName("sub.powerdns.com."), DNSName("powerdns.com."), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 60, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  for (const auto& rec : ret) {
    /* check that we applied the lowest TTL, here this is from the NSEC3 proving that the exact name did not exist (next closer) */
    BOOST_CHECK_LE(rec.d_ttl, 60U);
  }
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_wildcard_proof_cname)
{
  std::unique_ptr<SyncRes> resolver;
  initSR(resolver, true);

  setDNSSECValidation(resolver, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.powerdns.com.");
  const DNSName alias("alias.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  resolver->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /*sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
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
        addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53")) {
      setLWResult(res, 0, true, false, true);
      if (type == QType::NS) {
        if (domain == DNSName("powerdns.com.")) {
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        }
        else {
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        }
      }
      else {
        if (domain == target) {
          addRecordToLW(res, domain, QType::CNAME, "alias.powerdns.com.", DNSResourceRecord::ANSWER, 600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
          /* we need to add the proof that this name does not exist, so the wildcard may apply
             but we are NOT adding it! */
          /* first the closest encloser */
        }
        else if (domain == alias) {
          addRecordToLW(res, domain, QType::A, "192.0.2.42", DNSResourceRecord::ANSWER, 600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
        }
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = resolver->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::BogusInvalidDenial);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = resolver->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::BogusInvalidDenial);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_wildcard_too_many_iterations)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
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
          addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        if (type == QType::NS) {
          if (domain == DNSName("powerdns.com.")) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
          else {
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
        }
        else {
          addRecordToLW(res, domain, QType::A, "192.0.2.42");
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
          /* we need to add the proof that this name does not exist, so the wildcard may apply */
          /* first the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* then the next closer */
          addNSEC3NarrowRecordToLW(DNSName("www.powerdns.com."), DNSName("powerdns.com."), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, res->d_records, g_maxNSEC3Iterations + 100);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  /* the NSEC3 providing the denial of existence proof for the next closer has too many iterations,
     we should end up Insecure */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec_wildcard_missing)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == target) {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
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
          addRecordToLW(res, "powerdns.com.", QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        if (type == QType::NS) {
          if (domain == DNSName("powerdns.com.")) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
          else {
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
        }
        else {
          addRecordToLW(res, domain, QType::A, "192.0.2.42");
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusInvalidDenial);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusInvalidDenial);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_wildcard_expanded_onto_itself)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("*.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);

  g_luaconfs.setState(luaconfsCopy);

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == target) {
        const auto auth = DNSName("powerdns.com.");
        /* we don't want a cut there */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC denying the DS */
        std::set<uint16_t> types = {QType::NSEC};
        addNSECRecordToLW(domain, DNSName("z") + domain, types, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, boost::none, DNSName("*.powerdns.com"));
      /* we don't _really_ need to add the proof that the exact name does not exist because it does,
         it's the wildcard itself, but let's do it so other validators don't choke on it */
      addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
      addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
      return LWResult::Result::Success;
    }
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  /* A + RRSIG, NSEC + RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_wildcard_expanded_onto_itself_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("*.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);

  g_luaconfs.setState(luaconfsCopy);

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == target) {
        const auto auth = DNSName("powerdns.com.");
        /* we don't want a cut there */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC denying the DS */
        std::set<uint16_t> types = {QType::NSEC};
        addNSECRecordToLW(domain, DNSName("z") + domain, types, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "powerdns.com. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
      addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
      /* add the proof that the exact name does exist but that this type does not */
      addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("\\000.*.powerdns.com."), {QType::AAAA, QType::NSEC, QType::RRSIG}, 600, res->d_records);
      addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
      return LWResult::Result::Success;
    }
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  /* SOA + RRSIG, NSEC + RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_wildcard_like_expanded_from_wildcard)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("*.sub.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);

  g_luaconfs.setState(luaconfsCopy);

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == target) {
        const auto auth = DNSName("powerdns.com.");
        /* we don't want a cut there */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
        return LWResult::Result::Success;
      }
      if (domain == DNSName("sub.powerdns.com.")) {
        const auto auth = DNSName("powerdns.com.");
        /* we don't want a cut there */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC denying the DS */
        addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, boost::none, DNSName("*.powerdns.com"));
      addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
      addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
      return LWResult::Result::Success;
    }
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  /* A + RRSIG, NSEC + RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
}

// Tests PR 8648
BOOST_AUTO_TEST_CASE(test_dnssec_incomplete_cache_zonecut_qm)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true, false);
  sr->setQNameMinimization();
  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("net."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("herokuapp.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("nsone.net."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth(domain);
    DNSName com("com.");
    DNSName net("net.");
    DNSName nsone("nsone.net.");
    DNSName hero("herokuapp.com.");
    DNSName p03nsone("dns1.p03.nsone.net.");

    // cerr <<  ip.toString() << ": " << domain << '|' << QType(type).toString() << endl;
    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }

    if (isRootServer(address)) {
      if (domain == com) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, com, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(com, 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, g_rootdnsname, 300);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      }
      else if (domain == net) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, net, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(net, 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, g_rootdnsname, 300);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      }
      else if (domain == p03nsone && type == QType::A) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, nsone, QType::NS, "dns1.p01.nsone.net.", DNSResourceRecord::AUTHORITY, 3600);
        addNSECRecordToLW(nsone, DNSName("zzz.nsone.net."), {QType::NS, QType::SOA, QType::RRSIG, QType::DNSKEY}, 600, res->d_records);
        addRRSIG(keys, res->d_records, net, 300);
        addRecordToLW(res, "dns1.p01.nsone.net", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      else {
        BOOST_ASSERT(0);
      }
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.1:53")) {
      if (domain == hero && type == QType::NS) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, hero, QType::NS, "dns1.p03.nsone.net.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(hero, 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, com, 300);
      }
      else if (domain == nsone && type == QType::A) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, nsone, QType::NS, "dns1.p01.nsone.net.", DNSResourceRecord::AUTHORITY, 3600);
        addNSECRecordToLW(nsone, DNSName("zzz.nsone.net."), {QType::NS, QType::SOA, QType::RRSIG, QType::DNSKEY}, 600, res->d_records);
        addRRSIG(keys, res->d_records, net, 300);
        addRecordToLW(res, "dns1.p01.nsone.net", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      else {
        BOOST_ASSERT(0);
      }
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53")) {
      DNSName p01("p01.nsone.net.");
      DNSName p03("p03.nsone.net.");
      DNSName p01nsone("dns1.p01.nsone.net.");
      if (domain == hero && type == QType::NS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, hero, QType::NS, "dns1.p03.nsone.net.", DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, hero, 300);
      }
      else if (domain == p01nsone && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, p01nsone, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 3600);
      }
      else if (domain == p03nsone && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, p03nsone, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 3600);
      }
      else if (domain == p01 && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, p01, QType::SOA, "dns1.p01.nsone.net. hostmaster.nsone.net. 123 43200 7200 1209600 10800", DNSResourceRecord::AUTHORITY, 3600);
      }
      else if (domain == p03 && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, p03, QType::SOA, "dns1.p03.nsone.net. hostmaster.nsone.net. 123 43200 7200 1209600 10800", DNSResourceRecord::AUTHORITY, 3600);
      }
      else {
        BOOST_ASSERT(0);
      }
      return LWResult::Result::Success;
    }
    BOOST_ASSERT(0);
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("herokuapp.com."), QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  ret.clear();
  res = sr->beginResolve(DNSName("dns1.p03.nsone.net."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 14U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_servfail_ds)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  /* make sure that the signature inception and validity times are computed
     based on the SyncRes time, not the current one, in case the function
     takes too long. */

  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    if (domain == target) {
      auth = DNSName("powerdns.com.");
    }

    if (type == QType::DS && domain == DNSName("powerdns.com.")) {
      /* time out */
      return LWResult::Result::Timeout;
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, true, fixedNow);
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
      addDS(DNSName("com."), 300, res->d_records, keys);
      addRRSIG(keys, res->d_records, DNSName("."), 300, false, boost::none, boost::none, fixedNow);
      addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.1:53")) {
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
        addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, domain, 300);
      }
      else {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, auth, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
        /* do NOT include the DS here */
        // addDS(auth, 300, res->d_records, keys);
        // addRRSIG(keys, res->d_records, DNSName("com."), 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.2:53")) {
      if (type == QType::NS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, auth, 300);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  try {
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch (const ImmediateServFailException& e) {
    BOOST_CHECK(e.reason.find("Server Failure while retrieving DS records for powerdns.com") != string::npos);
  }

  /* and a second time to check nothing was cached */
  try {
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch (const ImmediateServFailException& e) {
    BOOST_CHECK(e.reason.find("Server Failure while retrieving DS records for powerdns.com") != string::npos);
  }
}

static void dnssec_secure_servfail_dnskey(DNSSECMode mode, vState /* expectedValidationResult */)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, mode);

  primeHints();
  const DNSName target("powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  /* make sure that the signature inception and validity times are computed
     based on the SyncRes time, not the current one, in case the function
     takes too long. */

  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    if (domain == target) {
      auth = DNSName("powerdns.com.");
    }

    if (type == QType::DNSKEY && domain == DNSName("powerdns.com.")) {
      /* time out */
      return LWResult::Result::Timeout;
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, true, fixedNow);
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
      addDS(DNSName("com."), 300, res->d_records, keys);
      addRRSIG(keys, res->d_records, DNSName("."), 300, false, boost::none, boost::none, fixedNow);
      addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.1:53")) {
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
        addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, domain, 300);
      }
      else {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, auth, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(auth, 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("com."), 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.2:53")) {
      if (type == QType::NS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, auth, 300);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  try {
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch (const ImmediateServFailException& e) {
    BOOST_CHECK(e.reason.find("Server Failure while retrieving DNSKEY records for powerdns.com") != string::npos);
  }

  /* and a second time to check nothing was cached */
  try {
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch (const ImmediateServFailException& e) {
    BOOST_CHECK(e.reason.find("Server Failure while retrieving DNSKEY records for powerdns.com") != string::npos);
  }
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_servfail_dnskey)
{
  dnssec_secure_servfail_dnskey(DNSSECMode::ValidateAll, vState::Indeterminate);
  dnssec_secure_servfail_dnskey(DNSSECMode::Off, vState::Indeterminate);
}

// Same test as above but powerdns.com is now Insecure according to parent, so failure to retrieve DNSSKEYs
// should be mostly harmless.
static void dnssec_secure_servfail_dnskey_insecure(DNSSECMode mode, vState expectedValidationResult)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, mode);

  primeHints();
  const DNSName target("powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");

  // We use two sets of keys, as powerdns.com is Insecure according to parent but returns signed results,
  // triggering a (failing) DNSKEY retrieval.
  testkeysset_t keys;
  testkeysset_t pdnskeys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, pdnskeys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  /* make sure that the signature inception and validity times are computed
     based on the SyncRes time, not the current one, in case the function
     takes too long. */

  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    if (domain == target) {
      auth = DNSName("powerdns.com.");
    }

    if (type == QType::DNSKEY && domain == DNSName("powerdns.com.")) {
      /* time out */
      return LWResult::Result::Timeout;
    }

    if (type == QType::DS || type == QType::DNSKEY) {
      // This one does not know about pdnskeys, so it will declare powerdns.com as Insecure
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, true, fixedNow);
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
      addDS(DNSName("com."), 300, res->d_records, keys);
      addRRSIG(keys, res->d_records, DNSName("."), 300, false, boost::none, boost::none, fixedNow);
      addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.1:53")) {
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
        addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(keys, res->d_records, domain, 300);
      }
      else {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, auth, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(auth, 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("com."), 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }

    if (address == ComboAddress("192.0.2.2:53")) {
      if (type == QType::NS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        addRRSIG(pdnskeys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        addRRSIG(pdnskeys, res->d_records, auth, 300);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(pdnskeys, res->d_records, auth, 300, false, boost::none, boost::none, fixedNow);
      }
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  auto res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(sr->getValidationState(), expectedValidationResult);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_servfail_dnskey_insecure)
{
  dnssec_secure_servfail_dnskey_insecure(DNSSECMode::ValidateAll, vState::Insecure);
  dnssec_secure_servfail_dnskey_insecure(DNSSECMode::Off, vState::Insecure);
}

BOOST_AUTO_TEST_SUITE_END()
