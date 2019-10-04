#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc5)

BOOST_AUTO_TEST_CASE(test_dnssec_secure_various_algos) {
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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys,fixedNow](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      if (domain == target) {
        auth = DNSName("powerdns.com.");
      }

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, true, fixedNow);
      }

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300, false, boost::none, boost::none, fixedNow);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }

      if (ip == ComboAddress("192.0.2.1:53")) {
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
        return 1;
      }

      if (ip == ComboAddress("192.0.2.2:53")) {
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
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_a_then_ns) {
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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      if (domain == target) {
        auth = DNSName("powerdns.com.");
      }

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }

      if (ip == ComboAddress("192.0.2.1:53")) {
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
        return 1;
      }

      if (ip == ComboAddress("192.0.2.2:53")) {
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
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* this time we ask for the NS that should be in the cache, to check
     the validation status */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);

}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_a_then_ns) {
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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      if (domain == target) {
        auth = DNSName("powerdns.com.");
      }

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }

      if (ip == ComboAddress("192.0.2.1:53")) {
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
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return 1;
      }

      if (ip == ComboAddress("192.0.2.2:53")) {
        if (type == QType::NS) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        else {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        }
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* this time we ask for the NS that should be in the cache, to check
     the validation status */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_with_nta) {
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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      if (domain == target) {
        auth = DNSName("powerdns.com.");
      }

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }

      if (ip == ComboAddress("192.0.2.1:53")) {
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
        return 1;
      }

      if (ip == ComboAddress("192.0.2.2:53")) {
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
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* Should be insecure because of the NTA */
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* Should be insecure because of the NTA */
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_with_nta) {
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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return 1;
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
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
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          if (type == QType::NS) {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          else {
            setLWResult(res, RCode::NoError, true, false, true);
            addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          }
          return 1;
        }
      }

      return 0;
    });

  /* There is TA for root but no DS/DNSKEY/RRSIG, should be Bogus, but.. */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* Should be insecure because of the NTA */
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec) {
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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
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
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
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
            addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS, QType::DNSKEY }, 600, res->d_records);
            addRRSIG(keys, res->d_records, domain, 300);
          }
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nxdomain_nsec) {
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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
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
          addNSECRecordToLW(DNSName("nw.powerdns.com."), DNSName("ny.powerdns.com."), { QType::RRSIG, QType::NSEC }, 600, res->d_records);
          addRRSIG(keys, res->d_records, auth, 300);
          return 1;
        }
        else {
          return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
        }
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
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
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
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
              addNSECRecordToLW(DNSName("nx.powerdns.com."), DNSName("nz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
              addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            }
          }
          else {
            setLWResult(res, RCode::NXDomain, true, false, true);
            addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, auth, 300);
            addNSECRecordToLW(DNSName("nw.powerdns.com."), DNSName("ny.powerdns.com."), { QType::RRSIG, QType::NSEC }, 600, res->d_records);
            addRRSIG(keys, res->d_records, auth, 300);
            /* add wildcard denial */
            addNSECRecordToLW(DNSName("powerdns.com."), DNSName("a.powerdns.com."), { QType::RRSIG, QType::NSEC }, 600, res->d_records);
            addRRSIG(keys, res->d_records, auth, 300);
          }
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec_wildcard) {
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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (type == QType::DS && domain == target) {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          return 1;
        }
        else {
          return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
        }
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
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
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
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
              addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
              addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            }
          }
          else {
            addRecordToLW(res, domain, QType::A, "192.0.2.42");
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
            /* we need to add the proof that this name does not exist, so the wildcard may apply */
            addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec_nodata_nowildcard) {
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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (type == QType::DS && domain == target) {
          DNSName auth("com.");
          setLWResult(res, 0, true, false, true);

          addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          addRRSIG(keys, res->d_records, auth, 300);
          /* add a NSEC denying the DS AND the existence of a cut (no NS) */
          addNSECRecordToLW(domain, DNSName("z") + domain, { QType::NSEC }, 600, res->d_records);
          addRRSIG(keys, res->d_records, auth, 300);
          return 1;
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
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
          setLWResult(res, 0, true, false, true);
          /* no data */
          addRecordToLW(res, DNSName("com."), QType::SOA, "com. com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* no record for this name */
          addNSECRecordToLW(DNSName("wwv.com."), DNSName("wwx.com."), { QType::NSEC, QType::RRSIG }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* a wildcard matches but has no record for this type */
          addNSECRecordToLW(DNSName("*.com."), DNSName("com."), { QType::AAAA, QType::NSEC, QType::RRSIG }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_nodata_nowildcard) {
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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (type == QType::DS && domain == target) {
          DNSName auth("com.");
          setLWResult(res, 0, true, false, true);

          addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          addRRSIG(keys, res->d_records, auth, 300);
          /* add a NSEC3 denying the DS AND the existence of a cut (no NS) */
          /* first the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("com."), auth, "whatever", { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, res->d_records);
          addRRSIG(keys, res->d_records, auth, 300);
          /* then the next closer */
          addNSEC3NarrowRecordToLW(domain, DNSName("com."), { QType::RRSIG, QType::NSEC }, 600, res->d_records);
          addRRSIG(keys, res->d_records, auth, 300);
          /* a wildcard matches but has no record for this type */
          addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", { QType::AAAA, QType::NSEC, QType::RRSIG }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
          return 1;
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
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
          setLWResult(res, 0, true, false, true);
          /* no data */
          addRecordToLW(res, DNSName("com."), QType::SOA, "com. com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* no record for this name */
          /* first the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("com."), DNSName("com."), "whatever", { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* then the next closer */
          addNSEC3NarrowRecordToLW(domain, DNSName("com."), { QType::RRSIG, QType::NSEC }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* a wildcard matches but has no record for this type */
          addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", { QType::AAAA, QType::NSEC, QType::RRSIG }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_nodata_nowildcard_too_many_iterations) {
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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (type == QType::DS && domain == target) {
          DNSName auth("com.");
          setLWResult(res, 0, true, false, true);

          addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          addRRSIG(keys, res->d_records, auth, 300);
          /* add a NSEC3 denying the DS AND the existence of a cut (no NS) */
          /* first the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("com."), auth, "whatever", { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, res->d_records, g_maxNSEC3Iterations + 100);
          addRRSIG(keys, res->d_records, auth, 300);
          /* then the next closer */
          addNSEC3NarrowRecordToLW(domain, DNSName("com."), { QType::RRSIG, QType::NSEC }, 600, res->d_records, g_maxNSEC3Iterations + 100);
          addRRSIG(keys, res->d_records, auth, 300);
          /* a wildcard matches but has no record for this type */
          addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", { QType::AAAA, QType::NSEC, QType::RRSIG }, 600, res->d_records, g_maxNSEC3Iterations + 100);
          addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
          return 1;
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
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
          setLWResult(res, 0, true, false, true);
          /* no data */
          addRecordToLW(res, DNSName("com."), QType::SOA, "com. com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* no record for this name */
          /* first the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("com."), DNSName("com."), "whatever", { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, res->d_records, g_maxNSEC3Iterations + 100);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* then the next closer */
          addNSEC3NarrowRecordToLW(domain, DNSName("com."), { QType::RRSIG, QType::NSEC }, 600, res->d_records, g_maxNSEC3Iterations + 100);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* a wildcard matches but has no record for this type */
          addNSEC3UnhashedRecordToLW(DNSName("*.com."), DNSName("com."), "whatever", { QType::AAAA, QType::NSEC, QType::RRSIG }, 600, res->d_records, g_maxNSEC3Iterations + 100);
          addRRSIG(keys, res->d_records, DNSName("com"), 300, false, boost::none, DNSName("*.com"));
          return 1;
        }
      }

      return 0;
    });

  /* we are generating NSEC3 with more iterations than we allow, so we should go Insecure */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_wildcard) {
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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (type == QType::DS && domain.isPartOf(DNSName("sub.powerdns.com"))) {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          if (domain == DNSName("sub.powerdns.com")) {
            addNSECRecordToLW(DNSName("sub.powerdns.com."), DNSName("sud.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
          }
          else if (domain == target) {
            addNSECRecordToLW(DNSName("www.sub.powerdns.com."), DNSName("wwz.sub.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
          }
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          return 1;
        }
        else {
          return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
        }
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
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
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
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
              addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
              addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            }
          }
          else {
            addRecordToLW(res, domain, QType::A, "192.0.2.42");
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
            /* we need to add the proof that this name does not exist, so the wildcard may apply */
            /* first the closest encloser */
            addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
            /* then the next closer */
            addNSEC3NarrowRecordToLW(DNSName("sub.powerdns.com."), DNSName("powerdns.com."), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          }
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 10U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 10U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec3_wildcard_too_many_iterations) {
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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (type == QType::DS && domain == target) {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          return 1;
        }
        else {
          return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
        }
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
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
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
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
              addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
              addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            }
          }
          else {
            addRecordToLW(res, domain, QType::A, "192.0.2.42");
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
            /* we need to add the proof that this name does not exist, so the wildcard may apply */
            /* first the closest encloser */
            addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
            /* then the next closer */
            addNSEC3NarrowRecordToLW(DNSName("www.powerdns.com."), DNSName("powerdns.com."), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, res->d_records, g_maxNSEC3Iterations + 100);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          }
          return 1;
        }
      }

      return 0;
    });

  /* the NSEC3 providing the denial of existence proof for the next closer has too many iterations,
     we should end up Insecure */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec_wildcard_missing) {
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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (type == QType::DS && domain == target) {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          return 1;
        }
        else {
          return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
        }
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
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
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
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
              addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
              addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
            }
          }
          else {
            addRecordToLW(res, domain, QType::A, "192.0.2.42");
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
          }
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_wildcard_expanded_onto_itself) {
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

  sr->setAsyncCallback([target,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == target) {
        const auto auth = DNSName("powerdns.com.");
        /* we don't want a cut there */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC denying the DS */
        std::set<uint16_t> types = { QType::NSEC };
        addNSECRecordToLW(domain, DNSName("z") + domain, types, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        return 1;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    else {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, boost::none, DNSName("*.powerdns.com"));
      /* we don't _really_ need to add the proof that the exact name does not exist because it does,
         it's the wildcard itself, but let's do it so other validators don't choke on it */
      addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
      addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
      return 1;
    }
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  /* A + RRSIG, NSEC + RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_wildcard_like_expanded_from_wildcard) {
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

  sr->setAsyncCallback([target,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == target) {
        const auto auth = DNSName("powerdns.com.");
        /* we don't want a cut there */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
        return 1;
      }
      else if (domain == DNSName("sub.powerdns.com.")) {
        const auto auth = DNSName("powerdns.com.");
        /* we don't want a cut there */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC denying the DS */
        addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
        return 1;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    else {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, boost::none, DNSName("*.powerdns.com"));
      addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("wwz.powerdns.com."), { QType::A, QType::NSEC, QType::RRSIG }, 600, res->d_records);
      addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
      return 1;
    }
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  /* A + RRSIG, NSEC + RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
}

BOOST_AUTO_TEST_SUITE_END()
