#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc6)

BOOST_AUTO_TEST_CASE(test_dnssec_no_ds_on_referral_secure) {
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
  size_t dsQueriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,&dsQueriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS) {
        DNSName auth(domain);
        auth.chopOff();
        dsQueriesCount++;

        if (domain == target) {
          if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys, false) == 0) {
            return 0;
          }
          return 1;
        }

        setLWResult(res, 0, true, false, true);
        addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER);
        addRRSIG(keys, res->d_records, auth, 300);
        return 1;
      }
      else if (type == QType::DNSKEY) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return 1;
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          /* No DS on referral, and no denial of the DS either */
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
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            /* No DS on referral, and no denial of the DS either */
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
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
  BOOST_CHECK_EQUAL(dsQueriesCount, 3U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
  BOOST_CHECK_EQUAL(dsQueriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_ds_sign_loop) {
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
  generateKeyMaterial(DNSName("www.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS) {
        DNSName auth(domain);
        auth.chopOff();

        setLWResult(res, 0, true, false, true);
        if (domain == target) {
          addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER);
          addRRSIG(keys, res->d_records, domain, 300);
        }
        else {
          addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER);
          addRRSIG(keys, res->d_records, auth, 300);
        }
        return 1;
      }
      else if (type == QType::DNSKEY) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return 1;
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          addDS(DNSName("com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
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
            /* no DS */
            addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS }, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          if (type == QType::NS) {
            if (domain == DNSName("powerdns.com.")) {
              setLWResult(res, RCode::Refused, false, false, true);
            }
            else {
              setLWResult(res, 0, true, false, true);
              addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
              addRRSIG(keys, res->d_records, domain, 300);
              addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
              addRRSIG(keys, res->d_records, domain, 300);
            }
          }
          else {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, domain, QType::A, "192.0.2.42");
            addRRSIG(keys, res->d_records, DNSName("www.powerdns.com"), 300);
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
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_dnskey_signed_child) {
  /* check that we don't accept a signer below us */
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
  generateKeyMaterial(DNSName("www.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.www.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS) {
        DNSName auth(domain);
        auth.chopOff();

        setLWResult(res, 0, true, false, true);
        addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER);
        addRRSIG(keys, res->d_records, auth, 300);
        return 1;
      }
      else if (type == QType::DNSKEY) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        if (domain == DNSName("www.powerdns.com.")) {
          addRRSIG(keys, res->d_records, DNSName("sub.www.powerdns.com."), 300);
        }
        else {
          addRRSIG(keys, res->d_records, domain, 300);
        }
        return 1;
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          addDS(DNSName("com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
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
          if (type == QType::NS) {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRRSIG(keys, res->d_records, domain, 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, domain, 300);
          }
          else {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, domain, QType::A, "192.0.2.42");
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
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 10U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 10U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_no_ds_on_referral_insecure) {
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

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  size_t dsQueriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,&dsQueriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS) {
        DNSName auth(domain);
        auth.chopOff();
        dsQueriesCount++;

        setLWResult(res, 0, true, false, true);
        if (domain == DNSName("com.")) {
          addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER);
        }
        else {
          addRecordToLW(res, "com.", QType::SOA, "a.gtld-servers.com. hostmastercom. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addNSECRecordToLW(domain, DNSName("powerdnt.com."), { QType::NS }, 600, res->d_records);
        }
        addRRSIG(keys, res->d_records, auth, 300);
        return 1;
      }
      else if (type == QType::DNSKEY) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return 1;
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          /* No DS on referral, and no denial of the DS either */
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
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            /* No DS on referral, and no denial of the DS either */
          }
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          setLWResult(res, 0, true, false, true);
          if (type == QType::NS) {
            if (domain == DNSName("powerdns.com.")) {
              addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
              addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            }
            else {
              addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            }
          }
          else {
            addRecordToLW(res, domain, QType::A, "192.0.2.42");
          }
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_bogus_unsigned_nsec) {
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
            addRecordToLW(res, DNSName("com."), QType::NS, "a.gtld-servers.com.");
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
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
          setLWResult(res, 0, true, false, true);
          if (type == QType::NS) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRRSIG(keys, res->d_records, domain, 300);
          }
          else {
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, domain, 300);
            addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS, QType::DNSKEY }, 600, res->d_records);
            /* NO RRSIG for the NSEC record! */
          }
          return 1;
        }
      }

      return 0;
    });

  /* NSEC record without the corresponding RRSIG in a secure zone, should be Bogus! */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_CHECK_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_bogus_no_nsec) {
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
            addRecordToLW(res, DNSName("com."), QType::NS, "a.gtld-servers.com.");
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
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
          setLWResult(res, 0, true, false, true);
          if (type == QType::NS) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRRSIG(keys, res->d_records, domain, 300);
          }
          else {
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, domain, 300);

            /* NO NSEC record! */
          }
          return 1;
        }
      }

      return 0;
    });

  /* no NSEC record in a secure zone, should be Bogus! */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure) {
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

      if (type == QType::DS) {
        if (domain == target) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          return 1;
        } else {
          return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
        }
      }
      else if (type == QType::DNSKEY) {
        if (domain == g_rootdnsname || domain == DNSName("com.")) {
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          return 1;
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
            addRecordToLW(res, DNSName("com."), QType::NS, "a.gtld-servers.com.");
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          }
          else {
            setLWResult(res, 0, false, false, true);
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            /* no DS */
            addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS }, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          setLWResult(res, 0, true, false, true);
          if (type == QType::NS) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
          }
          else {
            addRecordToLW(res, domain, QType::A, targetAddr.toString());
          }
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  /* 4 NS: com at ., com at com, powerdns.com at com, powerdns.com at powerdns.com
     4 DNSKEY: ., com (not for powerdns.com because DS denial in referral)
     1 query for A */
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}


BOOST_AUTO_TEST_CASE(test_dnssec_secure_direct_ds) {
  /*
    Direct DS query:
    - parent is secure, zone is secure: DS should be secure
  */
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
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::DS || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::DS || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_direct_ds) {
  /*
    Direct DS query:
    - parent is secure, zone is insecure: DS denial should be secure
  */
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
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::SOA || record.d_type == QType::NSEC || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::SOA || record.d_type == QType::NSEC || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_skipped_cut) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.sub.powerdns.com.");
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

      if (type == QType::DS) {
        if (domain == DNSName("sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          return 1;
        }
        else if (domain == DNSName("www.sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, DNSName("sub.powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          return 1;
        }
        else {
          return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
        }
      }
      else if (type == QType::DNSKEY) {
        if (domain == g_rootdnsname || domain == DNSName("com.") || domain == DNSName("powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          return 1;
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
            addRecordToLW(res, DNSName("com."), QType::NS, "a.gtld-servers.com.");
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          }
          else {
            setLWResult(res, 0, false, false, true);
            addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          setLWResult(res, 0, true, false, true);
          if (type == QType::NS) {
            if (domain == DNSName("www.sub.powerdns.com.")) {
              addRecordToLW(res, DNSName("sub.powerdns.com"), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            }
            else if (domain == DNSName("sub.powerdns.com.")) {
              addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            }
            else if (domain == DNSName("powerdns.com.")) {
              addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
              addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
            }
          } else {
            addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          }
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 9U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
}

BOOST_AUTO_TEST_SUITE_END()
