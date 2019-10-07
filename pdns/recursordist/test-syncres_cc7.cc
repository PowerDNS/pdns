#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc7)

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_to_ta_skipped_cut) {
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
  /* No key material for .com */
  /* But TA for sub.powerdns.com. */
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  luaconfsCopy.dsAnchors[DNSName("sub.powerdns.com.")].insert(keys[DNSName("sub.powerdns.com.")].second);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == DNSName("www.sub.powerdns.com")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, DNSName("sub.powerdns.com"), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com"), 300);
          addNSECRecordToLW(DNSName("www.sub.powerdns.com"), DNSName("vww.sub.powerdns.com."), { QType::A }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com"), 300);
        }
        else {
          setLWResult(res, 0, true, false, true);

          if (domain == DNSName("com.")) {
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, DNSName("."), 300);
            /* no DS */
            addNSECRecordToLW(DNSName("com."), DNSName("dom."), { QType::NS }, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("."), 300);
          }
          else {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          }
        }
        return 1;
      }
      else if (type == QType::DNSKEY) {
        if (domain == g_rootdnsname || domain == DNSName("sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* no DS */
          addNSECRecordToLW(DNSName("com."), DNSName("dom."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
          if (domain == DNSName("com.")) {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, DNSName("com."), QType::NS, "a.gtld-servers.com.");
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          }
          else if (domain.isPartOf(DNSName("powerdns.com."))) {
            setLWResult(res, 0, false, false, true);
            addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          setLWResult(res, 0, true, false, true);
          if (type == QType::NS) {
            if (domain == DNSName("www.sub.powerdns.com.")) {
              addRecordToLW(res, DNSName("sub.powerdns.com"), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
              addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com"), 300);
              addNSECRecordToLW(DNSName("www.sub.powerdns.com"), DNSName("vww.sub.powerdns.com."), { QType::A }, 600, res->d_records);
              addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com"), 300);
            }
            else if (domain == DNSName("sub.powerdns.com.")) {
              addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
              addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
            }
            else if (domain == DNSName("powerdns.com.")) {
              addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            }
          }
          else if (domain == DNSName("www.sub.powerdns.com.")) {
            addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
            addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
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
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_nodata) {
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

      if (type == QType::DS) {
        if (domain == target) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          return 1;
        }
        else {
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
            addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
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
          if (type == QType::NS) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          else {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
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
  /* 4 NS (com from root, com from com, powerdns.com from com,
     powerdns.com from powerdns.com)
     2 DNSKEY (. and com., none for powerdns.com because no DS)
     1 query for A
  */
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  const DNSName targetCName("power-dns.com.");
  const ComboAddress targetCNameAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == targetCName) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
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
          setLWResult(res, 0, false, false, true);
          if (domain == DNSName("com.")) {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
          }
          else {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            if (domain == DNSName("powerdns.com.")) {
              addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
            }
            else if (domain == targetCName) {
              addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
            }
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }

          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          setLWResult(res, 0, true, false, true);

          if (type == QType::NS) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            if (domain == DNSName("powerdns.com.")) {
              addRRSIG(keys, res->d_records, domain, 300);
            }
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            if (domain == DNSName("powerdns.com.")) {
              addRRSIG(keys, res->d_records, domain, 300);
            }
          }
          else {
            if (domain == DNSName("powerdns.com.")) {
              addRecordToLW(res, domain, QType::CNAME, targetCName.toString());
              addRRSIG(keys, res->d_records, domain, 300);
            }
            else if (domain == targetCName) {
              addRecordToLW(res, domain, QType::A, targetCNameAddr.toString());
            }
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
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 11U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 11U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_cname_glue) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  const DNSName targetCName1("cname.sub.powerdns.com.");
  const DNSName targetCName2("cname2.sub.powerdns.com.");
  const ComboAddress targetCName2Addr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetCName1,targetCName2,targetCName2Addr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (domain == DNSName("sub.powerdns.com")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
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
          setLWResult(res, 0, false, false, true);
          if (domain == DNSName("com.")) {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
          }
          else {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            if (domain == DNSName("powerdns.com.")) {
              addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
            }
            else if (domain == DNSName("sub.powerdns.com")) {
              addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
            }
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }

          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          setLWResult(res, 0, true, false, true);

          if (type == QType::NS) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            if (domain == DNSName("powerdns.com.")) {
              addRRSIG(keys, res->d_records, domain, 300);
            }
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            if (domain == DNSName("powerdns.com.")) {
              addRRSIG(keys, res->d_records, domain, 300);
            }
          }
          else {
            if (domain == DNSName("powerdns.com.")) {
              addRecordToLW(res, domain, QType::CNAME, targetCName1.toString());
              addRRSIG(keys, res->d_records, domain, 300);
              /* add the CNAME target as a glue, with no RRSIG since the sub zone is insecure */
              addRecordToLW(res, targetCName1, QType::CNAME, targetCName2.toString());
              addRecordToLW(res, targetCName2, QType::A, targetCName2Addr.toString());
            }
            else if (domain == targetCName1) {
              addRecordToLW(res, domain, QType::CNAME, targetCName2.toString());
            }
            else if (domain == targetCName2) {
              addRecordToLW(res, domain, QType::A, targetCName2Addr.toString());
            }
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
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 11U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 11U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_to_secure_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("power-dns.com.");
  const DNSName targetCName("powerdns.com.");
  const ComboAddress targetCNameAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == DNSName("power-dns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
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
            addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
          }
          else if (domain == DNSName("powerdns.com.") || domain == DNSName("power-dns.com.")) {
            setLWResult(res, 0, false, false, true);
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            if (domain == targetCName) {
              addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
            }
            else if (domain == target) {
              addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
            }
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          setLWResult(res, 0, true, false, true);
          if (type == QType::NS) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            if (domain == DNSName("powerdns.com.")) {
              addRRSIG(keys, res->d_records, domain, 300);
            }
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            if (domain == DNSName("powerdns.com.")) {
              addRRSIG(keys, res->d_records, domain, 300);
            }
          }
          else {
            if (domain == target) {
              addRecordToLW(res, domain, QType::CNAME, targetCName.toString());
            }
            else if (domain == targetCName) {
              addRecordToLW(res, domain, QType::A, targetCNameAddr.toString());
              addRRSIG(keys, res->d_records, domain, 300);
            }
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
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 11U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 11U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_to_secure_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("power-dns.com.");
  const DNSName targetCName("powerdns.com.");
  const ComboAddress targetCNameAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
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
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
          }
          else if (domain == DNSName("powerdns.com.") || domain == DNSName("power-dns.com.")) {
            setLWResult(res, 0, false, false, true);
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            addDS(DNSName(domain), 300, res->d_records, keys);
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
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, domain, 300);
          }
          else {
            if (domain == target) {
              addRecordToLW(res, domain, QType::CNAME, targetCName.toString());
              /* No RRSIG, leading to bogus */
            }
            else if (domain == targetCName) {
              addRecordToLW(res, domain, QType::A, targetCNameAddr.toString());
              addRRSIG(keys, res->d_records, domain, 300);
            }
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
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 11U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 11U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_bogus_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("power-dns.com.");
  const DNSName targetCName("powerdns.com.");
  const ComboAddress targetCNameAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
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
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
          }
          else if (domain == DNSName("powerdns.com.") || domain == DNSName("power-dns.com.")) {
            setLWResult(res, 0, false, false, true);
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            addDS(DNSName(domain), 300, res->d_records, keys);
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
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, domain, 300);
          }
          else {
            if (domain == target) {
              addRecordToLW(res, domain, QType::CNAME, targetCName.toString());
              addRRSIG(keys, res->d_records, domain, 300);
            }
            else if (domain == targetCName) {
              addRecordToLW(res, domain, QType::A, targetCNameAddr.toString());
              /* No RRSIG, leading to bogus */
            }
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
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 11U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 11U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_secure_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("power-dns.com.");
  const DNSName targetCName("powerdns.com.");
  const ComboAddress targetCNameAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
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
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
          }
          else if (domain == DNSName("powerdns.com.") || domain == DNSName("power-dns.com.")) {
            setLWResult(res, 0, false, false, true);
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            addDS(DNSName(domain), 300, res->d_records, keys);
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
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, domain, 300);
          }
          else {
            if (domain == target) {
              addRecordToLW(res, domain, QType::CNAME, targetCName.toString());
              addRRSIG(keys, res->d_records, domain, 300);
            }
            else if (domain == targetCName) {
              addRecordToLW(res, domain, QType::A, targetCNameAddr.toString());
              addRRSIG(keys, res->d_records, domain, 300);
            }
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
  BOOST_CHECK_EQUAL(queriesCount, 12U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 12U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_to_insecure_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  const DNSName targetCName("power-dns.com.");
  const ComboAddress targetCNameAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == DNSName("power-dns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
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
            addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
          }
          else if (domain == DNSName("powerdns.com.") || domain == DNSName("power-dns.com.")) {
            setLWResult(res, 0, false, false, true);
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            if (domain == DNSName("powerdns.com.")) {
              addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
            }
            else if (domain == targetCName) {
              addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
            }
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          setLWResult(res, 0, true, false, true);
          if (type == QType::NS) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          else {
            if (domain == DNSName("powerdns.com.")) {
              addRecordToLW(res, domain, QType::CNAME, targetCName.toString());
              /* No RRSIG -> Bogus */
            }
            else if (domain == targetCName) {
              addRecordToLW(res, domain, QType::A, targetCNameAddr.toString());
            }
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
  /* no RRSIG to show */
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 10U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 10U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_ta) {
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
  /* No key material for .com */
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  luaconfsCopy.dsAnchors[target].insert(keys[target].second);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DNSKEY) {
        if (domain == g_rootdnsname || domain == DNSName("powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        else if (domain == DNSName("com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, ". yop. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          return 1;
        }
      }
      else {
        if (isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addNSECRecordToLW(DNSName("com."), DNSName("com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
          if (target == domain) {
            setLWResult(res, 0, false, false, true);
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          else if (domain == DNSName("com.")) {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          }
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.2:53")) {
          setLWResult(res, 0, true, false, true);
          if (type == QType::NS) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
          }
          else {
            addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          }
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* should be insecure but we have a TA for powerdns.com. */
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  /* We got a RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_ta_norrsig) {
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
  /* No key material for .com */
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  luaconfsCopy.dsAnchors[target].insert(keys[target].second);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DNSKEY) {
        if (domain == g_rootdnsname || domain == DNSName("powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        else if (domain == DNSName("com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, ". yop. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          return 1;
        }
      }
      else {
        if (target.isPartOf(domain) && isRootServer(ip)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
          addNSECRecordToLW(DNSName("com."), DNSName("com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
          if (target == domain) {
            setLWResult(res, 0, false, false, true);
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
            addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          }
          else if (domain == DNSName("com.")) {
            setLWResult(res, 0, true, false, true);
            addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
            addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          }
          return 1;
        }
        else if (domain == target && ip == ComboAddress("192.0.2.2:53")) {
          setLWResult(res, 0, true, false, true);
          if (type == QType::NS) {
            addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
          }
          else {
            addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          }
          /* No RRSIG in a now (thanks to TA) Secure zone -> Bogus*/
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* should be insecure but we have a TA for powerdns.com., but no RRSIG so Bogus */
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  /* No RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_nta) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  /* Add a NTA for "." */
  luaconfsCopy.negAnchors[g_rootdnsname] = "NTA for Root";
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (domain == target && type == QType::NS) {

        setLWResult(res, 0, true, false, true);
        char addr[] = "a.root-servers.net.";
        for (char idx = 'a'; idx <= 'm'; idx++) {
          addr[0] = idx;
          addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
        }

        addRRSIG(keys, res->d_records, domain, 300);

        addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else if (domain == target && type == QType::DNSKEY) {

        setLWResult(res, 0, true, false, true);

        /* No DNSKEY */

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_no_ta) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  /* Remove the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (domain == target && type == QType::NS) {

        setLWResult(res, 0, true, false, true);
        char addr[] = "a.root-servers.net.";
        for (char idx = 'a'; idx <= 'm'; idx++) {
          addr[0] = idx;
          addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
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
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  /* 13 NS + 0 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 13U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 13U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_nodata) {
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

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
      else {

        setLWResult(res, 0, true, false, true);
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

BOOST_AUTO_TEST_SUITE_END()
