#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc7)

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_to_ta_skipped_cut)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.sub.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  /* No key material for .com */
  /* But TA for sub.powerdns.com. */
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  luaconfsCopy.dsAnchors[DNSName("sub.powerdns.com.")].insert(keys[DNSName("sub.powerdns.com.")].second);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == DNSName("www.sub.powerdns.com")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, DNSName("sub.powerdns.com"), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com"), 300);
        addNSECRecordToLW(DNSName("www.sub.powerdns.com"), DNSName("vww.sub.powerdns.com."), {QType::A}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com"), 300);
      }
      else {
        setLWResult(res, 0, true, false, true);

        if (domain == DNSName("com.")) {
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          /* no DS */
          addNSECRecordToLW(DNSName("com."), DNSName("dom."), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        }
      }
      return LWResult::Result::Success;
    }
    if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("sub.powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
    }
    else {
      if (isRootServer(address)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        /* no DS */
        addNSECRecordToLW(DNSName("com."), DNSName("dom."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.1:53")) {
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
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        if (type == QType::NS) {
          if (domain == DNSName("www.sub.powerdns.com.")) {
            addRecordToLW(res, DNSName("sub.powerdns.com"), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
            addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com"), 300);
            addNSECRecordToLW(DNSName("www.sub.powerdns.com"), DNSName("vww.sub.powerdns.com."), {QType::A}, 600, res->d_records);
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
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == target) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("z.powerdns.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    else if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      return LWResult::Result::Success;
    }
    else {
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
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
        }
        else {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* no DS */
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        if (type == QType::NS) {
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  /* 4 NS (com from root, com from com, powerdns.com from com,
     powerdns.com from powerdns.com)
     2 DNSKEY (. and com., none for powerdns.com because no DS)
     1 query for A
  */
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* Request the DS for powerdns.com, which does not exist. We should get
     the denial proof AND the SOA */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  bool soaFound = false;
  for (const auto& record : ret) {
    if (record.d_type == QType::SOA) {
      soaFound = true;
      break;
    }
  }
  BOOST_CHECK_EQUAL(soaFound, true);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_cname)
{
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == targetCName) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("z.power-dns.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("com.") || domain == DNSName("powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      return LWResult::Result::Success;
    }
    else {
      if (isRootServer(address)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.1:53")) {
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
            addNSECRecordToLW(domain, DNSName("z.power-dns.com."), {QType::NS}, 600, res->d_records);
          }
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }

        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
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

        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_cname_glue)
{
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == DNSName("sub.powerdns.com")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("z.power-dns.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
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
            addNSECRecordToLW(domain, DNSName("z.power-dns.com."), {QType::NS}, 600, res->d_records);
          }
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }

        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
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

        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_to_secure_cname)
{
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == DNSName("power-dns.com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("z.power-dns.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("com.") || domain == DNSName("powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      return LWResult::Result::Success;
    }
    else {
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
            addNSECRecordToLW(domain, DNSName("z.power-dns.com."), {QType::NS}, 600, res->d_records);
          }
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
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
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_to_secure_cname)
{
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
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
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
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
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_bogus_cname)
{
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
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
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
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
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_secure_cname)
{
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
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
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
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
  BOOST_CHECK_EQUAL(queriesCount, 9U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_to_insecure_cname)
{
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == DNSName("power-dns.com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("z.power-dns.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("com.") || domain == DNSName("powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      return LWResult::Result::Success;
    }
    else {
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
            addNSECRecordToLW(domain, DNSName("z.power-dns.com."), {QType::NS}, 600, res->d_records);
          }
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
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
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  /* no RRSIG to show */
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_ta)
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  /* No key material for .com */
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  luaconfsCopy.dsAnchors[target].insert(keys[target].second);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, ". yop. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
    }
    else {
      if (isRootServer(address)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addNSECRecordToLW(DNSName("com."), DNSName("com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.1:53")) {
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
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        if (type == QType::NS) {
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        }
        else {
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        }
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* should be insecure but we have a TA for powerdns.com. */
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  /* We got a RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_ta_norrsig)
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  /* No key material for .com */
  generateKeyMaterial(target, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  luaconfsCopy.dsAnchors[target].insert(keys[target].second);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, ". yop. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
    }
    else {
      if (target.isPartOf(domain) && isRootServer(address)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addNSECRecordToLW(DNSName("com."), DNSName("com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.1:53")) {
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
        return LWResult::Result::Success;
      }
      if (domain == target && address == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        if (type == QType::NS) {
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        }
        else {
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        }
        /* No RRSIG in a now (thanks to TA) Secure zone -> Bogus*/
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* should be insecure but we have a TA for powerdns.com., but no RRSIG so Bogus */
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  /* No RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_nta)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  /* Add a NTA for "." */
  luaconfsCopy.negAnchors[g_rootdnsname] = "NTA for Root";
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
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

      return LWResult::Result::Success;
    }
    if (domain == target && type == QType::DNSKEY) {

      setLWResult(res, 0, true, false, true);

      /* No DNSKEY */

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_no_ta)
{
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

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
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

      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  /* 13 NS + 0 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 13U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 13U);
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::A) {
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, DNSName("com"), QType::SOA, "whatever.com. blah.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com"), 300);
        addNSECRecordToLW(DNSName("com"), DNSName("com."), {QType::SOA}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      if (domain == target) {
        setLWResult(res, 0, true, false, true);
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusMissingNegativeIndication);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* powerdns.com|A, com|A, com|DNSKEY, powerdns.com|DS */
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusMissingNegativeIndication);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* we don't store empty results */
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_missing_soa_on_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain.isPartOf(target)) {
        /* proves cut */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, true);
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "ns1.com.", DNSResourceRecord::AUTHORITY, 3600);
      addDS(DNSName("com."), 300, res->d_records, keys);
      addRRSIG(keys, res->d_records, DNSName("com."), 300);
      addRecordToLW(res, "ns1.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    else {
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, DNSName("com"), QType::SOA, "whatever.com. blah.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com"), 300);
        addNSECRecordToLW(DNSName("com"), DNSName("com."), {QType::SOA}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      if (domain == target) {
        setLWResult(res, 0, true, false, true);
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* powerdns.com|A, com|A, com|DNSKEY, powerdns.com|DS */
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* we don't store empty results */
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_missing_soa_on_nxd)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain.isPartOf(target)) {
        /* proves cut */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, true);
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "ns1.com.", DNSResourceRecord::AUTHORITY, 3600);
      addDS(DNSName("com."), 300, res->d_records, keys);
      addRRSIG(keys, res->d_records, DNSName("com."), 300);
      addRecordToLW(res, "ns1.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    else {
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, DNSName("com"), QType::SOA, "whatever.com. blah.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com"), 300);
        addNSECRecordToLW(DNSName("com"), DNSName("com."), {QType::SOA}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      if (domain == target) {
        setLWResult(res, RCode::NXDomain, true, false, true);
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* powerdns.com|A, com|A, com|DNSKEY, powerdns.com|DS */
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* we don't store empty results */
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_nxdomain)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::A) {
      if (domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, DNSName("com"), QType::SOA, "whatever.com. blah.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com"), 300);
        addNSECRecordToLW(DNSName("com"), DNSName("com."), {QType::SOA}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      if (domain == target) {
        setLWResult(res, RCode::NXDomain, true, false, true);
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusMissingNegativeIndication);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);

  /* powerdns.com|A, com|A, powerdns.com|DS, com|DNSKEY */
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusMissingNegativeIndication);
  BOOST_REQUIRE_EQUAL(ret.size(), 0U);
  /* we don't store empty results */
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_cut_with_cname_at_apex)
{
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == DNSName("www.powerdns.com.") || domain == DNSName("www2.powerdns.com.")) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      return LWResult::Result::Success;
    }
    else {
      if (isRootServer(address)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.1:53")) {
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
          if (domain.isPartOf(DNSName("powerdns.com."))) {
            addNSECRecordToLW(domain, DNSName("z.powerdns.com."), {QType::NS}, 600, res->d_records);
          }
          else if (domain == targetCName) {
            addNSECRecordToLW(domain, DNSName("z.power-dns.com."), {QType::NS}, 600, res->d_records);
          }
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }

        return LWResult::Result::Success;
      }
      if (address == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);

        if (type == QType::NS) {
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        else {
          if (domain == DNSName("powerdns.com.")) {
            addRecordToLW(res, domain, QType::CNAME, targetCName.toString());
          }
          else if (domain == DNSName("www.powerdns.com.") || domain == DNSName("www2.powerdns.com.")) {
            addRecordToLW(res, domain, QType::A, "192.0.2.43");
          }
          else if (domain == targetCName) {
            addRecordToLW(res, domain, QType::A, targetCNameAddr.toString());
          }
        }

        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* this time we ask for www.powerdns.com, let's make sure the CNAME does not get in the way */
  ret.clear();
  res = sr->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* now we remove the denial of powerdns.com DS from the cache and ask www2 */
  BOOST_REQUIRE_EQUAL(g_negCache->wipe(target, false), 1U);
  ret.clear();
  res = sr->beginResolve(DNSName("www2.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 10U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_cname_inside_secure_zone)
{
  /* this test makes sure we don't request the DS
     again and again when there is a CNAME inside a
     Secure zone */
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain.isPartOf(DNSName("powerdns.com.")) || domain.isPartOf(DNSName("power-dns.com."))) {
        /* no cut */
        /* technically the zone is com., but we are going to chop off in genericDSAndDNSKEYHandler() */
        return genericDSAndDNSKEYHandler(res, domain, DNSName("powerdns.com."), type, keys, false);
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      return LWResult::Result::Success;
    }
    else {
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

        if (domain == DNSName("com.")) {
          addRecordToLW(res, domain, QType::NS, "a.gtld-servers.com.");
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
        }
        else {
          if (domain == DNSName("powerdns.com.")) {
            addRecordToLW(res, domain, QType::CNAME, targetCName.toString());
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
          }
          else if (domain == DNSName("www.powerdns.com.") || domain == DNSName("www2.powerdns.com.")) {
            addRecordToLW(res, domain, QType::A, "192.0.2.43");
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
          }
          else if (domain == targetCName) {
            addRecordToLW(res, domain, QType::A, targetCNameAddr.toString());
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
          }
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
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* this time we ask for www.powerdns.com, let's make sure the CNAME does not get in the way */
  ret.clear();
  res = sr->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* now we remove the denial of powerdns.com DS from the cache and ask www2 */
  g_negCache->wipe(target, false);
  ret.clear();
  res = sr->beginResolve(DNSName("www2.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_SUITE_END()
