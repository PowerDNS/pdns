#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc6)

BOOST_AUTO_TEST_CASE(test_dnssec_no_ds_on_referral_secure)
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
  size_t dsQueriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, &dsQueriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      DNSName auth(domain);
      auth.chopOff();
      dsQueriesCount++;

      if (domain == target) {
        if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys, false) == LWResult::Result::Timeout) {
          return LWResult::Result::Timeout;
        }
        return LWResult::Result::Success;
      }

      setLWResult(res, 0, true, false, true);
      addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER);
      addRRSIG(keys, res->d_records, auth, 300);
      return LWResult::Result::Success;
    }
    else if (type == QType::DNSKEY) {
      setLWResult(res, 0, true, false, true);
      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);
      return LWResult::Result::Success;
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        /* No DS on referral, and no denial of the DS either */
        return LWResult::Result::Success;
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
        return LWResult::Result::Success;
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
            addNSECRecordToLW(DNSName("www.powerdns.com."), DNSName("wwz.powerdns.com."), {QType::A, QType::NSEC, QType::RRSIG}, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
          }
        }
        else {
          addRecordToLW(res, domain, QType::A, "192.0.2.42");
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
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_ds_sign_loop)
{
  /* the DS for www.powerdns.com. is signed by www.powerdns.com. */
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

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
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
      return LWResult::Result::Success;
    }
    else if (type == QType::DNSKEY) {
      setLWResult(res, 0, true, false, true);
      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);
      return LWResult::Result::Success;
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
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
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
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

        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusSelfSignedDS);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusSelfSignedDS);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_ds_denial_loop)
{
  /* The denial of the DS sub.insecure.powerdns comes from the child zone, so is signed by sub.insecure.powerdns.
     but sub.insecure.powerdns. is actually insecure (no DS for insecure.powerdns.), both sub.insecure.powerdns AND
     insecure.powerdns are hosted on the same server but because of a misconfiguration, the server serves DS queries
     for the sub.insecure.powerdns from the _child_ side.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("sub.insecure.powerdns.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.insecure.powerdns."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DNSKEY || (type == QType::DS && domain != target)) {
      DNSName auth(domain);
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, true);
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addDS(DNSName("powerdns."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.1:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "insecure.powerdns.", QType::NS, "ns1.insecure.powerdns.", DNSResourceRecord::AUTHORITY, 3600);
        /* no DS */
        addNSECRecordToLW(domain, DNSName("z.powerdns."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns."), 300);
        addRecordToLW(res, "ns1.insecure.powerdns.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        if (type == QType::DS && domain == target) {
          /* in that case we return a NODATA signed by the DNSKEY of the child zone */
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, DNSName("sub.insecure.powerdns."), QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          addRRSIG(keys, res->d_records, DNSName("sub.insecure.powerdns."), 300);
          addNSECRecordToLW(domain, DNSName("+") + domain, {QType::RRSIG, QType::NS, QType::SOA, QType::A}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("sub.insecure.powerdns."), 300);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_ds_root)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      addRRSIG(keys, res->d_records, DNSName("."), 300);
      addNSECRecordToLW(domain, DNSName("aaa."), {QType::DNSKEY, QType::SOA, QType::NS, QType::NSEC, QType::RRSIG}, 600, res->d_records);
      addRRSIG(keys, res->d_records, DNSName("."), 300);
      return LWResult::Result::Success;
    }
    else if (type == QType::DNSKEY) {
      setLWResult(res, 0, true, false, true);
      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, DNSName("."), 300);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_dnskey_signed_child)
{
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

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      DNSName auth(domain);
      auth.chopOff();

      setLWResult(res, 0, true, false, true);
      addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER);
      addRRSIG(keys, res->d_records, auth, 300);
      return LWResult::Result::Success;
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
      return LWResult::Result::Success;
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
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
        return LWResult::Result::Success;
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

        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_dnskey_unpublished)
{
  /* check that we properly handle an insecure (no DS) but signed zone whose DNSKEY is not published (so NODATA) */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("unpublished.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("unpublished.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == target) {
        auto auth = domain;
        auth.chopOff();
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300, false);
        /* add a NSEC denying the DS and proving a cut */
        std::set<uint16_t> types = {QType::RRSIG, QType::NS};
        addNSECRecordToLW(domain, DNSName("+") + domain, types, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300, false);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, true /* cut */);
      }
    }
    else if (type == QType::DNSKEY) {
      if (domain == target) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, domain, 300, false);
        /* add a NSEC denying the DNSKEY */
        std::set<uint16_t> types = {QType::RRSIG, QType::SOA, QType::NS};
        addNSECRecordToLW(domain, DNSName("+") + domain, types, 600, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300, false);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.1:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        addRRSIG(keys, res->d_records, domain, 300);

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
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* now request the SOA */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::SOA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_dnskey_unpublished_nsec3)
{
  /* check that we properly handle an insecure (no DS) but signed zone whose DNSKEY is not published (so NODATA) with NSEC3 this time */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("unpublished.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("unpublished.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == target) {
        auto auth = domain;
        auth.chopOff();
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, auth, 300, false);
        /* add a NSEC denying the DS and proving a cut */
        std::set<uint16_t> types = {QType::RRSIG, QType::NS};
        addNSEC3UnhashedRecordToLW(domain, auth, (DNSName("+") + domain).toString(), types, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300, false);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, true /* cut */, boost::none, true /* nsec3 */);
      }
    }
    else if (type == QType::DNSKEY) {
      if (domain == target) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, domain, 300, false);
        /* add a NSEC denying the DNSKEY */
        std::set<uint16_t> types = {QType::RRSIG, QType::SOA, QType::NS};
        addNSEC3UnhashedRecordToLW(domain, domain, (DNSName("+") + domain).toString(), types, 600, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300, false);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, true /* cut */, boost::none, true /* nsec3 */);
      }
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.1:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        addRRSIG(keys, res->d_records, domain, 300);

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
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* now request the SOA */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::SOA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_no_ds_on_referral_insecure)
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

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  size_t dsQueriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, &dsQueriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
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
        addNSECRecordToLW(domain, DNSName("powerdnt.com."), {QType::NS}, 600, res->d_records);
      }
      addRRSIG(keys, res->d_records, auth, 300);
      return LWResult::Result::Success;
    }
    else if (type == QType::DNSKEY) {
      setLWResult(res, 0, true, false, true);
      addDNSKEY(keys, domain, 300, res->d_records);
      addRRSIG(keys, res->d_records, domain, 300);
      return LWResult::Result::Success;
    }
    else {
      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        /* No DS on referral, and no denial of the DS either */
        return LWResult::Result::Success;
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
        return LWResult::Result::Success;
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
  BOOST_CHECK_EQUAL(queriesCount, 7U);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_bogus_unsigned_nsec)
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

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
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
        return LWResult::Result::Success;
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
        return LWResult::Result::Success;
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
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), {QType::NS, QType::DNSKEY}, 600, res->d_records);
          /* NO RRSIG for the NSEC record! */
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  /* NSEC record without the corresponding RRSIG in a secure zone, should be Bogus! */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_CHECK_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_bogus_no_nsec)
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

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
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
        return LWResult::Result::Success;
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
        return LWResult::Result::Success;
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
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  /* no NSEC record in a secure zone, should be Bogus! */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusInvalidDenial);
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusInvalidDenial);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure)
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

  sr->setAsyncCallback([target, targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
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
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
    }
    else if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      else {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
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
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        if (type == QType::NS) {
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        }
        else {
          addRecordToLW(res, domain, QType::A, targetAddr.toString());
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
  BOOST_CHECK(ret[0].d_type == QType::A);
  /* 2 NS: com at ., powerdns.com at com
     2 DNSKEY: ., com (not for powerdns.com because DS denial in referral)
     1 query for A */
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_optout)
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

  sr->setAsyncCallback([target, targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == target) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("com."), DNSName("com."), DNSName("a.com.").toStringNoDot(), {QType::NS, QType::SOA}, 600, res->d_records, 10, true);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* next closer */
        addNSEC3UnhashedRecordToLW(DNSName("oowerdns.com."), DNSName("com."), DNSName("qowerdns.com.").toStringNoDot(), {QType::NS}, 600, res->d_records, 10, true);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, true, boost::none, true, true);
      }
    }
    else if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      else {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
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
          /* closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("com."), DNSName("com."), DNSName("a.com.").toStringNoDot(), {QType::NS, QType::SOA}, 600, res->d_records, 10, true);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* next closer */
          addNSEC3UnhashedRecordToLW(DNSName("oowerdns.com."), DNSName("com."), DNSName("qowerdns.com.").toStringNoDot(), {QType::NS}, 600, res->d_records, 10, true);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        if (type == QType::NS) {
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.");
        }
        else {
          addRecordToLW(res, domain, QType::A, targetAddr.toString());
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_nxd_optout)
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

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == target) {
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, DNSName("com."), QType::SOA, "a.gtld-servers.com. hostmastercom. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("com."), DNSName("com."), DNSName("a.com.").toStringNoDot(), {QType::SOA, QType::NS, QType::DS, QType::DNSKEY, QType::RRSIG, QType::NSEC3PARAM}, 600, res->d_records, 10, true);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        /* next closer */
        addNSEC3UnhashedRecordToLW(DNSName("oowerdns.com."), DNSName("com."), DNSName("qowerdns.com.").toStringNoDot(), {QType::NS}, 600, res->d_records, 10, true);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, true, boost::none, true, true);
      }
    }
    else if (type == QType::DNSKEY) {
      if (domain == g_rootdnsname || domain == DNSName("com.")) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      else {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, DNSName("com."), QType::SOA, "a.gtld-servers.com. hostmastercom. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
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
        if (domain == DNSName("com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, DNSName("com."), QType::NS, "a.gtld-servers.com.");
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        }
        else {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, DNSName("com."), QType::SOA, "a.gtld-servers.com. hostmastercom. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("com."), DNSName("com."), DNSName("a.com.").toStringNoDot(), {QType::SOA, QType::NS, QType::DS, QType::DNSKEY, QType::RRSIG, QType::NSEC3PARAM}, 600, res->d_records, 10, true);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          /* next closer */
          addNSEC3UnhashedRecordToLW(DNSName("oowerdns.com."), DNSName("com."), DNSName("qowerdns.com.").toStringNoDot(), {QType::NS}, 600, res->d_records, 10, true);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
        }
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_direct_ds)
{
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

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
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
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::DS || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::DS || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_direct_ds)
{
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

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
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
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::SOA || record.d_type == QType::NSEC || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::SOA || record.d_type == QType::NSEC || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_skipped_cut)
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == DNSName("sub.powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        addNSECRecordToLW(domain, DNSName("z.powerdns.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        return LWResult::Result::Success;
      }
      else if (domain == DNSName("www.sub.powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, DNSName("sub.powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
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
        return LWResult::Result::Success;
      }
      else {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
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
        return LWResult::Result::Success;
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
        }
        else {
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
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
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_secure_without_ds)
{
  /* the last zone has signatures but the DS has not been added
     to the parent zone yet, so it should be insecure */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == DNSName("powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, DNSName("com."), QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("z") + domain, {QType::NS, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
    }
    else if (type == QType::DNSKEY) {
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
        if (domain == DNSName("com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, DNSName("com."), QType::NS, "a.gtld-servers.com.");
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        }
        else {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* no DS */
          addNSECRecordToLW(DNSName("powerdns.com."), DNSName("z.powerdns.com."), {QType::NS, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);

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
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_broken_without_ds)
{
  /* the last zone has INVALID signatures but the DS has not been added
     to the parent zone yet, so it should be insecure */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      if (domain == DNSName("powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, DNSName("com."), QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("z") + domain, {QType::NS, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
    }
    else if (type == QType::DNSKEY) {
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
        if (domain == DNSName("com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, DNSName("com."), QType::NS, "a.gtld-servers.com.");
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        }
        else {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* no DS */
          addNSECRecordToLW(DNSName("powerdns.com."), DNSName("z.powerdns.com."), {QType::NS, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, /* broken SIG */ true);

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
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_broken_cname_ds)
{
  /* Test an Insecure domain that responds with a CNAME on a DS query */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.sub.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys, pdnskeys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();

  // We have two set of keys as powerdns.com and sub.powerdns.com are Insecure but still have RRSIGS
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, pdnskeys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, pdnskeys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, targetAddr, &queriesCount, keys, pdnskeys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      // Return a signed CNAME on a DS query for powerdns.com and sub.powerdns.com
      if (domain == DNSName("powerdns.com.") || domain == DNSName("sub.powerdns.com.")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::CNAME, "some.name", DNSResourceRecord::ANSWER, 300);
        addRRSIG(pdnskeys, res->d_records, domain, 300);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
    }
    else if (type == QType::DNSKEY) {
      if (domain == DNSName("powerdns.com.") || domain == DNSName("sub.powerdns.com.")) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, pdnskeys);
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
        return LWResult::Result::Success;
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
          addNSECRecordToLW(DNSName("powerdns.com."), DNSName("z.powerdns.com."), {QType::NS, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, DNSName("sub.powerdns.com."), QType::NS, "ns1.sub.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(pdnskeys, res->d_records, DNSName("powerdns.com."), 300);

        addRecordToLW(res, "ns1.sub.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 3600);
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.3:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(pdnskeys, res->d_records, DNSName("sub.powerdns.com."), 300);
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
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_cname_for_ds)
{
  /* Test an Secure domain that responds with a CNAME on a DS query goes Bogus */
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

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (type == QType::DS && domain == DNSName("powerdns.com")) {
        // Return a signed CNAME on a DS query for powerdns.com
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::CNAME, "some.name", DNSResourceRecord::ANSWER, 300);
        addRRSIG(keys, res->d_records, domain, 300);
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
        if (domain == DNSName("com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, DNSName("com."), QType::NS, "a.gtld-servers.com.");
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        }
        else {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        }
        return LWResult::Result::Success;
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, DNSName("www.powerdns.com."), QType::A, "192.168.1.1", DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);

        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusUnableToGetDSs);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusUnableToGetDSs);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

BOOST_AUTO_TEST_SUITE_END()
