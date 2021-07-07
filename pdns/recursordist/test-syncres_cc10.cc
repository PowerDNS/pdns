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
      return LWResult::Result::Success;
    }
    else if (ip == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, true, false, false);
      v4Hit |= true;
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }
      return LWResult::Result::Success;
    }
    else if (ip == ComboAddress("[2001:DB8:1::53]:53")) {
      setLWResult(res, 0, true, false, false);
      v6Hit |= true;
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }
      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
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
      return LWResult::Result::Success;
    }
    else if (ip == ComboAddress("[2001:DB8:1::53]:53")) {
      setLWResult(res, 0, true, false, false);
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }
      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
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
      return LWResult::Result::Success;
    }
    else if (ip == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, true, false, false);
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }
      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int rcode;
  rcode = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_REQUIRE_EQUAL(queries, 14); // The recursor tries all parent nameservers... this needs to be fixed
  BOOST_CHECK_EQUAL(rcode, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_skipped_cut_invalid_ds_denial)
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
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS) {
      /* powerdns.com and sub.powerdns.com are signed but not secure (no DS in the parent) */
      if (domain == DNSName("powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      else if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NODATA for the DS, but it is in fact a NXD proof, which would be bogus if the zone was actually secure */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        addNSECRecordToLW(DNSName("nw.powerdns.com."), DNSName("tz.powerdns.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
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
        if (domain.isPartOf(DNSName("powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* no DS */
          addNSECRecordToLW(DNSName("powerdns.com."), DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain.isPartOf(DNSName("sub.powerdns.com."))) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("nx.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* sends a NODATA for the DS, but it is in fact a NXD proof, which would be bogus if the zone was actually secure */
          addNSECRecordToLW(DNSName("nw.powerdns.com."), DNSName("tz.powerdns.com."), {QType::A}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  /* first we do a query in the parent zone (powerdns.com), insecure,
     to get the NS in cache so we don't learn the zone cut before
     validating */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("nx.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK(ret.at(0).d_type == QType::SOA);
  BOOST_CHECK(ret.at(1).d_type == QType::RRSIG);
  BOOST_CHECK(ret.at(2).d_type == QType::NSEC);
  BOOST_CHECK(ret.at(3).d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* now we query the sub zone */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 9U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 9U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_wrong_rrsig_fake_signer)
{
  /* We have an insecure (no DS at the parent) but signed zone, albeit
     badly broken (RRSIG do not validate, the signer is clearly not right).
     Check that we correctly detect the zone as Insecure.
  */
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
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS) {
      /* powerdns.com is not signed.
         sub.powerdns.com is signed but not secure, and actually badly broken */
      if (domain == DNSName("powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
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
        if (domain.isPartOf(DNSName("powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* no DS */
          addNSECRecordToLW(DNSName("powerdns.com."), DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain.isPartOf(DNSName("sub.powerdns.com."))) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("com.") /* wrong signer !! */, 300, /* broken !!!*/ true);
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("www.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  /* first we do a query in the parent zone (powerdns.com), insecure,
     to get the NS in cache so we don't learn the zone cut before
     validating */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* now we query the sub zone */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
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

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_missing_soa)
{
  /* We have an insecure (no DS at the parent) but signed zone, albeit
     slightly broken (no SOA in NXD/NODATA answers).
     Check that we correctly detect the zone as Insecure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS) {
      /* powerdns.com is not signed.
         sub.powerdns.com is signed but not secure */
      if (domain == DNSName("powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      else if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
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
        if (domain.isPartOf(DNSName("powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* no DS */
          addNSECRecordToLW(DNSName("powerdns.com."), DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == DNSName("nxd.sub.powerdns.com.")) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addNSECRecordToLW(DNSName("nxc.sub.powerdns.com."), DNSName("nxe.sub.powerdnsz.com."), {QType::AAAA}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("nodata.sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          /* NSEC but no SOA */
          addNSECRecordToLW(DNSName("nodata.sub.powerdns.com."), DNSName("nodata2.sub.powerdnsz.com."), {QType::AAAA}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("www.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  /* first we do a query in the parent zone (powerdns.com), insecure,
     to get the NS in cache so we don't learn the zone cut before
     validating */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* now we query the sub zone for the NXD */
  ret.clear();
  res = sr->beginResolve(DNSName("nxd.sub.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::NSEC);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache (we need to do the query again because there was no SOA -> no neg caching) */
  ret.clear();
  res = sr->beginResolve(DNSName("nxd.sub.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::NSEC);
  BOOST_CHECK_EQUAL(queriesCount, 9U);

  /* now we query the sub zone for the NODATA */
  ret.clear();
  res = sr->beginResolve(DNSName("nodata.sub.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::NSEC);
  BOOST_CHECK_EQUAL(queriesCount, 10U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(DNSName("nodata.sub.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::NSEC);
  BOOST_CHECK_EQUAL(queriesCount, 11U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_missing_dnskey)
{
  /* We have an insecure (no DS at the parent) but signed zone, albeit
     slightly broken (no DNSKEY).
     Check that we correctly detect the zone as Insecure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS) {
      /* powerdns.com is not signed.
         sub.powerdns.com is signed but not secure */
      if (domain == DNSName("powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      else if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
    }
    else if (type == QType::DNSKEY) {
      if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NODATA for the DNSKEY */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
        addNSECRecordToLW(domain, DNSName("sub2.powerdns.com."), {QType::SOA}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
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
        if (domain.isPartOf(DNSName("powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* no DS */
          addNSECRecordToLW(DNSName("powerdns.com."), DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == DNSName("www.sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("www.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  /* first we do a query in the parent zone (powerdns.com), insecure,
     to get the NS in cache so we don't learn the zone cut before
     validating */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* now we query the sub zone */
  ret.clear();
  res = sr->beginResolve(DNSName("www.sub.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(DNSName("www.sub.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_nxd_dnskey)
{
  /* We have an insecure (no DS at the parent) but signed zone, albeit
     slightly broken (no DNSKEY, returning NXD while there is data there).
     Check that we correctly detect the zone as Insecure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS) {
      /* powerdns.com is not signed.
         sub.powerdns.com is signed but not secure */
      if (domain == DNSName("powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      else if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
      else {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
    }
    else if (type == QType::DNSKEY) {
      if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NXD for the DNSKEY */
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
        addNSECRecordToLW(DNSName("sua.powerdnsz.com."), DNSName("suc.powerdns.com."), {QType::SOA}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
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
        if (domain.isPartOf(DNSName("powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* no DS */
          addNSECRecordToLW(DNSName("powerdns.com."), DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == DNSName("www.sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("www.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  /* first we do a query in the parent zone (powerdns.com), insecure,
     to get the NS in cache so we don't learn the zone cut before
     validating */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* now we query the sub zone */
  ret.clear();
  res = sr->beginResolve(DNSName("www.sub.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(DNSName("www.sub.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_nxd_ds)
{
  /* We have an insecure (no DS at the parent) but signed zone, albeit
     slightly broken (returning NXD when asking for the DS while there is data there).
     Check that we correctly detect the zone as Insecure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([targetAddr, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS) {
      /* powerdns.com is not signed.
         sub.powerdns.com is signed but not secure */
      if (domain == DNSName("powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        addNSECRecordToLW(domain, DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("com."), 300);
        return LWResult::Result::Success;
      }
      else if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NXD!! for the DS */
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
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
        if (domain.isPartOf(DNSName("powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* no DS */
          addNSECRecordToLW(DNSName("powerdns.com."), DNSName("powerdnsz.com."), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == DNSName("www.sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("www.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  /* first we do a query in the parent zone (powerdns.com), insecure,
     to get the NS in cache so we don't learn the zone cut before
     validating */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* now we query the sub zone */
  ret.clear();
  res = sr->beginResolve(DNSName("www.sub.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 8U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(DNSName("www.sub.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_dnskey_loop)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  /* Generate key material for "powerdns.com." */
  auto dcke = DNSCryptoKeyEngine::make(DNSSECKeeper::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey key;
  key.d_flags = 257;
  key.setKey(std::move(dcke));
  DSRecordContent drc = makeDSFromDNSKey(DNSName("powerdns.com."), key.getDNSKEY(), DNSSECKeeper::DIGEST_SHA256);

  testkeysset_t wrongKeys;
  auto wrongDcke = DNSCryptoKeyEngine::make(DNSSECKeeper::ECDSA256);
  wrongDcke->create(wrongDcke->getBits());
  DNSSECPrivateKey wrongKey;
  wrongKey.d_flags = 256;
  wrongKey.setKey(std::move(wrongDcke));
  DSRecordContent uselessdrc = makeDSFromDNSKey(DNSName("powerdns.com."), wrongKey.getDNSKEY(), DNSSECKeeper::DIGEST_SHA256);

  wrongKeys[DNSName("powerdns.com.")] = std::pair<DNSSECPrivateKey, DSRecordContent>(wrongKey, uselessdrc);
  keys[DNSName("powerdns.com.")] = std::pair<DNSSECPrivateKey, DSRecordContent>(key, drc);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([targetAddr, &queriesCount, keys, wrongKeys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    else if (type == QType::DNSKEY) {
      if (domain == DNSName("powerdns.com.")) {
        /* wrong DNSKEY */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, wrongKeys);
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
        if (domain.isPartOf(DNSName("powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == DNSName("www.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  /* first we do a query in the parent zone (powerdns.com), insecure,
     to get the NS in cache so we don't learn the zone cut before
     validating */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidDNSKEY);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoValidDNSKEY);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_SUITE_END()
