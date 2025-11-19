#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"
#include "taskqueue.hh"
#include "rec-taskqueue.hh"

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
  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queries++;
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      v4Hit |= address.isIPv4();
      v6Hit |= address.isIPv6();

      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "ns1.powerdns.com.", QType::AAAA, "2001:DB8:1::53", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53")) {
      setLWResult(res, 0, true, false, false);
      v4Hit |= true;
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
      }
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("[2001:DB8:1::53]:53")) {
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
  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queries++;
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);

      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "ns1.powerdns.com.", QType::AAAA, "2001:DB8:1::53", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("[2001:DB8:1::53]:53")) {
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
  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queries++;
    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      if (domain == DNSName("powerdns.com.")) {
        addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      }
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53")) {
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
  std::unique_ptr<SyncRes> resolver;
  initSR(resolver, true);

  setDNSSECValidation(resolver, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.sub.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  resolver->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
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
      if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NODATA for the DS, but it is in fact a NXD proof, which would be bogus if the zone was actually secure */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        addNSECRecordToLW(DNSName("nw.powerdns.com."), DNSName("tz.powerdns.com."), {QType::NS}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
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
      else if (address == ComboAddress("192.0.2.2:53")) {
        if (domain.isPartOf(DNSName("sub.powerdns.com."))) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        if (domain == DNSName("nx.powerdns.com.")) {
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
  int res = resolver->beginResolve(DNSName("nx.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK(ret.at(0).d_type == QType::SOA);
  BOOST_CHECK(ret.at(1).d_type == QType::RRSIG);
  BOOST_CHECK(ret.at(2).d_type == QType::NSEC);
  BOOST_CHECK(ret.at(3).d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* now we query the sub zone */
  ret.clear();
  res = resolver->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 9U);

  /* again, to test the cache */
  ret.clear();
  res = resolver->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::Insecure);
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
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
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
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
      else if (address == ComboAddress("192.0.2.2:53")) {
        if (domain.isPartOf(DNSName("sub.powerdns.com."))) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("com.") /* wrong signer !! */, 300, /* broken !!!*/ true);
          return LWResult::Result::Success;
        }
        if (domain == DNSName("www.powerdns.com.")) {
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
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
      if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
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
      else if (address == ComboAddress("192.0.2.2:53")) {
        if (domain == DNSName("nxd.sub.powerdns.com.")) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addNSECRecordToLW(DNSName("nxc.sub.powerdns.com."), DNSName("nxe.sub.powerdnsz.com."), {QType::AAAA}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        if (domain == DNSName("nodata.sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          /* NSEC but no SOA */
          addNSECRecordToLW(DNSName("nodata.sub.powerdns.com."), DNSName("nodata2.sub.powerdnsz.com."), {QType::AAAA}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        if (domain == DNSName("www.powerdns.com.")) {
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
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
      if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
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
      else if (address == ComboAddress("192.0.2.2:53")) {
        if (domain == DNSName("www.sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        if (domain == DNSName("www.powerdns.com.")) {
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
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
      if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NODATA for the DS */
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
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
      else if (address == ComboAddress("192.0.2.2:53")) {
        if (domain == DNSName("www.sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        if (domain == DNSName("www.powerdns.com.")) {
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
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
      if (domain == DNSName("sub.powerdns.com.")) {
        /* sends a NXD!! for the DS */
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return LWResult::Result::Success;
      }
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
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
      else if (address == ComboAddress("192.0.2.2:53")) {
        if (domain == DNSName("www.sub.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com."), 300);
          return LWResult::Result::Success;
        }
        if (domain == DNSName("www.powerdns.com.")) {
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  /* Generate key material for "powerdns.com." */
  auto dcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey key;
  key.setKey(std::move(dcke), 257);
  DSRecordContent drc = makeDSFromDNSKey(DNSName("powerdns.com."), key.getDNSKEY(), DNSSEC::DIGEST_SHA256);

  testkeysset_t wrongKeys;
  auto wrongDcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  wrongDcke->create(wrongDcke->getBits());
  DNSSECPrivateKey wrongKey;
  wrongKey.setKey(std::move(wrongDcke), 256);
  DSRecordContent uselessdrc = makeDSFromDNSKey(DNSName("powerdns.com."), wrongKey.getDNSKEY(), DNSSEC::DIGEST_SHA256);

  wrongKeys[DNSName("powerdns.com.")] = std::pair<DNSSECPrivateKey, DSRecordContent>(wrongKey, uselessdrc);
  keys[DNSName("powerdns.com.")] = std::pair<DNSSECPrivateKey, DSRecordContent>(key, drc);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DNSKEY) {
      if (domain == DNSName("powerdns.com.")) {
        /* wrong DNSKEY */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, wrongKeys);
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
        if (domain.isPartOf(DNSName("powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
      }
      else if (address == ComboAddress("192.0.2.2:53")) {
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

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_ds_loop)
{
  // Test the case where the RRSIG on the name *and* the RRSIG of the NSEC denying the DS is broken.
  // This sends te zone cut code trying extra hard to find a zone cut into an endless recursion.
  std::unique_ptr<SyncRes> resolver;
  initSR(resolver, true, false);

  setDNSSECValidation(resolver, DNSSECMode::ValidateAll);
  resolver->setQNameMinimization();

  primeHints();
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  /* Generate key material for "powerdns.com." */
  auto dcke = DNSCryptoKeyEngine::make(DNSSEC::ECDSA256);
  dcke->create(dcke->getBits());
  DNSSECPrivateKey key;
  key.setKey(std::move(dcke), 257);
  DSRecordContent drc = makeDSFromDNSKey(DNSName("powerdns.com."), key.getDNSKEY(), DNSSEC::DIGEST_SHA256);

  keys[DNSName("powerdns.com.")] = std::pair<DNSSECPrivateKey, DSRecordContent>(key, drc);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  resolver->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
    }
    if (type == QType::DS) {
      if (domain == DNSName("www.powerdns.com.")) {
        auto ret = genericDSAndDNSKEYHandler(res, domain, domain, type, keys, true, boost::none, false, false);
        for (auto& rec : res->d_records) {
          // We know the NSEC RRSIG for the DS is the only one
          if (rec.d_name == DNSName("www.powerdns.com") && rec.d_type == QType::RRSIG) {
            auto ptr = getRR<RRSIGRecordContent>(rec);
            ((char*)(void*)(ptr->d_signature.data()))[0] ^= 0x42; // NOLINT
          }
        }
        return ret;
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
        if (domain.isPartOf(DNSName("powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          addDS(DNSName("powerdns.com."), 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
      }
      else if (address == ComboAddress("192.0.2.2:53")) {
        if (domain == DNSName("www.powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, true);
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = resolver->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::BogusNoValidRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret.at(0).d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* again, to test the cache */
  ret.clear();
  res = resolver->beginResolve(DNSName("www.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(resolver->getValidationState(), vState::BogusNoValidRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 6U);
}

static auto createPID(std::string rem, int tcpsock, uint16_t type, std::string domain, int fd, uint16_t id)
{
  PacketID pid;
  pid.remote = ComboAddress(rem);
  pid.tcpsock = tcpsock;
  pid.type = type;
  pid.domain = DNSName(domain);
  pid.fd = fd;
  pid.id = id;
  return std::make_shared<PacketID>(pid);
}

BOOST_AUTO_TEST_CASE(test_PacketIDCompare)
{
  // Ordered by domain, but not by id
  auto a = createPID("1.2.3.4", -1, 1, "powerdns.com", -1, 1000);
  auto b = createPID("1.2.3.4", -1, 1, "powerdns.net", -1, 999);

  auto cmp = PacketIDCompare();
  auto bcmp = PacketIDBirthdayCompare();

  bool r1 = cmp.operator()(a, b);
  bool br1 = bcmp.operator()(a, b);
  bool r2 = cmp.operator()(b, a);
  bool br2 = bcmp.operator()(b, a);

  BOOST_CHECK(r1);
  BOOST_CHECK(br1);
  BOOST_CHECK(!r2);
  BOOST_CHECK(!br2);

  // Ordered by domain, but not by fd
  a = createPID("1.2.3.4", -1, 1, "powerdns.com", 1, 1000);
  b = createPID("1.2.3.4", -1, 1, "powerdns.net", -1, 1000);

  r1 = cmp.operator()(a, b);
  br1 = bcmp.operator()(a, b);
  r2 = cmp.operator()(b, a);
  br2 = bcmp.operator()(b, a);

  BOOST_CHECK(r1);
  BOOST_CHECK(br1);
  BOOST_CHECK(!r2);
  BOOST_CHECK(!br2);
}

BOOST_AUTO_TEST_CASE(test_servestale)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  MemRecursorCache::s_maxServedStaleExtensions = 1440;

  primeHints();

  const DNSName target("powerdns.com.");

  std::set<ComboAddress> downServers;
  size_t downCount = 0;
  size_t lookupCount = 0;

  const int theTTL = 5;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    /* this will cause issue with qname minimization if we ever implement it */
    if (downServers.find(address) != downServers.end()) {
      downCount++;
      return LWResult::Result::Timeout;
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 5);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 5);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, theTTL);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53") || address == ComboAddress("192.0.2.3:53") || address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("[2001:DB8::3]:53")) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.4", DNSResourceRecord::ANSWER, 5);
      lookupCount++;
      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
  });

  time_t now = time(nullptr);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 0U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  downServers.insert(ComboAddress("192.0.2.2:53"));
  downServers.insert(ComboAddress("192.0.2.3:53"));
  downServers.insert(ComboAddress("[2001:DB8::2]:53"));
  downServers.insert(ComboAddress("[2001:DB8::3]:53"));

  sr->setNow(timeval{now + theTTL + 1, 0});

  BOOST_REQUIRE_EQUAL(getTaskSize(), 0U);

  // record is expired, so serve stale should kick in
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  BOOST_REQUIRE_EQUAL(getTaskSize(), 1U);
  auto task = taskQueuePop();
  BOOST_CHECK(task.d_qname == target);
  BOOST_CHECK_EQUAL(task.d_qtype, QType::A);

  // Again, no lookup as the record is marked stale
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  // Again, no lookup as the record is marked stale but as the TTL has passed a task should have been pushed
  sr->setNow(timeval{now + 2 * (theTTL + 1), 0});
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  BOOST_REQUIRE_EQUAL(getTaskSize(), 1U);
  task = taskQueuePop();
  BOOST_CHECK(task.d_qname == target);
  BOOST_CHECK_EQUAL(task.d_qtype, QType::A);

  // Now simulate a succeeding task execution
  sr->setNow(timeval{now + 3 * (theTTL + 1), 0});
  downServers.clear();
  sr->setRefreshAlmostExpired(true);
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  // And again, result should come from cache
  sr->setRefreshAlmostExpired(false);
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_servestale_neg)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  MemRecursorCache::s_maxServedStaleExtensions = 1440;
  NegCache::s_maxServedStaleExtensions = 1440;

  primeHints();

  const DNSName target("powerdns.com.");

  std::set<ComboAddress> downServers;
  size_t downCount = 0;
  size_t lookupCount = 0;

  const int theTTL = 5;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    /* this will cause issue with qname minimization if we ever implement it */
    if (downServers.find(address) != downServers.end()) {
      downCount++;
      return LWResult::Result::Timeout;
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, theTTL);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53") || address == ComboAddress("192.0.2.3:53") || address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("[2001:DB8::3]:53")) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, "powerdns.com.", QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 60", DNSResourceRecord::AUTHORITY);
      lookupCount++;
      return LWResult::Result::Success;
    }
    else {
      return LWResult::Result::Timeout;
    }
  });

  time_t now = time(nullptr);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(downCount, 0U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  downServers.insert(ComboAddress("192.0.2.2:53"));
  downServers.insert(ComboAddress("192.0.2.3:53"));
  downServers.insert(ComboAddress("[2001:DB8::2]:53"));
  downServers.insert(ComboAddress("[2001:DB8::3]:53"));

  const int negTTL = 60;

  sr->setNow(timeval{now + negTTL + 1, 0});

  // record is expired, so serve stale should kick in
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  // Again, no lookup as the record is marked stale
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  // Again, no lookup as the record is marked stale but as the TTL has passed a task should have been pushed
  sr->setNow(timeval{now + 2 * (negTTL + 1), 0});
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  BOOST_REQUIRE_EQUAL(getTaskSize(), 1U);
  auto task = taskQueuePop();
  BOOST_CHECK(task.d_qname == target);
  BOOST_CHECK_EQUAL(task.d_qtype, QType::A);

  // Now simulate a succeeding task execution
  sr->setNow(timeval{now + 3 * (negTTL + 1), 0});
  downServers.clear();
  sr->setRefreshAlmostExpired(true);
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  // And again, result should come from cache
  sr->setRefreshAlmostExpired(false);
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_servestale_neg_to_available)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  MemRecursorCache::s_maxServedStaleExtensions = 1440;
  NegCache::s_maxServedStaleExtensions = 1440;

  primeHints();

  const DNSName target("powerdns.com.");

  std::set<ComboAddress> downServers;
  size_t downCount = 0;
  size_t lookupCount = 0;
  bool negLookup = true;

  const int theTTL = 5;
  const int negTTL = 60;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    /* this will cause issue with qname minimization if we ever implement it */
    if (downServers.find(address) != downServers.end()) {
      downCount++;
      return LWResult::Result::Timeout;
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, theTTL);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53") || address == ComboAddress("192.0.2.3:53") || address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("[2001:DB8::3]:53")) {
      if (negLookup) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, "powerdns.com.", QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 60", DNSResourceRecord::AUTHORITY, negTTL);
        lookupCount++;
        return LWResult::Result::Success;
      }
      {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.4", DNSResourceRecord::ANSWER, theTTL);
        lookupCount++;
        return LWResult::Result::Success;
      }
    }
    else {
      return LWResult::Result::Timeout;
    }
  });

  time_t now = time(nullptr);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(downCount, 0U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  downServers.insert(ComboAddress("192.0.2.2:53"));
  downServers.insert(ComboAddress("192.0.2.3:53"));
  downServers.insert(ComboAddress("[2001:DB8::2]:53"));
  downServers.insert(ComboAddress("[2001:DB8::3]:53"));

  sr->setNow(timeval{now + negTTL + 1, 0});

  // record is expired, so serve stale should kick in
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  // Again, no lookup as the record is marked stale
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  // Again, no lookup as the record is marked stale but as the TTL has passed a task should have been pushed
  sr->setNow(timeval{now + 2 * (negTTL + 1), 0});
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  BOOST_REQUIRE_EQUAL(getTaskSize(), 1U);
  auto task = taskQueuePop();
  BOOST_CHECK(task.d_qname == target);
  BOOST_CHECK_EQUAL(task.d_qtype, QType::A);

  // Now simulate a succeeding task execution an record has become available
  negLookup = false;
  sr->setNow(timeval{now + 3 * (negTTL + 1), 0});
  downServers.clear();
  sr->setRefreshAlmostExpired(true);
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  // And again, result should come from cache
  sr->setRefreshAlmostExpired(false);
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 4U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_servestale_cname_to_nxdomain)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  MemRecursorCache::s_maxServedStaleExtensions = 1440;
  NegCache::s_maxServedStaleExtensions = 1440;

  primeHints();

  const DNSName target("www.powerdns.com.");
  const DNSName auth("powerdns.com.");

  std::set<ComboAddress> downServers;
  size_t downCount = 0;
  size_t lookupCount = 0;
  bool cnameOK = true;

  const int theTTL = 5;
  const int negTTL = 60;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    /* this will cause issue with qname minimization if we ever implement it */
    if (downServers.find(address) != downServers.end()) {
      downCount++;
      return LWResult::Result::Timeout;
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, theTTL);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53") || address == ComboAddress("192.0.2.3:53") || address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("[2001:DB8::3]:53")) {
      if (cnameOK) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::CNAME, "cname.powerdns.com.", DNSResourceRecord::ANSWER, 5);
        addRecordToLW(res, DNSName("cname.powerdns.com"), QType::A, "192.0.2.4", DNSResourceRecord::ANSWER, theTTL);
        lookupCount++;
        return LWResult::Result::Success;
      }
      setLWResult(res, RCode::NXDomain, true, false, true);
      addRecordToLW(res, auth, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 60", DNSResourceRecord::AUTHORITY, negTTL);
      lookupCount++;
      return LWResult::Result::Success;
    }
    else {
      return LWResult::Result::Timeout;
    }
  });

  time_t now = time(nullptr);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(ret[1].d_name, DNSName("cname.powerdns.com"));
  BOOST_CHECK_EQUAL(downCount, 0U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  downServers.insert(ComboAddress("192.0.2.2:53"));
  downServers.insert(ComboAddress("192.0.2.3:53"));
  downServers.insert(ComboAddress("[2001:DB8::2]:53"));
  downServers.insert(ComboAddress("[2001:DB8::3]:53"));

  sr->setNow(timeval{now + theTTL + 1, 0});

  // record is expired, so serve stale should kick in
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(ret[1].d_name, DNSName("cname.powerdns.com"));
  BOOST_CHECK_EQUAL(downCount, 8U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  // Again, no lookup as the record is marked stale
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(ret[1].d_name, DNSName("cname.powerdns.com"));
  BOOST_CHECK_EQUAL(downCount, 8U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  // Again, no lookup as the record is marked stale but as the TTL has passed a task should have been pushed
  sr->setNow(timeval{now + 2 * (theTTL + 1), 0});
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(ret[1].d_name, DNSName("cname.powerdns.com"));
  BOOST_CHECK_EQUAL(downCount, 8U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  BOOST_REQUIRE_EQUAL(getTaskSize(), 2U);
  auto task = taskQueuePop();
  BOOST_CHECK(task.d_qname == target);
  BOOST_CHECK_EQUAL(task.d_qtype, QType::CNAME);
  task = taskQueuePop();
  BOOST_CHECK(task.d_qname == DNSName("cname.powerdns.com"));
  BOOST_CHECK_EQUAL(task.d_qtype, QType::A);

  // Now simulate a succeeding task execution and NxDomain on explicit CNAME result becomes available
  cnameOK = false;
  sr->setNow(timeval{now + 3 * (theTTL + 1), 0});
  downServers.clear();
  sr->setRefreshAlmostExpired(true);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::CNAME), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, auth);
  BOOST_CHECK_EQUAL(downCount, 8U);
  BOOST_CHECK_EQUAL(lookupCount, 3U);

  // And again, result should come from cache
  sr->setRefreshAlmostExpired(false);
  ret.clear();
  res = sr->beginResolve(target, QType(QType::CNAME), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, auth);
  BOOST_CHECK_EQUAL(downCount, 8U);
  BOOST_CHECK_EQUAL(lookupCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_servestale_cname_to_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  MemRecursorCache::s_maxServedStaleExtensions = 1440;
  NegCache::s_maxServedStaleExtensions = 1440;

  primeHints();

  const DNSName target("www.powerdns.com.");
  const DNSName auth("powerdns.com.");

  std::set<ComboAddress> downServers;
  size_t downCount = 0;
  size_t lookupCount = 0;
  bool cnameOK = true;

  const time_t theTTL = 5;
  const time_t negTTL = 60;

  sr->setAsyncCallback([&](const ComboAddress& ipAddress, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    /* this will cause issue with qname minimization if we ever implement it */
    if (downServers.find(ipAddress) != downServers.end()) {
      downCount++;
      return LWResult::Result::Timeout;
    }

    if (isRootServer(ipAddress)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL);
      return LWResult::Result::Success;
    }
    if (ipAddress == ComboAddress("192.0.2.1:53") || ipAddress == ComboAddress("[2001:DB8::1]:53")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, theTTL);
      return LWResult::Result::Success;
    }
    if (ipAddress == ComboAddress("192.0.2.2:53") || ipAddress == ComboAddress("192.0.2.3:53") || ipAddress == ComboAddress("[2001:DB8::2]:53") || ipAddress == ComboAddress("[2001:DB8::3]:53")) {
      if (cnameOK) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::CNAME, "cname.powerdns.com.", DNSResourceRecord::ANSWER, 5);
        addRecordToLW(res, DNSName("cname.powerdns.com"), QType::A, "192.0.2.4", DNSResourceRecord::ANSWER, theTTL);
        lookupCount++;
        return LWResult::Result::Success;
      }
      setLWResult(res, RCode::NoError, true, false, true);
      addRecordToLW(res, auth, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 60", DNSResourceRecord::AUTHORITY, negTTL);
      lookupCount++;
      return LWResult::Result::Success;
    }
    return LWResult::Result::Timeout;
  });

  time_t now = time(nullptr);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(ret[1].d_name, DNSName("cname.powerdns.com"));
  BOOST_CHECK_EQUAL(downCount, 0U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  downServers.insert(ComboAddress("192.0.2.2:53"));
  downServers.insert(ComboAddress("192.0.2.3:53"));
  downServers.insert(ComboAddress("[2001:DB8::2]:53"));
  downServers.insert(ComboAddress("[2001:DB8::3]:53"));

  sr->setNow(timeval{now + theTTL + 1, 0});

  // record is expired, so serve stale should kick in
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(ret[1].d_name, DNSName("cname.powerdns.com"));
  BOOST_CHECK_EQUAL(downCount, 8U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  // Again, no lookup as the record is marked stale
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(ret[1].d_name, DNSName("cname.powerdns.com"));
  BOOST_CHECK_EQUAL(downCount, 8U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  // Again, no lookup as the record is marked stale but as the TTL has passed a task should have been pushed
  sr->setNow(timeval{now + 2 * (theTTL + 1), 0});
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(ret[1].d_name, DNSName("cname.powerdns.com"));
  BOOST_CHECK_EQUAL(downCount, 8U);
  BOOST_CHECK_EQUAL(lookupCount, 2U);

  BOOST_REQUIRE_EQUAL(getTaskSize(), 2U);
  auto task = taskQueuePop();
  BOOST_CHECK(task.d_qname == target);
  BOOST_CHECK_EQUAL(task.d_qtype, QType::CNAME);
  task = taskQueuePop();
  BOOST_CHECK(task.d_qname == DNSName("cname.powerdns.com"));
  BOOST_CHECK_EQUAL(task.d_qtype, QType::A);

  // Now simulate a succeeding task execution and NoDATA on explicit CNAME result becomes available
  cnameOK = false;
  sr->setNow(timeval{now + 3 * (theTTL + 1), 0});
  downServers.clear();
  sr->setRefreshAlmostExpired(true);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::CNAME), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, auth);
  BOOST_CHECK_EQUAL(downCount, 8U);
  BOOST_CHECK_EQUAL(lookupCount, 3U);

  // And again, result should come from cache
  sr->setRefreshAlmostExpired(false);
  ret.clear();
  res = sr->beginResolve(target, QType(QType::CNAME), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(ret[0].d_name, auth);
  BOOST_CHECK_EQUAL(downCount, 8U);
  BOOST_CHECK_EQUAL(lookupCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_servestale_immediateservfail)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  MemRecursorCache::s_maxServedStaleExtensions = 1440;

  primeHints();

  const DNSName target("powerdns.com.");

  std::set<ComboAddress> downServers;
  size_t downCount = 0;
  size_t lookupCount = 0;

  const int theTTL = 5;

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    /* this will cause issue with qname minimization if we ever implement it */

    if (downServers.find(address) != downServers.end()) {
      downCount++;
      throw ImmediateServFailException("FAIL!");
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, theTTL);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 5);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, theTTL);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 5);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, theTTL);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53") || address == ComboAddress("192.0.2.3:53") || address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("[2001:DB8::3]:53")) {
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.4", DNSResourceRecord::ANSWER, 5);
      lookupCount++;
      return LWResult::Result::Success;
    }
    else {
      return LWResult::Result::Timeout;
    }
  });

  time_t now = time(nullptr);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(downCount, 0U);
  BOOST_CHECK_EQUAL(lookupCount, 1U);

  downServers.insert(ComboAddress("192.0.2.2:53"));
  downServers.insert(ComboAddress("192.0.2.3:53"));
  downServers.insert(ComboAddress("[2001:DB8::2]:53"));
  downServers.insert(ComboAddress("[2001:DB8::3]:53"));

  sr->setNow(timeval{now + theTTL + 1, 0});

  BOOST_REQUIRE_EQUAL(getTaskSize(), 0U);

  // record is expired, so serve stale should kick in
  ret.clear();
  BOOST_REQUIRE_THROW(sr->beginResolve(target, QType(QType::A), QClass::IN, ret), ImmediateServFailException);
  BOOST_CHECK_EQUAL(downCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_glued_referral_additional_update)
{
  // Test that additional records update the cache
  // We use two zones that share NS and their addresses
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("pdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    /* this will cause issue with qname minimization if we ever implement it */
    if (domain != target1 && domain != target2) {
      return LWResult::Result::Timeout;
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      if (domain == target1) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return LWResult::Result::Success;
      }
      if (domain == target2) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "pdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return LWResult::Result::Success;
      }
      return LWResult::Result::Timeout;
    }
    if (address == ComboAddress("192.0.2.2:53") || address == ComboAddress("192.0.2.3:53") || address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("[2001:DB8::3]:53")) {
      setLWResult(res, 0, true, false, true);
      if (domain == target1) {
        addRecordToLW(res, target1, QType::A, "192.0.2.4");
      }
      else if (domain == target2) {
        addRecordToLW(res, target2, QType::A, "192.0.2.5");
      }
      return LWResult::Result::Success;
    }
    else {
      return LWResult::Result::Timeout;
    }
  });

  // Lookup first name. We should see the address of a nameserver in the cache
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target1);

  auto firstTTL = g_recCache->get(sr->getNow().tv_sec, DNSName("pdns-public-ns1.powerdns.com"), QType::A, MemRecursorCache::None, nullptr, ComboAddress());

  // Move the time
  sr->setNow({sr->getNow().tv_sec + 2, sr->getNow().tv_usec});

  // Lookup second name. We should see the address rec of a nameserver in the cache being updated
  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target2);

  auto secondTTL = g_recCache->get(sr->getNow().tv_sec, DNSName("pdns-public-ns1.powerdns.com"), QType::A, MemRecursorCache::None, nullptr, ComboAddress());
  // TTL shoud be back to original value
  BOOST_CHECK_EQUAL(firstTTL, secondTTL);
}

BOOST_AUTO_TEST_CASE(test_glued_referral_additional_no_update_because_locked)
{
  // Test that additional records do not update the cache
  // We use two zones that share NS and their addresses
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  // Set the lock
  SyncRes::s_locked_ttlperc = 50;

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("pdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    /* this will cause issue with qname minimization if we ever implement it */
    if (domain != target1 && domain != target2) {
      return LWResult::Result::Timeout;
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      if (domain == target1) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return LWResult::Result::Success;
      }
      if (domain == target2) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "pdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return LWResult::Result::Success;
      }
      return LWResult::Result::Timeout;
    }
    if (address == ComboAddress("192.0.2.2:53") || address == ComboAddress("192.0.2.3:53") || address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("[2001:DB8::3]:53")) {
      setLWResult(res, 0, true, false, true);
      if (domain == target1) {
        addRecordToLW(res, target1, QType::A, "192.0.2.4");
      }
      else if (domain == target2) {
        addRecordToLW(res, target2, QType::A, "192.0.2.5");
      }
      return LWResult::Result::Success;
    }
    else {
      return LWResult::Result::Timeout;
    }
  });

  // Lookup first name. We should see the address of a nameserver in the cache
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target1);

  auto firstTTL = g_recCache->get(sr->getNow().tv_sec, DNSName("pdns-public-ns1.powerdns.com"), QType::A, MemRecursorCache::None, nullptr, ComboAddress());

  // Move the time
  sr->setNow({sr->getNow().tv_sec + 2, sr->getNow().tv_usec});

  // Lookup second name. We should see the address of a nameserver in the cache *not* being updated
  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target2);

  auto secondTTL = g_recCache->get(sr->getNow().tv_sec, DNSName("pdns-public-ns1.powerdns.com"), QType::A, MemRecursorCache::None, nullptr, ComboAddress());
  // Time has passed, so ttl1 != ttl2
  BOOST_CHECK_NE(firstTTL, secondTTL);
}

BOOST_AUTO_TEST_CASE(test_locked_nonauth_update_to_auth)
{
  // Test that a non-bogus authoritative record replaces a non-authoritative one
  // even if the cache is locked
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  // Set the lock
  SyncRes::s_locked_ttlperc = 50;

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([&](const ComboAddress& address, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    /* this will cause issue with qname minimization if we ever implement it */
    if (domain != target) {
      return LWResult::Result::Timeout;
    }

    if (isRootServer(address)) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
      addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.1:53") || address == ComboAddress("[2001:DB8::1]:53")) {
      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, target, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, target, QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
      addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
      addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
      return LWResult::Result::Success;
    }
    if (address == ComboAddress("192.0.2.2:53") || address == ComboAddress("192.0.2.3:53") || address == ComboAddress("[2001:DB8::2]:53") || address == ComboAddress("[2001:DB8::3]:53")) {
      if (type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.4");
        return LWResult::Result::Success;
      }
      if (type == QType::NS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::ANSWER, 172800);
        addRecordToLW(res, target, QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::ANSWER, 172800);
        return LWResult::Result::Success;
      }
    }
    return LWResult::Result::Timeout;
  });

  // Lookup first name. We should see the (unauth) nameserver in the cache
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);

  auto firstTTL = g_recCache->get(sr->getNow().tv_sec, target, QType::NS, MemRecursorCache::None, nullptr, ComboAddress());
  BOOST_CHECK_GT(firstTTL, 0);

  // Lookup NS records. We should see the nameserver in the cache being updated to auth
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK(ret[0].d_type == QType::NS);

  auto secondTTL = g_recCache->get(sr->getNow().tv_sec, target, QType::NS, MemRecursorCache::RequireAuth, nullptr, ComboAddress());
  BOOST_CHECK_GT(secondTTL, 0);
}

BOOST_AUTO_TEST_CASE(test_nodata_ok)
{
  vector<DNSRecord> vec;
  vec.emplace_back("nz.compass.com", nullptr, QType::CNAME, QClass::IN, 60, 0, DNSResourceRecord::ANSWER);
  vec.emplace_back("nz.compass.com", nullptr, QType::RRSIG, QClass::IN, 60, 0, DNSResourceRecord::ANSWER);
  vec.emplace_back("kslicmitv6qe1behk70g8q7e572vabp0.kompass.com", nullptr, QType::NSEC3, QClass::IN, 60, 0, DNSResourceRecord::AUTHORITY);
  vec.emplace_back("kslicmitv6qe1behk70g8q7e572vabp0.kompass.com", nullptr, QType::RRSIG, QClass::IN, 60, 0, DNSResourceRecord::AUTHORITY);

  BOOST_CHECK(SyncRes::answerIsNOData(QType::A, RCode::NoError, vec));
}

BOOST_AUTO_TEST_CASE(test_nodata_not)
{
  vector<DNSRecord> vec;
  vec.emplace_back("kc-pro.westeurope.cloudapp.azure.com", nullptr, QType::A, QClass::IN, 60, 0, DNSResourceRecord::ANSWER);
  vec.emplace_back("nz.compass.com", nullptr, QType::CNAME, QClass::IN, 60, 0, DNSResourceRecord::ANSWER);
  vec.emplace_back("nz.compass.com", nullptr, QType::RRSIG, QClass::IN, 60, 0, DNSResourceRecord::ANSWER);
  vec.emplace_back("kslicmitv6qe1behk70g8q7e572vabp0.kompass.com", nullptr, QType::NSEC3, QClass::IN, 60, 0, DNSResourceRecord::AUTHORITY);
  vec.emplace_back("kslicmitv6qe1behk70g8q7e572vabp0.kompass.com", nullptr, QType::RRSIG, QClass::IN, 60, 0, DNSResourceRecord::AUTHORITY);

  BOOST_CHECK(!SyncRes::answerIsNOData(QType::A, RCode::NoError, vec));
}

BOOST_AUTO_TEST_CASE(test_nodata_out_of_order)
{
  vector<DNSRecord> vec;
  vec.emplace_back("nz.compass.com", nullptr, QType::CNAME, QClass::IN, 60, 0, DNSResourceRecord::ANSWER);
  vec.emplace_back("nz.compass.com", nullptr, QType::RRSIG, QClass::IN, 60, 0, DNSResourceRecord::ANSWER);
  vec.emplace_back("kslicmitv6qe1behk70g8q7e572vabp0.kompass.com", nullptr, QType::NSEC3, QClass::IN, 60, 0, DNSResourceRecord::AUTHORITY);
  vec.emplace_back("kslicmitv6qe1behk70g8q7e572vabp0.kompass.com", nullptr, QType::RRSIG, QClass::IN, 60, 0, DNSResourceRecord::AUTHORITY);
  vec.emplace_back("kc-pro.westeurope.cloudapp.azure.com", nullptr, QType::A, QClass::IN, 60, 0, DNSResourceRecord::ANSWER);

  BOOST_CHECK(!SyncRes::answerIsNOData(QType::A, RCode::NoError, vec));
}

BOOST_AUTO_TEST_SUITE_END()
