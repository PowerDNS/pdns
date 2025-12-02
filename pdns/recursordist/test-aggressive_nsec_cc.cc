#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "aggressive_nsec.hh"
#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(aggressive_nsec_cc)

BOOST_AUTO_TEST_CASE(test_small_covering_nsec3)
{
  AggressiveNSECCache::s_maxNSEC3CommonPrefix = 1;

  const std::vector<std::tuple<string, string, uint8_t, bool>> table = {
    {"gujhshp2lhmnpoo9qde4blg4gq3hgl99", "gujhshp2lhmnpoo9qde4blg4gq3hgl9a", 157, true},
    {"gujhshp2lhmnpoo9qde4blg4gq3hgl99", "gujhshp2lhmnpoo9qde4blg4gq3hgl9a", 158, false},
    {"0ujhshp2lhmnpoo9qde4blg4gq3hgl99", "vujhshp2lhmnpoo9qde4blg4gq3hgl9a", 0, false},
    {"0ujhshp2lhmnpoo9qde4blg4gq3hgl99", "7ujhshp2lhmnpoo9qde4blg4gq3hgl9a", 1, true},
    {"0ujhshp2lhmnpoo9qde4blg4gq3hgl99", "7ujhshp2lhmnpoo9qde4blg4gq3hgl9a", 2, false},
    {"0ujhshp2lhmnpoo9qde4blg4gq3hgl99", "fujhshp2lhmnpoo9qde4blg4gq3hgl9a", 1, false},
    {"0ujhshp2lhmnpoo9qde4blg4gq3hgl99", "8ujhshp2lhmnpoo9qde4blg4gq3hgl9a", 1, false},
    {"8ujhshp2lhmnpoo9qde4blg4gq3hgl99", "8ujhshp2lhmnpoo9qde4blg4gq3hgl99", 0, false},
    {"8ujhshp2lhmnpoo9qde4blg4gq3hgl99", "8ujhshp2lhmnpoo9qde4blg4gq3hgl99", 1, false},
    {"8ujhshp2lhmnpoo9qde4blg4gq3hgl99", "8ujhshp2lhmnpoo9qde4blg4gq3hgl99", 157, false},
  };

  for (const auto& [owner, next, boundary, result] : table) {
    AggressiveNSECCache::s_maxNSEC3CommonPrefix = boundary;
    BOOST_CHECK_EQUAL(AggressiveNSECCache::isSmallCoveringNSEC3(DNSName(owner), fromBase32Hex(next)), result);
  }
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_nxdomain)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we first ask b.powerdns.com., get a NXD, then check that the aggressive
     NSEC cache will use the NSEC (a -> h) to prove that g.powerdns.com. does not exist
     either */
  const DNSName target1("b.powerdns.com.");
  const DNSName target2("g.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  // NOLINTNEXTLINE(bugprone-exception-escape) When this test throws an exception, that's ok
  sr->setAsyncCallback([target1, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC, name does not exist (the generic version will generate an exact NSEC for the target, which we don't want) */
        setLWResult(res, RCode::NoError, true, false, true);
        /* no data */
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* no record for this name */
        addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("h.powerdns.com."), {QType::A, QType::TXT, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* no wildcard either */
        addNSECRecordToLW(DNSName(").powerdns.com."), DNSName("a.powerdns.com."), {QType::AAAA, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        return LWResult::Result::Success;
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
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* no record for this name */
          addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("h.powerdns.com."), {QType::A, QType::TXT, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* no wildcard either */
          addNSECRecordToLW(DNSName(").powerdns.com."), DNSName("a.powerdns.com."), {QType::AAAA, QType::RRSIG}, 600, res->d_records);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we first ask a.powerdns.com. | A, get a NODATA, then check that the aggressive
     NSEC cache will use the NSEC to prove that the AAAA does not exist either */
  const DNSName target("a.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
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
        if (domain == target && type == QType::A) {
          setLWResult(res, RCode::NoError, true, false, true);
          /* no data */
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* no record for this name */
          /* exact match */
          addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), {QType::TXT, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* no need for wildcard in that case */
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
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_nodata_wildcard)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we first ask a.powerdns.com. | A, get a NODATA (no exact match but there is a wildcard match),
     then check that the aggressive NSEC cache will use the NSEC to prove that the AAAA does not exist either */
  const DNSName target("a.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC, name does not exist but there is a wildcard (the generic version will generate an exact NSEC for the target, which we don't want) */
        setLWResult(res, RCode::NoError, true, false, true);
        /* no data */
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* the name does not exist, a wildcard applies but does not have this type */
        addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("z.powerdns.com."), {QType::TXT, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, std::nullopt, DNSName("*.powerdns.com"));
        return LWResult::Result::Success;
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
        if (domain == target && type == QType::A) {
          setLWResult(res, RCode::NoError, true, false, true);
          /* no data */
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* the name does not exist, a wildcard applies but does not have this type */
          addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("z.powerdns.com."), {QType::TXT, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, std::nullopt, DNSName("*.powerdns.com"));
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
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_ancestor)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* powerdns.com is signed, sub.powerdns.com. is not.
     We first get a query for sub.powerdns.com. which leads to an ancestor NSEC covering sub.powerdns.com.|DS to be inserted
     into the aggressive cache, check that we don't mistakenly use that later to prove that something else below that name
     doesn't exist either. */
  const DNSName target("sub.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == DNSName("com.")) {
        /* no cut */
        return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys, false);
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
        if (domain.isPartOf(DNSName("sub.powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "sub.powerdns.com.", QType::NS, "ns.sub.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* proof that the DS doesn't exist follows */
          /* NSEC ancestor for sub.powerdns.com */
          addNSECRecordToLW(DNSName("sub.powerdns.com."), DNSName("sub1.powerdns.com"), {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          addRecordToLW(res, "ns.sub.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("sub16.powerdns.com.")) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          addNSECRecordToLW(DNSName("sub15.powerdns.com."), DNSName("sub17.powerdns.com."), {QType::A}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* then the wildcard *.powerdns.com
             next covers the wildcard *.sub.powerdns.com
          */
          addNSECRecordToLW(DNSName(").powerdns.com"), DNSName("+.sub.powerdns.com"), {QType::TXT, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          return LWResult::Result::Success;
        }
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == target && type == QType::A) {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, DNSName("sub.powerdns.com."), QType::A, "192.0.2.42");
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("4.sub.powerdns.com.") && type == QType::A) {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, DNSName("4.sub.powerdns.com."), QType::A, "192.0.2.84");
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* now we query sub16.powerdns.com, to get a NSEC covering the wildcard for *.sub.powerdns.com */
  ret.clear();
  res = sr->beginResolve(DNSName("sub16.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* now we query other2.sub.powerdns.com, we should NOT be able to use the NSECs we have
     to prove that the name does not exist */
  ret.clear();
  res = sr->beginResolve(DNSName("4.sub.powerdns.com"), QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_wildcard_synthesis)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we first ask a.powerdns.com. | A, get an answer synthesized from the wildcard.
     We can use it yet because we need the SOA, so let's request a non-existing type
     then check that the aggressive NSEC cache will use the wildcard to synthesize an answer
     for b.powerdns.com */
  const DNSName target("a.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC, name does not exist but there is a wildcard (the generic version will generate an exact NSEC for the target, which we don't want) */
        setLWResult(res, RCode::NoError, true, false, true);
        /* no data */
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* the name does not exist, a wildcard applies and have the requested type but no DS */
        addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("z.powerdns.com."), {QType::A, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, std::nullopt, DNSName("*.powerdns.com"));
        return LWResult::Result::Success;
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
        if (type == QType::A) {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, domain, QType::A, "192.0.2.1");
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, std::nullopt, DNSName("*.powerdns.com"));
          /* the name does not exist, a wildcard applies and has the requested type */
          addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("z.powerdns.com."), {QType::A, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, std::nullopt, DNSName("*.powerdns.com"));
          return LWResult::Result::Success;
        }
        else if (type == QType::TXT) {
          setLWResult(res, RCode::NoError, true, false, true);
          /* the name does not exist, a wildcard applies but does not have the requested type */
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("z.powerdns.com."), {QType::A, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, std::nullopt, DNSName("*.powerdns.com"));
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
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(ret.at(0).d_name, target);
  BOOST_CHECK_EQUAL(ret.at(0).d_type, QType(QType::A).getCode());
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* request the TXT to get the SOA */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::TXT), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(ret.at(0).d_name, DNSName("powerdns.com."));
  BOOST_CHECK_EQUAL(ret.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  ret.clear();
  res = sr->beginResolve(DNSName("b.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(ret.at(0).d_name, DNSName("b.powerdns.com."));
  BOOST_CHECK_EQUAL(ret.at(0).d_type, QType(QType::A).getCode());
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_nxdomain)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  AggressiveNSECCache::s_maxNSEC3CommonPrefix = 159;
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we are lucky enough that our hashes will cover g.powerdns.com. as well,
     so we first ask b.powerdns.com., get a NXD, then check that the aggressive
     NSEC cache will use the NSEC3 to prove that g.powerdns.com. does not exist
     either */
  const DNSName target1("b.powerdns.com.");
  const DNSName target2("g.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target1, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC3 */
        setLWResult(res, RCode::NXDomain, true, false, true);
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* no record for this name */
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* then the next closer */
        addNSEC3UnhashedRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* no wildcard */
        addNSEC3NarrowRecordToLW(DNSName("*.powerdns.com."), DNSName("powerdns.com."), {QType::AAAA, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300);
        return LWResult::Result::Success;
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
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* no record for this name */
          /* first the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* then the next closer */
          addNSEC3UnhashedRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* no wildcard */
          addNSEC3NarrowRecordToLW(DNSName("*.powerdns.com."), DNSName("powerdns.com."), {QType::AAAA, QType::RRSIG}, 600, res->d_records);
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
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_nodata)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we first ask a.powerdns.com. | A, get a NODATA, then check that the aggressive
     NSEC cache will use the NSEC3 to prove that the AAAA does not exist either */
  const DNSName target("a.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC3 */
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false, std::nullopt, true);
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
        if (domain == target && type == QType::A) {
          setLWResult(res, RCode::NoError, true, false, true);
          /* no data */
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* no record for this name */
          /* exact match */
          addNSEC3UnhashedRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::TXT, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* no need for next closer or wildcard in that case */
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
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_nodata_wildcard)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  AggressiveNSECCache::s_maxNSEC3CommonPrefix = 159;
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we first ask a.powerdns.com. | A, get a NODATA (no exact match but there is a wildcard match),
     then check that the aggressive NSEC cache will use the NSEC3 to prove that the AAAA does not exist either */
  const DNSName target("a.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC3, name does not exist but there is a wildcard (the generic version will generate an exact NSEC3 for the target, which we don't want) */
        setLWResult(res, RCode::NoError, true, false, true);
        /* no data */
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG}, 600, res->d_records, 10);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* then the next closer */
        addNSEC3UnhashedRecordToLW(DNSName("+.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG}, 600, res->d_records, 10);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* a wildcard applies but does not have this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::TXT, QType::RRSIG}, 600, res->d_records, 10);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, std::nullopt, DNSName("*.powerdns.com"));
        return LWResult::Result::Success;
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
        if (domain == target && type == QType::A) {
          setLWResult(res, RCode::NoError, true, false, true);
          /* no data */
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* first the closest encloser */
          addNSEC3NoDataNarrowRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), {QType::A, QType::TXT, QType::RRSIG}, 600, res->d_records, 10);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* then the next closer */
          addNSEC3NarrowRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), {QType::RRSIG}, 600, res->d_records, 10);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* a wildcard applies but does not have this type */
          addNSEC3NoDataNarrowRecordToLW(DNSName("*.powerdns.com."), DNSName("powerdns.com."), {QType::TXT, QType::RRSIG}, 600, res->d_records, 10);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, std::nullopt, DNSName("*.powerdns.com"));
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
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_ancestor)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* powerdns.com is signed, sub.powerdns.com. is not.
     We first get a query for sub.powerdns.com. which leads to an ancestor NSEC3 covering sub.powerdns.com.|DS to be inserted
     into the aggressive cache, check that we don't mistakenly use that later to prove that something else below that name
     doesn't exist either. */
  const DNSName target("sub.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain == DNSName("com.")) {
        /* no cut */
        return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys, false);
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
        if (domain.isPartOf(DNSName("sub.powerdns.com."))) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "sub.powerdns.com.", QType::NS, "ns.sub.powerdns.com.", DNSResourceRecord::AUTHORITY, 3600);
          /* proof that the DS doesn't exist follows */
          /* NSEC3 ancestor for sub.powerdns.com (1 additional iteration, deadbeef as salt), : 7v5rgf7okrmumvb8rscop0t3j1m5o4mb
             next is crafted to cover 4.sub.powerdns.com => 930v7tmju1s48fopjh5ktsp1jmagi20p */
          addNSEC3RecordToLW(DNSName("7v5rgf7okrmumvb8rscop0t3j1m5o4mb.powerdns.com."), fromBase32Hex("930v7tmju1s48fopjh5ktsp1jmagi20q"), "deadbeef", 1, {QType::NS}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          addRecordToLW(res, "ns.sub.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("sub16.powerdns.com.")) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* first the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::SOA, QType::NS}, 600, res->d_records, 1);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* then the next closer sub16.powerdns.com. */
          addNSEC3NarrowRecordToLW(DNSName("sub16.powerdns.com."), DNSName("powerdns.com."), {QType::A}, 600, res->d_records, 1);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* then the wildcard *.powerdns.com: mtrrinpd8l9e7fmn8lp74o8dffnivs8i (minus one because NXD)
             next is crafted to cover the wildcard *.sub.powerdns.com (ocgb0ilk3g1m3olpms0q1quhn18nncc0)
          */
          addNSEC3RecordToLW(DNSName("mtrrinpd8l9e7fmn8lp74o8dffnivs8h.powerdns.com."), fromBase32Hex("ocgb0ilk3g1m3olpms0q1quhn18nncc1"), "deadbeef", 1, {QType::TXT, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          return LWResult::Result::Success;
        }
      }
      else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == target && type == QType::A) {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, DNSName("sub.powerdns.com."), QType::A, "192.0.2.42");
          return LWResult::Result::Success;
        }
        else if (domain == DNSName("4.sub.powerdns.com.") && type == QType::A) {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, DNSName("4.sub.powerdns.com."), QType::A, "192.0.2.84");
          return LWResult::Result::Success;
        }
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  /* now we query sub16.powerdns.com, to get a hash covering the wildcard for
   *.sub.powerdns.com */
  ret.clear();
  res = sr->beginResolve(DNSName("sub16.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 6U);

  /* now we query other2.sub.powerdns.com, we should NOT be able to use the NSEC3s we have
     to prove that the name does not exist */
  ret.clear();
  res = sr->beginResolve(DNSName("4.sub.powerdns.com"), QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(queriesCount, 8U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_wildcard_synthesis)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we first ask a.powerdns.com. | A, get an answer synthesized from the wildcard.
     We can't use it right away because we don't have the SOA, so let's do a TXT query to get it,
     then check that the aggressive NSEC cache will use the wildcard to synthesize an answer
     for b.powerdns.com */
  const DNSName target("a.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, boost::optional<const ResolveContext&> /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC3, name does not exist but there is a wildcard (the generic version will generate an exact NSEC3 for the target, which we don't want) */
        setLWResult(res, RCode::NoError, true, false, true);
        /* no data */
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG}, 600, res->d_records, 10);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* then the next closer */
        addNSEC3UnhashedRecordToLW(DNSName("+.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG}, 600, res->d_records, 10);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* a wildcard applies but does not have this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::RRSIG}, 600, res->d_records, 10);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, std::nullopt, DNSName("*.powerdns.com"));
        return LWResult::Result::Success;
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
        if (type == QType::A) {
          setLWResult(res, RCode::NoError, true, false, true);
          addRecordToLW(res, domain, QType::A, "192.0.2.1");
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, std::nullopt, DNSName("*.powerdns.com"));
          /* no need for the closest encloser since we have a positive answer expanded from a wildcard */
          /* the next closer */
          addNSEC3UnhashedRecordToLW(DNSName("+.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG}, 600, res->d_records, 10);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* and of course we don't deny the wildcard itself */
          return LWResult::Result::Success;
        }
        else if (type == QType::TXT) {
          setLWResult(res, RCode::NoError, true, false, true);
          /* the name does not exist, a wildcard applies but does not have the requested type */
          addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* the closest encloser */
          addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "v", {QType::SOA, QType::NS, QType::NSEC3, QType::DNSKEY, QType::RRSIG}, 600, res->d_records, 10);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* the next closer */
          addNSEC3UnhashedRecordToLW(DNSName("+.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG}, 600, res->d_records, 10);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* and the wildcard expanded unto itself */
          addNSEC3UnhashedRecordToLW(DNSName("*.powerdns.com."), DNSName("powerdns.com."), "v", {QType::A}, 600, res->d_records, 10);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(ret.at(0).d_name, target);
  BOOST_CHECK_EQUAL(ret.at(0).d_type, QType(QType::A).getCode());
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::TXT), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(ret.at(0).d_name, DNSName("powerdns.com."));
  BOOST_CHECK_EQUAL(ret.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(queriesCount, 5U);

  ret.clear();
  res = sr->beginResolve(DNSName("b.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(ret.at(0).d_name, DNSName("b.powerdns.com."));
  BOOST_CHECK_EQUAL(ret.at(0).d_type, QType(QType::A).getCode());
  BOOST_CHECK_EQUAL(queriesCount, 5U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_replace)
{
  const size_t testSize = 10000;
  auto cache = make_unique<AggressiveNSECCache>(testSize);

  struct timeval now{};
  Utility::gettimeofday(&now, nullptr);

  vector<DNSName> names;
  names.reserve(testSize);
  for (size_t i = 0; i < testSize; i++) {
    names.emplace_back(std::to_string(i) + "powerdns.com");
  }

  DTime time;
  time.set();

  for (const auto& name : names) {
    DNSRecord rec;
    rec.d_name = name;
    rec.d_type = QType::NSEC3;
    rec.d_ttl = now.tv_sec + 10;
    rec.setContent(getRecordContent(QType::NSEC3, "1 0 500 ab HASG==== A RRSIG NSEC3"));
    auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 dummy. data");
    cache->insertNSEC(DNSName("powerdns.com"), rec.d_name, rec, {rrsig}, true);
  }
  auto diff1 = time.udiff(true);

  BOOST_CHECK_EQUAL(cache->getEntriesCount(), testSize);
  for (const auto& name : names) {
    DNSRecord rec;
    rec.d_name = name;
    rec.d_type = QType::NSEC3;
    rec.d_ttl = now.tv_sec + 10;
    rec.setContent(getRecordContent(QType::NSEC3, "1 0 500 ab HASG==== A RRSIG NSEC3"));
    auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC 5 3 10 20370101000000 20370101000000 24567 dummy. data");
    cache->insertNSEC(DNSName("powerdns.com"), rec.d_name, rec, {rrsig}, true);
  }

  BOOST_CHECK_EQUAL(cache->getEntriesCount(), testSize);

  auto diff2 = time.udiff(true);
  // Check that replace is about equally fast as insert
  BOOST_CHECK(diff1 < diff2 * 2 && diff2 < diff1 * 2);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_wiping)
{
  auto cache = make_unique<AggressiveNSECCache>(10000);

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  DNSRecord rec;
  rec.d_name = DNSName("www.powerdns.com");
  rec.d_type = QType::NSEC;
  rec.d_ttl = now.tv_sec + 10;
  rec.setContent(getRecordContent(QType::NSEC, "z.powerdns.com. A RRSIG NSEC"));
  auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC 5 3 10 20370101000000 20370101000000 24567 dummy. data");
  cache->insertNSEC(DNSName("powerdns.com"), rec.d_name, rec, {rrsig}, false);

  rec.d_name = DNSName("z.powerdns.com");
  rec.setContent(getRecordContent(QType::NSEC, "zz.powerdns.com. AAAA RRSIG NSEC"));
  cache->insertNSEC(DNSName("powerdns.com"), rec.d_name, rec, {rrsig}, false);

  rec.d_name = DNSName("www.powerdns.org");
  rec.d_type = QType::NSEC3;
  rec.d_ttl = now.tv_sec + 10;
  rec.setContent(getRecordContent(QType::NSEC3, "1 0 500 ab HASG==== A RRSIG NSEC3"));
  rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 dummy. data");
  cache->insertNSEC(DNSName("powerdns.org"), rec.d_name, rec, {rrsig}, true);

  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 3U);

  /* remove just that zone */
  cache->removeZoneInfo(DNSName("powerdns.org"), false);
  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 2U);

  /* add it back */
  cache->insertNSEC(DNSName("powerdns.org"), rec.d_name, rec, {rrsig}, true);
  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 3U);

  /* remove everything under .org (which should end up in the same way) */
  cache->removeZoneInfo(DNSName("org."), true);
  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 2U);

  /* add it back */
  cache->insertNSEC(DNSName("powerdns.org"), rec.d_name, rec, {rrsig}, true);
  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 3U);

  /* remove everything */
  cache->removeZoneInfo(DNSName("."), true);
  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 0U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_pruning)
{
  auto cache = make_unique<AggressiveNSECCache>(2);

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  DNSRecord rec;
  rec.d_name = DNSName("www.powerdns.com");
  rec.d_type = QType::NSEC;
  rec.d_ttl = now.tv_sec + 10;
  rec.setContent(getRecordContent(QType::NSEC, "z.powerdns.com. A RRSIG NSEC"));
  auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC 5 3 10 20370101000000 20370101000000 24567 dummy. data");
  cache->insertNSEC(DNSName("powerdns.com"), rec.d_name, rec, {rrsig}, false);

  rec.d_name = DNSName("z.powerdns.com");
  rec.setContent(getRecordContent(QType::NSEC, "zz.powerdns.com. AAAA RRSIG NSEC"));
  cache->insertNSEC(DNSName("powerdns.com"), rec.d_name, rec, {rrsig}, false);

  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 2U);
  /* we are at the limit of the number of entries, so we will scan 1/5th of the entries,
     and prune the expired ones, which mean we should not remove anything */
  cache->prune(now.tv_sec);
  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 2U);

  rec.d_name = DNSName("www.powerdns.org");
  rec.d_type = QType::NSEC3;
  rec.d_ttl = now.tv_sec + 20;
  rec.setContent(getRecordContent(QType::NSEC3, "1 0 500 ab HASG==== A RRSIG NSEC3"));
  rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 dummy. data");
  cache->insertNSEC(DNSName("powerdns.org"), rec.d_name, rec, {rrsig}, true);

  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 3U);

  /* we have set an upper bound to 2 entries, so we are above,
     and one entry is actually expired, so we will prune one entry
     to get below the limit */
  cache->prune(now.tv_sec + 15);
  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 2U);

  /* now we are at the limit, so we will scan 1/10th of all zones entries, rounded up,
     and prune the expired ones, which mean we will also be removing the remaining two */
  cache->prune(now.tv_sec + 600);
  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 0U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_dump)
{
  auto cache = make_unique<AggressiveNSECCache>(10000);

  std::vector<std::string> expected;
  expected.emplace_back("; Zone powerdns.com.\n");
  expected.emplace_back("www.powerdns.com. 10 IN NSEC z.powerdns.com. A RRSIG NSEC by ./TYPE0\n");
  expected.emplace_back("- RRSIG NSEC 5 3 10 20370101000000 20370101000000 24567 dummy. data\n");
  expected.emplace_back("z.powerdns.com. 10 IN NSEC zz.powerdns.com. AAAA RRSIG NSEC by ./TYPE0\n");
  expected.emplace_back("- RRSIG NSEC 5 3 10 20370101000000 20370101000000 24567 dummy. data\n");
  expected.emplace_back("; Zone powerdns.org.\n");
  expected.emplace_back("www.powerdns.org. 10 IN NSEC3 1 0 50 ab HASG==== A RRSIG NSEC3 by ./TYPE0\n");
  expected.emplace_back("- RRSIG NSEC3 5 3 10 20370101000000 20370101000000 24567 dummy. data\n");

  struct timeval now{};
  Utility::gettimeofday(&now, nullptr);

  DNSRecord rec;
  rec.d_name = DNSName("www.powerdns.com");
  rec.d_type = QType::NSEC;
  rec.d_ttl = now.tv_sec + 10;
  rec.setContent(getRecordContent(QType::NSEC, "z.powerdns.com. A RRSIG NSEC"));
  auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC 5 3 10 20370101000000 20370101000000 24567 dummy. data");
  cache->insertNSEC(DNSName("powerdns.com"), rec.d_name, rec, {rrsig}, false);

  rec.d_name = DNSName("z.powerdns.com");
  rec.setContent(getRecordContent(QType::NSEC, "zz.powerdns.com. AAAA RRSIG NSEC"));
  cache->insertNSEC(DNSName("powerdns.com"), rec.d_name, rec, {rrsig}, false);

  rec.d_name = DNSName("www.powerdns.org");
  rec.d_type = QType::NSEC3;
  rec.d_ttl = now.tv_sec + 10;
  rec.setContent(getRecordContent(QType::NSEC3, "1 0 50 ab HASG==== A RRSIG NSEC3"));
  rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 dummy. data");
  cache->insertNSEC(DNSName("powerdns.org"), rec.d_name, rec, {rrsig}, true);

  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 3U);

  auto filePtr = pdns::UniqueFilePtr(tmpfile());
  if (!filePtr) {
    BOOST_FAIL("Temporary file could not be opened");
  }

  BOOST_CHECK_EQUAL(cache->dumpToFile(filePtr, now), 3U);

  rewind(filePtr.get());
  char* line = nullptr;
  size_t len = 0;

  for (const auto& str : expected) {
    auto read = getline(&line, &len, filePtr.get());
    if (read == -1) {
      BOOST_FAIL("Unable to read a line from the temp file");
    }
    BOOST_CHECK_EQUAL(line, str);
  }

  expected.clear();
  expected.emplace_back("; Zone powerdns.com.\n");
  expected.emplace_back("www.powerdns.com. 10 IN NSEC z.powerdns.com. A RRSIG NSEC by ./TYPE0\n");
  expected.emplace_back("- RRSIG NSEC 5 3 10 20370101000000 20370101000000 24567 dummy. data\n");
  expected.emplace_back("z.powerdns.com. 30 IN NSEC zz.powerdns.com. AAAA RRSIG NSEC by ./TYPE0\n");
  expected.emplace_back("- RRSIG NSEC 5 3 10 20370101000000 20370101000000 24567 dummy. data\n");
  expected.emplace_back("; Zone powerdns.org.\n");
  expected.emplace_back("www.powerdns.org. 10 IN NSEC3 1 0 50 ab HASG==== A RRSIG NSEC3 by ./TYPE0\n");
  expected.emplace_back("- RRSIG NSEC3 5 3 10 20370101000000 20370101000000 24567 dummy. data\n");

  rec.d_name = DNSName("z.powerdns.com");
  rec.d_type = QType::NSEC;
  rec.d_ttl = now.tv_sec + 30;
  rec.setContent(getRecordContent(QType::NSEC, "zz.powerdns.com. AAAA RRSIG NSEC"));
  rrsig = std::make_shared<RRSIGRecordContent>("NSEC 5 3 10 20370101000000 20370101000000 24567 dummy. data");
  cache->insertNSEC(DNSName("powerdns.com"), rec.d_name, rec, {rrsig}, false);

  rewind(filePtr.get());
  BOOST_CHECK_EQUAL(cache->dumpToFile(filePtr, now), 3U);

  rewind(filePtr.get());

  for (const auto& str : expected) {
    auto read = getline(&line, &len, filePtr.get());
    if (read == -1) {
      BOOST_FAIL("Unable to read a line from the temp file");
    }
    BOOST_CHECK_EQUAL(line, str);
  }

  /* getline() allocates a buffer when called with a nullptr,
     then reallocates it when needed, but we need to free the
     last allocation if any. */
  free(line); // NOLINT: it's the API.
}

static bool getDenialWrapper(std::unique_ptr<AggressiveNSECCache>& cache, time_t now, const DNSName& name, const QType& qtype, const std::optional<int> expectedResult = std::nullopt, const std::optional<size_t> expectedRecordsCount = std::nullopt)
{
  int res;
  std::vector<DNSRecord> results;
  pdns::validation::ValidationContext validationContext;
  validationContext.d_nsec3IterationsRemainingQuota = std::numeric_limits<decltype(validationContext.d_nsec3IterationsRemainingQuota)>::max();
  bool found = cache->getDenial(now, name, qtype, results, res, ComboAddress("192.0.2.1"), std::nullopt, true, validationContext);
  if (expectedResult) {
    BOOST_CHECK_EQUAL(res, *expectedResult);
  }
  if (expectedRecordsCount) {
    BOOST_CHECK_EQUAL(results.size(), *expectedRecordsCount);
  }
  return found;
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_rollover)
{
  /* test that we don't compare a hash using the wrong (former) salt or iterations count in case of a rollover,
     or when different servers use different parameters */
  AggressiveNSECCache::s_maxNSEC3CommonPrefix = 159;
  auto cache = make_unique<AggressiveNSECCache>(10000);
  g_recCache = std::make_unique<MemRecursorCache>();

  const DNSName zone("powerdns.com");
  time_t now = time(nullptr);

  /* first we need a SOA */
  std::vector<DNSRecord> records;
  time_t ttd = now + 30;
  DNSRecord drSOA;
  drSOA.d_name = zone;
  drSOA.d_type = QType::SOA;
  drSOA.d_class = QClass::IN;
  drSOA.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  drSOA.d_ttl = static_cast<uint32_t>(ttd); // XXX truncation
  drSOA.d_place = DNSResourceRecord::ANSWER;
  records.push_back(drSOA);

  g_recCache->replace(now, zone, QType(QType::SOA), records, {}, {}, true, zone, std::nullopt, std::nullopt, vState::Secure);
  BOOST_CHECK_EQUAL(g_recCache->size(), 1U);

  std::string oldSalt = "ab";
  std::string newSalt = "cd";
  unsigned int oldIterationsCount = 2;
  unsigned int newIterationsCount = 1;
  DNSName name("www.powerdns.com");
  std::string hashed = hashQNameWithSalt(oldSalt, oldIterationsCount, name);

  DNSRecord rec;
  rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
  rec.d_type = QType::NSEC3;
  rec.d_ttl = now + 10;

  NSEC3RecordContent nrc;
  nrc.d_algorithm = 1;
  nrc.d_flags = 0;
  nrc.d_iterations = oldIterationsCount;
  nrc.d_salt = oldSalt;
  nrc.d_nexthash = hashed;
  incrementHash(nrc.d_nexthash);
  for (const auto& type : {QType::A}) {
    nrc.set(type);
  }

  rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
  auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 dummy. data");
  cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);

  /* we can use the NSEC3s we have */
  /* direct match */
  BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA), true);

  DNSName other("other.powerdns.com");
  /* now we insert a new NSEC3, with a different salt, changing that value for the zone */
  hashed = hashQNameWithSalt(newSalt, oldIterationsCount, other);
  rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
  rec.d_type = QType::NSEC3;
  rec.d_ttl = now + 10;
  nrc.d_algorithm = 1;
  nrc.d_flags = 0;
  nrc.d_iterations = oldIterationsCount;
  nrc.d_salt = newSalt;
  nrc.d_nexthash = hashed;
  incrementHash(nrc.d_nexthash);
  for (const auto& type : {QType::A}) {
    nrc.set(type);
  }

  rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
  rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 dummy. data");
  cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

  /* the existing entries should have been cleared */
  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);

  /* we should be able to find a direct match for that name */
  /* direct match */
  BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, other, QType::AAAA), true);

  /* but we should not be able to use the other NSEC3s */
  BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA), false);

  /* and the same thing but this time updating the iterations count instead of the salt */
  DNSName other2("other2.powerdns.com");
  hashed = hashQNameWithSalt(newSalt, newIterationsCount, other2);
  rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
  rec.d_type = QType::NSEC3;
  rec.d_ttl = now + 10;
  nrc.d_algorithm = 1;
  nrc.d_flags = 0;
  nrc.d_iterations = newIterationsCount;
  nrc.d_salt = newSalt;
  nrc.d_nexthash = hashed;
  incrementHash(nrc.d_nexthash);
  for (const auto& type : {QType::A}) {
    nrc.set(type);
  }

  rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
  rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 dummy. data");
  cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

  /* the existing entries should have been cleared */
  BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);

  /* we should be able to find a direct match for that name */
  /* direct match */
  BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, other2, QType::AAAA), true);

  /* but we should not be able to use the other NSEC3s */
  BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, other, QType::AAAA), false);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_ancestor_cases)
{
  auto cache = make_unique<AggressiveNSECCache>(10000);
  g_recCache = std::make_unique<MemRecursorCache>();

  const DNSName zone("powerdns.com");
  time_t now = time(nullptr);

  /* first we need a SOA */
  std::vector<DNSRecord> records;
  time_t ttd = now + 30;
  DNSRecord drSOA;
  drSOA.d_name = zone;
  drSOA.d_type = QType::SOA;
  drSOA.d_class = QClass::IN;
  drSOA.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  drSOA.d_ttl = static_cast<uint32_t>(ttd); // XXX truncation
  drSOA.d_place = DNSResourceRecord::ANSWER;
  records.push_back(drSOA);

  g_recCache->replace(now, zone, QType(QType::SOA), records, {}, {}, true, zone, std::nullopt, std::nullopt, vState::Secure);
  BOOST_CHECK_EQUAL(g_recCache->size(), 1U);

  {
    cache = make_unique<AggressiveNSECCache>(10000);
    /* insert a NSEC matching the exact name (apex) */
    DNSName name("sub.powerdns.com");
    DNSRecord rec;
    rec.d_name = name;
    rec.d_type = QType::NSEC;
    rec.d_ttl = now + 10;

    NSECRecordContent nrc;
    nrc.d_next = DNSName("sub1.powerdns.com");
    for (const auto& type : {QType::A}) {
      nrc.set(type);
    }

    rec.setContent(std::make_shared<NSECRecordContent>(nrc));
    auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC 5 3 10 20370101000000 20370101000000 24567 sub.powerdns.com. data");
    cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, false);

    BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);

    /* the cache should now be able to deny other types (except the DS) */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA, RCode::NoError, 3U), true);
    /* but not the DS that lives in the parent zone */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::DS, std::nullopt, 0U), false);
  }

  {
    cache = make_unique<AggressiveNSECCache>(10000);
    /* insert a NSEC matching the exact name, but it is an ancestor NSEC (delegation) */
    DNSName name("sub.powerdns.com");
    DNSRecord rec;
    rec.d_name = name;
    rec.d_type = QType::NSEC;
    rec.d_ttl = now + 10;

    NSECRecordContent nrc;
    nrc.d_next = DNSName("sub1.powerdns.com");
    for (const auto& type : {QType::NS}) {
      nrc.set(type);
    }

    rec.setContent(std::make_shared<NSECRecordContent>(nrc));
    auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
    cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, false);

    BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);

    /* the cache should now be able to deny the DS */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::DS, RCode::NoError, 3U), true);
    /* but not any type that lives in the child zone */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA), false);
  }

  {
    cache = make_unique<AggressiveNSECCache>(10000);
    /* insert a NSEC matching the exact name inside a zone (neither apex nor delegation point) */
    DNSName name("sub.powerdns.com");
    DNSRecord rec;
    rec.d_name = name;
    rec.d_type = QType::NSEC;
    rec.d_ttl = now + 10;

    NSECRecordContent nrc;
    nrc.d_next = DNSName("sub1.powerdns.com");
    for (const auto& type : {QType::A}) {
      nrc.set(type);
    }

    rec.setContent(std::make_shared<NSECRecordContent>(nrc));
    auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
    cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, false);

    BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);

    /* the cache should now be able to deny other types */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA, RCode::NoError, 3U), true);
    /* including the DS */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::DS, RCode::NoError, 3U), true);
  }

  {
    /* nxd inside a zone (neither apex nor delegation point) */
    cache = make_unique<AggressiveNSECCache>(10000);
    /* insert NSEC proving that the name does not exist */
    DNSName name("sub.powerdns.com.");
    DNSName wc("*.powerdns.com.");

    {
      DNSRecord rec;
      rec.d_name = DNSName("sua.powerdns.com");
      rec.d_type = QType::NSEC;
      rec.d_ttl = now + 10;

      NSECRecordContent nrc;
      nrc.d_next = DNSName("suc.powerdns.com");
      for (const auto& type : {QType::A, QType::SOA, QType::NS}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSECRecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, false);

      BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);
    }
    {
      /* wildcard */
      DNSRecord rec;
      rec.d_name = DNSName(").powerdns.com.");
      rec.d_type = QType::NSEC;
      rec.d_ttl = now + 10;

      NSECRecordContent nrc;
      nrc.d_next = DNSName("+.powerdns.com.");
      for (const auto& type : {QType::NS}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSECRecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, false);

      BOOST_CHECK_EQUAL(cache->getEntriesCount(), 2U);
    }

    /* the cache should now be able to deny any type for the name  */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA, RCode::NXDomain, 5U), true);

    /* including the DS, since we are not at the apex */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::DS, RCode::NXDomain, 5U), true);
  }
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_ancestor_cases)
{
  AggressiveNSECCache::s_maxNSEC3CommonPrefix = 159;
  auto cache = make_unique<AggressiveNSECCache>(10000);
  g_recCache = std::make_unique<MemRecursorCache>();

  const DNSName zone("powerdns.com");
  time_t now = time(nullptr);

  /* first we need a SOA */
  std::vector<DNSRecord> records;
  time_t ttd = now + 30;
  DNSRecord drSOA;
  drSOA.d_name = zone;
  drSOA.d_type = QType::SOA;
  drSOA.d_class = QClass::IN;
  drSOA.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  drSOA.d_ttl = static_cast<uint32_t>(ttd); // XXX truncation
  drSOA.d_place = DNSResourceRecord::ANSWER;
  records.push_back(drSOA);

  g_recCache->replace(now, zone, QType(QType::SOA), records, {}, {}, true, zone, std::nullopt, std::nullopt, vState::Secure);
  BOOST_CHECK_EQUAL(g_recCache->size(), 1U);

  const std::string salt("ab");
  const unsigned int iterationsCount = 1;

  {
    cache = make_unique<AggressiveNSECCache>(10000);
    /* insert a NSEC3 matching the exact name (apex) */
    DNSName name("sub.powerdns.com");
    std::string hashed = hashQNameWithSalt(salt, iterationsCount, name);
    DNSRecord rec;
    rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
    rec.d_type = QType::NSEC3;
    rec.d_ttl = now + 10;

    NSEC3RecordContent nrc;
    nrc.d_algorithm = 1;
    nrc.d_flags = 0;
    nrc.d_iterations = iterationsCount;
    nrc.d_salt = salt;
    nrc.d_nexthash = hashed;
    incrementHash(nrc.d_nexthash);
    for (const auto& type : {QType::A}) {
      nrc.set(type);
    }

    rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
    auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 sub.powerdns.com. data");
    cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

    BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);

    /* the cache should now be able to deny other types (except the DS) */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA, RCode::NoError, 3U), true);
    /* but not the DS that lives in the parent zone */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::DS, std::nullopt, 0U), false);
  }

  {
    cache = make_unique<AggressiveNSECCache>(10000);
    /* insert a NSEC3 matching the exact name, but it is an ancestor NSEC3 (delegation) */
    DNSName name("sub.powerdns.com");
    std::string hashed = hashQNameWithSalt(salt, iterationsCount, name);
    DNSRecord rec;
    rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
    rec.d_type = QType::NSEC3;
    rec.d_ttl = now + 10;

    NSEC3RecordContent nrc;
    nrc.d_algorithm = 1;
    nrc.d_flags = 0;
    nrc.d_iterations = iterationsCount;
    nrc.d_salt = salt;
    nrc.d_nexthash = hashed;
    incrementHash(nrc.d_nexthash);
    for (const auto& type : {QType::NS}) {
      nrc.set(type);
    }

    rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
    auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
    cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

    BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);

    /* the cache should now be able to deny the DS */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::DS, RCode::NoError, 3U), true);
    /* but not any type that lives in the child zone */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA), false);
  }

  {
    cache = make_unique<AggressiveNSECCache>(10000);
    /* insert a NSEC3 matching the exact name inside a zone (neither apex nor delegation point) */
    DNSName name("sub.powerdns.com");
    std::string hashed = hashQNameWithSalt(salt, iterationsCount, name);
    DNSRecord rec;
    rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
    rec.d_type = QType::NSEC3;
    rec.d_ttl = now + 10;

    NSEC3RecordContent nrc;
    nrc.d_algorithm = 1;
    nrc.d_flags = 0;
    nrc.d_iterations = iterationsCount;
    nrc.d_salt = salt;
    nrc.d_nexthash = hashed;
    incrementHash(nrc.d_nexthash);
    for (const auto& type : {QType::A}) {
      nrc.set(type);
    }

    rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
    auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
    cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

    BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);

    /* the cache should now be able to deny other types */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA, RCode::NoError, 3U), true);
    /* including the DS */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::DS, RCode::NoError, 3U), true);
  }

  {
    /* nxd inside a zone (neither apex nor delegation point) */
    cache = make_unique<AggressiveNSECCache>(10000);
    /* insert NSEC3s proving that the name does not exist */
    DNSName name("sub.powerdns.com.");
    DNSName closestEncloser("powerdns.com.");
    DNSName nextCloser("sub.powerdns.com.");
    DNSName wc("*.powerdns.com.");

    {
      /* closest encloser */
      std::string hashed = hashQNameWithSalt(salt, iterationsCount, closestEncloser);
      DNSRecord rec;
      rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
      rec.d_type = QType::NSEC3;
      rec.d_ttl = now + 10;

      NSEC3RecordContent nrc;
      nrc.d_algorithm = 1;
      nrc.d_flags = 0;
      nrc.d_iterations = iterationsCount;
      nrc.d_salt = salt;
      nrc.d_nexthash = hashed;
      incrementHash(nrc.d_nexthash);
      for (const auto& type : {QType::A, QType::SOA, QType::NS}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

      BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);
    }
    {
      /* next closer */
      std::string hashed = hashQNameWithSalt(salt, iterationsCount, nextCloser);
      decrementHash(hashed);

      DNSRecord rec;
      rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
      rec.d_type = QType::NSEC3;
      rec.d_ttl = now + 10;

      NSEC3RecordContent nrc;
      nrc.d_algorithm = 1;
      nrc.d_flags = 0;
      nrc.d_iterations = iterationsCount;
      nrc.d_salt = salt;
      nrc.d_nexthash = hashed;
      incrementHash(nrc.d_nexthash);
      incrementHash(nrc.d_nexthash);
      for (const auto& type : {QType::NS}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

      BOOST_CHECK_EQUAL(cache->getEntriesCount(), 2U);
    }
    {
      /* wildcard */
      std::string hashed = hashQNameWithSalt(salt, iterationsCount, wc);
      decrementHash(hashed);

      DNSRecord rec;
      rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
      rec.d_type = QType::NSEC3;
      rec.d_ttl = now + 10;

      NSEC3RecordContent nrc;
      nrc.d_algorithm = 1;
      nrc.d_flags = 0;
      nrc.d_iterations = iterationsCount;
      nrc.d_salt = salt;
      nrc.d_nexthash = hashed;
      incrementHash(nrc.d_nexthash);
      incrementHash(nrc.d_nexthash);
      for (const auto& type : {QType::NS}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

      BOOST_CHECK_EQUAL(cache->getEntriesCount(), 3U);
    }

    /* the cache should now be able to deny any type for the name  */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA, RCode::NXDomain, 7U), true);
    /* including the DS, since we are not at the apex */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::DS, RCode::NXDomain, 7U), true);
  }
  {
    /* we insert NSEC3s coming from the parent zone that could look like a valid denial but are not */
    cache = make_unique<AggressiveNSECCache>(10000);

    DNSName name("www.sub.powerdns.com.");
    DNSName closestEncloser("powerdns.com.");
    DNSName nextCloser("sub.powerdns.com.");
    DNSName wc("*.powerdns.com.");

    {
      /* closest encloser */
      std::string hashed = hashQNameWithSalt(salt, iterationsCount, closestEncloser);
      DNSRecord rec;
      rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
      rec.d_type = QType::NSEC3;
      rec.d_ttl = now + 10;

      NSEC3RecordContent nrc;
      nrc.d_algorithm = 1;
      nrc.d_flags = 0;
      nrc.d_iterations = iterationsCount;
      nrc.d_salt = salt;
      nrc.d_nexthash = hashed;
      incrementHash(nrc.d_nexthash);
      /* delegation ! */
      for (const auto& type : {QType::NS}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

      BOOST_CHECK_EQUAL(cache->getEntriesCount(), 1U);
    }
    {
      /* next closer */
      std::string hashed = hashQNameWithSalt(salt, iterationsCount, nextCloser);
      decrementHash(hashed);

      DNSRecord rec;
      rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
      rec.d_type = QType::NSEC3;
      rec.d_ttl = now + 10;

      NSEC3RecordContent nrc;
      nrc.d_algorithm = 1;
      nrc.d_flags = 0;
      nrc.d_iterations = iterationsCount;
      nrc.d_salt = salt;
      nrc.d_nexthash = hashed;
      incrementHash(nrc.d_nexthash);
      incrementHash(nrc.d_nexthash);
      for (const auto& type : {QType::A}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

      BOOST_CHECK_EQUAL(cache->getEntriesCount(), 2U);
    }
    {
      /* wildcard */
      std::string hashed = hashQNameWithSalt(salt, iterationsCount, wc);
      decrementHash(hashed);

      DNSRecord rec;
      rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
      rec.d_type = QType::NSEC3;
      rec.d_ttl = now + 10;

      NSEC3RecordContent nrc;
      nrc.d_algorithm = 1;
      nrc.d_flags = 0;
      nrc.d_iterations = iterationsCount;
      nrc.d_salt = salt;
      nrc.d_nexthash = hashed;
      incrementHash(nrc.d_nexthash);
      incrementHash(nrc.d_nexthash);
      for (const auto& type : {QType::A}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);

      BOOST_CHECK_EQUAL(cache->getEntriesCount(), 3U);
    }

    /* the cache should NOT be able to deny the name  */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::AAAA, std::nullopt, 0U), false);
    /* and the same for the DS */
    BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, name, QType::DS, std::nullopt, 0U), false);
  }
}

BOOST_AUTO_TEST_CASE(test_aggressive_max_nsec3_hash_cost)
{
  AggressiveNSECCache::s_maxNSEC3CommonPrefix = 159;
  g_recCache = std::make_unique<MemRecursorCache>();

  const DNSName zone("powerdns.com");
  time_t now = time(nullptr);

  /* first we need a SOA */
  std::vector<DNSRecord> records;
  time_t ttd = now + 30;
  DNSRecord drSOA;
  drSOA.d_name = zone;
  drSOA.d_type = QType::SOA;
  drSOA.d_class = QClass::IN;
  drSOA.setContent(std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600"));
  drSOA.d_ttl = static_cast<uint32_t>(ttd); // XXX truncation
  drSOA.d_place = DNSResourceRecord::ANSWER;
  records.push_back(drSOA);

  g_recCache->replace(now, zone, QType(QType::SOA), records, {}, {}, true, zone, std::nullopt, std::nullopt, vState::Secure);
  BOOST_CHECK_EQUAL(g_recCache->size(), 1U);

  auto insertNSEC3s = [zone, now](std::unique_ptr<AggressiveNSECCache>& cache, const std::string& salt, unsigned int iterationsCount) -> void {
    {
      /* insert a NSEC3 matching the apex (will be the closest encloser) */
      DNSName name("powerdns.com");
      std::string hashed = hashQNameWithSalt(salt, iterationsCount, name);
      DNSRecord rec;
      rec.d_name = DNSName(toBase32Hex(hashed)) + zone;
      rec.d_type = QType::NSEC3;
      rec.d_ttl = now + 10;

      NSEC3RecordContent nrc;
      nrc.d_algorithm = 1;
      nrc.d_flags = 0;
      nrc.d_iterations = iterationsCount;
      nrc.d_salt = salt;
      nrc.d_nexthash = hashed;
      incrementHash(nrc.d_nexthash);
      for (const auto& type : {QType::A}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);
    }
    {
      /* insert a NSEC3 matching *.powerdns.com (wildcard) */
      DNSName name("*.powerdns.com");
      std::string hashed = hashQNameWithSalt(salt, iterationsCount, name);
      auto before = hashed;
      decrementHash(before);
      DNSRecord rec;
      rec.d_name = DNSName(toBase32Hex(before)) + zone;
      rec.d_type = QType::NSEC3;
      rec.d_ttl = now + 10;

      NSEC3RecordContent nrc;
      nrc.d_algorithm = 1;
      nrc.d_flags = 0;
      nrc.d_iterations = iterationsCount;
      nrc.d_salt = salt;
      nrc.d_nexthash = hashed;
      incrementHash(nrc.d_nexthash);
      for (const auto& type : {QType::A}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);
    }
    {
      /* insert a NSEC3 matching sub.powerdns.com (next closer) */
      DNSName name("sub.powerdns.com");
      std::string hashed = hashQNameWithSalt(salt, iterationsCount, name);
      auto before = hashed;
      decrementHash(before);
      DNSRecord rec;
      rec.d_name = DNSName(toBase32Hex(before)) + zone;
      rec.d_type = QType::NSEC3;
      rec.d_ttl = now + 10;

      NSEC3RecordContent nrc;
      nrc.d_algorithm = 1;
      nrc.d_flags = 0;
      nrc.d_iterations = iterationsCount;
      nrc.d_salt = salt;
      nrc.d_nexthash = hashed;
      incrementHash(nrc.d_nexthash);
      for (const auto& type : {QType::A}) {
        nrc.set(type);
      }

      rec.setContent(std::make_shared<NSEC3RecordContent>(nrc));
      auto rrsig = std::make_shared<RRSIGRecordContent>("NSEC3 5 3 10 20370101000000 20370101000000 24567 powerdns.com. data");
      cache->insertNSEC(zone, rec.d_name, rec, {rrsig}, true);
    }
    BOOST_CHECK_EQUAL(cache->getEntriesCount(), 3U);
  };

  {
    /* zone with cheap parameters */
    const std::string salt;
    const unsigned int iterationsCount = 0;
    AggressiveNSECCache::s_nsec3DenialProofMaxCost = 10;

    auto cache = make_unique<AggressiveNSECCache>(10000);
    insertNSEC3s(cache, salt, iterationsCount);

    /* the cache should now be able to deny everything below sub.powerdns.com,
       IF IT DOES NOT EXCEED THE COST */
    {
      /* short name: 10 labels below the zone apex */
      DNSName lookupName("a.b.c.d.e.f.g.h.i.sub.powerdns.com.");
      BOOST_CHECK_EQUAL(lookupName.countLabels() - zone.countLabels(), 10U);
      BOOST_CHECK_LE(getNSEC3DenialProofWorstCaseIterationsCount(lookupName.countLabels() - zone.countLabels(), iterationsCount, salt.size()), AggressiveNSECCache::s_nsec3DenialProofMaxCost);
      BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, lookupName, QType::AAAA, RCode::NXDomain, 7U), true);
    }
    {
      /* longer name: 11 labels below the zone apex */
      DNSName lookupName("a.b.c.d.e.f.g.h.i.j.sub.powerdns.com.");
      BOOST_CHECK_EQUAL(lookupName.countLabels() - zone.countLabels(), 11U);
      BOOST_CHECK_GT(getNSEC3DenialProofWorstCaseIterationsCount(lookupName.countLabels() - zone.countLabels(), iterationsCount, salt.size()), AggressiveNSECCache::s_nsec3DenialProofMaxCost);
      BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, lookupName, QType::AAAA), false);
    }
  }

  {
    /* zone with expensive parameters */
    const std::string salt("deadbeef");
    const unsigned int iterationsCount = 50;
    AggressiveNSECCache::s_nsec3DenialProofMaxCost = 100;

    auto cache = make_unique<AggressiveNSECCache>(10000);
    insertNSEC3s(cache, salt, iterationsCount);

    /* the cache should now be able to deny everything below sub.powerdns.com,
       IF IT DOES NOT EXCEED THE COST */
    {
      /* short name: 1 label below the zone apex */
      DNSName lookupName("sub.powerdns.com.");
      BOOST_CHECK_EQUAL(lookupName.countLabels() - zone.countLabels(), 1U);
      BOOST_CHECK_LE(getNSEC3DenialProofWorstCaseIterationsCount(lookupName.countLabels() - zone.countLabels(), iterationsCount, salt.size()), AggressiveNSECCache::s_nsec3DenialProofMaxCost);
      BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, lookupName, QType::AAAA, RCode::NXDomain, 7U), true);
    }
    {
      /* longer name: 2 labels below the zone apex */
      DNSName lookupName("a.sub.powerdns.com.");
      BOOST_CHECK_EQUAL(lookupName.countLabels() - zone.countLabels(), 2U);
      BOOST_CHECK_GT(getNSEC3DenialProofWorstCaseIterationsCount(lookupName.countLabels() - zone.countLabels(), iterationsCount, salt.size()), AggressiveNSECCache::s_nsec3DenialProofMaxCost);
      BOOST_CHECK_EQUAL(getDenialWrapper(cache, now, lookupName, QType::AAAA), false);
    }
  }
}

BOOST_AUTO_TEST_SUITE_END()
