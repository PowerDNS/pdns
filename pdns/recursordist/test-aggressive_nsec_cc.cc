#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "aggressive_nsec.hh"
#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(aggressive_nsec_cc)

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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target1, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
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
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
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
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
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
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, boost::none, DNSName("*.powerdns.com"));
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
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, boost::none, DNSName("*.powerdns.com"));
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
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec_wildcard_synthesis)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we first ask a.powerdns.com. | A, get an answer synthesized from the wildcard,
     then check that the aggressive NSEC cache will use the wildcard to synthesize an answer
     for b.powerdns.com */
  const DNSName target("a.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
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
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, boost::none, DNSName("*.powerdns.com"));
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
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.1");
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, boost::none, DNSName("*.powerdns.com"));
        /* the name does not exist, a wildcard applies and has the requested type */
        addNSECRecordToLW(DNSName("*.powerdns.com."), DNSName("z.powerdns.com."), {QType::A, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, boost::none, DNSName("*.powerdns.com"));
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
  BOOST_CHECK_EQUAL(ret.at(0).d_name, target);
  BOOST_CHECK_EQUAL(ret.at(0).d_type, QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(DNSName("b.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(ret.at(0).d_name, DNSName("b.powerdns.com."));
  BOOST_CHECK_EQUAL(ret.at(0).d_type, QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_nxdomain)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
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
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
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
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_nodata_wildcard)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we first ask a.powerdns.com. | A, get a NODATA (no exact match but there is a wildcard match),
     then check that the aggressive NSEC cache will use the NSEC3 to prove that the AAAA does not exist either */
  const DNSName target("a.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC3, name does not exist but there is a wildcard (the generic version will generate an exact NSEC3 for the target, which we don't want) */
        setLWResult(res, RCode::NoError, true, false, true);
        /* no data */
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* then the next closer */
        addNSEC3UnhashedRecordToLW(DNSName("+.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* a wildcard applies but does not have this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::TXT, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
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
          addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* then the next closer */
          addNSEC3UnhashedRecordToLW(DNSName("+.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          /* a wildcard applies but does not have this type */
          addNSEC3UnhashedRecordToLW(DNSName("*.powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::TXT, QType::RRSIG}, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
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
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8U);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_CASE(test_aggressive_nsec3_wildcard_synthesis)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(10000);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* we first ask a.powerdns.com. | A, get an answer synthesized from the wildcard,
     then check that the aggressive NSEC cache will use the wildcard to synthesize an answer
     for b.powerdns.com */
  const DNSName target("a.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target, &queriesCount, keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      if (domain != DNSName("powerdns.com.") && domain.isPartOf(DNSName("powerdns.com."))) {
        /* no cut, NSEC3, name does not exist but there is a wildcard (the generic version will generate an exact NSEC3 for the target, which we don't want) */
        setLWResult(res, RCode::NoError, true, false, true);
        /* no data */
        addRecordToLW(res, DNSName("powerdns.com."), QType::SOA, "powerdns.com. powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* first the closest encloser */
        addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* then the next closer */
        addNSEC3UnhashedRecordToLW(DNSName("+.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* a wildcard applies but does not have this type */
        addNSEC3UnhashedRecordToLW(DNSName("*.powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com"), 300, false, boost::none, DNSName("*.powerdns.com"));
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
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.1");
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300, false, boost::none, DNSName("*.powerdns.com"));
        /* no need for the closest encloser since we have a positive answer expanded from a wildcard */
        /* the next closer */
        addNSEC3UnhashedRecordToLW(DNSName("+.powerdns.com."), DNSName("powerdns.com."), "v", {QType::RRSIG}, 600, res->d_records);
        addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
        /* and of course we don't deny the wildcard itself */
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
  BOOST_CHECK_EQUAL(ret.at(0).d_name, target);
  BOOST_CHECK_EQUAL(ret.at(0).d_type, QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);

  ret.clear();
  res = sr->beginResolve(DNSName("b.powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(ret.at(0).d_name, DNSName("b.powerdns.com."));
  BOOST_CHECK_EQUAL(ret.at(0).d_type, QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7U);
}

BOOST_AUTO_TEST_SUITE_END()
