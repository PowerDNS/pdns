#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "aggressive_nsec.hh"
#include "base32.hh"
#include "lua-recursor4.hh"
#include "root-dnssec.hh"
#include "rec-taskqueue.hh"
#include "test-syncres_cc.hh"
#include "recpacketcache.hh"

GlobalStateHolder<LuaConfigItems> g_luaconfs;
GlobalStateHolder<SuffixMatchNode> g_xdnssec;
GlobalStateHolder<SuffixMatchNode> g_dontThrottleNames;
GlobalStateHolder<NetmaskGroup> g_dontThrottleNetmasks;
GlobalStateHolder<SuffixMatchNode> g_DoTToAuthNames;
std::unique_ptr<MemRecursorCache> g_recCache;
std::unique_ptr<NegCache> g_negCache;
bool g_lowercaseOutgoing = false;
unsigned int g_networkTimeoutMsec = 1500;

/* Fake some required functions we didn't want the trouble to
   link with */
ArgvMap& arg()
{
  static ArgvMap theArg;
  return theArg;
}

BaseLua4::~BaseLua4()
{
}

void BaseLua4::getFeatures(Features& /* features */)
{
}

bool RecursorLua4::preoutquery(const ComboAddress& /* ns */, const ComboAddress& /* requestor */, const DNSName& /* query */, const QType& /* qtype */, bool /* isTcp */, vector<DNSRecord>& /* res */, int& /* ret */, RecEventTrace& /* et */, const struct timeval& /* tv */) const
{
  return false;
}

bool RecursorLua4::policyHitEventFilter(const ComboAddress& /* remote */, const DNSName& /* qname */, const QType& /* qtype */, bool /* tcp */, DNSFilterEngine::Policy& /* policy */, std::unordered_set<std::string>& /* tags */, std::unordered_map<std::string, bool>& /* discardedPolicies */) const
{
  return false;
}

RecursorLua4::~RecursorLua4()
{
}

void RecursorLua4::postPrepareContext()
{
}

void RecursorLua4::postLoad()
{
}

void RecursorLua4::getFeatures(Features& /* features */)
{
}

LWResult::Result asyncresolve(const ComboAddress& /* ip */, const DNSName& /* domain */, int /* type */, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, boost::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& /* outgoingLoggers */, const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& /* fstrmLoggers */, const std::set<uint16_t>& /* exportTypes */, LWResult* /* res */, bool* /* chained */)
{
  return LWResult::Result::Timeout;
}

/* primeHints() is only here for now because it
   was way too much trouble to link with the real one.
   We should fix this, empty functions are one thing, but this is
   bad.
*/

#include "root-addresses.hh"

bool primeHints(time_t now)
{
  vector<DNSRecord> nsset;
  if (!g_recCache) {
    g_recCache = std::make_unique<MemRecursorCache>();
  }
  if (!g_negCache) {
    g_negCache = std::make_unique<NegCache>();
  }

  DNSRecord arr;
  DNSRecord aaaarr;
  DNSRecord nsrr;
  nsrr.d_name = g_rootdnsname;
  arr.d_type = QType::A;
  aaaarr.d_type = QType::AAAA;
  nsrr.d_type = QType::NS;
  arr.d_ttl = aaaarr.d_ttl = nsrr.d_ttl = now + 3600000;

  for (char character = 'a'; character <= 'm'; ++character) {
    std::array<char, 40> templ{};
    strncpy(templ.data(), "a.root-servers.net.", sizeof(templ) - 1);
    templ[templ.size() - 1] = '\0';
    templ.at(0) = character;
    aaaarr.d_name = arr.d_name = DNSName(templ.data());
    nsrr.setContent(std::make_shared<NSRecordContent>(DNSName(templ.data())));
    arr.setContent(std::make_shared<ARecordContent>(ComboAddress(rootIps4.at(character - 'a'))));
    vector<DNSRecord> aset;
    aset.push_back(arr);
    g_recCache->replace(now, DNSName(templ.data()), QType(QType::A), aset, vector<std::shared_ptr<const RRSIGRecordContent>>(), {}, false, g_rootdnsname);
    if (!rootIps6.at(character - 'a').empty()) {
      aaaarr.setContent(std::make_shared<AAAARecordContent>(ComboAddress(rootIps6.at(character - 'a'))));

      vector<DNSRecord> aaaaset;
      aaaaset.push_back(aaaarr);
      g_recCache->replace(now, DNSName(templ.data()), QType(QType::AAAA), aaaaset, vector<std::shared_ptr<const RRSIGRecordContent>>(), {}, false, g_rootdnsname);
    }

    nsset.push_back(nsrr);
  }
  g_recCache->replace(now, g_rootdnsname, QType(QType::NS), nsset, vector<std::shared_ptr<const RRSIGRecordContent>>(), {}, false, g_rootdnsname); // and stuff in the cache
  return true;
}

LuaConfigItems::LuaConfigItems()
{
  for (const auto& dsRecord : rootDSs) {
    auto ds = std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(dsRecord));
    dsAnchors[g_rootdnsname].insert(*ds);
  }
}

/* Some helpers functions */

void initSR(bool debug)
{
  g_log.setName("test");
  g_log.disableSyslog(true);

  if (debug) {
    g_log.setLoglevel((Logger::Urgency)(6)); // info and up
    g_log.toConsole(Logger::Info);
  }
  else {
    g_log.setLoglevel(Logger::None);
    g_log.toConsole(Logger::Error);
  }

  RecursorPacketCache::s_refresh_ttlperc = 0;
  MemRecursorCache::resetStaticsForTests();
  NegCache::s_maxServedStaleExtensions = 0;
  g_recCache = std::make_unique<MemRecursorCache>();
  g_negCache = std::make_unique<NegCache>();

  SyncRes::s_maxqperq = 50;
  SyncRes::s_maxnsaddressqperq = 10;
  SyncRes::s_maxtotusec = 1000 * 7000;
  SyncRes::s_maxdepth = 40;
  SyncRes::s_maxnegttl = 3600;
  SyncRes::s_maxbogusttl = 3600;
  SyncRes::s_maxcachettl = 86400;
  SyncRes::s_packetcachettl = 3600;
  SyncRes::s_packetcacheservfailttl = 60;
  SyncRes::s_serverdownmaxfails = 64;
  SyncRes::s_serverdownthrottletime = 60;
  SyncRes::s_doIPv4 = true;
  SyncRes::s_doIPv6 = true;
  SyncRes::s_ecsipv4limit = 24;
  SyncRes::s_ecsipv6limit = 56;
  SyncRes::s_ecsipv4cachelimit = 24;
  SyncRes::s_ecsipv6cachelimit = 56;
  SyncRes::s_ecscachelimitttl = 0;
  SyncRes::s_rootNXTrust = true;
  SyncRes::s_hardenNXD = SyncRes::HardenNXD::DNSSEC;
  SyncRes::s_minimumTTL = 0;
  SyncRes::s_minimumECSTTL = 0;
  SyncRes::s_serverID = "PowerDNS Unit Tests Server ID";
  SyncRes::clearEDNSLocalSubnets();
  SyncRes::addEDNSLocalSubnet("0.0.0.0/0");
  SyncRes::addEDNSLocalSubnet("::/0");
  SyncRes::clearEDNSRemoteSubnets();
  SyncRes::clearEDNSDomains();
  SyncRes::clearDontQuery();
  SyncRes::setECSScopeZeroAddress(Netmask("127.0.0.1/32"));
  SyncRes::s_qnameminimization = false;
  SyncRes::s_nonresolvingnsmaxfails = 0;
  SyncRes::s_nonresolvingnsthrottletime = 0;
  SyncRes::s_refresh_ttlperc = 0;
  SyncRes::s_save_parent_ns_set = true;
  SyncRes::s_maxnsperresolve = 13;
  SyncRes::s_locked_ttlperc = 0;
  SyncRes::s_minimize_one_label = 4;
  SyncRes::s_max_minimize_count = 10;
  SyncRes::s_max_CNAMES_followed = 10;

  SyncRes::clearNSSpeeds();
  BOOST_CHECK_EQUAL(SyncRes::getNSSpeedsSize(), 0U);
  SyncRes::clearEDNSStatuses();
  BOOST_CHECK_EQUAL(SyncRes::getEDNSStatusesSize(), 0U);
  SyncRes::clearThrottle();
  BOOST_CHECK_EQUAL(SyncRes::getThrottledServersSize(), 0U);
  SyncRes::clearFailedServers();
  BOOST_CHECK_EQUAL(SyncRes::getFailedServersSize(), 0U);
  SyncRes::clearNonResolvingNS();
  BOOST_CHECK_EQUAL(SyncRes::getNonResolvingNSSize(), 0U);
  SyncRes::clearSaveParentsNSSets();
  BOOST_CHECK_EQUAL(SyncRes::getSaveParentsNSSetsSize(), 0U);

  SyncRes::clearECSStats();

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.clear();
  luaconfsCopy.dsAnchors.clear();
  for (const auto& dsRecord : rootDSs) {
    auto ds = std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(dsRecord));
    luaconfsCopy.dsAnchors[g_rootdnsname].insert(*ds);
  }
  luaconfsCopy.negAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  g_dnssecmode = DNSSECMode::Off;
  g_maxNSEC3Iterations = 2500;
  g_signatureInceptionSkew = 60;

  g_aggressiveNSECCache.reset();
  AggressiveNSECCache::s_maxNSEC3CommonPrefix = AggressiveNSECCache::s_default_maxNSEC3CommonPrefix;

  taskQueueClear();

  ::arg().set("version-string", "string reported on version.pdns or version.bind") = "PowerDNS Unit Tests";
  ::arg().set("rng") = "auto";
  ::arg().set("entropy-source") = "/dev/urandom";
  ::arg().set("hint-file") = "";
}

void initSR(std::unique_ptr<SyncRes>& sr, bool dnssec, bool debug, time_t fakeNow)
{
  struct timeval now;
  if (fakeNow > 0) {
    now.tv_sec = fakeNow;
    now.tv_usec = 0;
  }
  else {
    Utility::gettimeofday(&now, 0);
  }

  initSR(debug);

  sr = std::make_unique<SyncRes>(now);
  sr->setDoEDNS0(true);
  if (dnssec) {
    sr->setDoDNSSEC(dnssec);
  }

  sr->setLogMode(debug == false ? SyncRes::LogNone : SyncRes::Log);

  SyncRes::setDomainMap(std::make_shared<SyncRes::domainmap_t>());
  g_negCache->clear();
}

void setDNSSECValidation(std::unique_ptr<SyncRes>& sr, const DNSSECMode& mode)
{
  sr->setDNSSECValidationRequested(true);
  g_dnssecmode = mode;
}

void setLWResult(LWResult* res, int rcode, bool aa, bool tc, bool edns, bool validpacket)
{
  res->d_rcode = rcode;
  res->d_aabit = aa;
  res->d_tcbit = tc;
  res->d_haveEDNS = edns;
  res->d_validpacket = validpacket;
}

void addRecordToLW(LWResult* res, const DNSName& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place, uint32_t ttl)
{
  addRecordToList(res->d_records, name, type, content, place, ttl);
}

void addRecordToLW(LWResult* res, const std::string& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place, uint32_t ttl)
{
  addRecordToLW(res, DNSName(name), type, content, place, ttl);
}

bool isRootServer(const ComboAddress& ip)
{
  if (ip.isIPv4()) {
    for (size_t idx = 0; idx < rootIps4.size(); idx++) {
      if (ip.toString() == rootIps4[idx]) {
        return true;
      }
    }
  }
  else {
    for (size_t idx = 0; idx < rootIps6.size(); idx++) {
      if (ip.toString() == rootIps6[idx]) {
        return true;
      }
    }
  }

  return false;
}

void computeRRSIG(const DNSSECPrivateKey& dpk, const DNSName& signer, const DNSName& signQName, uint16_t signQType, uint32_t signTTL, uint32_t sigValidity, RRSIGRecordContent& rrc, const sortedRecords_t& toSign, boost::optional<uint8_t> algo, boost::optional<uint32_t> inception, boost::optional<time_t> now)
{
  if (!now) {
    now = time(nullptr);
  }
  DNSKEYRecordContent drc = dpk.getDNSKEY();
  const auto& rc = dpk.getKey();

  rrc.d_type = signQType;
  rrc.d_labels = signQName.countLabels() - (signQName.isWildcard() ? 1 : 0);
  rrc.d_originalttl = signTTL;
  rrc.d_siginception = inception ? *inception : (*now - 10);
  rrc.d_sigexpire = *now + sigValidity;
  rrc.d_signer = signer;
  rrc.d_tag = drc.getTag();
  rrc.d_algorithm = algo ? *algo : drc.d_algorithm;

  std::string msg = getMessageForRRSET(signQName, rrc, toSign);

  rrc.d_signature = rc->sign(msg);
}

typedef std::unordered_map<DNSName, std::pair<DNSSECPrivateKey, DSRecordContent>> testkeysset_t;

bool addRRSIG(const testkeysset_t& keys, std::vector<DNSRecord>& records, const DNSName& signer, uint32_t sigValidity, std::variant<bool, int> broken, boost::optional<uint8_t> algo, boost::optional<DNSName> wildcard, boost::optional<time_t> now)
{
  if (records.empty()) {
    return false;
  }

  const auto it = keys.find(signer);
  if (it == keys.cend()) {
    throw std::runtime_error("No DNSKEY found for " + signer.toLogString() + ", unable to compute the requested RRSIG");
  }

  DNSName name;
  uint16_t type{QType::ENT};
  DNSResourceRecord::Place place{DNSResourceRecord::ANSWER};
  uint32_t ttl{0};
  bool found = false;

  /* locate the last non-RRSIG record */
  for (auto recordIterator = records.rbegin(); recordIterator != records.rend(); ++recordIterator) {
    if (recordIterator->d_type != QType::RRSIG) {
      name = recordIterator->d_name;
      type = recordIterator->d_type;
      place = recordIterator->d_place;
      ttl = recordIterator->d_ttl;
      found = true;
      break;
    }
  }

  if (!found) {
    throw std::runtime_error("Unable to locate the record that the RRSIG should cover");
  }

  sortedRecords_t recordcontents;
  for (const auto& record : records) {
    if (record.d_name == name && record.d_type == type) {
      recordcontents.insert(record.getContent());
    }
  }

  RRSIGRecordContent rrc;
  computeRRSIG(it->second.first, signer, wildcard ? *wildcard : name, type, ttl, sigValidity, rrc, recordcontents, algo, boost::none, now);
  if (auto* bval = std::get_if<bool>(&broken); bval != nullptr && *bval) {
    rrc.d_signature[0] ^= 42;
  }
  else if (auto* ival = std::get_if<int>(&broken)) {
    rrc.d_signature[0] ^= *ival; // NOLINT(*-narrowing-conversions)
  }

  DNSRecord rec;
  rec.d_type = QType::RRSIG;
  rec.d_place = place;
  rec.d_name = name;
  rec.d_ttl = ttl;

  rec.setContent(std::make_shared<RRSIGRecordContent>(rrc));
  records.push_back(rec);

  return true;
}

void addDNSKEY(const testkeysset_t& keys, const DNSName& signer, uint32_t ttl, std::vector<DNSRecord>& records)
{
  const auto it = keys.find(signer);
  if (it == keys.cend()) {
    throw std::runtime_error("No DNSKEY found for " + signer.toLogString());
  }

  DNSRecord rec;
  rec.d_place = DNSResourceRecord::ANSWER;
  rec.d_name = signer;
  rec.d_type = QType::DNSKEY;
  rec.d_ttl = ttl;

  rec.setContent(std::make_shared<DNSKEYRecordContent>(it->second.first.getDNSKEY()));
  records.push_back(rec);
}

bool addDS(const DNSName& domain, uint32_t ttl, std::vector<DNSRecord>& records, const testkeysset_t& keys, DNSResourceRecord::Place place)
{
  const auto it = keys.find(domain);
  if (it == keys.cend()) {
    return false;
  }

  DNSRecord rec;
  rec.d_name = domain;
  rec.d_type = QType::DS;
  rec.d_place = place;
  rec.d_ttl = ttl;
  rec.setContent(std::make_shared<DSRecordContent>(it->second.second));

  records.push_back(rec);
  return true;
}

void addNSECRecordToLW(const DNSName& domain, const DNSName& next, const std::set<uint16_t>& types, uint32_t ttl, std::vector<DNSRecord>& records)
{
  NSECRecordContent nrc;
  nrc.d_next = next;
  for (const auto& type : types) {
    nrc.set(type);
  }

  DNSRecord rec;
  rec.d_name = domain;
  rec.d_ttl = ttl;
  rec.d_type = QType::NSEC;
  rec.setContent(std::make_shared<NSECRecordContent>(std::move(nrc)));
  rec.d_place = DNSResourceRecord::AUTHORITY;

  records.push_back(rec);
}

void addNSEC3RecordToLW(const DNSName& hashedName, const std::string& hashedNext, const std::string& salt, unsigned int iterations, const std::set<uint16_t>& types, uint32_t ttl, std::vector<DNSRecord>& records, bool optOut)
{
  NSEC3RecordContent nrc;
  nrc.d_algorithm = 1;
  nrc.d_flags = optOut ? 1 : 0;
  nrc.d_iterations = iterations;
  nrc.d_salt = salt;
  nrc.d_nexthash = hashedNext;
  for (const auto& type : types) {
    nrc.set(type);
  }

  DNSRecord rec;
  rec.d_name = hashedName;
  rec.d_ttl = ttl;
  rec.d_type = QType::NSEC3;
  rec.setContent(std::make_shared<NSEC3RecordContent>(std::move(nrc)));
  rec.d_place = DNSResourceRecord::AUTHORITY;

  records.push_back(rec);
}

void addNSEC3UnhashedRecordToLW(const DNSName& domain, const DNSName& zone, const std::string& next, const std::set<uint16_t>& types, uint32_t ttl, std::vector<DNSRecord>& records, unsigned int iterations, bool optOut)
{
  static const std::string salt = "deadbeef";
  std::string hashed = hashQNameWithSalt(salt, iterations, domain);

  addNSEC3RecordToLW(DNSName(toBase32Hex(hashed)) + zone, next, salt, iterations, types, ttl, records, optOut);
}

/* Proves a NODATA (name exists, type does not) but the next owner name is right behind, so it should not prove anything else unless we are very unlucky */
void addNSEC3NoDataNarrowRecordToLW(const DNSName& domain, const DNSName& zone, const std::set<uint16_t>& types, uint32_t ttl, std::vector<DNSRecord>& records, unsigned int iterations, bool optOut)
{
  static const std::string salt = "deadbeef";
  std::string hashed = hashQNameWithSalt(salt, iterations, domain);
  std::string hashedNext(hashed);
  incrementHash(hashedNext);

  addNSEC3RecordToLW(DNSName(toBase32Hex(hashed)) + zone, hashedNext, salt, iterations, types, ttl, records, optOut);
}

void addNSEC3NarrowRecordToLW(const DNSName& domain, const DNSName& zone, const std::set<uint16_t>& types, uint32_t ttl, std::vector<DNSRecord>& records, unsigned int iterations, bool optOut)
{
  static const std::string salt = "deadbeef";
  std::string hashed = hashQNameWithSalt(salt, iterations, domain);
  std::string hashedNext(hashed);
  incrementHash(hashedNext);
  decrementHash(hashed);

  addNSEC3RecordToLW(DNSName(toBase32Hex(hashed)) + zone, hashedNext, salt, iterations, types, ttl, records, optOut);
}

void generateKeyMaterial(const DNSName& name, unsigned int algo, uint8_t digest, testkeysset_t& keys)
{
  auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(algo));
  dcke->create((algo <= 10) ? 2048 : dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.setKey(dcke, 256);
  DSRecordContent ds = makeDSFromDNSKey(name, dpk.getDNSKEY(), digest);
  keys[name] = std::pair<DNSSECPrivateKey, DSRecordContent>(dpk, ds);
}

void generateKeyMaterial(const DNSName& name, unsigned int algo, uint8_t digest, testkeysset_t& keys, map<DNSName, dsset_t>& dsAnchors)
{
  generateKeyMaterial(name, algo, digest, keys);
  dsAnchors[name].insert(keys[name].second);
}

LWResult::Result genericDSAndDNSKEYHandler(LWResult* res, const DNSName& domain, DNSName auth, int type, const testkeysset_t& keys, bool proveCut, boost::optional<time_t> now, bool nsec3, bool optOut)
{
  if (type == QType::DS) {
    auth.chopOff();

    setLWResult(res, 0, true, false, true);

    if (addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER)) {
      addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, now);
    }
    else {
      addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);

      /* if the auth zone is signed, we need to provide a secure denial */
      const auto it = keys.find(auth);
      if (it != keys.cend()) {
        /* sign the SOA */
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, now);
        /* add a NSEC denying the DS */
        std::set<uint16_t> types = {QType::RRSIG};
        if (proveCut) {
          types.insert(QType::NS);
        }

        if (!nsec3) {
          addNSECRecordToLW(domain, DNSName("+") + domain, types, 600, res->d_records);
        }
        else {
          DNSName next(DNSName("z") + domain);
          next.makeUsRelative(auth);
          addNSEC3UnhashedRecordToLW(domain, auth, next.toString(), types, 600, res->d_records, 10, optOut);
        }

        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, now);
      }
    }

    return LWResult::Result::Success;
  }

  if (type == QType::DNSKEY) {
    setLWResult(res, 0, true, false, true);
    addDNSKEY(keys, domain, 300, res->d_records);
    addRRSIG(keys, res->d_records, domain, 300, false, boost::none, boost::none, now);
    return LWResult::Result::Success;
  }

  return LWResult::Result::Timeout;
}

LWResult::Result basicRecordsForQnameMinimization(LWResult* res, const DNSName& domain, int type)
{
  if (domain == DNSName(".") && type == QType::A) {
    setLWResult(res, 0, true);
    addRecordToLW(res, DNSName("."), QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2019042400 1800 900 604800 86400", DNSResourceRecord::AUTHORITY);
    return LWResult::Result::Success;
  }
  if (domain == DNSName("com") && type == QType::A) {
    setLWResult(res, 0, true);
    addRecordToLW(res, DNSName("com"), QType::NS, "ns1.com", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, DNSName("ns1.com"), QType::A, "1.2.3.4", DNSResourceRecord::ADDITIONAL);
    return LWResult::Result::Success;
  }
  if (domain == DNSName("ns1.com") && type == QType::A) {
    setLWResult(res, 0, true);
    addRecordToLW(res, DNSName("ns1.com"), QType::A, "1.2.3.4");
    return LWResult::Result::Success;
  }
  if (domain == DNSName("powerdns.com") && type == QType::A) {
    setLWResult(res, 0, true);
    addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, DNSName("ns1.powerdns.com"), QType::A, "4.5.6.7", DNSResourceRecord::ADDITIONAL);
    return LWResult::Result::Success;
  }
  if (domain == DNSName("powerdns.com") && type == QType::NS) {
    setLWResult(res, 0, true);
    addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com");
    addRecordToLW(res, DNSName("ns1.powerdns.com"), QType::A, "4.5.6.7", DNSResourceRecord::ADDITIONAL);
    return LWResult::Result::Success;
  }
  return LWResult::Result::Timeout;
}

#include "rec-web-stubs.hh"
