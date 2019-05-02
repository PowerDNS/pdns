#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>

#include "arguments.hh"
#include "base32.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "lua-recursor4.hh"
#include "namespaces.hh"
#include "rec-lua-conf.hh"
#include "root-dnssec.hh"
#include "syncres.hh"
#include "test-common.hh"
#include "utility.hh"
#include "validate-recursor.hh"

RecursorStats g_stats;
GlobalStateHolder<LuaConfigItems> g_luaconfs;
GlobalStateHolder<SuffixMatchNode> g_dontThrottleNames;
GlobalStateHolder<NetmaskGroup> g_dontThrottleNetmasks;
thread_local std::unique_ptr<MemRecursorCache> t_RC{nullptr};
unsigned int g_numThreads = 1;
bool g_lowercaseOutgoing = false;

/* Fake some required functions we didn't want the trouble to
   link with */
ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}

int getMTaskerTID()
{
  return 0;
}

bool RecursorLua4::preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, int& ret) const
{
  return false;
}

int asyncresolve(const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, const std::set<uint16_t>& exportTypes, LWResult* res, bool* chained)
{
  return 0;
}

/* primeHints() is only here for now because it
   was way too much trouble to link with the real one.
   We should fix this, empty functions are one thing, but this is
   bad.
*/

#include "root-addresses.hh"

void primeHints(void)
{
  vector<DNSRecord> nsset;
  if(!t_RC)
    t_RC = std::unique_ptr<MemRecursorCache>(new MemRecursorCache());

  DNSRecord arr, aaaarr, nsrr;
  nsrr.d_name=g_rootdnsname;
  arr.d_type=QType::A;
  aaaarr.d_type=QType::AAAA;
  nsrr.d_type=QType::NS;
  arr.d_ttl=aaaarr.d_ttl=nsrr.d_ttl=time(nullptr)+3600000;

  for(char c='a';c<='m';++c) {
    char templ[40];
    strncpy(templ,"a.root-servers.net.", sizeof(templ) - 1);
    templ[sizeof(templ)-1] = '\0';
    *templ=c;
    aaaarr.d_name=arr.d_name=DNSName(templ);
    nsrr.d_content=std::make_shared<NSRecordContent>(DNSName(templ));
    arr.d_content=std::make_shared<ARecordContent>(ComboAddress(rootIps4[c-'a']));
    vector<DNSRecord> aset;
    aset.push_back(arr);
    t_RC->replace(time(nullptr), DNSName(templ), QType(QType::A), aset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), true); // auth, nuke it all
    if (rootIps6[c-'a'] != NULL) {
      aaaarr.d_content=std::make_shared<AAAARecordContent>(ComboAddress(rootIps6[c-'a']));

      vector<DNSRecord> aaaaset;
      aaaaset.push_back(aaaarr);
      t_RC->replace(time(nullptr), DNSName(templ), QType(QType::AAAA), aaaaset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), true);
    }

    nsset.push_back(nsrr);
  }
  t_RC->replace(time(nullptr), g_rootdnsname, QType(QType::NS), nsset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), false); // and stuff in the cache
}

LuaConfigItems::LuaConfigItems()
{
  for (const auto &dsRecord : rootDSs) {
    auto ds=std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(dsRecord));
    dsAnchors[g_rootdnsname].insert(*ds);
  }
}

/* Some helpers functions */

static void init(bool debug=false)
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

  t_RC = std::unique_ptr<MemRecursorCache>(new MemRecursorCache());

  SyncRes::s_maxqperq = 50;
  SyncRes::s_maxtotusec = 1000*7000;
  SyncRes::s_maxdepth = 40;
  SyncRes::s_maxnegttl = 3600;
  SyncRes::s_maxbogusttl = 3600;
  SyncRes::s_maxcachettl = 86400;
  SyncRes::s_packetcachettl = 3600;
  SyncRes::s_packetcacheservfailttl = 60;
  SyncRes::s_serverdownmaxfails = 64;
  SyncRes::s_serverdownthrottletime = 60;
  SyncRes::s_doIPv6 = true;
  SyncRes::s_ecsipv4limit = 24;
  SyncRes::s_ecsipv6limit = 56;
  SyncRes::s_ecsipv4cachelimit = 24;
  SyncRes::s_ecsipv6cachelimit = 56;
  SyncRes::s_ecscachelimitttl = 0;
  SyncRes::s_rootNXTrust = true;
  SyncRes::s_minimumTTL = 0;
  SyncRes::s_minimumECSTTL = 0;
  SyncRes::s_serverID = "PowerDNS Unit Tests Server ID";
  SyncRes::clearEDNSLocalSubnets();
  SyncRes::addEDNSLocalSubnet("0.0.0.0/0");
  SyncRes::addEDNSLocalSubnet("::/0");
  SyncRes::clearEDNSRemoteSubnets();
  SyncRes::clearEDNSDomains();
  SyncRes::clearDelegationOnly();
  SyncRes::clearDontQuery();
  SyncRes::setECSScopeZeroAddress(Netmask("127.0.0.1/32"));

  SyncRes::clearNSSpeeds();
  BOOST_CHECK_EQUAL(SyncRes::getNSSpeedsSize(), 0);
  SyncRes::clearEDNSStatuses();
  BOOST_CHECK_EQUAL(SyncRes::getEDNSStatusesSize(), 0);
  SyncRes::clearThrottle();
  BOOST_CHECK_EQUAL(SyncRes::getThrottledServersSize(), 0);
  SyncRes::clearFailedServers();
  BOOST_CHECK_EQUAL(SyncRes::getFailedServersSize(), 0);

  SyncRes::clearECSStats();

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.clear();
  luaconfsCopy.dsAnchors.clear();
  for (const auto &dsRecord : rootDSs) {
    auto ds=std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(dsRecord));
    luaconfsCopy.dsAnchors[g_rootdnsname].insert(*ds);
  }
  luaconfsCopy.negAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  g_dnssecmode = DNSSECMode::Off;
  g_dnssecLOG = debug;
  g_maxNSEC3Iterations = 2500;

  ::arg().set("version-string", "string reported on version.pdns or version.bind")="PowerDNS Unit Tests";
  ::arg().set("rng")="auto";
  ::arg().set("entropy-source")="/dev/urandom";
}

static void initSR(std::unique_ptr<SyncRes>& sr, bool dnssec=false, bool debug=false, time_t fakeNow=0)
{
  struct timeval now;
  if (fakeNow > 0) {
    now.tv_sec = fakeNow;
    now.tv_usec = 0;
  }
  else {
    Utility::gettimeofday(&now, 0);
  }

  init(debug);

  sr = std::unique_ptr<SyncRes>(new SyncRes(now));
  sr->setDoEDNS0(true);
  if (dnssec) {
    sr->setDoDNSSEC(dnssec);
  }

  sr->setLogMode(debug == false ? SyncRes::LogNone : SyncRes::Log);

  SyncRes::setDomainMap(std::make_shared<SyncRes::domainmap_t>());
  SyncRes::clearNegCache();
}

static void setDNSSECValidation(std::unique_ptr<SyncRes>& sr, const DNSSECMode& mode)
{
  sr->setDNSSECValidationRequested(true);
  g_dnssecmode = mode;
}

static void setLWResult(LWResult* res, int rcode, bool aa=false, bool tc=false, bool edns=false, bool validpacket=true)
{
  res->d_rcode = rcode;
  res->d_aabit = aa;
  res->d_tcbit = tc;
  res->d_haveEDNS = edns;
  res->d_validpacket = validpacket;
}

static void addRecordToLW(LWResult* res, const DNSName& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER, uint32_t ttl=60)
{
  addRecordToList(res->d_records, name, type, content, place, ttl);
}

static void addRecordToLW(LWResult* res, const std::string& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER, uint32_t ttl=60)
{
  addRecordToLW(res, DNSName(name), type, content, place, ttl);
}

static bool isRootServer(const ComboAddress& ip)
{
  if (ip.isIPv4()) {
    for (size_t idx = 0; idx < rootIps4Count; idx++) {
      if (ip.toString() == rootIps4[idx]) {
        return true;
      }
    }
  }
  else {
    for (size_t idx = 0; idx < rootIps6Count; idx++) {
      if (ip.toString() == rootIps6[idx]) {
        return true;
      }
    }
  }

  return false;
}

static void computeRRSIG(const DNSSECPrivateKey& dpk, const DNSName& signer, const DNSName& signQName, uint16_t signQType, uint32_t signTTL, uint32_t sigValidity, RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& toSign, boost::optional<uint8_t> algo=boost::none, boost::optional<uint32_t> inception=boost::none, boost::optional<time_t> now=boost::none)
{
  if (!now) {
    now = time(nullptr);
  }
  DNSKEYRecordContent drc = dpk.getDNSKEY();
  const std::shared_ptr<DNSCryptoKeyEngine> rc = dpk.getKey();

  rrc.d_type = signQType;
  rrc.d_labels = signQName.countLabels() - signQName.isWildcard();
  rrc.d_originalttl = signTTL;
  rrc.d_siginception = inception ? *inception : (*now - 10);
  rrc.d_sigexpire = *now + sigValidity;
  rrc.d_signer = signer;
  rrc.d_tag = 0;
  rrc.d_tag = drc.getTag();
  rrc.d_algorithm = algo ? *algo : drc.d_algorithm;

  std::string msg = getMessageForRRSET(signQName, rrc, toSign);

  rrc.d_signature = rc->sign(msg);
}

typedef std::unordered_map<DNSName, std::pair<DNSSECPrivateKey, DSRecordContent> > testkeysset_t;

static bool addRRSIG(const testkeysset_t& keys, std::vector<DNSRecord>& records, const DNSName& signer, uint32_t sigValidity, bool broken=false, boost::optional<uint8_t> algo=boost::none, boost::optional<DNSName> wildcard=boost::none, boost::optional<time_t> now=boost::none)
{
  if (records.empty()) {
    return false;
  }

  const auto it = keys.find(signer);
  if (it == keys.cend()) {
    throw std::runtime_error("No DNSKEY found for " + signer.toLogString() + ", unable to compute the requested RRSIG");
  }

  size_t recordsCount = records.size();
  const DNSName& name = records[recordsCount-1].d_name;
  const uint16_t type = records[recordsCount-1].d_type;

  std::vector<std::shared_ptr<DNSRecordContent> > recordcontents;
  for (const auto record : records) {
    if (record.d_name == name && record.d_type == type) {
      recordcontents.push_back(record.d_content);
    }
  }

  RRSIGRecordContent rrc;
  computeRRSIG(it->second.first, signer, wildcard ? *wildcard : records[recordsCount-1].d_name, records[recordsCount-1].d_type, records[recordsCount-1].d_ttl, sigValidity, rrc, recordcontents, algo, boost::none, now);
  if (broken) {
    rrc.d_signature[0] ^= 42;
  }

  DNSRecord rec;
  rec.d_type = QType::RRSIG;
  rec.d_place = records[recordsCount-1].d_place;
  rec.d_name = records[recordsCount-1].d_name;
  rec.d_ttl = records[recordsCount-1].d_ttl;

  rec.d_content = std::make_shared<RRSIGRecordContent>(rrc);
  records.push_back(rec);

  return true;
}

static void addDNSKEY(const testkeysset_t& keys, const DNSName& signer, uint32_t ttl, std::vector<DNSRecord>& records)
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

  rec.d_content = std::make_shared<DNSKEYRecordContent>(it->second.first.getDNSKEY());
  records.push_back(rec);
}

static bool addDS(const DNSName& domain, uint32_t ttl, std::vector<DNSRecord>& records, const testkeysset_t& keys, DNSResourceRecord::Place place=DNSResourceRecord::AUTHORITY)
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
  rec.d_content = std::make_shared<DSRecordContent>(it->second.second);

  records.push_back(rec);
  return true;
}

static void addNSECRecordToLW(const DNSName& domain, const DNSName& next, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records)
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
  rec.d_content = std::make_shared<NSECRecordContent>(std::move(nrc));
  rec.d_place = DNSResourceRecord::AUTHORITY;

  records.push_back(rec);
}

static void addNSEC3RecordToLW(const DNSName& hashedName, const std::string& hashedNext, const std::string& salt, unsigned int iterations, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records)
{
  NSEC3RecordContent nrc;
  nrc.d_algorithm = 1;
  nrc.d_flags = 0;
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
  rec.d_content = std::make_shared<NSEC3RecordContent>(std::move(nrc));
  rec.d_place = DNSResourceRecord::AUTHORITY;

  records.push_back(rec);
}

static void addNSEC3UnhashedRecordToLW(const DNSName& domain, const DNSName& zone, const std::string& next, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records, unsigned int iterations=10)
{
  static const std::string salt = "deadbeef";
  std::string hashed = hashQNameWithSalt(salt, iterations, domain);

  addNSEC3RecordToLW(DNSName(toBase32Hex(hashed)) + zone, next, salt, iterations, types, ttl, records);
}

static void addNSEC3NarrowRecordToLW(const DNSName& domain, const DNSName& zone, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records, unsigned int iterations=10)
{
  static const std::string salt = "deadbeef";
  std::string hashed = hashQNameWithSalt(salt, iterations, domain);
  std::string hashedNext(hashed);
  incrementHash(hashedNext);
  decrementHash(hashed);

  addNSEC3RecordToLW(DNSName(toBase32Hex(hashed)) + zone, hashedNext, salt, iterations, types, ttl, records);
}

static void generateKeyMaterial(const DNSName& name, unsigned int algo, uint8_t digest, testkeysset_t& keys)
{
  auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(algo));
  dcke->create((algo <= 10) ? 2048 : dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.d_flags = 256;
  dpk.setKey(dcke);
  DSRecordContent ds = makeDSFromDNSKey(name, dpk.getDNSKEY(), digest);
  keys[name] = std::pair<DNSSECPrivateKey,DSRecordContent>(dpk,ds);
}

static void generateKeyMaterial(const DNSName& name, unsigned int algo, uint8_t digest, testkeysset_t& keys, map<DNSName,dsmap_t>& dsAnchors)
{
  generateKeyMaterial(name, algo, digest, keys);
  dsAnchors[name].insert(keys[name].second);
}

static int genericDSAndDNSKEYHandler(LWResult* res, const DNSName& domain, DNSName auth, int type, const testkeysset_t& keys, bool proveCut=true)
{
  if (type == QType::DS) {
    auth.chopOff();

    setLWResult(res, 0, true, false, true);

    if (addDS(domain, 300, res->d_records, keys, DNSResourceRecord::ANSWER)) {
      addRRSIG(keys, res->d_records, auth, 300);
    }
    else {
      addRecordToLW(res, auth, QType::SOA, "foo. bar. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);

      /* if the auth zone is signed, we need to provide a secure denial */
      const auto it = keys.find(auth);
      if (it != keys.cend()) {
        /* sign the SOA */
        addRRSIG(keys, res->d_records, auth, 300);
        /* add a NSEC denying the DS */
        std::set<uint16_t> types = { QType::NSEC };
        if (proveCut) {
          types.insert(QType::NS);
        }

        addNSECRecordToLW(domain, DNSName("z") + domain, types, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
      }
    }

    return 1;
  }

  if (type == QType::DNSKEY) {
    setLWResult(res, 0, true, false, true);
    addDNSKEY(keys, domain, 300, res->d_records);
    addRRSIG(keys, res->d_records, domain, 300);
    return 1;
  }

  return 0;
}

/* Real tests */

BOOST_AUTO_TEST_SUITE(syncres_cc)

BOOST_AUTO_TEST_CASE(test_root_primed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("a.root-servers.net.");

  /* we are primed, we should be able to resolve A a.root-servers.net. without any query */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);

  ret.clear();
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::AAAA);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_root_primed_ns) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();
  const DNSName target(".");

  /* we are primed, but we should not be able to NS . without any query
   because the . NS entry is not stored as authoritative */

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (domain == target && type == QType::NS) {

        setLWResult(res, 0, true, false, true);
        char addr[] = "a.root-servers.net.";
        for (char idx = 'a'; idx <= 'm'; idx++) {
          addr[0] = idx;
          addRecordToLW(res, g_rootdnsname, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 13);
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_root_not_primed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (domain == g_rootdnsname && type == QType::NS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, g_rootdnsname, QType::NS, "a.root-servers.net.", DNSResourceRecord::ANSWER, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      }

      return 0;
    });

  /* we are not primed yet, so SyncRes will have to call primeHints()
     then call getRootNS(), for which at least one of the root servers needs to answer */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("."), QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_root_not_primed_and_no_response) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  std::set<ComboAddress> downServers;

  /* we are not primed yet, so SyncRes will have to call primeHints()
     then call getRootNS(), for which at least one of the root servers needs to answer.
     None will, so it should ServFail.
  */
  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      downServers.insert(ip);
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("."), QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK(downServers.size() > 0);
  /* we explicitly refuse to mark the root servers down */
  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 0);
  }
}

BOOST_AUTO_TEST_CASE(test_edns_formerr_fallback) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  ComboAddress noEDNSServer;
  size_t queriesWithEDNS = 0;
  size_t queriesWithoutEDNS = 0;

  sr->setAsyncCallback([&queriesWithEDNS, &queriesWithoutEDNS, &noEDNSServer](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      if (EDNS0Level != 0) {
        queriesWithEDNS++;
        noEDNSServer = ip;

        setLWResult(res, RCode::FormErr);
        return 1;
      }

      queriesWithoutEDNS++;

      if (domain == DNSName("powerdns.com") && type == QType::A && !doTCP) {
        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.1");
        return 1;
      }

      return 0;
    });

  primeHints();

  /* fake that the root NS doesn't handle EDNS, check that we fallback */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesWithEDNS, 1);
  BOOST_CHECK_EQUAL(queriesWithoutEDNS, 1);
  BOOST_CHECK_EQUAL(SyncRes::getEDNSStatusesSize(), 1);
  BOOST_CHECK_EQUAL(SyncRes::getEDNSStatus(noEDNSServer), SyncRes::EDNSStatus::NOEDNS);
}

BOOST_AUTO_TEST_CASE(test_edns_formerr_but_edns_enabled) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  /* in this test, the auth answers with FormErr to an EDNS-enabled
     query, but the response does contain EDNS so we should not mark
     it as EDNS ignorant or intolerant.
  */
  size_t queriesWithEDNS = 0;
  size_t queriesWithoutEDNS = 0;
  std::set<ComboAddress> usedServers;

  sr->setAsyncCallback([&queriesWithEDNS, &queriesWithoutEDNS, &usedServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (EDNS0Level > 0) {
        queriesWithEDNS++;
      }
      else {
        queriesWithoutEDNS++;
      }
      usedServers.insert(ip);

      if (type == QType::DNAME) {
        setLWResult(res, RCode::FormErr);
        if (EDNS0Level > 0) {
          res->d_haveEDNS = true;
        }
        return 1;
      }

      return 0;
    });

  primeHints();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::DNAME), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(queriesWithEDNS, 26);
  BOOST_CHECK_EQUAL(queriesWithoutEDNS, 0);
  BOOST_CHECK_EQUAL(SyncRes::getEDNSStatusesSize(), 26);
  BOOST_CHECK_EQUAL(usedServers.size(), 26);
  for (const auto& server : usedServers) {
    BOOST_CHECK_EQUAL(SyncRes::getEDNSStatus(server), SyncRes::EDNSStatus::EDNSOK);
  }
}

BOOST_AUTO_TEST_CASE(test_meta_types) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  static const std::set<uint16_t> invalidTypes = { 128, QType::AXFR, QType::IXFR, QType::RRSIG, QType::NSEC3, QType::OPT, QType::TSIG, QType::TKEY, QType::MAILA, QType::MAILB, 65535 };

  for (const auto qtype : invalidTypes) {
    size_t queriesCount = 0;

    sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      return 0;
    });

    primeHints();

    vector<DNSRecord> ret;
    int res = sr->beginResolve(DNSName("powerdns.com."), QType(qtype), QClass::IN, ret);
    BOOST_CHECK_EQUAL(res, -1);
    BOOST_CHECK_EQUAL(ret.size(), 0);
    BOOST_CHECK_EQUAL(queriesCount, 0);
  }
}

BOOST_AUTO_TEST_CASE(test_tc_fallback_to_tcp) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  sr->setAsyncCallback([](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      if (!doTCP) {
        setLWResult(res, 0, false, true, false);
        return 1;
      }
      if (domain == DNSName("powerdns.com") && type == QType::A && doTCP) {
        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.1");
        return 1;
      }

      return 0;
    });

  primeHints();

  /* fake that the NS truncates every request over UDP, we should fallback to TCP */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
}

BOOST_AUTO_TEST_CASE(test_tc_over_tcp) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  size_t tcpQueriesCount = 0;

  sr->setAsyncCallback([&tcpQueriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      if (!doTCP) {
        setLWResult(res, 0, true, true, false);
        return 1;
      }

      /* first TCP query is answered with a TC response */
      tcpQueriesCount++;
      if (tcpQueriesCount == 1) {
        setLWResult(res, 0, true, true, false);
      }
      else {
        setLWResult(res, 0, true, false, false);
      }

      addRecordToLW(res, domain, QType::A, "192.0.2.1");
      return 1;
    });

  primeHints();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(tcpQueriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_all_nss_down) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return 1;
      }
      else {
        downServers.insert(ip);
        return 0;
      }
    });

  DNSName target("powerdns.com.");

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(downServers.size(), 4);

  time_t now = sr->getNow().tv_sec;
  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 1);
    BOOST_CHECK(SyncRes::isThrottled(now, server, target, QType::A));
  }
}

BOOST_AUTO_TEST_CASE(test_all_nss_network_error) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return 1;
      }
      else {
        downServers.insert(ip);
        return 0;
      }
    });

  /* exact same test than the previous one, except instead of a time out we fake a network error */
  DNSName target("powerdns.com.");

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(downServers.size(), 4);

  time_t now = sr->getNow().tv_sec;
  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 1);
    BOOST_CHECK(SyncRes::isThrottled(now, server, target, QType::A));
  }
}

BOOST_AUTO_TEST_CASE(test_only_one_ns_up_resolving_itself_with_glue) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  DNSName target("www.powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        if (domain == target) {
          addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
          addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        }
        else if (domain == DNSName("pdns-public-ns2.powerdns.net.")) {
          addRecordToLW(res, "powerdns.net.", QType::NS, "pdns-public-ns2.powerdns.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "powerdns.net.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "pdns-public-ns2.powerdns.net.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
          addRecordToLW(res, "pdns-public-ns2.powerdns.net.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        }
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.3:53")) {
        setLWResult(res, 0, true, false, true);
        if (domain == DNSName("pdns-public-ns2.powerdns.net.")) {
          if (type == QType::A) {
            addRecordToLW(res, "pdns-public-ns2.powerdns.net.", QType::A, "192.0.2.3");
          }
          else if (type == QType::AAAA) {
            addRecordToLW(res, "pdns-public-ns2.powerdns.net.", QType::AAAA, "2001:DB8::3");
          }
        }
        else if (domain == target) {
          if (type == QType::A) {
            addRecordToLW(res, domain, QType::A, "192.0.2.1");
          }
          else if (type == QType::AAAA) {
            addRecordToLW(res, domain, QType::AAAA, "2001:DB8::1");
          }
        }
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_os_limit_errors) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return 1;
      }
      else {
        if (downServers.size() < 3) {
          /* only the last one will answer */
          downServers.insert(ip);
          return -2;
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, "powerdns.com.", QType::A, "192.0.2.42");
          return 1;
        }
      }
    });

  DNSName target("powerdns.com.");

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(downServers.size(), 3);

  /* Error is reported as "OS limit error" (-2) so the servers should _NOT_ be marked down */
  time_t now = sr->getNow().tv_sec;
  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 0);
    BOOST_CHECK(!SyncRes::isThrottled(now, server, target, QType::A));
  }
}

BOOST_AUTO_TEST_CASE(test_glued_referral) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      /* this will cause issue with qname minimization if we ever implement it */
      if (domain != target) {
        return 0;
      }

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.2:53") || ip == ComboAddress("192.0.2.3:53") || ip == ComboAddress("[2001:DB8::2]:53") || ip == ComboAddress("[2001:DB8::3]:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.4");
        return 1;
      }
      else {
        return 0;
      }
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_glueless_referral) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);

        if (domain.isPartOf(DNSName("com."))) {
          addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        } else if (domain.isPartOf(DNSName("org."))) {
          addRecordToLW(res, "org.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        }
        else {
          setLWResult(res, RCode::NXDomain, false, false, true);
          return 1;
        }

        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        if (domain == target) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
          return 1;
        }
        else if (domain == DNSName("pdns-public-ns1.powerdns.org.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, "pdns-public-ns1.powerdns.org.", QType::A, "192.0.2.2");
          addRecordToLW(res, "pdns-public-ns1.powerdns.org.", QType::AAAA, "2001:DB8::2");
          return 1;
        }
        else if (domain == DNSName("pdns-public-ns2.powerdns.org.")) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, "pdns-public-ns2.powerdns.org.", QType::A, "192.0.2.3");
          addRecordToLW(res, "pdns-public-ns2.powerdns.org.", QType::AAAA, "2001:DB8::3");
          return 1;
        }

        setLWResult(res, RCode::NXDomain, false, false, true);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.2:53") || ip == ComboAddress("192.0.2.3:53") || ip == ComboAddress("[2001:DB8::2]:53") || ip == ComboAddress("[2001:DB8::3]:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.4");
        return 1;
      }
      else {
        return 0;
      }
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_edns_subnet_by_domain) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSDomain(target);

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

        /* this one did not use the ECS info */
        srcmask = boost::none;

        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        /* this one did, but only up to a precision of /16, not the full /24 */
        srcmask = Netmask("192.0.0.0/16");

        return 1;
      }

      return 0;
    });

  SyncRes::s_ecsqueries = 0;
  SyncRes::s_ecsresponses = 0;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(SyncRes::s_ecsqueries, 2);
  BOOST_CHECK_EQUAL(SyncRes::s_ecsresponses, 1);
  for (const auto& entry : SyncRes::s_ecsResponsesBySubnetSize4) {
    BOOST_CHECK_EQUAL(entry.second, entry.first == 15 ? 1 : 0);
  }
  for (const auto& entry : SyncRes::s_ecsResponsesBySubnetSize6) {
    BOOST_CHECK_EQUAL(entry.second, 0);
  }
}

BOOST_AUTO_TEST_CASE(test_edns_subnet_by_addr) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSRemoteSubnet("192.0.2.1/32");

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("2001:DB8::FF/128");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        BOOST_REQUIRE(srcmask);
        BOOST_CHECK_EQUAL(srcmask->toString(), "2001:db8::/56");

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  SyncRes::s_ecsqueries = 0;
  SyncRes::s_ecsresponses = 0;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(SyncRes::s_ecsqueries, 1);
  BOOST_CHECK_EQUAL(SyncRes::s_ecsresponses, 1);
  for (const auto& entry : SyncRes::s_ecsResponsesBySubnetSize4) {
    BOOST_CHECK_EQUAL(entry.second, 0);
  }
  for (const auto& entry : SyncRes::s_ecsResponsesBySubnetSize6) {
    BOOST_CHECK_EQUAL(entry.second, entry.first == 55 ? 1 : 0);
  }
}

BOOST_AUTO_TEST_CASE(test_ecs_use_requestor) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSRemoteSubnet("192.0.2.1/32");
  // No incoming ECS data
  sr->setQuerySource(ComboAddress("192.0.2.127"), boost::none);

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        BOOST_REQUIRE(srcmask);
        BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_ecs_use_scope_zero) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSRemoteSubnet("192.0.2.1/32");
  SyncRes::clearEDNSLocalSubnets();
  SyncRes::addEDNSLocalSubnet("192.0.2.254/32");
  // No incoming ECS data, Requestor IP not in ecs-add-for
  sr->setQuerySource(ComboAddress("192.0.2.127"), boost::none);

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        BOOST_REQUIRE(srcmask);
        BOOST_CHECK_EQUAL(srcmask->toString(), "127.0.0.1/32");

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_ecs_honor_incoming_mask) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSRemoteSubnet("192.0.2.1/32");
  SyncRes::clearEDNSLocalSubnets();
  SyncRes::addEDNSLocalSubnet("192.0.2.254/32");
  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.0.0/16");
  sr->setQuerySource(ComboAddress("192.0.2.127"), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        BOOST_REQUIRE(srcmask);
        BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.0.0/16");

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_ecs_honor_incoming_mask_zero) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSRemoteSubnet("192.0.2.1/32");
  SyncRes::clearEDNSLocalSubnets();
  SyncRes::addEDNSLocalSubnet("192.0.2.254/32");
  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("0.0.0.0/0");
  sr->setQuerySource(ComboAddress("192.0.2.127"), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        BOOST_REQUIRE(srcmask);
        BOOST_CHECK_EQUAL(srcmask->toString(), "127.0.0.1/32");

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_following_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cname.powerdns.com.");
  const DNSName cnameTarget("cname-target.powerdns.com");

  sr->setAsyncCallback([target, cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
          return 1;
        }
        else if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
        }

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[1].d_name, cnameTarget);
}

BOOST_AUTO_TEST_CASE(test_cname_nxdomain) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cname.powerdns.com.");
  const DNSName cnameTarget("cname-target.powerdns.com");

  sr->setAsyncCallback([target, cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        if (domain == target) {
          setLWResult(res, RCode::NXDomain, true, false, false);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
          addRecordToLW(res, "powerdns.com.", QType::SOA, "a.powerdns.com. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        } else if (domain == cnameTarget) {
          setLWResult(res, RCode::NXDomain, true, false, false);
          addRecordToLW(res, "powerdns.com.", QType::SOA, "a.powerdns.com. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          return 1;
        }

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[1].d_type == QType::SOA);

  /* a second time, to check the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[1].d_type == QType::SOA);
}

BOOST_AUTO_TEST_CASE(test_included_poisonous_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* In this test we directly get the NS server for cname.powerdns.com.,
     and we don't know whether it's also authoritative for
     cname-target.powerdns.com or powerdns.com, so we shouldn't accept
     the additional A record for cname-target.powerdns.com. */
  const DNSName target("cname.powerdns.com.");
  const DNSName cnameTarget("cname-target.powerdns.com");

  sr->setAsyncCallback([target, cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);

        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL);
          return 1;
        } else if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.3");
          return 1;
        }

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_REQUIRE(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK_EQUAL(getRR<CNAMERecordContent>(ret[0])->getTarget(), cnameTarget);
  BOOST_REQUIRE(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[1].d_name, cnameTarget);
  BOOST_CHECK(getRR<ARecordContent>(ret[1])->getCA() == ComboAddress("192.0.2.3"));
}

BOOST_AUTO_TEST_CASE(test_cname_loop) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t count = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&count](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      count++;

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::CNAME, domain.toString());
          return 1;
        }

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_GT(ret.size(), 0);
  BOOST_CHECK_EQUAL(count, 2);
}

BOOST_AUTO_TEST_CASE(test_cname_depth) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t depth = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&depth](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::CNAME, std::to_string(depth) + "-cname.powerdns.com");
        depth++;
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), depth);
  /* we have an arbitrary limit at 10 when following a CNAME chain */
  BOOST_CHECK_EQUAL(depth, 10 + 2);
}

BOOST_AUTO_TEST_CASE(test_time_limit) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queries = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queries++;

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        /* Pretend that this query took 2000 ms */
        res->d_usec = 2000;

        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  /* Set the maximum time to 1 ms */
  SyncRes::s_maxtotusec = 1000;

  try {
    vector<DNSRecord> ret;
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch(const ImmediateServFailException& e) {
  }
  BOOST_CHECK_EQUAL(queries, 1);
}

BOOST_AUTO_TEST_CASE(test_referral_depth) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queries = 0;
  const DNSName target("www.powerdns.com.");

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queries++;

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);

        if (domain == DNSName("www.powerdns.com.")) {
          addRecordToLW(res, domain, QType::NS, "ns.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        }
        else if (domain == DNSName("ns.powerdns.com.")) {
          addRecordToLW(res, domain, QType::NS, "ns1.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        }
        else if (domain == DNSName("ns1.powerdns.org.")) {
          addRecordToLW(res, domain, QType::NS, "ns2.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        }
        else if (domain == DNSName("ns2.powerdns.org.")) {
          addRecordToLW(res, domain, QType::NS, "ns3.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        }
        else if (domain == DNSName("ns3.powerdns.org.")) {
          addRecordToLW(res, domain, QType::NS, "ns4.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
        }
        else if (domain == DNSName("ns4.powerdns.org.")) {
          addRecordToLW(res, domain, QType::NS, "ns5.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, domain, QType::A, "192.0.2.1", DNSResourceRecord::AUTHORITY, 172800);
        }

        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  /* Set the maximum depth low */
  SyncRes::s_maxdepth = 10;

  try {
    vector<DNSRecord> ret;
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch(const ImmediateServFailException& e) {
  }
}

BOOST_AUTO_TEST_CASE(test_cname_qperq) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queries = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queries++;

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::CNAME, std::to_string(queries) + "-cname.powerdns.com");
        return 1;
      }

      return 0;
    });

  /* Set the maximum number of questions very low */
  SyncRes::s_maxqperq = 5;

  try {
    vector<DNSRecord> ret;
    sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK(false);
  }
  catch(const ImmediateServFailException& e) {
    BOOST_CHECK_EQUAL(queries, SyncRes::s_maxqperq);
  }
}

BOOST_AUTO_TEST_CASE(test_throttled_server) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("throttled.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([target,ns,&queriesToNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        queriesToNS++;

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        return 1;
      }

      return 0;
    });

  /* mark ns as down */
  time_t now = sr->getNow().tv_sec;
  SyncRes::doThrottle(now, ns, SyncRes::s_serverdownthrottletime, 10000);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  /* we should not have sent any queries to ns */
  BOOST_CHECK_EQUAL(queriesToNS, 0);
}

BOOST_AUTO_TEST_CASE(test_throttled_server_count) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const ComboAddress ns("192.0.2.1:53");

  const size_t blocks = 10;
  /* mark ns as down for 'blocks' queries */
  time_t now = sr->getNow().tv_sec;
  SyncRes::doThrottle(now, ns, SyncRes::s_serverdownthrottletime, blocks);

  for (size_t idx = 0; idx < blocks; idx++) {
    BOOST_CHECK(SyncRes::isThrottled(now, ns));
  }

  /* we have been throttled 'blocks' times, we should not be throttled anymore */
  BOOST_CHECK(!SyncRes::isThrottled(now, ns));
}

BOOST_AUTO_TEST_CASE(test_throttled_server_time) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const ComboAddress ns("192.0.2.1:53");

  const size_t seconds = 1;
  /* mark ns as down for 'seconds' seconds */
  time_t now = sr->getNow().tv_sec;
  SyncRes::doThrottle(now, ns, seconds, 10000);

  BOOST_CHECK(SyncRes::isThrottled(now, ns));

  /* we should not be throttled anymore */
  BOOST_CHECK(!SyncRes::isThrottled(now + 2, ns));
}

BOOST_AUTO_TEST_CASE(test_dont_query_server) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("throttled.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([target,ns,&queriesToNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        queriesToNS++;

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        return 1;
      }

      return 0;
    });

  /* prevent querying this NS */
  SyncRes::addDontQuery(Netmask(ns));

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  /* we should not have sent any queries to ns */
  BOOST_CHECK_EQUAL(queriesToNS, 0);
}

BOOST_AUTO_TEST_CASE(test_root_nx_trust) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("notpowerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([target1, target2, ns, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip)) {

        if (domain == target1) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        }

        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        return 1;
      }

      return 0;
    });

  SyncRes::s_maxnegttl = 3600;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  /* one for target1 and one for the entire TLD */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 2);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_LE(ret[0].d_ttl, SyncRes::s_maxnegttl);
  /* one for target1 and one for the entire TLD */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 2);

  /* we should have sent only one query */
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_root_nx_trust_specific) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("notpowerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  /* This time the root denies target1 with a "com." SOA instead of a "." one.
     We should add target1 to the negcache, but not "com.". */

  sr->setAsyncCallback([target1, target2, ns, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip)) {

        if (domain == target1) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, "com.", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        }

        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);

  /* even with root-nx-trust on and a NX answer from the root,
     we should not have cached the entire TLD this time. */
  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(ret[0].d_name, target2);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK(getRR<ARecordContent>(ret[0])->getCA() == ComboAddress("192.0.2.2"));

  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1);

  BOOST_CHECK_EQUAL(queriesCount, 3);
}

BOOST_AUTO_TEST_CASE(test_root_nx_dont_trust) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target1("powerdns.com.");
  const DNSName target2("notpowerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesCount = 0;

  sr->setAsyncCallback([target1, target2, ns, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip)) {

        if (domain == target1) {
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        }
        else {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        }

        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");

        return 1;
      }

      return 0;
    });

  SyncRes::s_rootNXTrust = false;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  /* one for target1 */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  /* one for target1 */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 1);

  /* we should have sent three queries */
  BOOST_CHECK_EQUAL(queriesCount, 3);
}

BOOST_AUTO_TEST_CASE(test_skip_negcache_for_variable_response) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");
  const DNSName cnameTarget("cname.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));

  sr->setAsyncCallback([target,cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

        srcmask = boost::none;

        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain == target) {
          /* Type 2 NXDOMAIN (rfc2308 section-2.1) */
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
          addRecordToLW(res, "powerdns.com", QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        }
        else if (domain == cnameTarget) {
          /* we shouldn't get there since the Type NXDOMAIN should have been enough,
             but we might if we still chase the CNAME. */
          setLWResult(res, RCode::NXDomain, true, false, true);
          addRecordToLW(res, "powerdns.com", QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        }

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 2);
  /* no negative cache entry because the response was variable */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 0);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_limit_allowed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::s_ecsipv4cachelimit = 24;

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.1");

      return 1;
    });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);

  /* should have been cached */
  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_limit_no_ttl_limit_allowed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("www.powerdns.com.");

  SyncRes::addEDNSDomain(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::s_ecsipv4cachelimit = 16;

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.1");

      return 1;
    });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);

  /* should have been cached because /24 is more specific than /16 but TTL limit is nof effective */
  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_ttllimit_allowed) {
    std::unique_ptr<SyncRes> sr;
    initSR(sr);

    primeHints();

    const DNSName target("www.powerdns.com.");

    SyncRes::addEDNSDomain(DNSName("powerdns.com."));

    EDNSSubnetOpts incomingECS;
    incomingECS.source = Netmask("192.0.2.128/32");
    sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
    SyncRes::s_ecscachelimitttl = 30;

    sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.1");

      return 1;
    });

    const time_t now = sr->getNow().tv_sec;
    vector<DNSRecord> ret;
    int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK_EQUAL(res, RCode::NoError);
    BOOST_CHECK_EQUAL(ret.size(), 1);

    /* should have been cached */
    const ComboAddress who("192.0.2.128");
    vector<DNSRecord> cached;
    BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
    BOOST_REQUIRE_EQUAL(cached.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_ttllimit_and_scope_allowed) {
    std::unique_ptr<SyncRes> sr;
    initSR(sr);

    primeHints();

    const DNSName target("www.powerdns.com.");

    SyncRes::addEDNSDomain(DNSName("powerdns.com."));

    EDNSSubnetOpts incomingECS;
    incomingECS.source = Netmask("192.0.2.128/32");
    sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
    SyncRes::s_ecscachelimitttl = 100;
    SyncRes::s_ecsipv4cachelimit = 24;

    sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.1");

      return 1;
    });

    const time_t now = sr->getNow().tv_sec;
    vector<DNSRecord> ret;
    int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK_EQUAL(res, RCode::NoError);
    BOOST_CHECK_EQUAL(ret.size(), 1);

    /* should have been cached */
    const ComboAddress who("192.0.2.128");
    vector<DNSRecord> cached;
    BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
    BOOST_REQUIRE_EQUAL(cached.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_ecs_cache_ttllimit_notallowed) {
    std::unique_ptr<SyncRes> sr;
    initSR(sr);

    primeHints();

    const DNSName target("www.powerdns.com.");

    SyncRes::addEDNSDomain(DNSName("powerdns.com."));

    EDNSSubnetOpts incomingECS;
    incomingECS.source = Netmask("192.0.2.128/32");
    sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
    SyncRes::s_ecscachelimitttl = 100;
    SyncRes::s_ecsipv4cachelimit = 16;

    sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, target, QType::A, "192.0.2.1");

      return 1;
    });

    const time_t now = sr->getNow().tv_sec;
    vector<DNSRecord> ret;
    int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
    BOOST_CHECK_EQUAL(res, RCode::NoError);
    BOOST_CHECK_EQUAL(ret.size(), 1);

    /* should have NOT been cached because TTL of 60 is too small and /24 is more specific than /16 */
    const ComboAddress who("192.0.2.128");
    vector<DNSRecord> cached;
    BOOST_REQUIRE_LT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
    BOOST_REQUIRE_EQUAL(cached.size(), 0);
}


BOOST_AUTO_TEST_CASE(test_ns_speed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  std::map<ComboAddress, uint64_t> nsCounts;

  sr->setAsyncCallback([target,&nsCounts](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns3.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);

        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "pdns-public-ns3.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "pdns-public-ns3.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else {
        nsCounts[ip]++;

        if (ip == ComboAddress("[2001:DB8::2]:53") || ip == ComboAddress("192.0.2.2:53")) {
          BOOST_CHECK_LT(nsCounts.size(), 3);

          /* let's time out on pdns-public-ns2.powerdns.com. */
          return 0;
        }
        else if (ip == ComboAddress("192.0.2.1:53")) {
          BOOST_CHECK_EQUAL(nsCounts.size(), 3);

          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, domain, QType::A, "192.0.2.254");
          return 1;
        }

        return 0;
      }

      return 0;
    });

  struct timeval now = sr->getNow();

  /* make pdns-public-ns2.powerdns.com. the fastest NS, with its IPv6 address faster than the IPV4 one,
     then pdns-public-ns1.powerdns.com. on IPv4 */
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns1.powerdns.com."), ComboAddress("192.0.2.1:53"), 100, &now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns1.powerdns.com."), ComboAddress("[2001:DB8::1]:53"), 10000, &now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns2.powerdns.com."), ComboAddress("192.0.2.2:53"), 10, &now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns2.powerdns.com."), ComboAddress("[2001:DB8::2]:53"), 1, &now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns3.powerdns.com."), ComboAddress("192.0.2.3:53"), 10000, &now);
  SyncRes::submitNSSpeed(DNSName("pdns-public-ns3.powerdns.com."), ComboAddress("[2001:DB8::3]:53"), 10000, &now);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(nsCounts.size(), 3);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("192.0.2.1:53")], 1);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("192.0.2.2:53")], 1);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("[2001:DB8::2]:53")], 1);
}

BOOST_AUTO_TEST_CASE(test_flawed_nsset) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);

        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.254");
        return 1;
      }

      return 0;
    });

  /* we populate the cache with a flawed NSset, i.e. there is a NS entry but no corresponding glue */
  time_t now = sr->getNow().tv_sec;
  std::vector<DNSRecord> records;
  std::vector<shared_ptr<RRSIGRecordContent> > sigs;
  addRecordToList(records, target, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, now + 3600);

  t_RC->replace(now, target, QType(QType::NS), records, sigs, vector<std::shared_ptr<DNSRecord>>(), true, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_completely_flawed_nsset) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount,target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip) && domain == target) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns3.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        return 1;
      } else if (domain == DNSName("pdns-public-ns2.powerdns.com.") || domain == DNSName("pdns-public-ns3.powerdns.com.")){
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, ".", QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  /* one query to get NSs, then A and AAAA for each NS */
  BOOST_CHECK_EQUAL(queriesCount, 5);
}

BOOST_AUTO_TEST_CASE(test_cache_hit) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      return 0;
    });

  /* we populate the cache with eveything we need */
  time_t now = sr->getNow().tv_sec;
  std::vector<DNSRecord> records;
  std::vector<shared_ptr<RRSIGRecordContent> > sigs;

  addRecordToList(records, target, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, now + 3600);
  t_RC->replace(now, target , QType(QType::A), records, sigs, vector<std::shared_ptr<DNSRecord>>(), true, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_no_rd) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  size_t queriesCount = 0;

  sr->setCacheOnly();

  sr->setAsyncCallback([target,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_cache_min_max_ttl) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cachettl.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 7200);
        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);

        return 1;
      }

      return 0;
    });

  const time_t now = sr->getNow().tv_sec;
  SyncRes::s_minimumTTL = 60;
  SyncRes::s_maxcachettl = 3600;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(ret[0].d_ttl, SyncRes::s_minimumTTL);

  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_EQUAL((cached[0].d_ttl - now), SyncRes::s_minimumTTL);

  cached.clear();
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::NS), false, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_LE((cached[0].d_ttl - now), SyncRes::s_maxcachettl);
}

BOOST_AUTO_TEST_CASE(test_cache_min_max_ecs_ttl) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cacheecsttl.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setQuerySource(ComboAddress(), boost::optional<const EDNSSubnetOpts&>(incomingECS));
  SyncRes::addEDNSDomain(target);

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      if (isRootServer(ip)) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 20);
        srcmask = boost::none;

        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, false);
        addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);

        return 1;
      }

      return 0;
    });

  const time_t now = sr->getNow().tv_sec;
  SyncRes::s_minimumTTL = 60;
  SyncRes::s_minimumECSTTL = 120;
  SyncRes::s_maxcachettl = 3600;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(ret[0].d_ttl, SyncRes::s_minimumECSTTL);

  const ComboAddress who("192.0.2.128");
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_EQUAL((cached[0].d_ttl - now), SyncRes::s_minimumECSTTL);

  cached.clear();
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::NS), false, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_LE((cached[0].d_ttl - now), SyncRes::s_maxcachettl);

  cached.clear();
  BOOST_REQUIRE_GT(t_RC->get(now, DNSName("a.gtld-servers.net."), QType(QType::A), false, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_LE((cached[0].d_ttl - now), SyncRes::s_minimumTTL);
}

BOOST_AUTO_TEST_CASE(test_cache_expired_ttl) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);

        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.2");
        return 1;
      }

      return 0;
    });

  /* we populate the cache with entries that expired 60s ago*/
  const time_t now = sr->getNow().tv_sec;

  std::vector<DNSRecord> records;
  std::vector<shared_ptr<RRSIGRecordContent> > sigs;
  addRecordToList(records, target, QType::A, "192.0.2.42", DNSResourceRecord::ANSWER, now - 60);

  t_RC->replace(now - 3600, target, QType(QType::A), records, sigs, vector<std::shared_ptr<DNSRecord>>(), true, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toStringWithPort(), ComboAddress("192.0.2.2").toStringWithPort());
}

BOOST_AUTO_TEST_CASE(test_cache_auth) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* the auth server is sending the same answer in answer and additional,
     check that we only return one result, and we only cache one too. */
  const DNSName target("cache-auth.powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ANSWER, 10);
      addRecordToLW(res, domain, QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 10);

      return 1;
    });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_REQUIRE_EQUAL(QType(ret.at(0).d_type).getName(), QType(QType::A).getName());
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret.at(0))->getCA().toString(), ComboAddress("192.0.2.2").toString());

  /* check that we correctly cached only the answer entry, not the additional one */
  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
  BOOST_REQUIRE_EQUAL(QType(cached.at(0).d_type).getName(), QType(QType::A).getName());
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(cached.at(0))->getCA().toString(), ComboAddress("192.0.2.2").toString());
}

BOOST_AUTO_TEST_CASE(test_delegation_only) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* Thanks, Verisign */
  SyncRes::addDelegationOnly(DNSName("com."));
  SyncRes::addDelegationOnly(DNSName("net."));

  const DNSName target("nx-powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_unauth_any) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_no_data) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_skip_opt_any) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      addRecordToLW(res, domain, QType::ANY, "0 0");
      addRecordToLW(res, domain, QType::OPT, "");
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_nodata_nsec_nodnssec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_nodata_nsec_dnssec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 4);
}

BOOST_AUTO_TEST_CASE(test_nx_nsec_nodnssec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, RCode::NXDomain, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_nx_nsec_dnssec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, RCode::NXDomain, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 2 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 4);
}

BOOST_AUTO_TEST_CASE(test_qclass_none) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* apart from special names and QClass::ANY, anything else than QClass::IN should be rejected right away */
  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      return 0;
    });

  const DNSName target("powerdns.com.");
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::NONE, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_answer_no_aa) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, false, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.1");
      return 1;
    });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);

  /* check that the record in the answer section has not been cached */
  const ComboAddress who;
  vector<DNSRecord> cached;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  BOOST_REQUIRE_EQUAL(t_RC->get(now, target, QType(QType::A), false, &cached, who, &signatures), -1);
}

BOOST_AUTO_TEST_CASE(test_special_types) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* {A,I}XFR, RRSIG and NSEC3 should be rejected right away */
  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      cerr<<"asyncresolve called to ask "<<ip.toStringWithPort()<<" about "<<domain.toString()<<" / "<<QType(type).getName()<<" over "<<(doTCP ? "TCP" : "UDP")<<" (rd: "<<sendRDQuery<<", EDNS0 level: "<<EDNS0Level<<")"<<endl;
      queriesCount++;
      return 0;
    });

  const DNSName target("powerdns.com.");
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::AXFR), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  res = sr->beginResolve(target, QType(QType::IXFR), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  res = sr->beginResolve(target, QType(QType::RRSIG), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  res = sr->beginResolve(target, QType(QType::NSEC3), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_special_names) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* special names should be handled internally */

  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("1.0.0.127.in-addr.arpa."), QType(QType::PTR), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("1.0.0.127.in-addr.arpa."), QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."), QType(QType::PTR), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."), QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("localhost."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toString(), "127.0.0.1");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("localhost."), QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::AAAA);
  BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(ret[0])->getCA().toString(), "::1");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("localhost."), QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& rec : ret) {
    BOOST_REQUIRE((rec.d_type == QType::A) || rec.d_type == QType::AAAA);
    if (rec.d_type == QType::A) {
      BOOST_CHECK_EQUAL(getRR<ARecordContent>(rec)->getCA().toString(), "127.0.0.1");
    }
    else {
      BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(rec)->getCA().toString(), "::1");
    }
  }
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("version.bind."), QType(QType::TXT), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("version.bind."), QType(QType::ANY), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("version.pdns."), QType(QType::TXT), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("version.pdns."), QType(QType::ANY), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("id.server."), QType(QType::TXT), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests Server ID\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("id.server."), QType(QType::ANY), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests Server ID\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_nameserver_ipv4_rpz) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, false, true, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  DNSFilterEngine::Policy pol;
  pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
  std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName("Unit test policy 0");
  zone->addNSIPTrigger(Netmask(ns, 32), std::move(pol));
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.addZone(zone);
  g_luaconfs.setState(luaconfsCopy);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -2);
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_nameserver_ipv6_rpz) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("[2001:DB8::42]:53");

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  DNSFilterEngine::Policy pol;
  pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
  std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName("Unit test policy 0");
  zone->addNSIPTrigger(Netmask(ns, 128), std::move(pol));
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.addZone(zone);
  g_luaconfs.setState(luaconfsCopy);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -2);
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_nameserver_name_rpz) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const DNSName nsName("ns1.powerdns.com.");

  sr->setAsyncCallback([target,ns,nsName](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, nsName.toString(), DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, nsName, QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  DNSFilterEngine::Policy pol;
  pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
  std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName("Unit test policy 0");
  zone->addNSTrigger(nsName, std::move(pol));
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.addZone(zone);
  g_luaconfs.setState(luaconfsCopy);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -2);
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_nameserver_name_rpz_disabled) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const DNSName nsName("ns1.powerdns.com.");

  sr->setAsyncCallback([target,ns,nsName](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::NS, nsName.toString(), DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, nsName, QType::A, ns.toString(), DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ns) {

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  DNSFilterEngine::Policy pol;
  pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
  std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setName("Unit test policy 0");
  zone->addNSIPTrigger(Netmask(ns, 128), DNSFilterEngine::Policy(pol));
  zone->addNSTrigger(nsName, std::move(pol));
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.addZone(zone);
  g_luaconfs.setState(luaconfsCopy);

  /* RPZ is disabled for this query, we should not be blocked */
  sr->setWantsRPZ(false);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_nord) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = false;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[target] = ad;

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (ip == forwardedNS) {
        BOOST_CHECK_EQUAL(sendRDQuery, false);

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  /* simulate a no-RD query */
  sr->setCacheOnly();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_rd) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  size_t queriesCount = 0;
  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[target] = ad;

  sr->setAsyncCallback([forwardedNS, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (ip == forwardedNS) {
        BOOST_CHECK_EQUAL(sendRDQuery, true);

        /* set AA=0, we are a recursor */
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 1);

  /* now make sure we can resolve from the cache (see #6340
     where the entries were added to the cache but not retrieved,
     because the recursor doesn't set the AA bit and we require
     it. We fixed it by not requiring the AA bit for forward-recurse
     answers. */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_nord) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[target] = ad;

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (ip == forwardedNS) {
        BOOST_CHECK_EQUAL(sendRDQuery, false);

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  /* simulate a no-RD query */
  sr->setCacheOnly();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[target] = ad;

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      if (ip == forwardedNS) {
        BOOST_CHECK_EQUAL(sendRDQuery, true);

        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd_dnssec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* signed */
  const DNSName target("test.");
  /* unsigned */
  const DNSName cnameTarget("cname.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  const ComboAddress forwardedNS("192.0.2.42:53");
  size_t queriesCount = 0;

  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[g_rootdnsname] = ad;

  sr->setAsyncCallback([target,cnameTarget,keys,forwardedNS,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      BOOST_CHECK_EQUAL(sendRDQuery, true);

      if (ip != forwardedNS) {
        return 0;
      }

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys);
      }

      if (domain == target && type == QType::A) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, target, QType::CNAME, cnameTarget.toString());
        addRRSIG(keys, res->d_records, domain, 300);
        addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");

        return 1;
      }
      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 5);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 5);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd_dnssec_bogus) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  /* signed */
  const DNSName target("test.");
  /* signed */
  const DNSName cnameTarget("cname.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(cnameTarget, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  const ComboAddress forwardedNS("192.0.2.42:53");
  size_t queriesCount = 0;

  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[g_rootdnsname] = ad;

  sr->setAsyncCallback([target,cnameTarget,keys,forwardedNS,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      BOOST_CHECK_EQUAL(sendRDQuery, true);

      if (ip != forwardedNS) {
        return 0;
      }

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys);
      }

      if (domain == target && type == QType::A) {

        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, target, QType::CNAME, cnameTarget.toString());
        addRRSIG(keys, res->d_records, domain, 300);
        addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
        /* no RRSIG in a signed zone, Bogus ! */

        return 1;
      }
      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 5);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 5);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd_dnssec_nodata_bogus) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  const ComboAddress forwardedNS("192.0.2.42:53");
  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[g_rootdnsname] = ad;

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,forwardedNS,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      BOOST_CHECK_EQUAL(sendRDQuery, true);

      if (ip != forwardedNS) {
        return 0;
      }

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }
      else {

        setLWResult(res, 0, false, false, true);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 0);
  /* com|NS, powerdns.com|NS, powerdns.com|A */
  BOOST_CHECK_EQUAL(queriesCount, 3);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 0);
  /* we don't store empty results */
  BOOST_CHECK_EQUAL(queriesCount, 4);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_oob) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("test.xx.");
  const ComboAddress targetAddr("127.0.0.1");
  const DNSName authZone("test.xx");

  SyncRes::AuthDomain ad;
  DNSRecord dr;

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::A;
  dr.d_ttl = 1800;
  dr.d_content = std::make_shared<ARecordContent>(targetAddr);
  ad.d_records.insert(dr);

  (*SyncRes::t_sstorage.domainmap)[authZone] = ad;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
        queriesCount++;
        return 0;
      });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);

  /* a second time, to check that the OOB flag is set when the query cache is used */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);

  /* a third time, to check that the validation is disabled when the OOB flag is set */
  ret.clear();
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_oob_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("cname.test.xx.");
  const DNSName targetCname("cname-target.test.xx.");
  const ComboAddress targetCnameAddr("127.0.0.1");
  const DNSName authZone("test.xx");

  SyncRes::AuthDomain ad;
  DNSRecord dr;

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::CNAME;
  dr.d_ttl = 1800;
  dr.d_content = std::make_shared<CNAMERecordContent>(targetCname);
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = targetCname;
  dr.d_type = QType::A;
  dr.d_ttl = 1800;
  dr.d_content = std::make_shared<ARecordContent>(targetCnameAddr);
  ad.d_records.insert(dr);

  (*SyncRes::t_sstorage.domainmap)[authZone] = ad;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
        queriesCount++;
        return 0;
      });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);

  /* a second time, to check that the OOB flag is set when the query cache is used */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);

  /* a third time, to check that the validation is disabled when the OOB flag is set */
  ret.clear();
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0);
  BOOST_CHECK(sr->wasOutOfBand());
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
}

BOOST_AUTO_TEST_CASE(test_auth_zone) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("powerdns.com.");
  const ComboAddress addr("192.0.2.5");

  SyncRes::AuthDomain ad;
  ad.d_name = target;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<ARecordContent>(addr);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[target] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return 1;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_cname_lead_to_oob) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("powerdns.com.");
  const DNSName authZone("internal.powerdns.com.");
  const ComboAddress addr("192.0.2.5");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<ARecordContent>(addr);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount,target,authZone](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (domain == target) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::CNAME, authZone.toString(), DNSResourceRecord::ANSWER, 3600);
        return 1;
      }

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(getRR<CNAMERecordContent>(ret[0])->getTarget().toString(), authZone.toString());
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[1])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_oob_lead_to_outgoing_queryb) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("powerdns.com.");
  const DNSName externalCNAME("www.open-xchange.com.");
  const ComboAddress addr("192.0.2.5");

  SyncRes::AuthDomain ad;
  ad.d_name = target;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::CNAME;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<CNAMERecordContent>(externalCNAME);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[target] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount,externalCNAME,addr](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (domain == externalCNAME) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, externalCNAME, QType::A, addr.toString(), DNSResourceRecord::ANSWER, 3600);
        return 1;
      }

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(getRR<CNAMERecordContent>(ret[0])->getTarget().toString(), externalCNAME.toString());
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[1])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_nodata) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("nodata.powerdns.com.");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<ARecordContent>(ComboAddress("192.0.2.1"));
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_nx) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("nx.powerdns.com.");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("powerdns.com.");
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_delegation) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true, false);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("www.test.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.2");
  const DNSName ns("ns1.test.powerdns.com.");
  const ComboAddress nsAddr("192.0.2.1");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("test.powerdns.com.");
  dr.d_type = QType::NS;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<NSRecordContent>(ns);
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = ns;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<ARecordContent>(nsAddr);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  testkeysset_t keys;
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::RSASHA512, DNSSECKeeper::SHA384, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  sr->setAsyncCallback([&queriesCount,target,targetAddr,nsAddr,authZone,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys, domain == authZone);
      }

      if (ip == ComboAddress(nsAddr.toString(), 53) && domain == target) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        return 1;
      }

      return 0;
  });

  sr->setDNSSECValidationRequested(true);
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 4);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_delegation_point) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("test.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.2");
  const DNSName ns("ns1.test.powerdns.com.");
  const ComboAddress nsAddr("192.0.2.1");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("test.powerdns.com.");
  dr.d_type = QType::NS;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<NSRecordContent>(ns);
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = ns;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<ARecordContent>(nsAddr);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount,nsAddr,target,targetAddr](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (ip == ComboAddress(nsAddr.toString(), 53) && domain == target) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        return 1;
      }

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_wildcard) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("test.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.2");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("*.powerdns.com.");
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<ARecordContent>(targetAddr);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_wildcard_nodata) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("test.powerdns.com.");
  const ComboAddress targetAddr("192.0.2.2");
  const DNSName authZone("powerdns.com");

  SyncRes::AuthDomain ad;
  ad.d_name = authZone;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = DNSName("*.powerdns.com.");
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<ARecordContent>(targetAddr);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[authZone] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::SOA);
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_auth_zone_cache_only) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("powerdns.com.");
  const ComboAddress addr("192.0.2.5");

  SyncRes::AuthDomain ad;
  ad.d_name = target;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::SOA;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<SOARecordContent>("pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = target;
  dr.d_type = QType::A;
  dr.d_ttl = 3600;
  dr.d_content = std::make_shared<ARecordContent>(addr);
  ad.d_records.insert(dr);

  auto map = std::make_shared<SyncRes::domainmap_t>();
  (*map)[target] = ad;
  SyncRes::setDomainMap(map);

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;
      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.42");
      return 1;
  });

  /* simulate a no-RD query */
  sr->setCacheOnly();

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toString(), addr.toString());
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig) {
  init();

  auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(DNSSECKeeper::ECDSA256));
  dcke->create(dcke->getBits());
  // cerr<<dcke->convertToISC()<<endl;
  DNSSECPrivateKey dpk;
  dpk.d_flags = 256;
  dpk.setKey(dcke);

  std::vector<std::shared_ptr<DNSRecordContent> > recordcontents;
  recordcontents.push_back(getRecordContent(QType::A, "192.0.2.1"));

  DNSName qname("powerdns.com.");

  time_t now = time(nullptr);
  RRSIGRecordContent rrc;
  /* this RRSIG is valid for the current second only */
  computeRRSIG(dpk, qname, qname, QType::A, 600, 0, rrc, recordcontents, boost::none, now);

  skeyset_t keyset;
  keyset.insert(std::make_shared<DNSKEYRecordContent>(dpk.getDNSKEY()));

  std::vector<std::shared_ptr<RRSIGRecordContent> > sigs;
  sigs.push_back(std::make_shared<RRSIGRecordContent>(rrc));

  BOOST_CHECK(validateWithKeySet(now, qname, recordcontents, sigs, keyset));
}

BOOST_AUTO_TEST_CASE(test_dnssec_root_validation_csk) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
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

        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_dnssec_root_validation_ksk_zsk) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t zskeys;
  testkeysset_t kskeys;

  /* Generate key material for "." */
  auto dckeZ = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(DNSSECKeeper::ECDSA256));
  dckeZ->create(dckeZ->getBits());
  DNSSECPrivateKey ksk;
  ksk.d_flags = 257;
  ksk.setKey(dckeZ);
  DSRecordContent kskds = makeDSFromDNSKey(target, ksk.getDNSKEY(), DNSSECKeeper::SHA256);

  auto dckeK = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(DNSSECKeeper::ECDSA256));
  dckeK->create(dckeK->getBits());
  DNSSECPrivateKey zsk;
  zsk.d_flags = 256;
  zsk.setKey(dckeK);
  DSRecordContent zskds = makeDSFromDNSKey(target, zsk.getDNSKEY(), DNSSECKeeper::SHA256);

  kskeys[target] = std::pair<DNSSECPrivateKey,DSRecordContent>(ksk, kskds);
  zskeys[target] = std::pair<DNSSECPrivateKey,DSRecordContent>(zsk, zskds);

  /* Set the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(kskds);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,zskeys,kskeys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (domain == target && type == QType::NS) {

        setLWResult(res, 0, true, false, true);
        char addr[] = "a.root-servers.net.";
        for (char idx = 'a'; idx <= 'm'; idx++) {
          addr[0] = idx;
          addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
        }

        addRRSIG(zskeys, res->d_records, domain, 300);

        addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else if (domain == target && type == QType::DNSKEY) {

        setLWResult(res, 0, true, false, true);

        addDNSKEY(kskeys, domain, 300, res->d_records);
        addDNSKEY(zskeys, domain, 300, res->d_records);
        addRRSIG(kskeys, res->d_records, domain, 300);

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_no_dnskey) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
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
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_dnskey_doesnt_match_ds) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t dskeys;
  testkeysset_t keys;

  /* Generate key material for "." */
  auto dckeDS = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(DNSSECKeeper::ECDSA256));
  dckeDS->create(dckeDS->getBits());
  DNSSECPrivateKey dskey;
  dskey.d_flags = 257;
  dskey.setKey(dckeDS);
  DSRecordContent drc = makeDSFromDNSKey(target, dskey.getDNSKEY(), DNSSECKeeper::SHA256);

  auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(DNSSECKeeper::ECDSA256));
  dcke->create(dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.d_flags = 256;
  dpk.setKey(dcke);
  DSRecordContent uselessdrc = makeDSFromDNSKey(target, dpk.getDNSKEY(), DNSSECKeeper::SHA256);

  dskeys[target] = std::pair<DNSSECPrivateKey,DSRecordContent>(dskey, drc);
  keys[target] = std::pair<DNSSECPrivateKey,DSRecordContent>(dpk, uselessdrc);

  /* Set the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(drc);
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

        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_rrsig_signed_with_unknown_dnskey) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;
  testkeysset_t rrsigkeys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  auto dckeRRSIG = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(DNSSECKeeper::ECDSA256));
  dckeRRSIG->create(dckeRRSIG->getBits());
  DNSSECPrivateKey rrsigkey;
  rrsigkey.d_flags = 257;
  rrsigkey.setKey(dckeRRSIG);
  DSRecordContent rrsigds = makeDSFromDNSKey(target, rrsigkey.getDNSKEY(), DNSSECKeeper::SHA256);

  rrsigkeys[target] = std::pair<DNSSECPrivateKey,DSRecordContent>(rrsigkey, rrsigds);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys,rrsigkeys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (domain == target && type == QType::NS) {

        setLWResult(res, 0, true, false, true);
        char addr[] = "a.root-servers.net.";
        for (char idx = 'a'; idx <= 'm'; idx++) {
          addr[0] = idx;
          addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
        }

        addRRSIG(rrsigkeys, res->d_records, domain, 300);

        addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else if (domain == target && type == QType::DNSKEY) {

        setLWResult(res, 0, true, false, true);

        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(rrsigkeys, res->d_records, domain, 300);

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_no_rrsig) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (domain == target && type == QType::NS) {

        setLWResult(res, 0, true, false, true);
        char addr[] = "a.root-servers.net.";
        for (char idx = 'a'; idx <= 'm'; idx++) {
          addr[0] = idx;
          addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 86400);
        }

        /* No RRSIG */

        addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else if (domain == target && type == QType::DNSKEY) {

        setLWResult(res, 0, true, false, true);

        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);

        return 1;
      }

      return 0;
    });

  SyncRes::s_maxcachettl = 86400;
  SyncRes::s_maxbogusttl = 3600;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  /* 13 NS + 0 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 13);
  /* no RRSIG so no query for DNSKEYs */
  BOOST_CHECK_EQUAL(queriesCount, 1);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 13);
  /* check that we capped the TTL to max-cache-bogus-ttl */
  for (const auto& record : ret) {
    BOOST_CHECK_LE(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_unknown_ds_algorithm) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  /* Generate key material for "." */
  auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(DNSSECKeeper::ECDSA256));
  dcke->create(dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.d_flags = 256;
  dpk.setKey(dcke);
  /* Fake algorithm number (private) */
  dpk.d_algorithm = 253;

  DSRecordContent drc = makeDSFromDNSKey(target, dpk.getDNSKEY(), DNSSECKeeper::SHA256);
  keys[target] = std::pair<DNSSECPrivateKey,DSRecordContent>(dpk, drc);
  /* Fake algorithm number (private) */
  drc.d_algorithm = 253;

  /* Set the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(drc);
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

        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  /* no supported DS so no query for DNSKEYs */
  BOOST_CHECK_EQUAL(queriesCount, 1);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_unknown_ds_digest) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  /* Generate key material for "." */
  auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(DNSSECKeeper::ECDSA256));
  dcke->create(dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.d_flags = 256;
  dpk.setKey(dcke);
  DSRecordContent drc = makeDSFromDNSKey(target, dpk.getDNSKEY(), DNSSECKeeper::SHA256);
  /* Fake digest number (reserved) */
  drc.d_digesttype = 0;

  keys[target] = std::pair<DNSSECPrivateKey, DSRecordContent>(dpk, drc);

  /* Set the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  luaconfsCopy.dsAnchors[g_rootdnsname].insert(drc);
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

        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  /* no supported DS so no query for DNSKEYs */
  BOOST_CHECK_EQUAL(queriesCount, 1);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_bad_sig) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::RSASHA512, DNSSECKeeper::SHA384, keys, luaconfsCopy.dsAnchors);

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

        addRRSIG(keys, res->d_records, domain, 300, true);

        addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else if (domain == target && type == QType::DNSKEY) {

        setLWResult(res, 0, true, false, true);

        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_bad_algo) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::RSASHA512, DNSSECKeeper::SHA384, keys, luaconfsCopy.dsAnchors);

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

        /* FORCE WRONG ALGO */
        addRRSIG(keys, res->d_records, domain, 300, false, DNSSECKeeper::RSASHA256);

        addRecordToLW(res, "a.root-servers.net.", QType::A, "198.41.0.4", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.root-servers.net.", QType::AAAA, "2001:503:ba3e::2:30", DNSResourceRecord::ADDITIONAL, 3600);

        return 1;
      } else if (domain == target && type == QType::DNSKEY) {

        setLWResult(res, 0, true, false, true);

        addDNSKEY(keys, domain, 300, res->d_records);
        addRRSIG(keys, res->d_records, domain, 300);

        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  /* 13 NS + 1 RRSIG */
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_unsigned_ds) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::RSASHA512, DNSSECKeeper::SHA384, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys) == 0) {
          return 0;
        }

        if (type == QType::DS && domain == target) {
          /* remove the last record, which is the DS's RRSIG */
          res->d_records.pop_back();
        }

        return 1;
      }

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        /* Include the DS but omit the RRSIG*/
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }

      if (ip == ComboAddress("192.0.2.1:53")) {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, auth, 300);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 4);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 4);

  /* now we ask directly for the DS */
  ret.clear();
  res = sr->beginResolve(DNSName("com."), QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 4);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_unsigned_ds_direct) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::RSASHA512, DNSSECKeeper::SHA384, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys) == 0) {
          return 0;
        }

        if (type == QType::DS && domain == target) {
          /* remove the last record, which is the DS's RRSIG */
          res->d_records.pop_back();
        }

        return 1;
      }

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.com.", DNSResourceRecord::AUTHORITY, 3600);
        /* Include the DS but omit the RRSIG*/
        addDS(DNSName("com."), 300, res->d_records, keys);
        addRecordToLW(res, "a.gtld-servers.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("com."), QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::RSASHA512, DNSSECKeeper::SHA384, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA384, DNSSECKeeper::SHA384, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 8);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 8);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 8);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 8);

  /* this time we ask for the NS that should be in the cache, to check
     the validation status */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 9);

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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 7);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 7);

  /* this time we ask for the NS that should be in the cache, to check
     the validation status */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 8);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 5);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* Should be insecure because of the NTA */
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 5);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 4);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 4);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 8);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 8);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 6);
  BOOST_CHECK_EQUAL(queriesCount, 9);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6);
  BOOST_CHECK_EQUAL(queriesCount, 9);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 9);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 9);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 6);
  BOOST_CHECK_EQUAL(queriesCount, 6);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6);
  BOOST_CHECK_EQUAL(queriesCount, 6);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 8);
  BOOST_CHECK_EQUAL(queriesCount, 6);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8);
  BOOST_CHECK_EQUAL(queriesCount, 6);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 8);
  BOOST_CHECK_EQUAL(queriesCount, 6);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 8);
  BOOST_CHECK_EQUAL(queriesCount, 6);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 6);
  BOOST_CHECK_EQUAL(queriesCount, 10);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6);
  BOOST_CHECK_EQUAL(queriesCount, 10);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 6);
  BOOST_CHECK_EQUAL(queriesCount, 9);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 6);
  BOOST_CHECK_EQUAL(queriesCount, 9);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 9);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 9);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
}

BOOST_AUTO_TEST_CASE(test_dnssec_no_ds_on_referral_secure) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("www.powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 9);
  BOOST_CHECK_EQUAL(dsQueriesCount, 3);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 9);
  BOOST_CHECK_EQUAL(dsQueriesCount, 3);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("www.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS) {
        DNSName auth(domain);
        auth.chopOff();

        setLWResult(res, 0, true, false, true);
        if (domain == target) {
          addRecordToLW(res, domain, QType::SOA, "ns1.powerdns.com. blah. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          addRRSIG(keys, res->d_records, target, 300);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 9);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 9);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("www.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("sub.www.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS) {
        DNSName auth(domain);
        auth.chopOff();

        setLWResult(res, 0, true, false, true);
        if (domain == target) {
          addRecordToLW(res, domain, QType::SOA, "ns1.powerdns.com. blah. 2017032800 1800 900 604800 86400", DNSResourceRecord::AUTHORITY, 86400);
          addRRSIG(keys, res->d_records, target, 300);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 9);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 9);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 7);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 7);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_CHECK_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 8);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 8);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_CHECK_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 8);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 8);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  /* 4 NS: com at ., com at com, powerdns.com at com, powerdns.com at powerdns.com
     4 DNSKEY: ., com (not for powerdns.com because DS denial in referral)
     1 query for A */
  BOOST_CHECK_EQUAL(queriesCount, 7);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::DS || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::DS || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::SOA || record.d_type == QType::NSEC || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::SOA || record.d_type == QType::NSEC || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 9);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 9);
}

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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  /* No key material for .com */
  /* But TA for sub.powerdns.com. */
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 8);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 8);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

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
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  /* 4 NS (com from root, com from com, powerdns.com from com,
     powerdns.com from powerdns.com)
     2 DNSKEY (. and com., none for powerdns.com because no DS)
     1 query for A
  */
  BOOST_CHECK_EQUAL(queriesCount, 7);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 7);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 11);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 11);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 11);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 11);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 11);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 11);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 11);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 11);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 11);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 11);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 12);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 12);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(DNSName("power-dns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_CHECK_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 10);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_CHECK_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 10);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  /* No key material for .com */
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 5);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  /* No key material for .com */
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 4);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 4);
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
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 1);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 14);
  BOOST_CHECK_EQUAL(queriesCount, 1);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 13);
  BOOST_CHECK_EQUAL(queriesCount, 1);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 13);
  BOOST_CHECK_EQUAL(queriesCount, 1);
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
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
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
  BOOST_REQUIRE_EQUAL(ret.size(), 0);
  /* com|NS, powerdns.com|NS, powerdns.com|A */
  BOOST_CHECK_EQUAL(queriesCount, 3);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 0);
  /* we don't store empty results */
  BOOST_CHECK_EQUAL(queriesCount, 4);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_nowrap) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    No wrap test case:
    a.example.org. -> d.example.org. denies the existence of b.example.org.
   */
  addNSECRecordToLW(DNSName("a.example.org."), DNSName("d.example.org"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a.example.org."), QType::NSEC)] = pair;

  /* add wildcard denial */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName("example.org."), DNSName("+.example.org"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(DNSName("example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("d.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_wrap_case_1) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    Wrap case 1 test case:
    z.example.org. -> b.example.org. denies the existence of a.example.org.
   */
  addNSECRecordToLW(DNSName("z.example.org."), DNSName("b.example.org"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("z.example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("a.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("d.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_wrap_case_2) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    Wrap case 2 test case:
    y.example.org. -> a.example.org. denies the existence of z.example.org.
   */
  addNSECRecordToLW(DNSName("y.example.org."), DNSName("a.example.org"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("y.example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("z.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("d.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_only_one_nsec) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    Only one NSEC in the whole zone test case:
    a.example.org. -> a.example.org. denies the existence of b.example.org.
   */
  addNSECRecordToLW(DNSName("a.example.org."), DNSName("a.example.org"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a.example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("a.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_root_nxd_denial) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    The RRSIG from "." denies the existence of anything between a. and c.,
    including b.
  */
  addNSECRecordToLW(DNSName("a."), DNSName("c."), { QType::NS }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a."), QType::NSEC)] = pair;

  /* add wildcard denial */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName("."), DNSName("+"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(DNSName("."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);
}

BOOST_AUTO_TEST_CASE(test_nsec_ancestor_nxqtype_denial) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    The RRSIG from "." denies the existence of any type except NS at a.
    However since it's an ancestor delegation NSEC (NS bit set, SOA bit clear,
    signer field that is shorter than the owner name of the NSEC RR) it can't
    be used to deny anything except the whole name or a DS.
  */
  addNSECRecordToLW(DNSName("a."), DNSName("b."), { QType::NS }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a."), QType::NSEC)] = pair;

  /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
     Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
     nonexistence of any RRs below that zone cut, which include all RRs at
     that (original) owner name other than DS RRs, and all RRs below that
     owner name regardless of type.
  */

  dState denialState = getDenial(denialMap, DNSName("a."), QType::A, false, false);
  /* no data means the qname/qtype is not denied, because an ancestor
     delegation NSEC can only deny the DS */
  BOOST_CHECK_EQUAL(denialState, NODATA);

  /* it can not be used to deny any RRs below that owner name either */
  denialState = getDenial(denialMap, DNSName("sub.a."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NODATA);

  denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, NXQTYPE);
}

BOOST_AUTO_TEST_CASE(test_nsec_insecure_delegation_denial) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
   * RFC 5155 section 8.9:
   * If there is an NSEC3 RR present in the response that matches the
   * delegation name, then the validator MUST ensure that the NS bit is
   * set and that the DS bit is not set in the Type Bit Maps field of the
   * NSEC3 RR.
   */
  /*
    The RRSIG from "." denies the existence of any type at a.
    NS should be set if it was proving an insecure delegation, let's check that
    we correctly detect that it's not.
  */
  addNSECRecordToLW(DNSName("a."), DNSName("b."), { }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a."), QType::NSEC)] = pair;

  /* Insecure because the NS is not set, so while it does
     denies the DS, it can't prove an insecure delegation */
  dState denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_nxqtype_cname) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("a.c.powerdns.com."), { QType::CNAME }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a.powerdns.com."), QType::NSEC)] = pair;

  /* this NSEC is not valid to deny a.powerdns.com|A since it states that a CNAME exists */
  dState denialState = getDenial(denialMap, DNSName("a.powerdns.com."), QType::A, true, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec3_nxqtype_cname) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  addNSEC3UnhashedRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), "whatever", { QType::CNAME }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  /* this NSEC3 is not valid to deny a.powerdns.com|A since it states that a CNAME exists */
  dState denialState = getDenial(denialMap, DNSName("a.powerdns.com."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_nxdomain_denial_missing_wildcard) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("d.powerdns.com"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a.powerdns.com."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec3_nxdomain_denial_missing_wildcard) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  addNSEC3NarrowRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* Add NSEC3 for the closest encloser */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_ent_denial) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("a.c.powerdns.com."), { QType::A }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a.powerdns.com."), QType::NSEC)] = pair;

  /* this NSEC is valid to prove a NXQTYPE at c.powerdns.com because it proves that
     it is an ENT */
  dState denialState = getDenial(denialMap, DNSName("c.powerdns.com."), QType::AAAA, true, true);
  BOOST_CHECK_EQUAL(denialState, NXQTYPE);

  /* this NSEC is not valid to prove a NXQTYPE at b.powerdns.com,
     it could prove a NXDOMAIN if it had an additional wildcard denial */
  denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::AAAA, true, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);

  /* this NSEC is not valid to prove a NXQTYPE for QType::A at a.c.powerdns.com either */
  denialState = getDenial(denialMap, DNSName("a.c.powerdns.com."), QType::A, true, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);

  /* if we add the wildcard denial proof, we should get a NXDOMAIN proof for b.powerdns.com */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName(").powerdns.com."), DNSName("+.powerdns.com."), { }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();
  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(DNSName(").powerdns.com."), QType::NSEC)] = pair;

  denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::A, true, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);
}

BOOST_AUTO_TEST_CASE(test_nsec3_ancestor_nxqtype_denial) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    The RRSIG from "." denies the existence of any type except NS at a.
    However since it's an ancestor delegation NSEC (NS bit set, SOA bit clear,
    signer field that is shorter than the owner name of the NSEC RR) it can't
    be used to deny anything except the whole name or a DS.
  */
  addNSEC3UnhashedRecordToLW(DNSName("a."), DNSName("."), "whatever", { QType::NS }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
     Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
     nonexistence of any RRs below that zone cut, which include all RRs at
     that (original) owner name other than DS RRs, and all RRs below that
     owner name regardless of type.
  */

  dState denialState = getDenial(denialMap, DNSName("a."), QType::A, false, true);
  /* no data means the qname/qtype is not denied, because an ancestor
     delegation NSEC3 can only deny the DS */
  BOOST_CHECK_EQUAL(denialState, NODATA);

  denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, NXQTYPE);

  /* it can not be used to deny any RRs below that owner name either */
  /* Add NSEC3 for the next closer */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3NarrowRecordToLW(DNSName("sub.a."), DNSName("."), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC3 }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* add wildcard denial */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3NarrowRecordToLW(DNSName("*.a."), DNSName("."), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC3 }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  denialState = getDenial(denialMap, DNSName("sub.a."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec3_denial_too_many_iterations) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /* adding a NSEC3 with more iterations that we support */
  addNSEC3UnhashedRecordToLW(DNSName("a."), DNSName("."), "whatever", { QType::AAAA }, 600, records, g_maxNSEC3Iterations + 100);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  dState denialState = getDenial(denialMap, DNSName("a."), QType::A, false, true);
  /* since we refuse to compute more than g_maxNSEC3Iterations iterations, it should be Insecure */
  BOOST_CHECK_EQUAL(denialState, INSECURE);
}

BOOST_AUTO_TEST_CASE(test_nsec3_insecure_delegation_denial) {
  init();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
   * RFC 5155 section 8.9:
   * If there is an NSEC3 RR present in the response that matches the
   * delegation name, then the validator MUST ensure that the NS bit is
   * set and that the DS bit is not set in the Type Bit Maps field of the
   * NSEC3 RR.
   */
  /*
    The RRSIG from "." denies the existence of any type at a.
    NS should be set if it was proving an insecure delegation, let's check that
    we correctly detect that it's not.
  */
  addNSEC3UnhashedRecordToLW(DNSName("a."), DNSName("."), "whatever", { }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  /* Insecure because the NS is not set, so while it does
     denies the DS, it can't prove an insecure delegation */
  dState denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_negcache_validity) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([target,&queriesCount,keys,fixedNow](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      auth.chopOff();

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, domain, 300);
        addNSECRecordToLW(domain, DNSName("z."), { QType::NSEC, QType::RRSIG }, 600, res->d_records);
        addRRSIG(keys, res->d_records, domain, 1, false, boost::none, boost::none, fixedNow);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 4);

  /* check that the entry has not been negatively cached for longer than the RRSIG validity */
  const NegCache::NegCacheEntry* ne = nullptr;
  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_ttd, fixedNow + 1);
  BOOST_CHECK_EQUAL(ne->d_validationState, Secure);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 1);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 1);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 4);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_negcache_bogus_validity) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([target,&queriesCount,keys,fixedNow](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      auth.chopOff();

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, domain, 86400);
        addNSECRecordToLW(domain, DNSName("z."), { QType::NSEC, QType::RRSIG }, 86400, res->d_records);
        /* no RRSIG */
        return 1;
      }

      return 0;
    });

  SyncRes::s_maxnegttl = 3600;
  SyncRes::s_maxbogusttl = 360;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 4);

  /* check that the entry has been negatively cached but not longer than s_maxbogusttl */
  const NegCache::NegCacheEntry* ne = nullptr;
  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_ttd, fixedNow + SyncRes::s_maxbogusttl);
  BOOST_CHECK_EQUAL(ne->d_validationState, Bogus);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 1);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 0);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);
  BOOST_CHECK_EQUAL(queriesCount, 4);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_cache_validity) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  const time_t tnow = sr->getNow().tv_sec;

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys,tnow](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      auth.chopOff();

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, domain, 1, false, boost::none, boost::none, tnow);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 4);

  /* check that the entry has not been cached for longer than the RRSIG validity */
  const ComboAddress who;
  vector<DNSRecord> cached;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  BOOST_REQUIRE_EQUAL(t_RC->get(tnow, target, QType(QType::A), true, &cached, who, &signatures), 1);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
  BOOST_REQUIRE_EQUAL(signatures.size(), 1);
  BOOST_CHECK_EQUAL((cached[0].d_ttl - tnow), 1);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 4);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cache_secure) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Secure, after just-in-time validation.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        if (domain == target && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::A, "192.0.2.1");
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1);


  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cache_insecure) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Insecure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        if (domain == target && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::A, "192.0.2.1");
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1);


  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cache_bogus) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Bogus.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        if (domain == target && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
          /* no RRSIG */
          return 1;
        }
      }

      return 0;
    });

  SyncRes::s_maxbogusttl = 3600;

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, 86400);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1);


  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  /* check that we correctly capped the TTD for a Bogus record after
     just-in-time validation */
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3);

  ret.clear();
  /* third time also _does_ require validation, so we
     can check that the cache has been updated */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cname_cache_secure) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Secure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  const DNSName cnameTarget("cname-com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,cnameTarget,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        if (domain == target && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::CNAME, cnameTarget.toString());
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        } else if (domain == cnameTarget && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 2);


  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 5);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cname_cache_insecure) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Insecure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  const DNSName cnameTarget("cname-com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,cnameTarget,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        if (domain == target && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::CNAME, cnameTarget.toString());
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
          return 1;
        } else if (domain == cnameTarget && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1");
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 2);


  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cname_cache_bogus) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Bogus.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  const DNSName cnameTarget("cname-com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,cnameTarget,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        if (domain == target && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::CNAME, cnameTarget.toString(), DNSResourceRecord::ANSWER, 86400);
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
          /* no RRSIG */
          return 1;
        } else if (domain == cnameTarget && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
          /* no RRSIG */
          return 1;
        }
      }

      return 0;
    });

  SyncRes::s_maxbogusttl = 60;
  SyncRes::s_maxnegttl = 3600;

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, 86400);
  }
  BOOST_CHECK_EQUAL(queriesCount, 2);


  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  /* check that we correctly capped the TTD for a Bogus record after
     just-in-time validation */
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 5);

  ret.clear();
  /* and a third time to make sure that the validation status (and TTL!)
     was properly updated in the cache */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::CNAME || record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 5);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_additional_without_rrsig) {
  /*
    We get a record from a secure zone in the additional section, without
    the corresponding RRSIG. The record should not be marked as authoritative
    and should be correctly validated.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  const DNSName addTarget("nsX.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,addTarget,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (domain == addTarget) {
          DNSName auth(domain);
          /* no DS for com, auth will be . */
          auth.chopOff();
          return genericDSAndDNSKEYHandler(res, domain, auth, type, keys, false);
        }
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        if (domain == target && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::A, "192.0.2.1");
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, addTarget, QType::A, "192.0.2.42", DNSResourceRecord::ADDITIONAL);
          /* no RRSIG for the additional record */
          return 1;
        } else if (domain == addTarget && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, addTarget, QType::A, "192.0.2.42");
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  /* first query for target/A, will pick up the additional record as non-auth / unvalidated */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_CHECK_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::RRSIG || record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1);

  ret.clear();
  /* ask for the additional record directly, we should not use
     the non-auth one and issue a new query, properly validated */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(addTarget, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_CHECK_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::RRSIG || record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 5);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_negcache_secure) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is negatively cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Secure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      auth.chopOff();

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, domain, 300);
        addNSECRecordToLW(domain, DNSName("z."), { QType::NSEC, QType::RRSIG }, 600, res->d_records);
        addRRSIG(keys, res->d_records, domain, 1);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 1);
  /* check that the entry has not been negatively cached */
  const NegCache::NegCacheEntry* ne = nullptr;
  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_validationState, Indeterminate);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 1);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 1);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 4);
  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_validationState, Secure);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 1);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_negcache_secure_ds) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is negatively cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Secure.
    The difference with test_dnssec_validation_from_negcache_secure is
    that have one more level here, so we are going to look for the proof
    that the DS does not exist for the last level. Since there is no cut,
    we should accept the fact that the NSEC denies DS and NS both.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("www.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        if (domain == target) {
          /* there is no cut */
          return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
        }
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys);
      }

      return 0;
    });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 1);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::DS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 4);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_negcache_insecure) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is negatively cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Insecure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      auth.chopOff();

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 1);
  /* check that the entry has not been negatively cached */
  const NegCache::NegCacheEntry* ne = nullptr;
  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_validationState, Indeterminate);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 0);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 0);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 0);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 1);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_validationState, Insecure);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 0);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 0);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_negcache_bogus) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is negatively cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Bogus.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      auth.chopOff();

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, domain, 86400);
        /* no denial */
        return 1;
      }

      return 0;
    });

  SyncRes::s_maxbogusttl = 60;
  SyncRes::s_maxnegttl = 3600;
  const auto now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    if (record.d_type == QType::SOA) {
      BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxnegttl);
    }
  }
  BOOST_CHECK_EQUAL(queriesCount, 1);
  const NegCache::NegCacheEntry* ne = nullptr;
  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_validationState, Indeterminate);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 1);
  BOOST_CHECK_EQUAL(ne->d_ttd, now + SyncRes::s_maxnegttl);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 0);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 0);

  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_validationState, Bogus);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 1);
  BOOST_CHECK_EQUAL(ne->d_ttd, now + SyncRes::s_maxbogusttl);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 0);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 0);

  ret.clear();
  /* third one _does_ not require validation, we just check that
     the cache (status and TTL) has been correctly updated */
  sr->setDNSSECValidationRequested(false);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  for (const auto& record : ret) {
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 4);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_validationState, Bogus);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 1);
  BOOST_CHECK_EQUAL(ne->d_ttd, now + SyncRes::s_maxbogusttl);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 0);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_lowercase_outgoing) {
  g_lowercaseOutgoing = true;
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  vector<DNSName> sentOutQnames;

  const DNSName target("WWW.POWERDNS.COM");
  const DNSName cname("WWW.PowerDNS.org");

  sr->setAsyncCallback([target, cname, &sentOutQnames](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      sentOutQnames.push_back(domain);

      if (isRootServer(ip)) {
        if (domain == target) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        if (domain == cname) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, "powerdns.org.", QType::NS, "pdns-public-ns1.powerdns.org.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "pdns-public-ns1.powerdns.org.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::CNAME, cname.toString());
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == cname) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "127.0.0.1");
          return 1;
        }
      }
      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);

  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(ret[0].d_content->getZoneRepresentation(), cname.toString());

  BOOST_REQUIRE_EQUAL(sentOutQnames.size(), 4);
  BOOST_CHECK_EQUAL(sentOutQnames[0].toString(), target.makeLowerCase().toString());
  BOOST_CHECK_EQUAL(sentOutQnames[1].toString(), target.makeLowerCase().toString());
  BOOST_CHECK_EQUAL(sentOutQnames[2].toString(), cname.makeLowerCase().toString());
  BOOST_CHECK_EQUAL(sentOutQnames[3].toString(), cname.makeLowerCase().toString());

  g_lowercaseOutgoing = false;
}

BOOST_AUTO_TEST_CASE(test_getDSRecords_multialgo) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys, keys2;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  // As testkeysset_t only contains one DSRecordContent, create another one with a different hash algo
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA1, keys2);
  // But add the existing root key otherwise no RRSIG can be created
  auto rootkey = keys.find(g_rootdnsname);
  keys2.insert(*rootkey);

  sr->setAsyncCallback([target, keys, keys2](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      DNSName auth = domain;
      auth.chopOff();
      if (type == QType::DS || type == QType::DNSKEY) {
        if (domain == target) {
          if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys2) != 1) {
            return 0;
          }
        }
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      return 0;
    });

  dsmap_t ds;
  auto state = sr->getDSRecords(target, ds, false, 0, false);
  BOOST_CHECK_EQUAL(state, Secure);
  BOOST_REQUIRE_EQUAL(ds.size(), 1);
  for (const auto& i : ds) {
    BOOST_CHECK_EQUAL(i.d_digesttype, DNSSECKeeper::SHA256);
  }
}

BOOST_AUTO_TEST_CASE(test_getDSRecords_multialgo_all_sha) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys, keys2, keys3;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  // As testkeysset_t only contains one DSRecordContent, create another one with a different hash algo
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA1, keys2);
  // But add the existing root key otherwise no RRSIG can be created
  auto rootkey = keys.find(g_rootdnsname);
  keys2.insert(*rootkey);

  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA384, keys3);
  // But add the existing root key otherwise no RRSIG can be created
  keys3.insert(*rootkey);

  sr->setAsyncCallback([target, keys, keys2, keys3](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      DNSName auth = domain;
      auth.chopOff();
      if (type == QType::DS || type == QType::DNSKEY) {
        if (domain == target) {
          if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys2) != 1) {
            return 0;
          }
          if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys3) != 1) {
            return 0;
          }
        }
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      return 0;
    });

  dsmap_t ds;
  auto state = sr->getDSRecords(target, ds, false, 0, false);
  BOOST_CHECK_EQUAL(state, Secure);
  BOOST_REQUIRE_EQUAL(ds.size(), 1);
  for (const auto& i : ds) {
    BOOST_CHECK_EQUAL(i.d_digesttype, DNSSECKeeper::SHA384);
  }
}

BOOST_AUTO_TEST_CASE(test_getDSRecords_multialgo_two_highest) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys, keys2, keys3;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  // As testkeysset_t only contains one DSRecordContent, create another one with a different hash algo
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys2);
  // But add the existing root key otherwise no RRSIG can be created
  auto rootkey = keys.find(g_rootdnsname);
  keys2.insert(*rootkey);

  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA1, keys3);
  // But add the existing root key otherwise no RRSIG can be created
  keys3.insert(*rootkey);

  sr->setAsyncCallback([target, keys, keys2, keys3](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      DNSName auth = domain;
      auth.chopOff();
      if (type == QType::DS || type == QType::DNSKEY) {
        if (domain == target) {
          if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys2) != 1) {
            return 0;
          }
          if (genericDSAndDNSKEYHandler(res, domain, auth, type, keys3) != 1) {
            return 0;
          }
        }
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      return 0;
    });

  dsmap_t ds;
  auto state = sr->getDSRecords(target, ds, false, 0, false);
  BOOST_CHECK_EQUAL(state, Secure);
  BOOST_REQUIRE_EQUAL(ds.size(), 2);
  for (const auto& i : ds) {
    BOOST_CHECK_EQUAL(i.d_digesttype, DNSSECKeeper::SHA256);
  }
}

BOOST_AUTO_TEST_CASE(test_cname_plus_authority_ns_ttl) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("cname.powerdns.com.");
  const DNSName cnameTarget("cname-target.powerdns.com");
  size_t queriesCount = 0;

  sr->setAsyncCallback([target, cnameTarget, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

       queriesCount++;

       if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, DNSName("powerdns.com"), QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 42);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      } else if (ip == ComboAddress("192.0.2.1:53")) {
         if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
          addRecordToLW(res, cnameTarget, QType::A, "192.0.2.2");
          addRecordToLW(res, DNSName("powerdns.com."), QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, DNSName("a.gtld-servers.net."), QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        else if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
        }

         return 1;
      }

      return 0;
    });

  const time_t now = sr->getNow().tv_sec;
  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[1].d_name, cnameTarget);

  /* check that the NS in authority has not replaced the one in the cache
     with auth=0 (or at least has not raised the TTL since it could otherwise
     be used to create a never-ending ghost zone even after the NS have been
     changed in the parent.
  */
  const ComboAddress who;
  vector<DNSRecord> cached;
  bool wasAuth = false;

  auto ttl = t_RC->get(now, DNSName("powerdns.com."), QType(QType::NS), false, &cached, who, nullptr, nullptr, nullptr, nullptr, &wasAuth);
  BOOST_REQUIRE_GE(ttl, 1);
  BOOST_REQUIRE_LE(ttl, 42);
  BOOST_CHECK_EQUAL(cached.size(), 1);
  BOOST_CHECK_EQUAL(wasAuth, false);

  cached.clear();

  /* Also check that the the part in additional is still not auth */
  BOOST_REQUIRE_GE(t_RC->get(now, DNSName("a.gtld-servers.net."), QType(QType::A), false, &cached, who, nullptr, nullptr, nullptr, nullptr, &wasAuth), -1);
  BOOST_CHECK_EQUAL(cached.size(), 1);
  BOOST_CHECK_EQUAL(wasAuth, false);
}

BOOST_AUTO_TEST_CASE(test_records_sanitization_general) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("sanitization.powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.1");
      /* should be scrubbed because it doesn't match the QType */
      addRecordToLW(res, domain, QType::AAAA, "2001:db8::1");
      /* should be scrubbed because the DNAME is not relevant to the qname */
      addRecordToLW(res, DNSName("not-sanitization.powerdns.com."), QType::DNAME, "not-sanitization.powerdns.net.");
      /* should be scrubbed because a MX has no reason to show up in AUTHORITY */
      addRecordToLW(res, domain, QType::MX, "10 mx.powerdns.com.", DNSResourceRecord::AUTHORITY);
      /* should be scrubbed because the SOA name is not relevant to the qname */
      addRecordToLW(res, DNSName("not-sanitization.powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY);
      /* should be scrubbed because types other than A or AAAA are not really supposed to show up in ADDITIONAL */
      addRecordToLW(res, domain, QType::TXT, "TXT", DNSResourceRecord::ADDITIONAL);
      /* should be scrubbed because it doesn't match any of the accepted names in this answer (mostly 'domain') */
      addRecordToLW(res, DNSName("powerdns.com."), QType::AAAA, "2001:db8::1", DNSResourceRecord::ADDITIONAL);
      return 1;
    });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);

  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_CHECK_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  cached.clear();
  BOOST_CHECK_LT(t_RC->get(now, target, QType(QType::AAAA), true, &cached, who), 0);
  BOOST_CHECK_EQUAL(t_RC->get(now, DNSName("not-sanitization.powerdns.com."), QType(QType::DNAME), true, &cached, who), -1);
  BOOST_CHECK_LT(t_RC->get(now, target, QType(QType::MX), true, &cached, who), 0);
  BOOST_CHECK_EQUAL(t_RC->get(now, DNSName("not-sanitization.powerdns.com."), QType(QType::SOA), true, &cached, who), -1);
  BOOST_CHECK_LT(t_RC->get(now, target, QType(QType::TXT), false, &cached, who), 0);
  BOOST_CHECK_EQUAL(t_RC->get(now, DNSName("powerdns.com."), QType(QType::AAAA), false, &cached, who), -1);
}

BOOST_AUTO_TEST_CASE(test_records_sanitization_keep_relevant_additional_aaaa) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("sanitization.powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::A, "192.0.2.1");
      addRecordToLW(res, domain, QType::AAAA, "2001:db8::1", DNSResourceRecord::ADDITIONAL);
      return 1;
    });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);

  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_CHECK_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  cached.clear();
  /* not auth since it was in the additional section */
  BOOST_CHECK_LT(t_RC->get(now, target, QType(QType::AAAA), true, &cached, who), 0);
  BOOST_CHECK_GT(t_RC->get(now, target, QType(QType::AAAA), false, &cached, who), 0);
}

BOOST_AUTO_TEST_CASE(test_records_sanitization_keep_glue) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("sanitization-glue.powerdns.com.");

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

      queriesCount++;

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns2.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::AAAA, "2001:DB8::2", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::A, "192.0.2.3", DNSResourceRecord::ADDITIONAL, 172800);
        addRecordToLW(res, "pdns-public-ns2.powerdns.com.", QType::AAAA, "2001:DB8::3", DNSResourceRecord::ADDITIONAL, 172800);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.2:53") || ip == ComboAddress("192.0.2.3:53") || ip == ComboAddress("[2001:DB8::2]:53") || ip == ComboAddress("[2001:DB8::3]:53")) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.4");
        return 1;
      }
      else {
        return 0;
      }
    });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 3);

  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_CHECK_GT(t_RC->get(now, target, QType(QType::A), true, &cached, who), 0);
  cached.clear();

  BOOST_CHECK_GT(t_RC->get(now, DNSName("com."), QType(QType::NS), false, &cached, who), 0);
  BOOST_CHECK_GT(t_RC->get(now, DNSName("a.gtld-servers.net."), QType(QType::A), false, &cached, who), 0);
  BOOST_CHECK_GT(t_RC->get(now, DNSName("a.gtld-servers.net."), QType(QType::AAAA), false, &cached, who), 0);
  BOOST_CHECK_GT(t_RC->get(now, DNSName("powerdns.com."), QType(QType::NS), false, &cached, who), 0);
  BOOST_CHECK_GT(t_RC->get(now, DNSName("pdns-public-ns1.powerdns.com."), QType(QType::A), false, &cached, who), 0);
  BOOST_CHECK_GT(t_RC->get(now, DNSName("pdns-public-ns1.powerdns.com."), QType(QType::AAAA), false, &cached, who), 0);
  BOOST_CHECK_GT(t_RC->get(now, DNSName("pdns-public-ns2.powerdns.com."), QType(QType::A), false, &cached, who), 0);
  BOOST_CHECK_GT(t_RC->get(now, DNSName("pdns-public-ns2.powerdns.com."), QType(QType::AAAA), false, &cached, who), 0);
}

BOOST_AUTO_TEST_CASE(test_records_sanitization_scrubs_ns_nxd) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("sanitization-ns-nxd.powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {

     setLWResult(res, RCode::NXDomain, true, false, true);
     addRecordToLW(res, "powerdns.com.", QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY);
     addRecordToLW(res, "powerdns.com.", QType::NS, "spoofed.ns.", DNSResourceRecord::AUTHORITY, 172800);
     addRecordToLW(res, "spoofed.ns.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
     addRecordToLW(res, "spoofed.ns.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
     return 1;
    });

  const time_t now = sr->getNow().tv_sec;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);

  const ComboAddress who;
  vector<DNSRecord> cached;
  BOOST_CHECK_GT(t_RC->get(now, DNSName("powerdns.com."), QType(QType::SOA), true, &cached, who), 0);
  cached.clear();

  BOOST_CHECK_LT(t_RC->get(now, DNSName("powerdns.com."), QType(QType::NS), false, &cached, who), 0);
  BOOST_CHECK_LT(t_RC->get(now, DNSName("spoofed.ns."), QType(QType::A), false, &cached, who), 0);
  BOOST_CHECK_LT(t_RC->get(now, DNSName("spoofed.ns."), QType(QType::AAAA), false, &cached, who), 0);
}

BOOST_AUTO_TEST_CASE(test_dname_processing) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName dnameOwner("powerdns.com");
  const DNSName dnameTarget("powerdns.net");

  const DNSName target("dname.powerdns.com.");
  const DNSName cnameTarget("dname.powerdns.net");

  const DNSName uncachedTarget("dname-uncached.powerdns.com.");
  const DNSName uncachedCNAMETarget("dname-uncached.powerdns.net.");

  const DNSName synthCNAME("cname-uncached.powerdns.com.");
  const DNSName synthCNAMETarget("cname-uncached.powerdns.net.");

  size_t queries = 0;

  sr->setAsyncCallback([dnameOwner, dnameTarget, target, cnameTarget, uncachedTarget, uncachedCNAMETarget, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queries++;

      if (isRootServer(ip)) {
        if (domain.isPartOf(dnameOwner)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameOwner, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        if (domain.isPartOf(dnameTarget)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameTarget, QType::NS, "b.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "b.gtld-servers.net.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, dnameOwner, QType::DNAME, dnameTarget.toString());
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString());
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
        }
        if (domain == uncachedCNAMETarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.3");
        }
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);

  BOOST_CHECK_EQUAL(queries, 4);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[1].d_name, target);

  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[2].d_name, cnameTarget);

  // Now check the cache
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);

  BOOST_CHECK_EQUAL(queries, 4);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[1].d_name, target);

  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[2].d_name, cnameTarget);

  // Check if we correctly return a synthesizd CNAME, should send out just 1 more query
  ret.clear();
  res = sr->beginResolve(uncachedTarget, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(queries, 5);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_REQUIRE(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[1].d_name, uncachedTarget);
  BOOST_CHECK_EQUAL(getRR<CNAMERecordContent>(ret[1])->getTarget(), uncachedCNAMETarget);

  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[2].d_name, uncachedCNAMETarget);

  // Check if we correctly return the DNAME from cache when asked
  ret.clear();
  res = sr->beginResolve(dnameOwner, QType(QType::DNAME), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(queries, 5);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  // Check if we correctly return the synthesized CNAME from cache when asked
  ret.clear();
  res = sr->beginResolve(synthCNAME, QType(QType::CNAME), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(queries, 5);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_REQUIRE(ret[1].d_type == QType::CNAME);
  BOOST_CHECK(ret[1].d_name == synthCNAME);
  BOOST_CHECK_EQUAL(getRR<CNAMERecordContent>(ret[1])->getTarget(), synthCNAMETarget);
}

BOOST_AUTO_TEST_CASE(test_dname_dnssec_secure) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();

  const DNSName dnameOwner("powerdns");
  const DNSName dnameTarget("example");

  const DNSName target("dname.powerdns");
  const DNSName cnameTarget("dname.example");

  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(dnameOwner, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  generateKeyMaterial(dnameTarget, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queries = 0;

  sr->setAsyncCallback([dnameOwner, dnameTarget, target, cnameTarget, keys, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queries++;
      /* We don't use the genericDSAndDNSKEYHandler here, as it would deny names existing at the wrong level of the tree, due to the way computeZoneCuts works
       * As such, we need to do some more work to make the answers correct.
       */

      if (isRootServer(ip)) {
        if (domain.countLabels() == 0 && type == QType::DNSKEY) { // .|DNSKEY
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
        if (domain.countLabels() == 1 && type == QType::DS) { // powerdns|DS or example|DS
          setLWResult(res, 0, true, false, true);
          addDS(domain, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
        // For the rest, delegate!
        if (domain.isPartOf(dnameOwner)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameOwner, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addDS(dnameOwner, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        if (domain.isPartOf(dnameTarget)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameTarget, QType::NS, "b.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addDS(dnameTarget, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "b.gtld-servers.net.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain.countLabels() == 1 && type == QType::DNSKEY) { // powerdns|DNSKEY
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        if (domain == target && type == QType::DS) { // dname.powerdns|DS
          return genericDSAndDNSKEYHandler(res, domain, dnameOwner, type, keys);
        }
        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, dnameOwner, QType::DNAME, dnameTarget.toString());
          addRRSIG(keys, res->d_records, dnameOwner, 300);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString()); // CNAME from a DNAME is not signed
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain.countLabels() == 1 && type == QType::DNSKEY) { // example|DNSKEY
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        if (domain == target && type == QType::DS) { // dname.example|DS
          return genericDSAndDNSKEYHandler(res, domain, dnameTarget, type, keys);
        }
        if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
          addRRSIG(keys, res->d_records, dnameTarget, 300);
        }
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 5); /* DNAME + RRSIG(DNAME) + CNAME + A + RRSIG(A) */

  BOOST_CHECK_EQUAL(queries, 11);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_REQUIRE(ret[1].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[1].d_name, dnameOwner);

  BOOST_CHECK(ret[2].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[2].d_name, target);

  BOOST_CHECK(ret[3].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[3].d_name, cnameTarget);

  BOOST_CHECK(ret[4].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[4].d_name, cnameTarget);

  // And the cache
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 5); /* DNAME + RRSIG(DNAME) + CNAME + A + RRSIG(A) */

  BOOST_CHECK_EQUAL(queries, 11);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[1].d_name, dnameOwner);

  BOOST_CHECK(ret[2].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[2].d_name, target);

  BOOST_CHECK(ret[3].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[3].d_name, cnameTarget);

  BOOST_CHECK(ret[4].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[4].d_name, cnameTarget);

}

BOOST_AUTO_TEST_CASE(test_dname_dnssec_insecure) {
  /*
   * The DNAME itself is signed, but the final A record is not
   */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();

  const DNSName dnameOwner("powerdns");
  const DNSName dnameTarget("example");

  const DNSName target("dname.powerdns");
  const DNSName cnameTarget("dname.example");

  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(dnameOwner, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queries = 0;

  sr->setAsyncCallback([dnameOwner, dnameTarget, target, cnameTarget, keys, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queries++;

      if (isRootServer(ip)) {
        if (domain.countLabels() == 0 && type == QType::DNSKEY) { // .|DNSKEY
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
        if (domain == dnameOwner && type == QType::DS) { // powerdns|DS
          setLWResult(res, 0, true, false, true);
          addDS(domain, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
        if (domain == dnameTarget && type == QType::DS) { // example|DS
          return genericDSAndDNSKEYHandler(res, domain, DNSName("."), type, keys);
        }
        // For the rest, delegate!
        if (domain.isPartOf(dnameOwner)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameOwner, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addDS(dnameOwner, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        if (domain.isPartOf(dnameTarget)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameTarget, QType::NS, "b.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addDS(dnameTarget, 300, res->d_records, keys);
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          addRecordToLW(res, "b.gtld-servers.net.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain.countLabels() == 1 && type == QType::DNSKEY) { // powerdns|DNSKEY
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        if (domain == target && type == QType::DS) { // dname.powerdns|DS
          return genericDSAndDNSKEYHandler(res, domain, dnameOwner, type, keys);
        }
        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, dnameOwner, QType::DNAME, dnameTarget.toString());
          addRRSIG(keys, res->d_records, dnameOwner, 300);
          addRecordToLW(res, domain, QType::CNAME, cnameTarget.toString()); // CNAME from a DNAME is not signed
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == target && type == QType::DS) { // dname.example|DS
          return genericDSAndDNSKEYHandler(res, domain, dnameTarget, type, keys);
        }
        if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
        }
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4); /* DNAME + RRSIG(DNAME) + CNAME + A */

  BOOST_CHECK_EQUAL(queries, 9);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[1].d_name, dnameOwner);

  BOOST_CHECK(ret[2].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[2].d_name, target);

  BOOST_CHECK(ret[3].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[3].d_name, cnameTarget);

  // And the cache
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4); /* DNAME + RRSIG(DNAME) + CNAME + A */

  BOOST_CHECK_EQUAL(queries, 9);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::RRSIG);
  BOOST_CHECK_EQUAL(ret[1].d_name, dnameOwner);

  BOOST_CHECK(ret[2].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[2].d_name, target);

  BOOST_CHECK(ret[3].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[3].d_name, cnameTarget);
}

BOOST_AUTO_TEST_CASE(test_dname_processing_no_CNAME) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName dnameOwner("powerdns.com");
  const DNSName dnameTarget("powerdns.net");

  const DNSName target("dname.powerdns.com.");
  const DNSName cnameTarget("dname.powerdns.net");

  size_t queries = 0;

  sr->setAsyncCallback([dnameOwner, dnameTarget, target, cnameTarget, &queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queries++;

      if (isRootServer(ip)) {
        if (domain.isPartOf(dnameOwner)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameOwner, QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
        if (domain.isPartOf(dnameTarget)) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, dnameTarget, QType::NS, "b.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
          addRecordToLW(res, "b.gtld-servers.net.", QType::A, "192.0.2.2", DNSResourceRecord::ADDITIONAL, 3600);
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.1:53")) {
        if (domain == target) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, dnameOwner, QType::DNAME, dnameTarget.toString());
          // No CNAME, recursor should synth
          return 1;
        }
      } else if (ip == ComboAddress("192.0.2.2:53")) {
        if (domain == cnameTarget) {
          setLWResult(res, 0, true, false, false);
          addRecordToLW(res, domain, QType::A, "192.0.2.2");
        }
        return 1;
      }
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);

  BOOST_CHECK_EQUAL(queries, 4);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[1].d_name, target);

  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[2].d_name, cnameTarget);

  // Now check the cache
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);

  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_REQUIRE_EQUAL(ret.size(), 3);

  BOOST_CHECK_EQUAL(queries, 4);

  BOOST_REQUIRE(ret[0].d_type == QType::DNAME);
  BOOST_CHECK(ret[0].d_name == dnameOwner);
  BOOST_CHECK_EQUAL(getRR<DNAMERecordContent>(ret[0])->getTarget(), dnameTarget);

  BOOST_CHECK(ret[1].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[1].d_name, target);

  BOOST_CHECK(ret[2].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[2].d_name, cnameTarget);
}

/*
// cerr<<"asyncresolve called to ask "<<ip.toStringWithPort()<<" about "<<domain.toString()<<" / "<<QType(type).getName()<<" over "<<(doTCP ? "TCP" : "UDP")<<" (rd: "<<sendRDQuery<<", EDNS0 level: "<<EDNS0Level<<")"<<endl;

- check out of band support

- check preoutquery

*/

BOOST_AUTO_TEST_SUITE_END()
