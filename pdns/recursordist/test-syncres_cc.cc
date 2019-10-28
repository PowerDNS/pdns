#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "base32.hh"
#include "lua-recursor4.hh"
#include "root-dnssec.hh"
#include "test-syncres_cc.hh"

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

void primeRootNSZones(bool)
{
}

bool RecursorLua4::preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, int& ret) const
{
  return false;
}

int asyncresolve(const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstrmLoggers,const std::set<uint16_t>& exportTypes, LWResult* res, bool* chained)
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
  SyncRes::s_hardenNXD = true;
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
  BOOST_CHECK_EQUAL(SyncRes::getNSSpeedsSize(), 0U);
  SyncRes::clearEDNSStatuses();
  BOOST_CHECK_EQUAL(SyncRes::getEDNSStatusesSize(), 0U);
  SyncRes::clearThrottle();
  BOOST_CHECK_EQUAL(SyncRes::getThrottledServersSize(), 0U);
  SyncRes::clearFailedServers();
  BOOST_CHECK_EQUAL(SyncRes::getFailedServersSize(), 0U);

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
  ::arg().setSwitch("qname-minimization", "Use Query Name Minimization") = "no";
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

  sr = std::unique_ptr<SyncRes>(new SyncRes(now));
  sr->setDoEDNS0(true);
  if (dnssec) {
    sr->setDoDNSSEC(dnssec);
  }

  sr->setLogMode(debug == false ? SyncRes::LogNone : SyncRes::Log);

  SyncRes::setDomainMap(std::make_shared<SyncRes::domainmap_t>());
  SyncRes::clearNegCache();
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

void computeRRSIG(const DNSSECPrivateKey& dpk, const DNSName& signer, const DNSName& signQName, uint16_t signQType, uint32_t signTTL, uint32_t sigValidity, RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& toSign, boost::optional<uint8_t> algo, boost::optional<uint32_t> inception, boost::optional<time_t> now)
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

bool addRRSIG(const testkeysset_t& keys, std::vector<DNSRecord>& records, const DNSName& signer, uint32_t sigValidity, bool broken, boost::optional<uint8_t> algo, boost::optional<DNSName> wildcard, boost::optional<time_t> now)
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

  rec.d_content = std::make_shared<DNSKEYRecordContent>(it->second.first.getDNSKEY());
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
  rec.d_content = std::make_shared<DSRecordContent>(it->second.second);

  records.push_back(rec);
  return true;
}

void addNSECRecordToLW(const DNSName& domain, const DNSName& next, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records)
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

void addNSEC3RecordToLW(const DNSName& hashedName, const std::string& hashedNext, const std::string& salt, unsigned int iterations, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records)
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

void addNSEC3UnhashedRecordToLW(const DNSName& domain, const DNSName& zone, const std::string& next, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records, unsigned int iterations)
{
  static const std::string salt = "deadbeef";
  std::string hashed = hashQNameWithSalt(salt, iterations, domain);

  addNSEC3RecordToLW(DNSName(toBase32Hex(hashed)) + zone, next, salt, iterations, types, ttl, records);
}

void addNSEC3NarrowRecordToLW(const DNSName& domain, const DNSName& zone, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records, unsigned int iterations)
{
  static const std::string salt = "deadbeef";
  std::string hashed = hashQNameWithSalt(salt, iterations, domain);
  std::string hashedNext(hashed);
  incrementHash(hashedNext);
  decrementHash(hashed);

  addNSEC3RecordToLW(DNSName(toBase32Hex(hashed)) + zone, hashedNext, salt, iterations, types, ttl, records);
}

void generateKeyMaterial(const DNSName& name, unsigned int algo, uint8_t digest, testkeysset_t& keys)
{
  auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::make(algo));
  dcke->create((algo <= 10) ? 2048 : dcke->getBits());
  DNSSECPrivateKey dpk;
  dpk.d_flags = 256;
  dpk.setKey(dcke);
  DSRecordContent ds = makeDSFromDNSKey(name, dpk.getDNSKEY(), digest);
  keys[name] = std::pair<DNSSECPrivateKey,DSRecordContent>(dpk,ds);
}

void generateKeyMaterial(const DNSName& name, unsigned int algo, uint8_t digest, testkeysset_t& keys, map<DNSName,dsmap_t>& dsAnchors)
{
  generateKeyMaterial(name, algo, digest, keys);
  dsAnchors[name].insert(keys[name].second);
}

int genericDSAndDNSKEYHandler(LWResult* res, const DNSName& domain, DNSName auth, int type, const testkeysset_t& keys, bool proveCut, boost::optional<time_t> now)
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
        std::set<uint16_t> types = { QType::NSEC };
        if (proveCut) {
          types.insert(QType::NS);
        }

        addNSECRecordToLW(domain, DNSName("z") + domain, types, 600, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300, false, boost::none, boost::none, now);
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

int basicRecordsForQnameMinimization(LWResult* res, const DNSName& domain, int type) {
  if (domain == DNSName(".") && type == QType::A) {
    setLWResult(res, 0, true);
    addRecordToLW(res, DNSName("."), QType::SOA, "a.root-servers.net. nstld.verisign-grs.com. 2019042400 1800 900 604800 86400", DNSResourceRecord::AUTHORITY);
    return 1;
  }
  if (domain == DNSName("com") && type == QType::A) {
    setLWResult(res, 0, true);
    addRecordToLW(res, DNSName("com"), QType::NS, "ns1.com", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, DNSName("ns1.com"), QType::A, "1.2.3.4", DNSResourceRecord::ADDITIONAL);
    return 1;
  }
  if (domain == DNSName("ns1.com") && type == QType::A) {
    setLWResult(res, 0, true);
    addRecordToLW(res, DNSName("ns1.com"), QType::A, "1.2.3.4");
    return 1;
  }
  if (domain == DNSName("powerdns.com") && type == QType::A) {
    setLWResult(res, 0, true);
    addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com", DNSResourceRecord::AUTHORITY);
    addRecordToLW(res, DNSName("ns1.powerdns.com"), QType::A, "4.5.6.7", DNSResourceRecord::ADDITIONAL);
    return 1;
  }
  if (domain == DNSName("powerdns.com") && type == QType::NS) {
    setLWResult(res, 0, true);
    addRecordToLW(res, domain, QType::NS, "ns1.powerdns.com");
    addRecordToLW(res, DNSName("ns1.powerdns.com"), QType::A, "4.5.6.7", DNSResourceRecord::ADDITIONAL);
    return 1;
  }
  return 0;
}
