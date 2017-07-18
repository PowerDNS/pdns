#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>

#include "arguments.hh"
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
thread_local std::unique_ptr<MemRecursorCache> t_RC{nullptr};
unsigned int g_numThreads = 1;

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

bool RecursorLua4::preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, int& ret)
{
  return false;
}

int asyncresolve(const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res)
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
    static char templ[40];
    strncpy(templ,"a.root-servers.net.", sizeof(templ) - 1);
    templ[sizeof(templ)-1] = '\0';
    *templ=c;
    aaaarr.d_name=arr.d_name=DNSName(templ);
    nsrr.d_content=std::make_shared<NSRecordContent>(DNSName(templ));
    arr.d_content=std::make_shared<ARecordContent>(ComboAddress(rootIps4[c-'a']));
    vector<DNSRecord> aset;
    aset.push_back(arr);
    t_RC->replace(time(0), DNSName(templ), QType(QType::A), aset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), true); // auth, nuke it all
    if (rootIps6[c-'a'] != NULL) {
      aaaarr.d_content=std::make_shared<AAAARecordContent>(ComboAddress(rootIps6[c-'a']));

      vector<DNSRecord> aaaaset;
      aaaaset.push_back(aaaarr);
      t_RC->replace(time(0), DNSName(templ), QType(QType::AAAA), aaaaset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), true);
    }

    nsset.push_back(nsrr);
  }
  t_RC->replace(time(0), g_rootdnsname, QType(QType::NS), nsset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), false); // and stuff in the cache
}

LuaConfigItems::LuaConfigItems()
{
  for (const auto &dsRecord : rootDSs) {
    auto ds=unique_ptr<DSRecordContent>(dynamic_cast<DSRecordContent*>(DSRecordContent::make(dsRecord)));
    dsAnchors[g_rootdnsname].insert(*ds);
  }
}

/* Some helpers functions */

static void init(bool debug=false)
{
  if (debug) {
    L.setName("test");
    L.setLoglevel((Logger::Urgency)(6)); // info and up
    L.disableSyslog(true);
    L.toConsole(Logger::Info);
  }

  seedRandom("/dev/urandom");
  reportAllTypes();

  t_RC = std::unique_ptr<MemRecursorCache>(new MemRecursorCache());

  SyncRes::s_maxqperq = 50;
  SyncRes::s_maxtotusec = 1000*7000;
  SyncRes::s_maxdepth = 40;
  SyncRes::s_maxnegttl = 3600;
  SyncRes::s_maxcachettl = 86400;
  SyncRes::s_packetcachettl = 3600;
  SyncRes::s_packetcacheservfailttl = 60;
  SyncRes::s_serverdownmaxfails = 64;
  SyncRes::s_serverdownthrottletime = 60;
  SyncRes::s_doIPv6 = true;
  SyncRes::s_ecsipv4limit = 24;
  SyncRes::s_ecsipv6limit = 56;
  SyncRes::s_rootNXTrust = true;
  SyncRes::s_minimumTTL = 0;
  SyncRes::s_serverID = "PowerDNS Unit Tests Server ID";
  SyncRes::clearEDNSSubnets();
  SyncRes::clearEDNSDomains();
  SyncRes::clearDelegationOnly();
  SyncRes::clearDontQuery();

  SyncRes::clearNSSpeeds();
  BOOST_CHECK_EQUAL(SyncRes::getNSSpeedsSize(), 0);
  SyncRes::clearEDNSStatuses();
  BOOST_CHECK_EQUAL(SyncRes::getEDNSStatusesSize(), 0);
  SyncRes::clearThrottle();
  BOOST_CHECK_EQUAL(SyncRes::getThrottledServersSize(), 0);
  SyncRes::clearFailedServers();
  BOOST_CHECK_EQUAL(SyncRes::getFailedServersSize(), 0);

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.clear();
  luaconfsCopy.dsAnchors.clear();
  for (const auto &dsRecord : rootDSs) {
    auto ds=unique_ptr<DSRecordContent>(dynamic_cast<DSRecordContent*>(DSRecordContent::make(dsRecord)));
    luaconfsCopy.dsAnchors[g_rootdnsname].insert(*ds);
  }
  luaconfsCopy.negAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  g_dnssecmode = DNSSECMode::Off;
  g_dnssecLOG = debug;

  ::arg().set("version-string", "string reported on version.pdns or version.bind")="PowerDNS Unit Tests";
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
  sr->setDoDNSSEC(dnssec);
  sr->setLogMode(debug == false ? SyncRes::LogNone : SyncRes::Log);

  SyncRes::setDomainMap(std::make_shared<SyncRes::domainmap_t>());
  SyncRes::clearNegCache();
}

static void setLWResult(LWResult* res, int rcode, bool aa=false, bool tc=false, bool edns=false)
{
  res->d_rcode = rcode;
  res->d_aabit = aa;
  res->d_tcbit = tc;
  res->d_haveEDNS = edns;
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

static void computeRRSIG(const DNSSECPrivateKey& dpk, const DNSName& signer, const DNSName& signQName, uint16_t signQType, uint32_t signTTL, uint32_t sigValidity, RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& toSign, boost::optional<uint8_t> algo=boost::none, boost::optional<uint32_t> inception=boost::none)
{
  time_t now = time(nullptr);
  DNSKEYRecordContent drc = dpk.getDNSKEY();
  const std::shared_ptr<DNSCryptoKeyEngine> rc = dpk.getKey();

  rrc.d_type = signQType;
  rrc.d_labels = signQName.countLabels() - signQName.isWildcard();
  rrc.d_originalttl = signTTL;
  rrc.d_siginception = inception ? *inception : (now - 10);
  rrc.d_sigexpire = now + sigValidity;
  rrc.d_signer = signer;
  rrc.d_tag = 0;
  rrc.d_tag = drc.getTag();
  rrc.d_algorithm = algo ? *algo : drc.d_algorithm;

  std::string msg = getMessageForRRSET(signQName, rrc, toSign);

  rrc.d_signature = rc->sign(msg);
}

typedef std::unordered_map<DNSName, std::pair<DNSSECPrivateKey, DSRecordContent> > testkeysset_t;

static void addRRSIG(const testkeysset_t& keys, std::vector<DNSRecord>& records, const DNSName& signer, uint32_t sigValidity, bool broken=false, boost::optional<uint8_t> algo=boost::none, boost::optional<DNSName> wildcard=boost::none)
{
  if (records.empty()) {
    return;
  }

  const auto it = keys.find(signer);
  if (it == keys.cend()) {
    throw std::runtime_error("No DNSKEY found for " + signer.toString() + ", unable to compute the requested RRSIG");
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
  computeRRSIG(it->second.first, signer, wildcard ? *wildcard : records[recordsCount-1].d_name, records[recordsCount-1].d_type, records[recordsCount-1].d_ttl, sigValidity, rrc, recordcontents, algo);
  if (broken) {
    rrc.d_signature[0] ^= 42;
  }

  DNSRecord rec;
  rec.d_place = records[recordsCount-1].d_place;
  rec.d_name = records[recordsCount-1].d_name;
  rec.d_type = QType::RRSIG;
  rec.d_ttl = sigValidity;

  rec.d_content = std::make_shared<RRSIGRecordContent>(rrc);
  records.push_back(rec);
}

static void addDNSKEY(const testkeysset_t& keys, const DNSName& signer, uint32_t ttl, std::vector<DNSRecord>& records)
{
  const auto it = keys.find(signer);
  if (it == keys.cend()) {
    throw std::runtime_error("No DNSKEY found for " + signer.toString());
  }

  DNSRecord rec;
  rec.d_place = DNSResourceRecord::ANSWER;
  rec.d_name = signer;
  rec.d_type = QType::DNSKEY;
  rec.d_ttl = ttl;

  rec.d_content = std::make_shared<DNSKEYRecordContent>(it->second.first.getDNSKEY());
  records.push_back(rec);
}

static void addDS(const DNSName& domain, uint32_t ttl, std::vector<DNSRecord>& records, const testkeysset_t& keys, DNSResourceRecord::Place place=DNSResourceRecord::AUTHORITY)
{
  const auto it = keys.find(domain);
  if (it == keys.cend()) {
    return;
  }

  DNSRecord rec;
  rec.d_name = domain;
  rec.d_type = QType::DS;
  rec.d_place = place;
  rec.d_ttl = ttl;
  rec.d_content = std::make_shared<DSRecordContent>(it->second.second);

  records.push_back(rec);
}

static void addNSECRecordToLW(const DNSName& domain, const DNSName& next, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records)
{
  NSECRecordContent nrc;
  nrc.d_next = next;
  nrc.d_set = types;

  DNSRecord rec;
  rec.d_name = domain;
  rec.d_ttl = ttl;
  rec.d_type = QType::NSEC;
  rec.d_content = std::make_shared<NSECRecordContent>(nrc);
  rec.d_place = DNSResourceRecord::AUTHORITY;

  records.push_back(rec);
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

  sr->setAsyncCallback([target,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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
  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([&queriesWithEDNS, &queriesWithoutEDNS, &noEDNSServer](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

BOOST_AUTO_TEST_CASE(test_edns_notimp_fallback) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  size_t queriesWithEDNS = 0;
  size_t queriesWithoutEDNS = 0;

  sr->setAsyncCallback([&queriesWithEDNS, &queriesWithoutEDNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      if (EDNS0Level != 0) {
        queriesWithEDNS++;
        setLWResult(res, RCode::NotImp);
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

  /* fake that the NS doesn't handle EDNS, check that we fallback */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesWithEDNS, 1);
  BOOST_CHECK_EQUAL(queriesWithoutEDNS, 1);
}

BOOST_AUTO_TEST_CASE(test_tc_fallback_to_tcp) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  sr->setAsyncCallback([](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  sr->setAsyncCallback([&tcpQueriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 1);
    BOOST_CHECK(SyncRes::isThrottled(time(nullptr), server, target, QType::A));
  }
}

BOOST_AUTO_TEST_CASE(test_all_nss_network_error) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
        return -1;
      }
    });

  /* exact same test than the previous one, except instead of a time out we fake a network error */
  DNSName target("powerdns.com.");

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(downServers.size(), 4);

  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 1);
    BOOST_CHECK(SyncRes::isThrottled(time(nullptr), server, target, QType::A));
;
  }
}

BOOST_AUTO_TEST_CASE(test_os_limit_errors) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(SyncRes::getServerFailsCount(server), 0);
    BOOST_CHECK(!SyncRes::isThrottled(time(nullptr), server, target, QType::A));
  }
}

BOOST_AUTO_TEST_CASE(test_glued_referral) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

BOOST_AUTO_TEST_CASE(test_edns_submask_by_domain) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSDomain(target);

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setIncomingECSFound(true);
  sr->setIncomingECS(incomingECS);

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
}

BOOST_AUTO_TEST_CASE(test_edns_submask_by_addr) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");
  SyncRes::addEDNSSubnet(Netmask("192.0.2.1/32"));

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("2001:DB8::FF/128");
  sr->setIncomingECSFound(true);
  sr->setIncomingECS(incomingECS);

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target, cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target, cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target,&count](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target,&depth](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target,ns,&queriesToNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  SyncRes::doThrottle(time(nullptr), ns, SyncRes::s_serverdownthrottletime, 10000);

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
  SyncRes::doThrottle(time(nullptr), ns, SyncRes::s_serverdownthrottletime, blocks);

  for (size_t idx = 0; idx < blocks; idx++) {
    BOOST_CHECK(SyncRes::isThrottled(time(nullptr), ns));
  }

  /* we have been throttled 'blocks' times, we should not be throttled anymore */
  BOOST_CHECK(!SyncRes::isThrottled(time(nullptr), ns));
}

BOOST_AUTO_TEST_CASE(test_throttled_server_time) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const ComboAddress ns("192.0.2.1:53");

  const size_t seconds = 1;
  /* mark ns as down for 'seconds' seconds */
  SyncRes::doThrottle(time(nullptr), ns, seconds, 10000);

  BOOST_CHECK(SyncRes::isThrottled(time(nullptr), ns));

  sleep(seconds + 1);

  /* we should not be throttled anymore */
  BOOST_CHECK(!SyncRes::isThrottled(time(nullptr), ns));
}

BOOST_AUTO_TEST_CASE(test_dont_query_server) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("throttled.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([target,ns,&queriesToNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target1, target2, ns, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target1, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  /* one for target1 and one for the entire TLD */
  BOOST_CHECK_EQUAL(SyncRes::getNegCacheSize(), 2);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
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

  sr->setAsyncCallback([target1, target2, ns, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target2);
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

  sr->setAsyncCallback([target1, target2, ns, &queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  sr->setIncomingECSFound(true);
  sr->setIncomingECS(incomingECS);

  sr->setAsyncCallback([target,cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      if (isRootServer(ip)) {
        setLWResult(res, 0, false, false, true);
        addRecordToLW(res, "powerdns.com.", QType::NS, "pdns-public-ns1.powerdns.com.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "pdns-public-ns1.powerdns.com.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);

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

BOOST_AUTO_TEST_CASE(test_ns_speed) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  std::map<ComboAddress, uint64_t> nsCounts;

  sr->setAsyncCallback([target,&nsCounts](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  struct timeval now;
  gettimeofday(&now, 0);

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

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  time_t now = time(nullptr);
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

  sr->setAsyncCallback([&queriesCount,target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      return 0;
    });

  /* we populate the cache with eveything we need */
  time_t now = time(nullptr);
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

  sr->setAsyncCallback([target,&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  const time_t now = time(nullptr);
  initSR(sr);

  primeHints();

  const DNSName target("cachettl.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

BOOST_AUTO_TEST_CASE(test_cache_expired_ttl) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  time_t now = time(nullptr);
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

BOOST_AUTO_TEST_CASE(test_delegation_only) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* Thanks, Verisign */
  SyncRes::addDelegationOnly(DNSName("com."));
  SyncRes::addDelegationOnly(DNSName("net."));

  const DNSName target("nx-powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

BOOST_AUTO_TEST_CASE(test_xfr) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* {A,I}XFR should be rejected right away */
  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
}

BOOST_AUTO_TEST_CASE(test_special_names) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr);

  primeHints();

  /* special names should be handled internally */

  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  zone->addNSIPTrigger(Netmask(ns, 32), pol);
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

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  zone->addNSIPTrigger(Netmask(ns, 128), pol);
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

  sr->setAsyncCallback([target,ns,nsName](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  zone->addNSTrigger(nsName, pol);
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

  sr->setAsyncCallback([target,ns,nsName](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  zone->addNSIPTrigger(Netmask(ns, 128), pol);
  zone->addNSTrigger(nsName, pol);
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

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  SyncRes::AuthDomain ad;
  ad.d_rdForward = false;
  ad.d_servers.push_back(forwardedNS);
  (*SyncRes::t_sstorage.domainmap)[target] = ad;

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (ip == forwardedNS) {
        BOOST_CHECK_EQUAL(sendRDQuery, false);

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

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

BOOST_AUTO_TEST_CASE(test_auth_zone_delegation_oob) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  size_t queriesCount = 0;
  const DNSName target("test.xx.");
  const ComboAddress targetAddr("127.0.0.1");
  const DNSName ns("localhost.");
  const ComboAddress nsAddr("127.0.0.1");
  const DNSName authZone("test.xx");

  SyncRes::AuthDomain ad;
  DNSRecord dr;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::NS;
  dr.d_ttl = 1800;
  dr.d_content = std::make_shared<NSRecordContent>("localhost.");
  ad.d_records.insert(dr);

  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_name = authZone;
  dr.d_type = QType::A;
  dr.d_ttl = 1800;
  dr.d_content = std::make_shared<ARecordContent>(nsAddr);
  ad.d_records.insert(dr);

  (*SyncRes::t_sstorage.domainmap)[authZone] = ad;

  sr->setAsyncCallback([&queriesCount,nsAddr,target,targetAddr](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  /* a second time, to check that the OOB flag is set when the query cache is used */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 0);
  BOOST_CHECK(sr->wasOutOfBand());
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

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([&queriesCount,target,authZone](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([&queriesCount,externalCNAME,addr](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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
  initSR(sr);

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

  sr->setAsyncCallback([&queriesCount,target,targetAddr,nsAddr](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([&queriesCount,nsAddr,target,targetAddr](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

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

  g_dnssecmode = DNSSECMode::ValidateAll;

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,zskeys,kskeys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  g_dnssecmode = DNSSECMode::ValidateAll;

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,keys,rrsigkeys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  g_dnssecmode = DNSSECMode::ValidateAll;

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(target, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (domain == target && type == QType::NS) {

        setLWResult(res, 0, true, false, true);
        char addr[] = "a.root-servers.net.";
        for (char idx = 'a'; idx <= 'm'; idx++) {
          addr[0] = idx;
          addRecordToLW(res, domain, QType::NS, std::string(addr), DNSResourceRecord::ANSWER, 3600);
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
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_unknown_ds_algorithm) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  g_dnssecmode = DNSSECMode::ValidateAll;

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::RSASHA512, DNSSECKeeper::SHA384, keys, luaconfsCopy.dsAnchors);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  g_dnssecmode = DNSSECMode::ValidateAll;

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::RSASHA512, DNSSECKeeper::SHA384, keys, luaconfsCopy.dsAnchors);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

BOOST_AUTO_TEST_CASE(test_dnssec_secure_various_algos) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      DNSName auth = domain;
      if (domain == target) {
        auth = DNSName("powerdns.com.");
      }
      if (type == QType::DS) {
        return 0;
      }
      else if (type == QType::DNSKEY) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, auth, 300, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        return 1;
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      DNSName auth = domain;
      if (domain == target) {
        auth = DNSName("powerdns.com.");
      }
      if (type == QType::DS) {
        return 0;
      }
      else if (type == QType::DNSKEY) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, auth, 300, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        return 1;
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
  BOOST_CHECK_EQUAL(queriesCount, 8);

}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_a_then_ns) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      DNSName auth = domain;
      if (domain == target) {
        auth = DNSName("powerdns.com.");
      }
      if (type == QType::DS) {
        return 0;
      }
      else if (type == QType::DNSKEY) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, auth, 300, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        return 1;
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
            /* no DS */
            addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS }, 600, res->d_records);
            addRRSIG(keys, res->d_records, DNSName("com."), 300);
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
  BOOST_CHECK_EQUAL(queriesCount, 7);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_with_nta) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      DNSName auth = domain;
      if (domain == target) {
        auth = DNSName("powerdns.com.");
      }
      if (type == QType::DS) {
        return 0;
      }
      else if (type == QType::DNSKEY) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, auth, 300, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        return 1;
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
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* Should be insecure because of the NTA */
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 7);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  /* Should be insecure because of the NTA */
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 7);
}

BOOST_AUTO_TEST_CASE(test_dnssec_bogus_with_nta) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        setLWResult(res, 0, false, false, true);
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
  /* and a such, no query for the DNSKEYs */
  BOOST_CHECK_EQUAL(queriesCount, 6);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 6);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        return 0;
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      DNSName auth = domain;
      if (domain == target) {
        auth = DNSName("powerdns.com.");
      }
      if (type == QType::DS) {
        return 0;
      }
      else if (type == QType::DNSKEY) {
        setLWResult(res, 0, true, false, true);
        addDNSKEY(keys, auth, 300, res->d_records);
        addRRSIG(keys, res->d_records, auth, 300);
        return 1;
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
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 9);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4);
  BOOST_CHECK_EQUAL(queriesCount, 9);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_nsec_wildcard) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        return 0;
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

BOOST_AUTO_TEST_CASE(test_dnssec_no_ds_on_referral_secure) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,&dsQueriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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
  BOOST_CHECK_EQUAL(queriesCount, 11);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(queriesCount, 11);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_dnssec_no_ds_on_referral_insecure) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,&dsQueriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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
  BOOST_CHECK_EQUAL(queriesCount, 10);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 10);
  BOOST_CHECK_EQUAL(dsQueriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_bogus_unsigned_nsec) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        return 0;
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        return 0;
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == target) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          return 1;
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
          setLWResult(res, 0, false, false, true);
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

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_skipped_cut) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == DNSName("sub.powerdns.com.")) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("powerdns.com."), 300);
          return 1;
        }
        else if (domain == DNSName("www.sub.powerdns.com.")) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("sub.powerdns.com."), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          return 1;
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
          setLWResult(res, 0, false, false, true);
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
  BOOST_CHECK_EQUAL(queriesCount, 11);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 11);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_to_ta_skipped_cut) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == DNSName("www.sub.powerdns.com")) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, DNSName("sub.powerdns.com"), QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com"), 300);
          addNSECRecordToLW(DNSName("www.sub.powerdns.com"), DNSName("vww.sub.powerdns.com."), { QType::A }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("sub.powerdns.com"), 300);
        }
        else {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
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
          else if (domain == DNSName("powerdns.com.")) {
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
  BOOST_CHECK_EQUAL(queriesCount, 9);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 9);
}

BOOST_AUTO_TEST_CASE(test_dnssec_secure_to_insecure_nodata) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

  primeHints();
  const DNSName target("powerdns.com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::SHA256, keys);

  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == target) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addNSECRecordToLW(domain, DNSName("z.powerdns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          return 1;
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
          setLWResult(res, 0, false, false, true);
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == target) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          return 1;
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
          setLWResult(res, 0, false, false, true);
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

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_to_secure_cname) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == DNSName("power-dns.com.")) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          return 1;
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
          setLWResult(res, 0, false, false, true);
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        return 0;
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        return 0;
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        return 0;
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetCName,targetCNameAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DS) {
        if (domain == DNSName("power-dns.com.")) {
          setLWResult(res, 0, false, false, true);
          addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
          addNSECRecordToLW(domain, DNSName("z.power-dns.com."), { QType::NS }, 600, res->d_records);
          addRRSIG(keys, res->d_records, DNSName("com."), 300);
          return 1;
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
          setLWResult(res, 0, false, false, true);
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

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DNSKEY) {
        if (domain == g_rootdnsname || domain == DNSName("powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        else if (domain == DNSName("com.")) {
          setLWResult(res, 0, false, false, true);
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
  /* - NS com. (at . and com.)
     - NS powerdns.com (com. and powerdns.com.)
     - DNSKEY (. and powerdns.com.)
     - A powerdns.com
  */
  BOOST_CHECK_EQUAL(queriesCount, 7);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 7);
}

BOOST_AUTO_TEST_CASE(test_dnssec_insecure_ta_norrsig) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      queriesCount++;

      if (type == QType::DNSKEY) {
        if (domain == g_rootdnsname || domain == DNSName("powerdns.com.")) {
          setLWResult(res, 0, true, false, true);
          addDNSKEY(keys, domain, 300, res->d_records);
          addRRSIG(keys, res->d_records, domain, 300);
          return 1;
        }
        else if (domain == DNSName("com.")) {
          setLWResult(res, 0, false, false, true);
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
  /* - NS com. (at . and com.)
     - NS powerdns.com (com. and powerdns.com.)
     - DNSKEY (.)
     - A powerdns.com (no DNSKEY because no RRSIG)
  */
  BOOST_CHECK_EQUAL(queriesCount, 6);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(queriesCount, 6);
}

BOOST_AUTO_TEST_CASE(test_dnssec_nta) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  g_dnssecmode = DNSSECMode::ValidateAll;

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

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

  g_dnssecmode = DNSSECMode::ValidateAll;

  primeHints();
  const DNSName target(".");
  testkeysset_t keys;

  /* Remove the root DS */
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
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

/*
// cerr<<"asyncresolve called to ask "<<ip.toStringWithPort()<<" about "<<domain.toString()<<" / "<<QType(type).getName()<<" over "<<(doTCP ? "TCP" : "UDP")<<" (rd: "<<sendRDQuery<<", EDNS0 level: "<<EDNS0Level<<")"<<endl;

- check out of band support

- check preoutquery

*/

BOOST_AUTO_TEST_SUITE_END()
