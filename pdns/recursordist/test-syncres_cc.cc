#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>

#include "arguments.hh"
#include "lua-recursor4.hh"
#include "namespaces.hh"
#include "rec-lua-conf.hh"
#include "root-dnssec.hh"
#include "syncres.hh"
#include "validate-recursor.hh"

std::unordered_set<DNSName> g_delegationOnly;
RecursorStats g_stats;
GlobalStateHolder<LuaConfigItems> g_luaconfs;
NetmaskGroup* g_dontQuery{nullptr};
__thread MemRecursorCache* t_RC{nullptr};
SyncRes::domainmap_t* g_initialDomainMap{nullptr};
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
    t_RC = new MemRecursorCache();

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
    t_RC->replace(time(0), DNSName(templ), QType(QType::A), aset, vector<std::shared_ptr<RRSIGRecordContent>>(), true); // auth, nuke it all
    if (rootIps6[c-'a'] != NULL) {
      aaaarr.d_content=std::make_shared<AAAARecordContent>(ComboAddress(rootIps6[c-'a']));

      vector<DNSRecord> aaaaset;
      aaaaset.push_back(aaaarr);
      t_RC->replace(time(0), DNSName(templ), QType(QType::AAAA), aaaaset, vector<std::shared_ptr<RRSIGRecordContent>>(), true);
    }

    nsset.push_back(nsrr);
  }
  t_RC->replace(time(0), g_rootdnsname, QType(QType::NS), nsset, vector<std::shared_ptr<RRSIGRecordContent>>(), false); // and stuff in the cache
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

  if (g_dontQuery)
    delete g_dontQuery;
  g_dontQuery = new NetmaskGroup();

  if (t_RC)
    delete t_RC;
  t_RC = new MemRecursorCache();

  if (g_initialDomainMap)
    delete g_initialDomainMap;
  g_initialDomainMap = new SyncRes::domainmap_t(); // new threads needs this to be setup

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

  g_ednssubnets = NetmaskGroup();
  g_ednsdomains = SuffixMatchNode();
  g_useIncomingECS = false;
  g_delegationOnly.clear();

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.clear();
  g_luaconfs.setState(luaconfsCopy);

  ::arg().set("version-string", "string reported on version.pdns or version.bind")="PowerDNS Unit Tests";
}

static void initSR(std::unique_ptr<SyncRes>& sr, bool edns0, bool dnssec, SyncRes::LogMode lm=SyncRes::LogNone, time_t fakeNow=0)
{
  struct timeval now;
  if (fakeNow > 0) {
    now.tv_sec = fakeNow;
    now.tv_usec = 0;
  }
  else {
    Utility::gettimeofday(&now, 0);
  }

  sr = std::unique_ptr<SyncRes>(new SyncRes(now));
  sr->setDoEDNS0(edns0);
  sr->setDoDNSSEC(dnssec);
  sr->setLogMode(lm);
  t_sstorage->domainmap = g_initialDomainMap;
  t_sstorage->negcache.clear();
  t_sstorage->nsSpeeds.clear();
  t_sstorage->ednsstatus.clear();
  t_sstorage->throttle.clear();
  t_sstorage->fails.clear();
  t_sstorage->dnssecmap.clear();
}

static void setLWResult(LWResult* res, int rcode, bool aa=false, bool tc=false, bool edns=false)
{
  res->d_rcode = rcode;
  res->d_aabit = aa;
  res->d_tcbit = tc;
  res->d_haveEDNS = edns;
}

static void addRecordToList(std::vector<DNSRecord>& records, const DNSName& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place, uint32_t ttl)
{
  DNSRecord rec;
  rec.d_place = place;
  rec.d_name = name;
  rec.d_type = type;
  rec.d_ttl = ttl;

  if (type == QType::NS) {
    rec.d_content = std::make_shared<NSRecordContent>(DNSName(content));
  }
  else if (type == QType::A) {
    rec.d_content = std::make_shared<ARecordContent>(ComboAddress(content));
  }
  else if (type == QType::AAAA) {
    rec.d_content = std::make_shared<AAAARecordContent>(ComboAddress(content));
  }
  else if (type == QType::CNAME) {
    rec.d_content = std::make_shared<CNAMERecordContent>(DNSName(content));
  }
  else if (type == QType::OPT) {
    rec.d_content = std::make_shared<OPTRecordContent>();
  }
  else {
    rec.d_content = shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(type, QClass::IN, content));
  }

  records.push_back(rec);
}

static void addRecordToList(std::vector<DNSRecord>& records, const std::string& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place, uint32_t ttl)
{
  addRecordToList(records, name, type, content, place, ttl);
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
  for (size_t idx = 0; idx < rootIps4Count; idx++) {
    if (ip.toString() == rootIps4[idx]) {
      return true;
    }
  }

  for (size_t idx = 0; idx < rootIps6Count; idx++) {
    if (ip.toString() == rootIps6[idx]) {
      return true;
    }
  }
  return false;
}

/* Real tests */

BOOST_AUTO_TEST_SUITE(syncres_cc)

BOOST_AUTO_TEST_CASE(test_root_primed) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  /* we are primed, we should be able to resolve NS . without any query */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("."), QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 13);
}

BOOST_AUTO_TEST_CASE(test_root_not_primed) {
  std::unique_ptr<SyncRes> sr;
  init(false);
  initSR(sr, true, false);

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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesCount, 2);
}

BOOST_AUTO_TEST_CASE(test_root_not_primed_and_no_response) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);
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
    BOOST_CHECK_EQUAL(t_sstorage->fails.value(server), 0);
  }
}

BOOST_AUTO_TEST_CASE(test_edns_formerr_fallback) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesWithEDNS, 1);
  BOOST_CHECK_EQUAL(queriesWithoutEDNS, 1);
  BOOST_CHECK_EQUAL(t_sstorage->ednsstatus.size(), 1);
  BOOST_CHECK_EQUAL(t_sstorage->ednsstatus[noEDNSServer].mode, SyncRes::EDNSStatus::NOEDNS);
}

BOOST_AUTO_TEST_CASE(test_edns_notimp_fallback) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(queriesWithEDNS, 1);
  BOOST_CHECK_EQUAL(queriesWithoutEDNS, 1);
}

BOOST_AUTO_TEST_CASE(test_tc_fallback_to_tcp) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

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
  BOOST_CHECK_EQUAL(res, 0);
}

BOOST_AUTO_TEST_CASE(test_all_nss_down) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, true, false, true);
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
    BOOST_CHECK_EQUAL(t_sstorage->fails.value(server), 1);
    BOOST_CHECK(t_sstorage->throttle.shouldThrottle(time(nullptr), boost::make_tuple(server, target, QType::A)));
  }
}

BOOST_AUTO_TEST_CASE(test_all_nss_network_error) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, true, false, true);
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
    BOOST_CHECK_EQUAL(t_sstorage->fails.value(server), 1);
    BOOST_CHECK(t_sstorage->throttle.shouldThrottle(time(nullptr), boost::make_tuple(server, target, QType::A)));
  }
}

BOOST_AUTO_TEST_CASE(test_os_limit_errors) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);
  std::set<ComboAddress> downServers;

  primeHints();

  sr->setAsyncCallback([&downServers](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, true, false, true);
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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(downServers.size(), 3);

  /* Error is reported as "OS limit error" (-2) so the servers should _NOT_ be marked down */
  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(t_sstorage->fails.value(server), 0);
    BOOST_CHECK(!t_sstorage->throttle.shouldThrottle(time(nullptr), boost::make_tuple(server, target, QType::A)));
  }
}

BOOST_AUTO_TEST_CASE(test_glued_referral) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      /* this will cause issue with qname minimization if we ever implement it */
      if (domain != target) {
        return 0;
      }

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, "com.", QType::NS, "a.gtld-servers.net.", DNSResourceRecord::AUTHORITY, 172800);
        addRecordToLW(res, "a.gtld-servers.net.", QType::A, "192.0.2.1", DNSResourceRecord::ADDITIONAL, 3600);
        addRecordToLW(res, "a.gtld-servers.net.", QType::AAAA, "2001:DB8::1", DNSResourceRecord::ADDITIONAL, 3600);
        return 1;
      }
      else if (ip == ComboAddress("192.0.2.1:53") || ip == ComboAddress("[2001:DB8::1]:53")) {
        setLWResult(res, 0, true, false, true);
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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_glueless_referral) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);

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
          setLWResult(res, 0, true, false, true);
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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_edns_submask_by_domain) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");
  g_useIncomingECS = true;
  g_ednsdomains.add(target);

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
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");
  g_useIncomingECS = true;
  g_ednssubnets.addMask("192.0.2.1/32");

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("2001:DB8::FF/128");
  sr->setIncomingECSFound(true);
  sr->setIncomingECS(incomingECS);

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        BOOST_REQUIRE(!srcmask);

        setLWResult(res, 0, true, false, true);
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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
}

BOOST_AUTO_TEST_CASE(test_following_cname) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("cname.powerdns.com.");
  const DNSName cnameTarget("cname-target.powerdns.com");

  sr->setAsyncCallback([target, cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 2);
  BOOST_CHECK(ret[0].d_type == QType::CNAME);
  BOOST_CHECK_EQUAL(ret[0].d_name, target);
  BOOST_CHECK(ret[1].d_type == QType::A);
  BOOST_CHECK_EQUAL(ret[1].d_name, cnameTarget);
}

BOOST_AUTO_TEST_CASE(test_included_poisonous_cname) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  /* In this test we directly get the NS server for cname.powerdns.com.,
     and we don't know whether it's also authoritative for
     cname-target.powerdns.com or powerdns.com, so we shouldn't accept
     the additional A record for cname-target.powerdns.com. */
  const DNSName target("cname.powerdns.com.");
  const DNSName cnameTarget("cname-target.powerdns.com");

  sr->setAsyncCallback([target, cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, true, false, true);

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
  BOOST_CHECK_EQUAL(res, 0);
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
  init();
  initSR(sr, true, false);

  primeHints();

  size_t count = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&count](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      count++;

      if (isRootServer(ip)) {

        setLWResult(res, 0, true, false, true);
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
  init();
  initSR(sr, true, false);

  primeHints();

  size_t depth = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&depth](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, true, false, true);
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
  init();
  initSR(sr, true, false);

  primeHints();

  size_t queries = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      queries++;

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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
  init();
  initSR(sr, true, false);

  primeHints();

  size_t queries = 0;
  const DNSName target("www.powerdns.com.");

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      queries++;

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);

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
  init();
  initSR(sr, true, false);

  primeHints();

  size_t queries = 0;
  const DNSName target("cname.powerdns.com.");

  sr->setAsyncCallback([target,&queries](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      queries++;

      if (isRootServer(ip)) {

        setLWResult(res, 0, true, false, true);
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
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("throttled.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([target,ns,&queriesToNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, true, false, true);
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
  t_sstorage->throttle.throttle(time(nullptr), boost::make_tuple(ns, "", 0), SyncRes::s_serverdownthrottletime, 10000);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  /* we should not have sent any queries to ns */
  BOOST_CHECK_EQUAL(queriesToNS, 0);
}

BOOST_AUTO_TEST_CASE(test_throttled_server_count) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const ComboAddress ns("192.0.2.1:53");

  const size_t blocks = 10;
  /* mark ns as down for 'blocks' queries */
  t_sstorage->throttle.throttle(time(nullptr), boost::make_tuple(ns, "", 0), SyncRes::s_serverdownthrottletime, blocks);

  for (size_t idx = 0; idx < blocks; idx++) {
    BOOST_CHECK(t_sstorage->throttle.shouldThrottle(time(nullptr), boost::make_tuple(ns, "", 0)));
  }

  /* we have been throttled 'blocks' times, we should not be throttled anymore */
  BOOST_CHECK(!t_sstorage->throttle.shouldThrottle(time(nullptr), boost::make_tuple(ns, "", 0)));
}

BOOST_AUTO_TEST_CASE(test_throttled_server_time) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const ComboAddress ns("192.0.2.1:53");

  const size_t seconds = 1;
  /* mark ns as down for 'seconds' seconds */
  t_sstorage->throttle.throttle(time(nullptr), boost::make_tuple(ns, "", 0), seconds, 10000);
  BOOST_CHECK(t_sstorage->throttle.shouldThrottle(time(nullptr), boost::make_tuple(ns, "", 0)));

  sleep(seconds + 1);

  /* we should not be throttled anymore */
  BOOST_CHECK(!t_sstorage->throttle.shouldThrottle(time(nullptr), boost::make_tuple(ns, "", 0)));
}

BOOST_AUTO_TEST_CASE(test_dont_query_server) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("throttled.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  size_t queriesToNS = 0;

  sr->setAsyncCallback([target,ns,&queriesToNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, true, false, true);
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
  g_dontQuery->addMask(Netmask(ns));

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::ServFail);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  /* we should not have sent any queries to ns */
  BOOST_CHECK_EQUAL(queriesToNS, 0);
}

BOOST_AUTO_TEST_CASE(test_root_nx_trust) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

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
  BOOST_CHECK_EQUAL(t_sstorage->negcache.size(), 2);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NXDomain);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  /* one for target1 and one for the entire TLD */
  BOOST_CHECK_EQUAL(t_sstorage->negcache.size(), 2);

  /* we should have sent only one query */
  BOOST_CHECK_EQUAL(queriesCount, 1);
}

BOOST_AUTO_TEST_CASE(test_root_nx_dont_trust) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

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
  BOOST_CHECK_EQUAL(t_sstorage->negcache.size(), 1);

  ret.clear();
  res = sr->beginResolve(target2, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  /* one for target1 */
  BOOST_CHECK_EQUAL(t_sstorage->negcache.size(), 1);

  /* we should have sent three queries */
  BOOST_CHECK_EQUAL(queriesCount, 3);
}

BOOST_AUTO_TEST_CASE(test_skip_negcache_for_variable_response) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("www.powerdns.com.");
  const DNSName cnameTarget("cname.powerdns.com.");

  g_useIncomingECS = true;
  g_ednsdomains.add(DNSName("powerdns.com."));

  EDNSSubnetOpts incomingECS;
  incomingECS.source = Netmask("192.0.2.128/32");
  sr->setIncomingECSFound(true);
  sr->setIncomingECS(incomingECS);

  sr->setAsyncCallback([target,cnameTarget](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      BOOST_REQUIRE(srcmask);
      BOOST_CHECK_EQUAL(srcmask->toString(), "192.0.2.0/24");

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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
  BOOST_CHECK_EQUAL(t_sstorage->negcache.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_ns_speed) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");

  std::map<ComboAddress, uint64_t> nsCounts;

  sr->setAsyncCallback([target,&nsCounts](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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
  t_sstorage->nsSpeeds[DNSName("pdns-public-ns1.powerdns.com.")].submit(ComboAddress("192.0.2.1:53"), 100, &now);
  t_sstorage->nsSpeeds[DNSName("pdns-public-ns1.powerdns.com.")].submit(ComboAddress("[2001:DB8::1]:53"), 10000, &now);
  t_sstorage->nsSpeeds[DNSName("pdns-public-ns2.powerdns.com.")].submit(ComboAddress("192.0.2.2:53"), 10, &now);
  t_sstorage->nsSpeeds[DNSName("pdns-public-ns2.powerdns.com.")].submit(ComboAddress("[2001:DB8::2]:53"), 1, &now);
  t_sstorage->nsSpeeds[DNSName("pdns-public-ns3.powerdns.com.")].submit(ComboAddress("192.0.2.3:53"), 10000, &now);
  t_sstorage->nsSpeeds[DNSName("pdns-public-ns3.powerdns.com.")].submit(ComboAddress("[2001:DB8::3]:53"), 10000, &now);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(nsCounts.size(), 3);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("192.0.2.1:53")], 1);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("192.0.2.2:53")], 1);
  BOOST_CHECK_EQUAL(nsCounts[ComboAddress("[2001:DB8::2]:53")], 1);
}

BOOST_AUTO_TEST_CASE(test_flawed_nsset) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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

  t_RC->replace(now, target, QType(QType::NS), records, sigs, true, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_cache_hit) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

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
  t_RC->replace(now, target , QType(QType::A), records, sigs, true, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_no_rd) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_cache_min_max_ttl) {
  std::unique_ptr<SyncRes> sr;
  init(false);
  initSR(sr, true, false);

  primeHints();

  const DNSName target("cachettl.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {

        setLWResult(res, 0, true, false, true);
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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK_EQUAL(ret[0].d_ttl, SyncRes::s_minimumTTL);

  const ComboAddress who;
  vector<DNSRecord> cached;
  const time_t now = time(nullptr);
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::A), &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_EQUAL((cached[0].d_ttl - now), SyncRes::s_minimumTTL);

  cached.clear();
  BOOST_REQUIRE_GT(t_RC->get(now, target, QType(QType::NS), &cached, who), 0);
  BOOST_REQUIRE_EQUAL(cached.size(), 1);
  BOOST_REQUIRE_GT(cached[0].d_ttl, now);
  BOOST_CHECK_LE((cached[0].d_ttl - now), SyncRes::s_maxcachettl);
}

BOOST_AUTO_TEST_CASE(test_cache_expired_ttl) {
  std::unique_ptr<SyncRes> sr;
  init(false);
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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

  t_RC->replace(now - 3600, target, QType(QType::A), records, sigs, true, boost::optional<Netmask>());

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_REQUIRE(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toStringWithPort(), ComboAddress("192.0.2.2").toStringWithPort());
}

BOOST_AUTO_TEST_CASE(test_delegation_only) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  /* Thanks, Verisign */
  g_delegationOnly.insert(DNSName("com."));
  g_delegationOnly.insert(DNSName("net."));

  const DNSName target("nx-powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      setLWResult(res, 0, true, false, true);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_skip_opt_any) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_nodata_nsec_nodnssec) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_nodata_nsec_dnssec) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      setLWResult(res, 0, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "SOA 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
      return 1;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 4);
}

BOOST_AUTO_TEST_CASE(test_nx_nsec_nodnssec) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      setLWResult(res, RCode::NXDomain, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
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
  init();
  initSR(sr, true, true);

  primeHints();

  const DNSName target("powerdns.com.");

  sr->setAsyncCallback([target](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      setLWResult(res, RCode::NXDomain, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      /* the NSEC and RRSIG contents are complete garbage, please ignore them */
      addRecordToLW(res, domain, QType::NSEC, "deadbeef", DNSResourceRecord::AUTHORITY);
      addRecordToLW(res, domain, QType::RRSIG, "NSEC 5 3 600 2100010100000000 2100010100000000 24567 dummy data", DNSResourceRecord::AUTHORITY);
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
  init();
  initSR(sr, true, true);

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
  init();
  initSR(sr, true, true);

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
  init();
  initSR(sr, true, true);

  primeHints();

  /* special names should be handled internally */

  size_t queriesCount = 0;

  sr->setAsyncCallback([&queriesCount](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      queriesCount++;
      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("1.0.0.127.in-addr.arpa."), QType(QType::PTR), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("1.0.0.127.in-addr.arpa."), QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."), QType(QType::PTR), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."), QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::PTR);
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("localhost."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::A);
  BOOST_CHECK_EQUAL(getRR<ARecordContent>(ret[0])->getCA().toString(), "127.0.0.1");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("localhost."), QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::AAAA);
  BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(ret[0])->getCA().toString(), "::1");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("localhost."), QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("version.bind."), QType(QType::ANY), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("version.pdns."), QType(QType::TXT), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("version.pdns."), QType(QType::ANY), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("id.server."), QType(QType::TXT), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests Server ID\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);

  ret.clear();
  res = sr->beginResolve(DNSName("id.server."), QType(QType::ANY), QClass::CHAOS, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(ret.size(), 1);
  BOOST_CHECK(ret[0].d_type == QType::TXT);
  BOOST_CHECK_EQUAL(getRR<TXTRecordContent>(ret[0])->d_text, "\"PowerDNS Unit Tests Server ID\"");
  BOOST_CHECK_EQUAL(queriesCount, 0);
}

BOOST_AUTO_TEST_CASE(test_nameserver_ipv4_rpz) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.setPolicyName(0, "Unit test policy 0");
  luaconfsCopy.dfe.addNSIPTrigger(Netmask(ns, 32), pol, 0);
  g_luaconfs.setState(luaconfsCopy);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -2);
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_nameserver_ipv6_rpz) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("[2001:DB8::42]:53");

  sr->setAsyncCallback([target,ns](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.setPolicyName(0, "Unit test policy 0");
  luaconfsCopy.dfe.addNSIPTrigger(Netmask(ns, 128), pol, 0);
  g_luaconfs.setState(luaconfsCopy);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -2);
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_nameserver_name_rpz) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const DNSName nsName("ns1.powerdns.com.");

  sr->setAsyncCallback([target,ns,nsName](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.setPolicyName(0, "Unit test policy 0");
  luaconfsCopy.dfe.addNSTrigger(nsName, pol, 0);
  g_luaconfs.setState(luaconfsCopy);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, -2);
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_CASE(test_nameserver_name_rpz_disabled) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("rpz.powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const DNSName nsName("ns1.powerdns.com.");

  sr->setAsyncCallback([target,ns,nsName](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (isRootServer(ip)) {
        setLWResult(res, 0, true, false, true);
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
  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dfe.setPolicyName(0, "Unit test policy 0");
  luaconfsCopy.dfe.addNSIPTrigger(Netmask(ns, 128), pol, 0);
  luaconfsCopy.dfe.addNSTrigger(nsName, pol, 0);
  g_luaconfs.setState(luaconfsCopy);

  /* RPZ is disabled for this query, we should not be blocked */
  sr->setWantsRPZ(false);

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_nord) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = false;
  ad.d_servers.push_back(forwardedNS);
  (*t_sstorage->domainmap)[target] = ad;

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (ip == forwardedNS) {
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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_rd) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = false;
  ad.d_servers.push_back(forwardedNS);
  (*t_sstorage->domainmap)[target] = ad;

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (ip == forwardedNS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_nord) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*t_sstorage->domainmap)[target] = ad;

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (ip == forwardedNS) {
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
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_CASE(test_forward_zone_recurse_rd) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  primeHints();

  const DNSName target("powerdns.com.");
  const ComboAddress ns("192.0.2.1:53");
  const ComboAddress forwardedNS("192.0.2.42:53");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = true;
  ad.d_servers.push_back(forwardedNS);
  (*t_sstorage->domainmap)[target] = ad;

  sr->setAsyncCallback([forwardedNS](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {

      if (ip == forwardedNS) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, domain, QType::A, "192.0.2.42");
        return 1;
      }

      return 0;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
}

/*
// cerr<<"asyncresolve called to ask "<<ip.toStringWithPort()<<" about "<<domain.toString()<<" / "<<QType(type).getName()<<" over "<<(doTCP ? "TCP" : "UDP")<<" (rd: "<<sendRDQuery<<", EDNS0 level: "<<EDNS0Level<<")"<<endl;

- check out of band support

- check preoutquery

*/

BOOST_AUTO_TEST_SUITE_END()
