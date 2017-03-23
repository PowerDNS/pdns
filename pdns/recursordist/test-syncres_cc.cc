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

  g_ednssubnets = NetmaskGroup();
  g_ednsdomains = SuffixMatchNode();
  g_useIncomingECS = false;
}

static void initSR(std::unique_ptr<SyncRes>& sr, bool edns0, bool dnssec, SyncRes::LogMode lm=SyncRes::LogNone)
{
  struct timeval now;
  Utility::gettimeofday(&now, 0);
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

static void addRecordToLW(LWResult* res, const DNSName& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER, uint32_t ttl=60)
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
  else {
    rec.d_content = shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(type, QClass::IN, content));
  }

  res->d_records.push_back(rec);
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
  BOOST_CHECK_EQUAL(res, 2);
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

  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 2);
  BOOST_CHECK_EQUAL(ret.size(), 0);
  BOOST_CHECK_EQUAL(downServers.size(), 4);

  for (const auto& server : downServers) {
    BOOST_CHECK_EQUAL(t_sstorage->fails.value(server), 1);
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
  BOOST_CHECK_EQUAL(res, 2);
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
        BOOST_REQUIRE(!srcmask);

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
  BOOST_CHECK_EQUAL(res, 2);
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
        BOOST_REQUIRE(!srcmask);

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
  BOOST_CHECK_EQUAL(res, 2);
  /* we have an arbitrary limit at 10 when following a CNAME chain */
  BOOST_CHECK_EQUAL(depth, 10 + 2);
}

/*
  TODO:

// cerr<<"asyncresolve called to ask "<<ip.toStringWithPort()<<" about "<<domain.toString()<<" / "<<QType(type).getName()<<" over "<<(doTCP ? "TCP" : "UDP")<<" (rd: "<<sendRDQuery<<", EDNS0 level: "<<EDNS0Level<<")"<<endl;

check RPZ (nameservers name blocked, name server IP blocked)
check that wantsRPZ false skip the RPZ checks

check that we are asking the more specific nameservers

check that we correctly ignore unauth data?

check out of band support

check throttled

check blocked

check we query the fastest auth available first?

check we correctly store slow servers

if possible, check preoutquery

check depth limit (CNAME and referral)

check time limit

check we correctly populate the cache from the results

check we correctly populate the negcache

check we honor s_minimumTTL and s_maxcachettl

check delegation only

check root NX trust

nxdomain answer
nodata answer
*/

BOOST_AUTO_TEST_SUITE_END()
