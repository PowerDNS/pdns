/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#include <string>
#include <atomic>
#include "utility.hh"
#include "dns.hh"
#include "qtype.hh"
#include <vector>
#include <set>
#include <unordered_set>
#include <map>
#include <cmath>
#include <iostream>
#include <utility>
#include "misc.hh"
#include "lwres.hh"
#include <boost/optional.hpp>
#include <boost/utility.hpp>
#include "circular_buffer.hh"
#include "sstuff.hh"
#include "recursor_cache.hh"
#include "mtasker.hh"
#include "iputils.hh"
#include "validate-recursor.hh"
#include "ednssubnet.hh"
#include "filterpo.hh"
#include "negcache.hh"
#include "proxy-protocol.hh"
#include "sholder.hh"
#include "histogram.hh"
#include "stat_t.hh"
#include "tcpiohandler.hh"
#include "rec-eventtrace.hh"
#include "logr.hh"
#include "rec-tcounters.hh"
#include "ednsextendederror.hh"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/uuid/uuid.hpp>
#ifdef HAVE_FSTRM
#include "fstrm_logger.hh"
#endif /* HAVE_FSTRM */

extern GlobalStateHolder<SuffixMatchNode> g_xdnssec;
extern GlobalStateHolder<SuffixMatchNode> g_dontThrottleNames;
extern GlobalStateHolder<NetmaskGroup> g_dontThrottleNetmasks;
extern GlobalStateHolder<SuffixMatchNode> g_DoTToAuthNames;

enum class AdditionalMode : uint8_t; // defined in rec-lua-conf.hh

class RecursorLua4;

using NsSet = std::unordered_map<DNSName, pair<vector<ComboAddress>, bool>>;

extern std::unique_ptr<NegCache> g_negCache;

class SyncRes : public boost::noncopyable
{
public:
  enum LogMode
  {
    LogNone,
    Log,
    Store
  };
  using asyncresolve_t = std::function<LWResult::Result(const ComboAddress&, const DNSName&, int, bool, bool, int, struct timeval*, boost::optional<Netmask>&, const ResolveContext&, LWResult*, bool*)>;

  enum class HardenNXD
  {
    No,
    DNSSEC,
    Yes
  };

  struct Context
  {
    boost::optional<EDNSExtendedError> extendedError;
    vState state{vState::Indeterminate};
  };

  vState getDSRecords(const DNSName& zone, dsset_t& dsSet, bool onlyTA, unsigned int depth, const string& prefix, bool bogusOnNXD = true, bool* foundCut = nullptr);

  class AuthDomain
  {
  public:
    using records_t = multi_index_container<
      DNSRecord,
      indexed_by<
        ordered_non_unique<
          composite_key<DNSRecord,
                        member<DNSRecord, DNSName, &DNSRecord::d_name>,
                        member<DNSRecord, uint16_t, &DNSRecord::d_type>>,
          composite_key_compare<std::less<>, std::less<>>>>>;

    records_t d_records;
    vector<ComboAddress> d_servers;
    DNSName d_name;
    bool d_rdForward{false};

    bool operator==(const AuthDomain& rhs) const;

    [[nodiscard]] std::string print(const std::string& indent = "",
                                    const std::string& indentLevel = "  ") const;

    int getRecords(const DNSName& qname, QType qtype, std::vector<DNSRecord>& records) const;
    [[nodiscard]] bool isAuth() const
    {
      return d_servers.empty();
    }
    [[nodiscard]] bool isForward() const
    {
      return !isAuth();
    }
    [[nodiscard]] bool shouldRecurse() const
    {
      return d_rdForward;
    }
    [[nodiscard]] const DNSName& getName() const
    {
      return d_name;
    }

  private:
    void addSOA(std::vector<DNSRecord>& records) const;
  };

  using domainmap_t = std::unordered_map<DNSName, AuthDomain>;

  struct ThreadLocalStorage
  {
    std::shared_ptr<domainmap_t> domainmap;
  };

  static void setDefaultLogMode(LogMode logmode)
  {
    s_lm = logmode;
  }

  OptLog LogObject(const string& prefix);

  static uint64_t doEDNSDump(int fileDesc);
  static uint64_t doDumpNSSpeeds(int fileDesc);
  static uint64_t doDumpThrottleMap(int fileDesc);
  static uint64_t doDumpFailedServers(int fileDesc);
  static uint64_t doDumpNonResolvingNS(int fileDesc);
  static uint64_t doDumpSavedParentNSSets(int fileDesc);
  static uint64_t doDumpDoTProbeMap(int fileDesc);

  static int getRootNS(struct timeval now, asyncresolve_t asyncCallback, unsigned int depth, Logr::log_t);
  static void addDontQuery(const std::string& mask)
  {
    if (!s_dontQuery) {
      s_dontQuery = std::make_unique<NetmaskGroup>();
    }
    s_dontQuery->addMask(mask);
  }
  static void addDontQuery(const Netmask& mask)
  {
    if (!s_dontQuery) {
      s_dontQuery = std::make_unique<NetmaskGroup>();
    }
    s_dontQuery->addMask(mask);
  }
  static void clearDontQuery()
  {
    s_dontQuery = nullptr;
  }
  static void parseEDNSSubnetAllowlist(const std::string& alist);
  static void parseEDNSSubnetAddFor(const std::string& subnetlist);
  static void addEDNSLocalSubnet(const std::string& subnet)
  {
    s_ednslocalsubnets.addMask(subnet);
  }
  static void addEDNSRemoteSubnet(const std::string& subnet)
  {
    s_ednsremotesubnets.addMask(subnet);
  }
  static void addEDNSDomain(const DNSName& domain)
  {
    s_ednsdomains.add(domain);
  }
  static void clearEDNSLocalSubnets()
  {
    s_ednslocalsubnets.clear();
  }
  static void clearEDNSRemoteSubnets()
  {
    s_ednsremotesubnets.clear();
  }
  static void clearEDNSDomains()
  {
    s_ednsdomains = SuffixMatchNode();
  }

  static void pruneNSSpeeds(time_t limit);
  static uint64_t getNSSpeedsSize();
  static void submitNSSpeed(const DNSName& server, const ComboAddress& address, int usec, const struct timeval& now);
  static void clearNSSpeeds();
  static float getNSSpeed(const DNSName& server, const ComboAddress& address);

  struct EDNSStatus
  {
    EDNSStatus(const ComboAddress& arg) :
      address(arg) {}
    ComboAddress address;
    time_t ttd{0};
    enum EDNSMode : uint8_t
    {
      EDNSOK = 0,
      EDNSIGNORANT = 1,
      NOEDNS = 2
    } mode{EDNSOK};

    [[nodiscard]] std::string toString() const
    {
      const std::array<std::string, 3> modes = {"OK", "Ignorant", "No"};
      auto umode = static_cast<unsigned int>(mode);
      if (umode >= modes.size()) {
        return "?";
      }
      return modes.at(umode);
    }
  };

  static EDNSStatus::EDNSMode getEDNSStatus(const ComboAddress& server);
  static uint64_t getEDNSStatusesSize();
  static void clearEDNSStatuses();
  static void pruneEDNSStatuses(time_t cutoff);

  static uint64_t getThrottledServersSize();
  static void pruneThrottledServers(time_t now);
  static void clearThrottle();
  static bool isThrottled(time_t now, const ComboAddress& server, const DNSName& target, QType qtype);
  static bool isThrottled(time_t now, const ComboAddress& server);

  enum class ThrottleReason : uint8_t
  {
    None,
    ServerDown,
    PermanentError,
    Timeout,
    ParseError,
    RCodeServFail,
    RCodeRefused,
    RCodeOther,
    TCPTruncate,
    Lame,
  };
  static void doThrottle(time_t now, const ComboAddress& server, time_t duration, unsigned int tries, ThrottleReason reason);
  static void doThrottle(time_t now, const ComboAddress& server, const DNSName& name, QType qtype, time_t duration, unsigned int tries, ThrottleReason reason);
  static void unThrottle(const ComboAddress& server, const DNSName& qname, QType qtype);

  static uint64_t getFailedServersSize();
  static void clearFailedServers();
  static void pruneFailedServers(time_t cutoff);
  static unsigned long getServerFailsCount(const ComboAddress& server);

  static void clearNonResolvingNS();
  static uint64_t getNonResolvingNSSize();
  static void pruneNonResolving(time_t cutoff);

  static void clearSaveParentsNSSets();
  static size_t getSaveParentsNSSetsSize();
  static void pruneSaveParentsNSSets(time_t now);

  static void pruneDoTProbeMap(time_t cutoff);

  static void setDomainMap(std::shared_ptr<domainmap_t> newMap)
  {
    t_sstorage.domainmap = std::move(newMap);
  }
  static std::shared_ptr<domainmap_t> getDomainMap()
  {
    return t_sstorage.domainmap;
  }
  static bool isRecursiveForward(const DNSName& qname);

  static void setECSScopeZeroAddress(const Netmask& scopeZeroMask)
  {
    s_ecsScopeZero.source = scopeZeroMask;
  }

  static void clearECSStats()
  {
    s_ecsqueries.store(0);
    s_ecsresponses.store(0);

    for (size_t idx = 0; idx < 32; idx++) {
      SyncRes::s_ecsResponsesBySubnetSize4[idx].store(0);
    }

    for (size_t idx = 0; idx < 128; idx++) {
      SyncRes::s_ecsResponsesBySubnetSize6[idx].store(0);
    }
  }

  explicit SyncRes(const struct timeval& now);

  int beginResolve(const DNSName& qname, QType qtype, QClass qclass, vector<DNSRecord>& ret, unsigned int depth = 0);
  bool tryDoT(const DNSName& qname, QType qtype, const DNSName& nsName, ComboAddress address, time_t);

  void setId(int threadid)
  {
    if (doLog()) {
      d_prefix = "[" + std::to_string(threadid) + "] ";
    }
  }

  void setId(const string& prefix)
  {
    if (doLog()) {
      d_prefix = "[" + prefix + "] ";
    }
  }

  void setLogMode(LogMode logmode)
  {
    d_lm = logmode;
  }

  bool doLog() const
  {
    return d_lm != LogNone;
  }

  bool setCacheOnly(bool state = true)
  {
    bool old = d_cacheonly;
    d_cacheonly = state;
    return old;
  }

  bool setRefreshAlmostExpired(bool doit)
  {
    auto old = d_refresh;
    d_refresh = doit;
    return old;
  }

  bool setQNameMinimization(bool state = true)
  {
    auto old = d_qNameMinimization;
    d_qNameMinimization = state;
    return old;
  }

  bool setQMFallbackMode(bool state = true)
  {
    auto old = d_qNameMinimizationFallbackMode;
    d_qNameMinimizationFallbackMode = state;
    return old;
  }

  bool getQMFallbackMode() const
  {
    return d_qNameMinimizationFallbackMode;
  }

  void setDoEDNS0(bool state = true)
  {
    d_doEDNS0 = state;
  }

  void setDoDNSSEC(bool state = true)
  {
    d_doDNSSEC = state;
  }

  void setDNSSECValidationRequested(bool requested = true)
  {
    d_DNSSECValidationRequested = requested;
  }

  bool isDNSSECValidationRequested() const
  {
    return d_DNSSECValidationRequested;
  }

  bool shouldValidate() const
  {
    return d_DNSSECValidationRequested && !d_wasOutOfBand;
  }

  void setWantsRPZ(bool state = true)
  {
    d_wantsRPZ = state;
  }

  bool getWantsRPZ() const
  {
    return d_wantsRPZ;
  }

  string getTrace() const
  {
    return d_trace.str();
  }

  bool getQNameMinimization() const
  {
    return d_qNameMinimization;
  }

  void setLuaEngine(shared_ptr<RecursorLua4> pdl)
  {
    d_pdl = std::move(pdl);
  }

  bool wasVariable() const
  {
    return d_wasVariable;
  }

  bool wasOutOfBand() const
  {
    return d_wasOutOfBand;
  }

  struct timeval getNow() const
  {
    return d_now;
  }

  // For debugging purposes
  void setNow(const struct timeval& tval)
  {
    d_now = tval;
  }

  void setQuerySource(const ComboAddress& requestor, const boost::optional<const EDNSSubnetOpts&>& incomingECS);
  void setQuerySource(const Netmask& netmask);

  void setInitialRequestId(const boost::optional<const boost::uuids::uuid&>& initialRequestId)
  {
    d_initialRequestId = initialRequestId;
  }

  void setOutgoingProtobufServers(std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& servers)
  {
    d_outgoingProtobufServers = servers;
  }

#ifdef HAVE_FSTRM
  void setFrameStreamServers(std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& servers)
  {
    d_frameStreamServers = servers;
  }
#endif /* HAVE_FSTRM */

  void setAsyncCallback(asyncresolve_t func)
  {
    d_asyncResolve = std::move(func);
  }

  vState getValidationState() const
  {
    return d_queryValidationState;
  }

  [[nodiscard]] bool getDNSSECLimitHit() const
  {
    return d_validationContext.d_limitHit;
  }

  void setQueryReceivedOverTCP(bool tcp)
  {
    d_queryReceivedOverTCP = tcp;
  }

  static bool isUnsupported(QType qtype)
  {
    auto qcode = qtype.getCode();
    // rfc6895 section 3.1, note ANY is 255 and falls outside the range
    if (qcode >= QType::rfc6895MetaLowerBound && qcode <= QType::rfc6895MetaUpperBound) {
      return true;
    }
    switch (qcode) {
      // Internal types
    case QType::ENT: // aka TYPE0
    case QType::ADDR:
      // RFC
    case QType::rfc6895Reserved:
      // Other
    case QType::RRSIG:
    case QType::NSEC3: // We use the same logic as for an auth: NSEC is queryable, NSEC3 not
    case QType::OPT:
      return true;
    }
    return false;
  }

  static bool answerIsNOData(uint16_t requestedType, int rcode, const std::vector<DNSRecord>& records);

  static thread_local ThreadLocalStorage t_sstorage;

  static pdns::stat_t s_ecsqueries;
  static pdns::stat_t s_ecsresponses;
  static std::map<uint8_t, pdns::stat_t> s_ecsResponsesBySubnetSize4;
  static std::map<uint8_t, pdns::stat_t> s_ecsResponsesBySubnetSize6;

  static string s_serverID;
  static unsigned int s_minimumTTL;
  static unsigned int s_minimumECSTTL;
  static unsigned int s_maxqperq;
  static unsigned int s_maxnsperresolve;
  static unsigned int s_maxnsaddressqperq;
  static unsigned int s_maxtotusec;
  static unsigned int s_maxdepth;
  static unsigned int s_maxnegttl;
  static unsigned int s_maxbogusttl;
  static unsigned int s_maxcachettl;
  static unsigned int s_packetcachettl;
  static unsigned int s_packetcacheservfailttl;
  static unsigned int s_packetcachenegativettl;
  static unsigned int s_serverdownmaxfails;
  static unsigned int s_serverdownthrottletime;
  static unsigned int s_nonresolvingnsmaxfails;
  static unsigned int s_nonresolvingnsthrottletime;
  static unsigned int s_unthrottle_n;
  static unsigned int s_ecscachelimitttl;
  static unsigned int s_maxvalidationsperq;
  static unsigned int s_maxnsec3iterationsperq;
  static uint8_t s_ecsipv4limit;
  static uint8_t s_ecsipv6limit;
  static uint8_t s_ecsipv4cachelimit;
  static uint8_t s_ecsipv6cachelimit;
  static bool s_ecsipv4nevercache;
  static bool s_ecsipv6nevercache;

  static bool s_doIPv4;
  static bool s_doIPv6;
  static bool s_noEDNSPing;
  static bool s_noEDNS;
  static bool s_rootNXTrust;
  static bool s_qnameminimization;
  static HardenNXD s_hardenNXD;
  static unsigned int s_refresh_ttlperc;
  static unsigned int s_locked_ttlperc;
  static int s_tcp_fast_open;
  static bool s_tcp_fast_open_connect;
  static bool s_dot_to_port_853;
  static unsigned int s_max_busy_dot_probes;
  static unsigned int s_max_CNAMES_followed;
  static unsigned int s_max_minimize_count;
  static unsigned int s_minimize_one_label;

  static const int event_trace_to_pb = 1;
  static const int event_trace_to_log = 2;
  static int s_event_trace_enabled;
  static bool s_save_parent_ns_set;
  static bool s_addExtendedResolutionDNSErrors;

  std::unordered_map<std::string, bool> d_discardedPolicies;
  DNSFilterEngine::Policy d_appliedPolicy;
  std::unordered_set<std::string> d_policyTags;
  boost::optional<string> d_routingTag;
  ComboAddress d_fromAuthIP;
  RecEventTrace d_eventTrace;
  std::shared_ptr<Logr::Logger> d_slog = g_slog->withName("syncres");
  boost::optional<EDNSExtendedError> d_extendedError;

  unsigned int d_authzonequeries;
  unsigned int d_outqueries;
  unsigned int d_tcpoutqueries;
  unsigned int d_dotoutqueries;
  unsigned int d_throttledqueries;
  unsigned int d_timeouts;
  unsigned int d_unreachables;
  unsigned int d_totUsec;
  unsigned int d_maxdepth{0};
  // Initialized ony once, as opposed to d_now which gets updated after outgoing requests
  struct timeval d_fixednow;

private:
  ComboAddress d_requestor;
  ComboAddress d_cacheRemote;

  static NetmaskGroup s_ednslocalsubnets;
  static NetmaskGroup s_ednsremotesubnets;
  static SuffixMatchNode s_ednsdomains;
  static EDNSSubnetOpts s_ecsScopeZero;
  static LogMode s_lm;
  static std::unique_ptr<NetmaskGroup> s_dontQuery;

  struct GetBestNSAnswer
  {
    DNSName qname;
    set<pair<DNSName, DNSName>> bestns;
    uint8_t qtype;
    bool operator<(const GetBestNSAnswer& bestAnswer) const
    {
      return std::tie(qtype, qname, bestns) < std::tie(bestAnswer.qtype, bestAnswer.qname, bestAnswer.bestns);
    }
  };

  using zonesStates_t = std::map<DNSName, vState>;
  enum StopAtDelegation
  {
    DontStop,
    Stop,
    Stopped
  };

  void resolveAdditionals(const DNSName& qname, QType qtype, AdditionalMode mode, std::vector<DNSRecord>& additionals, unsigned int depth, bool& additionalsNotInCache);
  void addAdditionals(QType qtype, const vector<DNSRecord>& start, vector<DNSRecord>& additionals, std::set<std::pair<DNSName, QType>>& uniqueCalls, std::set<std::tuple<DNSName, QType, QType>>& uniqueResults, unsigned int depth, unsigned int additionaldepth, bool& additionalsNotInCache);
  bool addAdditionals(QType qtype, vector<DNSRecord>& ret, unsigned int depth);

  void updateQueryCounts(const string& prefix, const DNSName& qname, const ComboAddress& address, bool doTCP, bool doDoT);
  static bool doDoTtoAuth(const DNSName& nameServer);
  int doResolveAt(NsSet& nameservers, DNSName auth, bool flawedNSSet, const DNSName& qname, QType qtype, vector<DNSRecord>& ret,
                  unsigned int depth, const string& prefix, set<GetBestNSAnswer>& beenthere, Context& context, StopAtDelegation* stopAtDelegation,
                  std::map<DNSName, std::vector<ComboAddress>>* fallback);
  void ednsStats(boost::optional<Netmask>& ednsmask, const DNSName& qname, const string& prefix);
  void incTimeoutStats(const ComboAddress& remoteIP);
  void checkTotalTime(const DNSName& qname, QType qtype, boost::optional<EDNSExtendedError>& extendedError) const;
  bool doResolveAtThisIP(const std::string& prefix, const DNSName& qname, QType qtype, LWResult& lwr, boost::optional<Netmask>& ednsmask, const DNSName& auth, bool sendRDQuery, bool wasForwarded, const DNSName& nsName, const ComboAddress& remoteIP, bool doTCP, bool doDoT, bool& truncated, bool& spoofed, boost::optional<EDNSExtendedError>& extendedError, bool dontThrottle = false);
  bool processAnswer(unsigned int depth, const string& prefix, LWResult& lwr, const DNSName& qname, QType qtype, DNSName& auth, bool wasForwarded, const boost::optional<Netmask>& ednsmask, bool sendRDQuery, NsSet& nameservers, std::vector<DNSRecord>& ret, const DNSFilterEngine& dfe, bool* gotNewServers, int* rcode, vState& state, const ComboAddress& remoteIP);

  int doResolve(const DNSName& qname, QType qtype, vector<DNSRecord>& ret, unsigned int depth, set<GetBestNSAnswer>& beenthere, Context& context);
  int doResolveNoQNameMinimization(const DNSName& qname, QType qtype, vector<DNSRecord>& ret, unsigned int depth, set<GetBestNSAnswer>& beenthere, Context& context, bool* fromCache = nullptr, StopAtDelegation* stopAtDelegation = nullptr);
  bool doOOBResolve(const AuthDomain& domain, const DNSName& qname, QType qtype, vector<DNSRecord>& ret, int& res);
  bool doOOBResolve(const DNSName& qname, QType qtype, vector<DNSRecord>& ret, unsigned int depth, const string& prefix, int& res);
  static bool isRecursiveForwardOrAuth(const DNSName& qname);
  static bool isForwardOrAuth(const DNSName& qname);
  static domainmap_t::const_iterator getBestAuthZone(DNSName* qname);
  bool doCNAMECacheCheck(const DNSName& qname, QType qtype, vector<DNSRecord>& ret, unsigned int depth, const string& prefix, int& res, Context& context, bool wasAuthZone, bool wasForwardRecurse, bool checkForDups);
  bool doCacheCheck(const DNSName& qname, const DNSName& authname, bool wasForwardedOrAuthZone, bool wasAuthZone, bool wasForwardRecurse, QType qtype, vector<DNSRecord>& ret, unsigned int depth, const string& prefix, int& res, Context& context);
  bool canUseRecords(const std::string& prefix, const DNSName& qname, const DNSName& name, QType qtype, vState state);
  void getBestNSFromCache(const DNSName& qname, QType qtype, vector<DNSRecord>& bestns, bool* flawedNSSet, unsigned int depth, const string& prefix, set<GetBestNSAnswer>& beenthere, const boost::optional<DNSName>& cutOffDomain = boost::none);
  DNSName getBestNSNamesFromCache(const DNSName& qname, QType qtype, NsSet& nsset, bool* flawedNSSet, unsigned int depth, const string& prefix, set<GetBestNSAnswer>& beenthere);

  vector<std::pair<DNSName, float>> shuffleInSpeedOrder(const DNSName& qname, NsSet& nameservers, const string& prefix);
  vector<ComboAddress> shuffleForwardSpeed(const DNSName& qname, const vector<ComboAddress>& rnameservers, const string& prefix, bool wasRd);
  static bool moreSpecificThan(const DNSName& lhs, const DNSName& rhs);
  void selectNSOnSpeed(const DNSName& qname, const string& prefix, vector<ComboAddress>& ret);
  vector<ComboAddress> getAddrs(const DNSName& qname, unsigned int depth, const string& prefix, set<GetBestNSAnswer>& beenthere, bool cacheOnly, unsigned int& addressQueriesForNS);

  bool nameserversBlockedByRPZ(const DNSFilterEngine& dfe, const NsSet& nameservers);
  bool nameserverIPBlockedByRPZ(const DNSFilterEngine& dfe, const ComboAddress&);
  void checkMaxQperQ(const DNSName& qname) const;
  bool throttledOrBlocked(const std::string& prefix, const ComboAddress& remoteIP, const DNSName& qname, QType qtype, bool pierceDontQuery);

  vector<ComboAddress> retrieveAddressesForNS(const std::string& prefix, const DNSName& qname, vector<std::pair<DNSName, float>>::const_iterator& tns, unsigned int depth, set<GetBestNSAnswer>& beenthere, const vector<std::pair<DNSName, float>>& rnameservers, NsSet& nameservers, bool& sendRDQuery, bool& pierceDontQuery, bool& flawedNSSet, bool cacheOnly, unsigned int& nretrieveAddressesForNS);

  void sanitizeRecords(const std::string& prefix, LWResult& lwr, const DNSName& qname, QType qtype, const DNSName& auth, bool wasForwarded, bool rdQuery);
  void sanitizeRecordsPass2(const std::string& prefix, LWResult& lwr, const DNSName& qname, QType qtype, const DNSName& auth, std::unordered_set<DNSName>& allowedAnswerNames, std::unordered_set<DNSName>& allowedAdditionals, bool cnameSeen, bool delegationAccepted, std::vector<bool>& skipvec, unsigned int& skipCount);
  /* This function will check whether the answer should have the AA bit set, and will set if it should be set and isn't.
     This is unfortunately needed to deal with very crappy so-called DNS servers */
  void fixupAnswer(const std::string& prefix, LWResult& lwr, const DNSName& qname, QType qtype, const DNSName& auth, bool wasForwarded, bool rdQuery);
  void rememberParentSetIfNeeded(const DNSName& domain, const vector<DNSRecord>& newRecords, unsigned int depth, const string& prefix);
  RCode::rcodes_ updateCacheFromRecords(unsigned int depth, const string& prefix, LWResult& lwr, const DNSName& qname, QType qtype, const DNSName& auth, bool wasForwarded, const boost::optional<Netmask>&, vState& state, bool& needWildcardProof, bool& gatherWildcardProof, unsigned int& wildcardLabelsCount, bool sendRDQuery, const ComboAddress& remoteIP);
  bool processRecords(const std::string& prefix, const DNSName& qname, QType qtype, const DNSName& auth, LWResult& lwr, bool sendRDQuery, vector<DNSRecord>& ret, set<DNSName>& nsset, DNSName& newtarget, DNSName& newauth, bool& realreferral, bool& negindic, vState& state, bool needWildcardProof, bool gatherwildcardProof, unsigned int wildcardLabelsCount, int& rcode, bool& negIndicHasSignatures, unsigned int depth);

  bool doSpecialNamesResolve(const DNSName& qname, QType qtype, QClass qclass, vector<DNSRecord>& ret);

  LWResult::Result asyncresolveWrapper(const ComboAddress& address, bool ednsMANDATORY, const DNSName& domain, const DNSName& auth, int type, bool doTCP, bool sendRDQuery, struct timeval* now, boost::optional<Netmask>& srcmask, LWResult* res, bool* chained, const DNSName& nsName) const;

  boost::optional<Netmask> getEDNSSubnetMask(const DNSName& name, const ComboAddress& rem);

  static bool validationEnabled();
  uint32_t computeLowestTTD(const std::vector<DNSRecord>& records, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures, uint32_t signaturesTTL, const std::vector<std::shared_ptr<DNSRecord>>& authorityRecs) const;
  void updateValidationState(const DNSName& qname, vState& state, vState stateUpdate, const string& prefix);
  vState validateRecordsWithSigs(unsigned int depth, const string& prefix, const DNSName& qname, QType qtype, const DNSName& name, QType type, const std::vector<DNSRecord>& records, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures);
  vState validateDNSKeys(const DNSName& zone, const std::vector<DNSRecord>& dnskeys, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures, unsigned int depth, const string& prefix);
  vState getDNSKeys(const DNSName& signer, skeyset_t& keys, bool& servFailOccurred, unsigned int depth, const string& prefix);
  dState getDenialValidationState(const NegCache::NegCacheEntry& negEntry, dState expectedState, bool referralToUnsigned, const string& prefix);
  void updateDenialValidationState(const DNSName& qname, vState& neValidationState, const DNSName& neName, vState& state, dState denialState, dState expectedState, bool isDS, unsigned int depth, const string& prefix);
  void computeNegCacheValidationStatus(const NegCache::NegCacheEntry& negEntry, const DNSName& qname, QType qtype, int res, vState& state, unsigned int depth, const string& prefix);
  vState getTA(const DNSName& zone, dsset_t& dsSet, const string& prefix);
  vState getValidationStatus(const DNSName& name, bool wouldBeValid, bool typeIsDS, unsigned int depth, const string& prefix);
  void updateValidationStatusInCache(const DNSName& qname, QType qtype, bool aaFlag, vState newState) const;
  void initZoneCutsFromTA(const DNSName& from, const string& prefix);
  size_t countSupportedDS(const dsset_t& dsSet, const string& prefix);

  void handleNewTarget(const std::string& prefix, const DNSName& qname, const DNSName& newtarget, QType qtype, std::vector<DNSRecord>& ret, int& rcode, unsigned int depth, const std::vector<DNSRecord>& recordsFromAnswer, vState& state);

  void handlePolicyHit(const std::string& prefix, const DNSName& qname, QType qtype, vector<DNSRecord>& ret, bool& done, int& rcode, unsigned int depth);
  unsigned int getAdjustedRecursionBound() const;

  void checkWildcardProof(const DNSName& qname, const QType& qtype, DNSRecord& rec, const LWResult& lwr, vState& state, unsigned int depth, const std::string& prefix, unsigned int wildcardLabelsCount);

  void setUpdatingRootNS()
  {
    d_updatingRootNS = true;
  }

  std::string getPrefix(unsigned int depth) const
  {
    if (!doLog()) {
      return "";
    }
    auto prefix = d_prefix;
    prefix.append(depth, ' ');
    return prefix;
  }

  zonesStates_t d_cutStates;
  ostringstream d_trace;
  shared_ptr<RecursorLua4> d_pdl;
  boost::optional<Netmask> d_outgoingECSNetwork;
  std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>> d_outgoingProtobufServers;
  std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>> d_frameStreamServers;
  boost::optional<const boost::uuids::uuid&> d_initialRequestId;
  pdns::validation::ValidationContext d_validationContext;
  asyncresolve_t d_asyncResolve{nullptr};
  // d_now is initialized in the constructor and updates after outgoing requests in lwres.cc:asyncresolve
  struct timeval d_now;
  /* if the client is asking for a DS that does not exist, we need to provide the SOA along with the NSEC(3) proof
     and we might not have it if we picked up the proof from a delegation */
  DNSName d_externalDSQuery;
  string d_prefix;
  vState d_queryValidationState{vState::Indeterminate};

  /* When d_cacheonly is set to true, we will only check the cache.
   * This is set when the RD bit is unset in the incoming query
   */
  bool d_cacheonly;
  bool d_doDNSSEC;
  bool d_DNSSECValidationRequested{false};
  bool d_doEDNS0{true};
  bool d_requireAuthData{true};
  bool d_updatingRootNS{false};
  bool d_wantsRPZ{true};
  bool d_wasOutOfBand{false};
  bool d_wasVariable{false};
  bool d_qNameMinimization{false};
  bool d_qNameMinimizationFallbackMode{false};
  bool d_queryReceivedOverTCP{false};
  bool d_followCNAME{true};
  bool d_refresh{false};
  bool d_serveStale{false};

  LogMode d_lm;
};

/* external functions, opaque to us */
LWResult::Result asendtcp(const PacketBuffer& data, shared_ptr<TCPIOHandler>&);
LWResult::Result arecvtcp(PacketBuffer& data, size_t len, shared_ptr<TCPIOHandler>&, bool incompleteOkay);
void mthreadSleep(unsigned int jitterMsec);

enum TCPAction : uint8_t
{
  DoingRead,
  DoingWrite
};

struct PacketID
{
  PacketID()
  {
    remote.reset();
  }

  ComboAddress remote; // this is the remote
  DNSName domain; // this is the question

  PacketBuffer inMSG; // they'll go here
  PacketBuffer outMSG; // the outgoing message that needs to be sent

  using chain_t = set<std::pair<int, uint16_t>>;
  mutable chain_t authReqChain;
  shared_ptr<TCPIOHandler> tcphandler{nullptr};
  timeval creationTime{};
  std::optional<Netmask> ecsSubnet;
  string::size_type inPos{0}; // how far are we along in the inMSG
  size_t inWanted{0}; // if this is set, we'll read until inWanted bytes are read
  string::size_type outPos{0}; // how far we are along in the outMSG
  mutable uint32_t nearMisses{0}; // number of near misses - host correct, id wrong
  int fd{-1};
  int tcpsock{0}; // or wait for an event on a TCP fd
  mutable bool closed{false}; // Processing already started, don't accept new chained ids
  bool inIncompleteOkay{false};
  uint16_t id{0}; // wait for a specific id/remote pair
  uint16_t type{0}; // and this is its type
  TCPAction highState{TCPAction::DoingRead};
  IOState lowState{IOState::NeedRead};

  bool operator<(const PacketID& /* b */) const
  {
    // We don't want explicit PacketID compare here, but always via predicate classes below
    assert(0); // NOLINT: lib
  }
};

inline ostream& operator<<(ostream& ostr, const PacketID& pid)
{
  return ostr << "PacketID(id=" << pid.id << ",remote=" << pid.remote.toString() << ",type=" << pid.type << ",tcpsock=" << pid.tcpsock << ",fd=" << pid.fd << ",name=" << pid.domain << ",ecs=" << (pid.ecsSubnet ? pid.ecsSubnet->toString() : "") << ')';
}

inline ostream& operator<<(ostream& ostr, const shared_ptr<PacketID>& pid)
{
  return ostr << *pid;
}

/*
 * The two compare predicates below must be consistent!
 * PacketIDBirthdayCompare can omit minor fields, but not change the or skip fields
 * order! See boost docs on CompatibleCompare.
 */
struct PacketIDCompare
{
  bool operator()(const std::shared_ptr<PacketID>& lhs, const std::shared_ptr<PacketID>& rhs) const
  {
    if (std::tie(lhs->remote, lhs->tcpsock, lhs->type) < std::tie(rhs->remote, rhs->tcpsock, rhs->type)) {
      return true;
    }
    if (std::tie(lhs->remote, lhs->tcpsock, lhs->type) > std::tie(rhs->remote, rhs->tcpsock, rhs->type)) {
      return false;
    }

    return std::tie(lhs->domain, lhs->fd, lhs->id) < std::tie(rhs->domain, rhs->fd, rhs->id);
  }
};

struct PacketIDBirthdayCompare
{
  bool operator()(const std::shared_ptr<PacketID>& lhs, const std::shared_ptr<PacketID>& rhs) const
  {
    if (std::tie(lhs->remote, lhs->tcpsock, lhs->type) < std::tie(rhs->remote, rhs->tcpsock, rhs->type)) {
      return true;
    }
    if (std::tie(lhs->remote, lhs->tcpsock, lhs->type) > std::tie(rhs->remote, rhs->tcpsock, rhs->type)) {
      return false;
    }
    return lhs->domain < rhs->domain;
  }
};
extern std::unique_ptr<MemRecursorCache> g_recCache;

extern rec::GlobalCounters g_Counters;
extern thread_local rec::TCounters t_Counters;

//! represents a running TCP/IP client session
class TCPConnection
{
public:
  TCPConnection(int fileDesc, const ComboAddress& addr);
  ~TCPConnection();
  TCPConnection(const TCPConnection&) = delete;
  TCPConnection& operator=(const TCPConnection&) = delete;
  TCPConnection(TCPConnection&&) = delete;
  TCPConnection& operator=(TCPConnection&&) = delete;

  [[nodiscard]] int getFD() const
  {
    return d_fd;
  }
  void setDropOnIdle()
  {
    d_dropOnIdle = true;
  }
  [[nodiscard]] bool isDropOnIdle() const
  {
    return d_dropOnIdle;
  }

  // The max number of concurrent TCP requests we're willing to process
  static uint16_t s_maxInFlight;
  static unsigned int getCurrentConnections() { return s_currentConnections; }

  std::vector<ProxyProtocolValue> proxyProtocolValues;
  std::string data;
  ComboAddress d_remote;
  ComboAddress d_source;
  ComboAddress d_destination;
  ComboAddress d_mappedSource;
  size_t queriesCount{0};
  size_t proxyProtocolGot{0};
  ssize_t proxyProtocolNeed{0};
  enum stateenum
  {
    PROXYPROTOCOLHEADER,
    BYTE0,
    BYTE1,
    GETQUESTION,
    DONE
  } state{BYTE0};
  uint16_t qlen{0};
  uint16_t bytesread{0};
  uint16_t d_requestsInFlight{0}; // number of mthreads spawned for this connection

private:
  int d_fd;
  static std::atomic<uint32_t> s_currentConnections; //!< total number of current TCP connections
  bool d_dropOnIdle{false};
};

class ImmediateServFailException
{
public:
  ImmediateServFailException(string reason_) :
    reason(std::move(reason_)){};

  string reason; //! Print this to tell the user what went wrong
};

class PolicyHitException
{
};

class ImmediateQueryDropException
{
};

class SendTruncatedAnswerException
{
};

using addrringbuf_t = boost::circular_buffer<ComboAddress>;
extern thread_local std::unique_ptr<addrringbuf_t> t_servfailremotes, t_largeanswerremotes, t_remotes, t_bogusremotes, t_timeouts;

extern thread_local std::unique_ptr<boost::circular_buffer<pair<DNSName, uint16_t>>> t_queryring, t_servfailqueryring, t_bogusqueryring;
extern thread_local std::shared_ptr<NetmaskGroup> t_allowFrom;
extern thread_local std::shared_ptr<NetmaskGroup> t_allowNotifyFrom;
extern unsigned int g_networkTimeoutMsec;
extern uint16_t g_outgoingEDNSBufsize;
extern std::atomic<uint32_t> g_maxCacheEntries, g_maxPacketCacheEntries;
extern bool g_lowercaseOutgoing;

using pipefunc_t = std::function<void*()>;
void broadcastFunction(const pipefunc_t& func);
void distributeAsyncFunction(const std::string& packet, const pipefunc_t& func);

int directResolve(const DNSName& qname, QType qtype, QClass qclass, vector<DNSRecord>& ret, const shared_ptr<RecursorLua4>& pdl, Logr::log_t);
int directResolve(const DNSName& qname, QType qtype, QClass qclass, vector<DNSRecord>& ret, const shared_ptr<RecursorLua4>& pdl, bool qnamemin, Logr::log_t);
int followCNAMERecords(std::vector<DNSRecord>& ret, QType qtype, int rcode);
int getFakeAAAARecords(const DNSName& qname, ComboAddress prefix, vector<DNSRecord>& ret);
int getFakePTRRecords(const DNSName& qname, vector<DNSRecord>& ret);

template <class T>
T broadcastAccFunction(const std::function<T*()>& func);

using notifyset_t = std::unordered_set<DNSName>;
std::tuple<std::shared_ptr<SyncRes::domainmap_t>, std::shared_ptr<notifyset_t>> parseZoneConfiguration(bool yaml);
void* pleaseSupplantAllowNotifyFor(std::shared_ptr<notifyset_t> allowNotifyFor);

uint64_t* pleaseGetNsSpeedsSize();
uint64_t* pleaseGetFailedServersSize();
uint64_t* pleaseGetConcurrentQueries();
uint64_t* pleaseGetThrottleSize();
void doCarbonDump(void*);
bool primeHints(time_t now = time(nullptr));

using timebuf_t = std::array<char, 64>;
const char* isoDateTimeMillis(const struct timeval& tval, timebuf_t& buf);

struct WipeCacheResult
{
  int record_count = 0;
  int negative_record_count = 0;
  int packet_count = 0;
};

struct WipeCacheResult wipeCaches(const DNSName& canon, bool subtree, uint16_t qtype);

extern __thread struct timeval g_now;

struct ThreadTimes
{
  uint64_t msec{0};
  vector<uint64_t> times;
  ThreadTimes& operator+=(const ThreadTimes& rhs)
  {
    times.push_back(rhs.msec);
    return *this;
  }
};
