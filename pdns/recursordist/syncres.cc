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
#include <optional>
#ifdef HAVE_CONFIG_H
#include <utility>

#include "config.h"
#endif

#include "arguments.hh"
#include "aggressive_nsec.hh"
#include "cachecleaner.hh"
#include "dns_random.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "ednssubnet.hh"
#include "logger.hh"
#include "lua-recursor4.hh"
#include "rec-lua-conf.hh"
#include "syncres.hh"
#include "dnssec.hh"
#include "validate-recursor.hh"
#include "rec-taskqueue.hh"
#include "shuffle.hh"
#include "rec-nsspeeds.hh"

rec::GlobalCounters g_Counters;
thread_local rec::TCounters t_Counters(g_Counters);

template <class T>
class fails_t : public boost::noncopyable
{
public:
  using counter_t = uint64_t;
  struct value_t
  {
    value_t(T arg) :
      key(std::move(arg)) {}
    T key;
    mutable counter_t value{0};
    time_t last{0};
  };

  using cont_t = multi_index_container<value_t,
                                       indexed_by<
                                         ordered_unique<tag<T>, member<value_t, T, &value_t::key>>,
                                         ordered_non_unique<tag<time_t>, member<value_t, time_t, &value_t::last>>>>;

  [[nodiscard]] cont_t getMapCopy() const
  {
    return d_cont;
  }

  [[nodiscard]] counter_t value(const T& arg) const
  {
    auto iter = d_cont.find(arg);

    if (iter == d_cont.end()) {
      return 0;
    }
    return iter->value;
  }

  counter_t incr(const T& key, const struct timeval& now)
  {
    auto iter = d_cont.insert(key).first;

    if (iter->value < std::numeric_limits<counter_t>::max()) {
      iter->value++;
    }
    auto& ind = d_cont.template get<T>();
    time_t nowSecs = now.tv_sec;
    ind.modify(iter, [nowSecs](value_t& val) { val.last = nowSecs; });
    return iter->value;
  }

  void clear(const T& arg)
  {
    d_cont.erase(arg);
  }

  void clear()
  {
    d_cont.clear();
  }

  [[nodiscard]] size_t size() const
  {
    return d_cont.size();
  }

  void prune(time_t cutoff)
  {
    auto& ind = d_cont.template get<time_t>();
    ind.erase(ind.begin(), ind.upper_bound(cutoff));
  }

private:
  cont_t d_cont;
};

static LockGuarded<nsspeeds_t> s_nsSpeeds;

size_t SyncRes::getNSSpeedTable(size_t maxSize, std::string& ret)
{
  const auto copy = *s_nsSpeeds.lock();
  return copy.getPB(s_serverID, maxSize, ret);
}

size_t SyncRes::putIntoNSSpeedTable(const std::string& ret)
{
  auto lock = s_nsSpeeds.lock();
  return lock->putPB(time(nullptr) - 300, ret);
}

class Throttle
{
public:
  Throttle() = default;
  ~Throttle() = default;
  Throttle(Throttle&&) = delete;
  Throttle& operator=(const Throttle&) = default;
  Throttle& operator=(Throttle&&) = delete;
  Throttle(const Throttle&) = delete;

  using Key = std::tuple<ComboAddress, DNSName, QType>;
  using Reason = SyncRes::ThrottleReason;

  struct entry_t
  {
    entry_t(Key thing_, time_t ttd_, unsigned int count_, Reason reason_) :
      thing(std::move(thing_)), ttd(ttd_), count(count_), reason(reason_)
    {
    }
    Key thing;
    time_t ttd;
    mutable unsigned int count;
    Reason reason;
  };
  using cont_t = multi_index_container<entry_t,
                                       indexed_by<
                                         ordered_unique<tag<Key>, member<entry_t, Key, &entry_t::thing>>,
                                         ordered_non_unique<tag<time_t>, member<entry_t, time_t, &entry_t::ttd>>>>;

  bool shouldThrottle(time_t now, const Key& arg)
  {
    auto iter = d_cont.find(arg);
    if (iter == d_cont.end()) {
      return false;
    }
    if (now > iter->ttd || iter->count == 0) {
      d_cont.erase(iter);
      return false;
    }
    iter->count--;

    return true; // still listed, still blocked
  }

  void throttle(time_t now, const Key& arg, time_t ttl, unsigned int count, Reason reason)
  {
    auto iter = d_cont.find(arg);
    time_t ttd = now + ttl;
    if (iter == d_cont.end()) {
      d_cont.emplace(arg, ttd, count, reason);
    }
    else if (ttd > iter->ttd || count > iter->count) {
      ttd = std::max(iter->ttd, ttd);
      count = std::max(iter->count, count);
      auto& ind = d_cont.template get<Key>();
      ind.modify(iter, [ttd, count, reason](entry_t& entry) {
        entry.ttd = ttd;
        entry.count = count;
        entry.reason = reason;
      });
    }
  }

  [[nodiscard]] size_t size() const
  {
    return d_cont.size();
  }

  [[nodiscard]] cont_t getThrottleMap() const
  {
    return d_cont;
  }

  void clear()
  {
    d_cont.clear();
  }

  void clear(const Key& thing)
  {
    d_cont.erase(thing);
  }
  void prune(time_t now)
  {
    auto& ind = d_cont.template get<time_t>();
    ind.erase(ind.begin(), ind.upper_bound(now));
  }

  static std::string toString(Reason reason)
  {
    static const std::array<std::string, 10> reasons = {
      "None",
      "ServerDown",
      "PermanentError",
      "Timeout",
      "ParseError",
      "RCodeServFail",
      "RCodeRefused",
      "RCodeOther",
      "TCPTruncate",
      "Lame"};
    const auto index = static_cast<unsigned int>(reason);
    if (index >= reasons.size()) {
      return "?";
    }
    return reasons.at(index);
  }

private:
  cont_t d_cont;
};

static LockGuarded<Throttle> s_throttle;

struct SavedParentEntry
{
  SavedParentEntry(DNSName name, map<DNSName, vector<ComboAddress>>&& nsAddresses, time_t ttd) :
    d_domain(std::move(name)), d_nsAddresses(std::move(nsAddresses)), d_ttd(ttd)
  {
  }
  DNSName d_domain;
  map<DNSName, vector<ComboAddress>> d_nsAddresses;
  time_t d_ttd;
  mutable uint64_t d_count{0};
};

using SavedParentNSSetBase = multi_index_container<
  SavedParentEntry,
  indexed_by<ordered_unique<tag<DNSName>, member<SavedParentEntry, DNSName, &SavedParentEntry::d_domain>>,
             ordered_non_unique<tag<time_t>, member<SavedParentEntry, time_t, &SavedParentEntry::d_ttd>>>>;

class SavedParentNSSet : public SavedParentNSSetBase
{
public:
  void prune(time_t now)
  {
    auto& ind = get<time_t>();
    ind.erase(ind.begin(), ind.upper_bound(now));
  }
  void inc(const DNSName& name)
  {
    auto iter = find(name);
    if (iter != end()) {
      ++(*iter).d_count;
    }
  }
  [[nodiscard]] SavedParentNSSet getMapCopy() const
  {
    return *this;
  }
};

static LockGuarded<SavedParentNSSet> s_savedParentNSSet;

thread_local SyncRes::ThreadLocalStorage SyncRes::t_sstorage;
thread_local std::unique_ptr<addrringbuf_t> t_timeouts;

std::unique_ptr<NetmaskGroup> SyncRes::s_dontQuery{nullptr};
NetmaskGroup SyncRes::s_ednslocalsubnets;
NetmaskGroup SyncRes::s_ednsremotesubnets;
SuffixMatchNode SyncRes::s_ednsdomains;
EDNSSubnetOpts SyncRes::s_ecsScopeZero;
string SyncRes::s_serverID;
SyncRes::LogMode SyncRes::s_lm;
static LockGuarded<fails_t<ComboAddress>> s_fails;
static LockGuarded<fails_t<DNSName>> s_nonresolving;

struct DoTStatus
{
  DoTStatus(const ComboAddress& address, DNSName auth, time_t ttd) :
    d_address(address), d_auth(std::move(auth)), d_ttd(ttd)
  {
  }
  enum Status : uint8_t
  {
    Unknown,
    Busy,
    Bad,
    Good
  };
  ComboAddress d_address;
  DNSName d_auth;
  time_t d_ttd;
  mutable uint64_t d_count{0};
  mutable Status d_status{Unknown};
  std::string toString() const
  {
    const std::array<std::string, 4> names{"Unknown", "Busy", "Bad", "Good"};
    auto val = static_cast<unsigned int>(d_status);
    return val >= names.size() ? "?" : names.at(val);
  }
};

struct DoTMap
{
  multi_index_container<DoTStatus,
                        indexed_by<
                          ordered_unique<tag<ComboAddress>, member<DoTStatus, const ComboAddress, &DoTStatus::d_address>>,
                          ordered_non_unique<tag<time_t>, member<DoTStatus, time_t, &DoTStatus::d_ttd>>>>
    d_map;
  uint64_t d_numBusy{0};

  void prune(time_t cutoff)
  {
    auto& ind = d_map.template get<time_t>();
    ind.erase(ind.begin(), ind.upper_bound(cutoff));
  }
};

static LockGuarded<DoTMap> s_dotMap;

static const time_t dotFailWait = static_cast<time_t>(24) * 3600;
static const time_t dotSuccessWait = static_cast<time_t>(3) * 24 * 3600;
static bool shouldDoDoT(ComboAddress address, time_t now);

unsigned int SyncRes::s_maxnegttl;
unsigned int SyncRes::s_maxbogusttl;
unsigned int SyncRes::s_maxcachettl;
unsigned int SyncRes::s_maxqperq;
unsigned int SyncRes::s_maxnsperresolve;
unsigned int SyncRes::s_maxnsaddressqperq;
unsigned int SyncRes::s_maxtotusec;
unsigned int SyncRes::s_maxdepth;
unsigned int SyncRes::s_minimumTTL;
unsigned int SyncRes::s_minimumECSTTL;
unsigned int SyncRes::s_packetcachettl;
unsigned int SyncRes::s_packetcacheservfailttl;
unsigned int SyncRes::s_packetcachenegativettl;
unsigned int SyncRes::s_serverdownmaxfails;
unsigned int SyncRes::s_serverdownthrottletime;
unsigned int SyncRes::s_unthrottle_n;
unsigned int SyncRes::s_nonresolvingnsmaxfails;
unsigned int SyncRes::s_nonresolvingnsthrottletime;
unsigned int SyncRes::s_ecscachelimitttl;
unsigned int SyncRes::s_maxvalidationsperq;
unsigned int SyncRes::s_maxnsec3iterationsperq;
pdns::stat_t SyncRes::s_ecsqueries;
pdns::stat_t SyncRes::s_ecsresponses;
std::map<uint8_t, pdns::stat_t> SyncRes::s_ecsResponsesBySubnetSize4;
std::map<uint8_t, pdns::stat_t> SyncRes::s_ecsResponsesBySubnetSize6;

uint8_t SyncRes::s_ecsipv4limit;
uint8_t SyncRes::s_ecsipv6limit;
uint8_t SyncRes::s_ecsipv4cachelimit;
uint8_t SyncRes::s_ecsipv6cachelimit;
bool SyncRes::s_ecsipv4nevercache;
bool SyncRes::s_ecsipv6nevercache;

bool SyncRes::s_doIPv4;
bool SyncRes::s_doIPv6;
bool SyncRes::s_rootNXTrust;
bool SyncRes::s_noEDNS;
bool SyncRes::s_qnameminimization;
bool SyncRes::s_outAnyToTcp;
SyncRes::HardenNXD SyncRes::s_hardenNXD;
unsigned int SyncRes::s_refresh_ttlperc;
unsigned int SyncRes::s_locked_ttlperc;
int SyncRes::s_tcp_fast_open;
bool SyncRes::s_tcp_fast_open_connect;
bool SyncRes::s_dot_to_port_853;
int SyncRes::s_event_trace_enabled;
bool SyncRes::s_save_parent_ns_set;
unsigned int SyncRes::s_max_busy_dot_probes;
unsigned int SyncRes::s_max_CNAMES_followed;
bool SyncRes::s_addExtendedResolutionDNSErrors;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LOG(x)                       \
  if (d_lm == Log) {                 \
    g_log << Logger::Warning << x;   \
  }                                  \
  else if (d_lm == Store) {          \
    addTraceTS(d_fixednow, d_trace); \
    d_trace << x;                    \
  }

OptLog SyncRes::LogObject(const string& prefix)
{
  OptLog ret;
  if (d_lm == Log) {
    ret = {prefix, d_fixednow, g_log};
  }
  else if (d_lm == Store) {
    ret = {prefix, d_fixednow, d_trace};
  }
  return ret;
}

static bool pushResolveIfNotInNegCache(const DNSName& qname, QType qtype, const struct timeval& now)
{
  NegCache::NegCacheEntry negEntry;
  bool inNegCache = g_negCache->get(qname, qtype, now, negEntry, false);
  if (!inNegCache) {
    // There are a few cases where an answer is neither stored in the record cache nor in the neg cache.
    // An example is a SOA-less NODATA response. Rate limiting will kick in if those tasks are pushed too often.
    // We might want to fix these cases (and always either store positive or negative) some day.
    pushResolveTask(qname, qtype, now.tv_sec, now.tv_sec + 60, false);
  }
  return !inNegCache;
}

// A helper function to print a double with specific printf format.
// Not using boost::format since it is not thread safe while calling
// into locale handling code according to tsan.
// This allocates a string, but that's nothing compared to what
// boost::format is doing and may even be optimized away anyway.
static inline std::string fmtfloat(double value)
{
  std::array<char, 20> buf{};
  int ret = snprintf(buf.data(), buf.size(), "%0.2f", value);
  if (ret < 0 || ret >= static_cast<int>(buf.size())) {
    return "?";
  }
  return {buf.data(), static_cast<size_t>(ret)};
}

static inline void accountAuthLatency(uint64_t usec, int family)
{
  if (family == AF_INET) {
    t_Counters.at(rec::Histogram::auth4Answers)(usec);
    t_Counters.at(rec::Histogram::cumulativeAuth4Answers)(usec);
  }
  else {
    t_Counters.at(rec::Histogram::auth6Answers)(usec);
    t_Counters.at(rec::Histogram::cumulativeAuth6Answers)(usec);
  }
}

SyncRes::SyncRes(const struct timeval& now) :
  d_authzonequeries(0), d_outqueries(0), d_tcpoutqueries(0), d_dotoutqueries(0), d_throttledqueries(0), d_timeouts(0), d_unreachables(0), d_totUsec(0), d_fixednow(now), d_now(now), d_cacheonly(false), d_doDNSSEC(false), d_doEDNS0(false), d_qNameMinimization(s_qnameminimization), d_lm(s_lm)
{
  d_validationContext.d_nsec3IterationsRemainingQuota = s_maxnsec3iterationsperq > 0 ? s_maxnsec3iterationsperq : std::numeric_limits<decltype(d_validationContext.d_nsec3IterationsRemainingQuota)>::max();
}

static void allowAdditionalEntry(std::unordered_set<DNSName>& allowedAdditionals, const DNSRecord& rec);

void SyncRes::resolveAdditionals(const DNSName& qname, QType qtype, AdditionalMode mode, std::vector<DNSRecord>& additionals, unsigned int depth, bool& additionalsNotInCache)
{
  vector<DNSRecord> addRecords;

  Context context;
  switch (mode) {
  case AdditionalMode::ResolveImmediately: {
    set<GetBestNSAnswer> beenthere;
    int res = doResolve(qname, qtype, addRecords, depth, beenthere, context);
    if (res != 0) {
      return;
    }
    // We're conservative here. We do not add Bogus records in any circumstance, we add Indeterminates only if no
    // validation is required.
    if (vStateIsBogus(context.state)) {
      return;
    }
    if (shouldValidate() && context.state != vState::Secure && context.state != vState::Insecure) {
      return;
    }
    for (auto& rec : addRecords) {
      if (rec.d_place == DNSResourceRecord::ANSWER) {
        additionals.push_back(std::move(rec));
      }
    }
    break;
  }
  case AdditionalMode::CacheOnly:
  case AdditionalMode::CacheOnlyRequireAuth: {
    // Peek into cache
    MemRecursorCache::Flags flags = mode == AdditionalMode::CacheOnlyRequireAuth ? MemRecursorCache::RequireAuth : MemRecursorCache::None;
    if (g_recCache->get(d_now.tv_sec, qname, qtype, flags, &addRecords, d_cacheRemote, d_routingTag, nullptr, nullptr, nullptr, &context.state) <= 0) {
      return;
    }
    // See the comment for the ResolveImmediately case
    if (vStateIsBogus(context.state)) {
      return;
    }
    if (shouldValidate() && context.state != vState::Secure && context.state != vState::Insecure) {
      return;
    }
    for (auto& rec : addRecords) {
      if (rec.d_place == DNSResourceRecord::ANSWER) {
        rec.d_ttl -= d_now.tv_sec;
        additionals.push_back(std::move(rec));
      }
    }
    break;
  }
  case AdditionalMode::ResolveDeferred: {
    const bool oldCacheOnly = setCacheOnly(true);
    set<GetBestNSAnswer> beenthere;
    int res = doResolve(qname, qtype, addRecords, depth, beenthere, context);
    setCacheOnly(oldCacheOnly);
    if (res == 0 && !addRecords.empty()) {
      // We're conservative here. We do not add Bogus records in any circumstance, we add Indeterminates only if no
      // validation is required.
      if (vStateIsBogus(context.state)) {
        return;
      }
      if (shouldValidate() && context.state != vState::Secure && context.state != vState::Insecure) {
        return;
      }
      bool found = false;
      for (auto& rec : addRecords) {
        if (rec.d_place == DNSResourceRecord::ANSWER) {
          found = true;
          additionals.push_back(std::move(rec));
        }
      }
      if (found) {
        return;
      }
    }
    // Not found in cache, check negcache and push task if also not in negcache
    if (pushResolveIfNotInNegCache(qname, qtype, d_now)) {
      additionalsNotInCache = true;
    }
    break;
  }
  case AdditionalMode::Ignore:
    break;
  }
}

// The main (recursive) function to add additionals
// qtype: the original query type to expand
// start: records to start from
// This function uses to state sets to avoid infinite recursion and allow depulication
// depth is the main recursion depth
// additionaldepth is the depth for addAdditionals itself
void SyncRes::addAdditionals(QType qtype, const vector<DNSRecord>& start, vector<DNSRecord>& additionals, std::set<std::pair<DNSName, QType>>& uniqueCalls, std::set<std::tuple<DNSName, QType, QType>>& uniqueResults, unsigned int depth, unsigned additionaldepth, bool& additionalsNotInCache)
{
  if (additionaldepth >= 5 || start.empty()) {
    return;
  }

  auto luaLocal = g_luaconfs.getLocal();
  const auto iter = luaLocal->allowAdditionalQTypes.find(qtype);
  if (iter == luaLocal->allowAdditionalQTypes.end()) {
    return;
  }
  std::unordered_set<DNSName> addnames;
  for (const auto& rec : start) {
    if (rec.d_place == DNSResourceRecord::ANSWER) {
      // currently, this function only knows about names, we could also take the target types that are dependent on
      // record contents into account
      // e.g. for NAPTR records, go only for SRV for flag value "s", or A/AAAA for flag value "a"
      allowAdditionalEntry(addnames, rec);
    }
  }

  // We maintain two sets for deduplication:
  // - uniqueCalls makes sure we never resolve a qname/qtype twice
  // - uniqueResults makes sure we never add the same qname/qytype RRSet to the result twice,
  //   but note that that set might contain multiple elements.

  auto mode = iter->second.second;
  for (const auto& targettype : iter->second.first) {
    for (const auto& addname : addnames) {
      std::vector<DNSRecord> records;
      bool inserted = uniqueCalls.emplace(addname, targettype).second;
      if (inserted) {
        resolveAdditionals(addname, targettype, mode, records, depth, additionalsNotInCache);
      }
      if (!records.empty()) {
        for (auto record = records.begin(); record != records.end();) {
          QType covered = QType::ENT;
          if (record->d_type == QType::RRSIG) {
            if (auto rsig = getRR<RRSIGRecordContent>(*record); rsig != nullptr) {
              covered = rsig->d_type;
            }
          }
          if (uniqueResults.count(std::tuple(record->d_name, QType(record->d_type), covered)) > 0) {
            // A bit expensive for vectors, but they are small
            record = records.erase(record);
          }
          else {
            ++record;
          }
        }
        for (const auto& record : records) {
          additionals.push_back(record);
          QType covered = QType::ENT;
          if (record.d_type == QType::RRSIG) {
            if (auto rsig = getRR<RRSIGRecordContent>(record); rsig != nullptr) {
              covered = rsig->d_type;
            }
          }
          uniqueResults.emplace(record.d_name, record.d_type, covered);
        }
        addAdditionals(targettype, records, additionals, uniqueCalls, uniqueResults, depth, additionaldepth + 1, additionalsNotInCache);
      }
    }
  }
}

// The entry point for other code
bool SyncRes::addAdditionals(QType qtype, vector<DNSRecord>& ret, unsigned int depth)
{
  // The additional records of interest
  std::vector<DNSRecord> additionals;

  // We only call resolve for a specific name/type combo once
  std::set<std::pair<DNSName, QType>> uniqueCalls;

  // Collect multiple name/qtype from a single resolve but do not add a new set from new resolve calls
  // For RRSIGs, the type covered is stored in the second Qtype
  std::set<std::tuple<DNSName, QType, QType>> uniqueResults;

  bool additionalsNotInCache = false;
  addAdditionals(qtype, ret, additionals, uniqueCalls, uniqueResults, depth, 0, additionalsNotInCache);

  for (auto& rec : additionals) {
    rec.d_place = DNSResourceRecord::ADDITIONAL;
    ret.push_back(std::move(rec));
  }
  return additionalsNotInCache;
}

/** everything begins here - this is the entry point just after receiving a packet */
int SyncRes::beginResolve(const DNSName& qname, const QType qtype, QClass qclass, vector<DNSRecord>& ret, unsigned int depth)
{
  auto newParent = d_eventTrace.add(RecEventTrace::SyncRes);
  auto oldParent = d_eventTrace.setParent(newParent);
  RecEventTrace::EventScope traceScope(oldParent, d_eventTrace);

  d_wasVariable = false;
  d_wasOutOfBand = false;
  d_cutStates.clear();

  if (doSpecialNamesResolve(qname, qtype, qclass, ret)) {
    d_queryValidationState = vState::Insecure; // this could fool our stats into thinking a validation took place
    return 0; // so do check before updating counters (we do now)
  }

  if (isUnsupported(qtype)) {
    return -1;
  }

  if (qclass == QClass::ANY) {
    qclass = QClass::IN;
  }
  else if (qclass != QClass::IN) {
    return -1;
  }

  if (qtype == QType::DS) {
    d_externalDSQuery = qname;
  }
  else {
    d_externalDSQuery.clear();
  }

  set<GetBestNSAnswer> beenthere;
  Context context;
  int res = doResolve(qname, qtype, ret, depth, beenthere, context);
  d_queryValidationState = context.state;
  d_extendedError = context.extendedError;

  if (shouldValidate()) {
    if (d_queryValidationState != vState::Indeterminate) {
      t_Counters.at(rec::Counter::dnssecValidations)++;
    }
    auto xdnssec = g_xdnssec.getLocal();
    if (xdnssec->check(qname)) {
      increaseXDNSSECStateCounter(d_queryValidationState);
    }
    else {
      increaseDNSSECStateCounter(d_queryValidationState);
    }
  }

  // Avoid calling addAdditionals() if we know we won't find anything
  auto luaLocal = g_luaconfs.getLocal();
  if (res == 0 && qclass == QClass::IN && luaLocal->allowAdditionalQTypes.find(qtype) != luaLocal->allowAdditionalQTypes.end()) {
    bool additionalsNotInCache = addAdditionals(qtype, ret, depth);
    if (additionalsNotInCache) {
      d_wasVariable = true;
    }
  }
  traceScope.close(res);
  return res;
}

/*! Handles all special, built-in names
 * Fills ret with an answer and returns true if it handled the query.
 *
 * Handles the following queries (and their ANY variants):
 *
 * - localhost. IN A
 * - localhost. IN AAAA
 * - 1.0.0.127.in-addr.arpa. IN PTR
 * - 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa. IN PTR
 * - version.bind. CH TXT
 * - version.pdns. CH TXT
 * - id.server. CH TXT
 * - trustanchor.server CH TXT
 * - negativetrustanchor.server CH TXT
 */
bool SyncRes::doSpecialNamesResolve(const DNSName& qname, const QType qtype, const QClass qclass, vector<DNSRecord>& ret)
{
  static const DNSName arpa("1.0.0.127.in-addr.arpa.");
  static const DNSName ip6_arpa("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.");
  static const DNSName localhost("localhost.");
  static const DNSName versionbind("version.bind.");
  static const DNSName idserver("id.server.");
  static const DNSName versionpdns("version.pdns.");
  static const DNSName trustanchorserver("trustanchor.server.");
  static const DNSName negativetrustanchorserver("negativetrustanchor.server.");

  bool handled = false;
  vector<pair<QType::typeenum, string>> answers;

  if ((qname == arpa || qname == ip6_arpa) && qclass == QClass::IN) {
    handled = true;
    if (qtype == QType::PTR || qtype == QType::ANY) {
      answers.emplace_back(QType::PTR, "localhost.");
    }
  }

  if (qname.isPartOf(localhost) && qclass == QClass::IN) {
    handled = true;
    if (qtype == QType::A || qtype == QType::ANY) {
      answers.emplace_back(QType::A, "127.0.0.1");
    }
    if (qtype == QType::AAAA || qtype == QType::ANY) {
      answers.emplace_back(QType::AAAA, "::1");
    }
  }

  if ((qname == versionbind || qname == idserver || qname == versionpdns) && qclass == QClass::CHAOS) {
    handled = true;
    if (qtype == QType::TXT || qtype == QType::ANY) {
      if (qname == versionbind || qname == versionpdns) {
        answers.emplace_back(QType::TXT, "\"" + ::arg()["version-string"] + "\"");
      }
      else if (s_serverID != "disabled") {
        answers.emplace_back(QType::TXT, "\"" + s_serverID + "\"");
      }
    }
  }

  if (qname == trustanchorserver && qclass == QClass::CHAOS && ::arg().mustDo("allow-trust-anchor-query")) {
    handled = true;
    if (qtype == QType::TXT || qtype == QType::ANY) {
      auto luaLocal = g_luaconfs.getLocal();
      for (auto const& dsAnchor : luaLocal->dsAnchors) {
        ostringstream ans;
        ans << "\"";
        ans << dsAnchor.first.toString(); // Explicit toString to have a trailing dot
        for (auto const& dsRecord : dsAnchor.second) {
          ans << " ";
          ans << dsRecord.d_tag;
        }
        ans << "\"";
        answers.emplace_back(QType::TXT, ans.str());
      }
      d_wasVariable = true;
    }
  }

  if (qname == negativetrustanchorserver && qclass == QClass::CHAOS && ::arg().mustDo("allow-trust-anchor-query")) {
    handled = true;
    if (qtype == QType::TXT || qtype == QType::ANY) {
      auto luaLocal = g_luaconfs.getLocal();
      for (auto const& negAnchor : luaLocal->negAnchors) {
        ostringstream ans;
        ans << "\"";
        ans << negAnchor.first.toString(); // Explicit toString to have a trailing dot
        if (negAnchor.second.length() != 0) {
          ans << " " << txtEscape(negAnchor.second);
        }
        ans << "\"";
        answers.emplace_back(QType::TXT, ans.str());
      }
      d_wasVariable = true;
    }
  }

  if (handled && !answers.empty()) {
    ret.clear();
    d_wasOutOfBand = true;

    DNSRecord dnsRecord;
    dnsRecord.d_name = qname;
    dnsRecord.d_place = DNSResourceRecord::ANSWER;
    dnsRecord.d_class = qclass;
    dnsRecord.d_ttl = 86400;
    for (const auto& ans : answers) {
      dnsRecord.d_type = ans.first;
      dnsRecord.setContent(DNSRecordContent::make(ans.first, qclass, ans.second));
      ret.push_back(dnsRecord);
    }
  }

  return handled;
}

//! This is the 'out of band resolver', in other words, the authoritative server
void SyncRes::AuthDomain::addSOA(std::vector<DNSRecord>& records) const
{
  SyncRes::AuthDomain::records_t::const_iterator ziter = d_records.find(std::tuple(getName(), QType::SOA));
  if (ziter != d_records.end()) {
    DNSRecord dnsRecord = *ziter;
    dnsRecord.d_place = DNSResourceRecord::AUTHORITY;
    records.push_back(std::move(dnsRecord));
  }
}

bool SyncRes::AuthDomain::operator==(const AuthDomain& rhs) const
{
  return d_records == rhs.d_records
    && d_servers == rhs.d_servers
    && d_name == rhs.d_name
    && d_rdForward == rhs.d_rdForward;
}

[[nodiscard]] std::string SyncRes::AuthDomain::print(const std::string& indent,
                                                     const std::string& indentLevel) const
{
  std::stringstream outputsStream;
  outputsStream << indent << "DNSName = " << d_name << std::endl;
  outputsStream << indent << "rdForward = " << d_rdForward << std::endl;
  outputsStream << indent << "Records {" << std::endl;
  auto recordContentIndentation = indent;
  recordContentIndentation += indentLevel;
  recordContentIndentation += indentLevel;
  for (const auto& record : d_records) {
    outputsStream << indent << indentLevel << "Record `" << record.d_name << "` {" << std::endl;
    outputsStream << record.print(recordContentIndentation);
    outputsStream << indent << indentLevel << "}" << std::endl;
  }
  outputsStream << indent << "}" << std::endl;
  outputsStream << indent << "Servers {" << std::endl;
  for (const auto& server : d_servers) {
    outputsStream << indent << indentLevel << server.toString() << std::endl;
  }
  outputsStream << indent << "}" << std::endl;
  return outputsStream.str();
}

int SyncRes::AuthDomain::getRecords(const DNSName& qname, const QType qtype, std::vector<DNSRecord>& records) const
{
  int result = RCode::NoError;
  records.clear();

  // partial lookup
  std::pair<records_t::const_iterator, records_t::const_iterator> range = d_records.equal_range(std::tie(qname));

  SyncRes::AuthDomain::records_t::const_iterator ziter;
  bool somedata = false;

  for (ziter = range.first; ziter != range.second; ++ziter) {
    somedata = true;

    if (qtype == QType::ANY || ziter->d_type == qtype || ziter->d_type == QType::CNAME) {
      // let rest of nameserver do the legwork on this one
      records.push_back(*ziter);
    }
    else if (ziter->d_type == QType::NS && ziter->d_name.countLabels() > getName().countLabels()) {
      // we hit a delegation point!
      DNSRecord dnsRecord = *ziter;
      dnsRecord.d_place = DNSResourceRecord::AUTHORITY;
      records.push_back(std::move(dnsRecord));
    }
  }

  if (!records.empty()) {
    /* We have found an exact match, we're done */
    return result;
  }

  if (somedata) {
    /* We have records for that name, but not of the wanted qtype */
    addSOA(records);

    return result;
  }

  DNSName wcarddomain(qname);
  while (wcarddomain != getName() && wcarddomain.chopOff()) {
    range = d_records.equal_range(std::tuple(g_wildcarddnsname + wcarddomain));
    if (range.first == range.second) {
      continue;
    }
    for (ziter = range.first; ziter != range.second; ++ziter) {
      DNSRecord dnsRecord = *ziter;
      // if we hit a CNAME, just answer that - rest of recursor will do the needful & follow
      if (dnsRecord.d_type == qtype || qtype == QType::ANY || dnsRecord.d_type == QType::CNAME) {
        dnsRecord.d_name = qname;
        dnsRecord.d_place = DNSResourceRecord::ANSWER;
        records.push_back(std::move(dnsRecord));
      }
    }

    if (records.empty()) {
      addSOA(records);
    }

    return result;
  }

  /* Nothing for this name, no wildcard, let's see if there is some NS */
  DNSName nsdomain(qname);
  while (nsdomain.chopOff() && nsdomain != getName()) {
    range = d_records.equal_range(std::tuple(nsdomain, QType::NS));
    if (range.first == range.second) {
      continue;
    }
    for (ziter = range.first; ziter != range.second; ++ziter) {
      DNSRecord dnsRecord = *ziter;
      dnsRecord.d_place = DNSResourceRecord::AUTHORITY;
      records.push_back(std::move(dnsRecord));
    }
  }

  if (records.empty()) {
    addSOA(records);
    result = RCode::NXDomain;
  }

  return result;
}

bool SyncRes::doOOBResolve(const AuthDomain& domain, const DNSName& qname, const QType qtype, vector<DNSRecord>& ret, int& res)
{
  d_authzonequeries++;
  t_Counters.at(rec::Counter::authzonequeries)++;

  res = domain.getRecords(qname, qtype, ret);
  return true;
}

bool SyncRes::doOOBResolve(const DNSName& qname, const QType qtype, vector<DNSRecord>& ret, unsigned int /* depth */, const string& prefix, int& res)
{
  DNSName authdomain(qname);
  const auto iter = getBestAuthZone(&authdomain);
  if (iter == t_sstorage.domainmap->end() || !iter->second.isAuth()) {
    LOG(prefix << qname << ": Auth storage has no zone for this query!" << endl);
    return false;
  }

  LOG(prefix << qname << ": Auth storage has data, zone='" << authdomain << "'" << endl);
  return doOOBResolve(iter->second, qname, qtype, ret, res);
}

bool SyncRes::isRecursiveForwardOrAuth(const DNSName& qname)
{
  DNSName authname(qname);
  const auto iter = getBestAuthZone(&authname);
  return iter != t_sstorage.domainmap->end() && (iter->second.isAuth() || iter->second.shouldRecurse());
}

bool SyncRes::isRecursiveForward(const DNSName& qname)
{
  DNSName authname(qname);
  const auto iter = getBestAuthZone(&authname);
  return iter != t_sstorage.domainmap->end() && iter->second.shouldRecurse();
}

bool SyncRes::isForwardOrAuth(const DNSName& qname)
{
  DNSName authname(qname);
  const auto iter = getBestAuthZone(&authname);
  return iter != t_sstorage.domainmap->end();
}

const char* isoDateTimeMillis(const struct timeval& tval, timebuf_t& buf)
{
  const std::string s_timestampFormat = "%Y-%m-%dT%T";
  struct tm tmval{};
  size_t len = strftime(buf.data(), buf.size(), s_timestampFormat.c_str(), localtime_r(&tval.tv_sec, &tmval));
  if (len == 0) {
    int ret = snprintf(buf.data(), buf.size(), "%lld", static_cast<long long>(tval.tv_sec));
    if (ret < 0 || static_cast<size_t>(ret) >= buf.size()) {
      buf[0] = '\0';
      return buf.data();
    }
    len = ret;
  }

  if (buf.size() > len + 4) {
    snprintf(&buf.at(len), buf.size() - len, ".%03ld", static_cast<long>(tval.tv_usec) / 1000);
  }
  return buf.data();
}

struct ednsstatus_t : public multi_index_container<SyncRes::EDNSStatus,
                                                   indexed_by<
                                                     ordered_unique<tag<ComboAddress>, member<SyncRes::EDNSStatus, ComboAddress, &SyncRes::EDNSStatus::address>>,
                                                     ordered_non_unique<tag<time_t>, member<SyncRes::EDNSStatus, time_t, &SyncRes::EDNSStatus::ttd>>>>
{
  // Get a copy
  [[nodiscard]] ednsstatus_t getMap() const
  {
    return *this;
  }

  static void setMode(index<ComboAddress>::type& ind, iterator iter, SyncRes::EDNSStatus::EDNSMode mode, time_t theTime)
  {
    if (iter->mode != mode || iter->ttd == 0) {
      ind.modify(iter, [=](SyncRes::EDNSStatus& status) { status.mode = mode; status.ttd = theTime + Expire; });
    }
  }

  void prune(time_t now)
  {
    auto& ind = get<time_t>();
    ind.erase(ind.begin(), ind.upper_bound(now));
  }

  static const time_t Expire = 7200;
};

static LockGuarded<ednsstatus_t> s_ednsstatus;

SyncRes::EDNSStatus::EDNSMode SyncRes::getEDNSStatus(const ComboAddress& server)
{
  auto lock = s_ednsstatus.lock();
  const auto& iter = lock->find(server);
  if (iter == lock->end()) {
    return EDNSStatus::EDNSOK;
  }
  return iter->mode;
}

uint64_t SyncRes::getEDNSStatusesSize()
{
  return s_ednsstatus.lock()->size();
}

void SyncRes::clearEDNSStatuses()
{
  s_ednsstatus.lock()->clear();
}

void SyncRes::pruneEDNSStatuses(time_t cutoff)
{
  s_ednsstatus.lock()->prune(cutoff);
}

uint64_t SyncRes::doEDNSDump(int fileDesc)
{
  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    close(newfd);
    return 0;
  }
  uint64_t count = 0;

  fprintf(filePtr.get(), "; edns dump follows\n; ip\tstatus\tttd\n");
  const auto copy = s_ednsstatus.lock()->getMap();
  for (const auto& eds : copy) {
    count++;
    timebuf_t tmp;
    fprintf(filePtr.get(), "%s\t%s\t%s\n", eds.address.toString().c_str(), eds.toString().c_str(), timestamp(eds.ttd, tmp));
  }
  return count;
}

void SyncRes::pruneNSSpeeds(time_t limit)
{
  auto lock = s_nsSpeeds.lock();
  auto& ind = lock->get<timeval>();
  ind.erase(ind.begin(), ind.upper_bound(timeval{limit, 0}));
}

uint64_t SyncRes::getNSSpeedsSize()
{
  return s_nsSpeeds.lock()->size();
}

void SyncRes::submitNSSpeed(const DNSName& server, const ComboAddress& address, int usec, const struct timeval& now)
{
  auto lock = s_nsSpeeds.lock();
  lock->find_or_enter(server, now).submit(address, usec, now);
}

void SyncRes::clearNSSpeeds()
{
  s_nsSpeeds.lock()->clear();
}

float SyncRes::getNSSpeed(const DNSName& server, const ComboAddress& address)
{
  auto lock = s_nsSpeeds.lock();
  return lock->find_or_enter(server).d_collection[address].peek();
}

uint64_t SyncRes::doDumpNSSpeeds(int fileDesc)
{
  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    close(newfd);
    return 0;
  }

  fprintf(filePtr.get(), "; nsspeed dump follows\n; nsname\ttimestamp\t[ip/decaying-ms/last-ms...]\n");
  uint64_t count = 0;

  // Create a copy to avoid holding the lock while doing I/O
  for (const auto& iter : *s_nsSpeeds.lock()) {
    count++;

    // an <empty> can appear hear in case of authoritative (hosted) zones
    timebuf_t tmp;
    fprintf(filePtr.get(), "%s\t%s\t", iter.d_name.toLogString().c_str(), isoDateTimeMillis(iter.d_lastget, tmp));
    bool first = true;
    for (const auto& line : iter.d_collection) {
      fprintf(filePtr.get(), "%s%s/%.3f/%.3f", first ? "" : "\t", line.first.toStringWithPortExcept(53).c_str(), line.second.peek() / 1000.0F, static_cast<float>(line.second.last()) / 1000.0F);
      first = false;
    }
    fprintf(filePtr.get(), "\n");
  }
  return count;
}

uint64_t SyncRes::getThrottledServersSize()
{
  return s_throttle.lock()->size();
}

void SyncRes::pruneThrottledServers(time_t now)
{
  s_throttle.lock()->prune(now);
}

void SyncRes::clearThrottle()
{
  s_throttle.lock()->clear();
}

bool SyncRes::isThrottled(time_t now, const ComboAddress& server, const DNSName& target, QType qtype)
{
  return s_throttle.lock()->shouldThrottle(now, std::tuple(server, target, qtype));
}

bool SyncRes::isThrottled(time_t now, const ComboAddress& server)
{
  auto throttled = s_throttle.lock()->shouldThrottle(now, std::tuple(server, g_rootdnsname, 0));
  if (throttled) {
    // Give fully throttled servers a chance to be used, to avoid having one bad zone spoil the NS
    // record for others using the same NS. If the NS answers, it will be unThrottled immediately
    if (s_unthrottle_n > 0 && dns_random(s_unthrottle_n) == 0) {
      throttled = false;
    }
  }
  return throttled;
}

void SyncRes::unThrottle(const ComboAddress& server, const DNSName& name, QType qtype)
{
  s_throttle.lock()->clear(std::tuple(server, g_rootdnsname, 0));
  s_throttle.lock()->clear(std::tuple(server, name, qtype));
}

void SyncRes::doThrottle(time_t now, const ComboAddress& server, time_t duration, unsigned int tries, Throttle::Reason reason)
{
  s_throttle.lock()->throttle(now, std::tuple(server, g_rootdnsname, 0), duration, tries, reason);
}

void SyncRes::doThrottle(time_t now, const ComboAddress& server, const DNSName& name, QType qtype, time_t duration, unsigned int tries, Throttle::Reason reason)
{
  s_throttle.lock()->throttle(now, std::tuple(server, name, qtype), duration, tries, reason);
}

uint64_t SyncRes::doDumpThrottleMap(int fileDesc)
{
  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    close(newfd);
    return 0;
  }
  fprintf(filePtr.get(), "; throttle map dump follows\n");
  fprintf(filePtr.get(), "; remote IP\tqname\tqtype\tcount\tttd\treason\n");
  uint64_t count = 0;

  // Get a copy to avoid holding the lock while doing I/O
  const auto throttleMap = s_throttle.lock()->getThrottleMap();
  for (const auto& iter : throttleMap) {
    count++;
    timebuf_t tmp;
    // remote IP, dns name, qtype, count, ttd, reason
    fprintf(filePtr.get(), "%s\t%s\t%s\t%u\t%s\t%s\n", std::get<0>(iter.thing).toString().c_str(), std::get<1>(iter.thing).toLogString().c_str(), std::get<2>(iter.thing).toString().c_str(), iter.count, timestamp(iter.ttd, tmp), Throttle::toString(iter.reason).c_str());
  }

  return count;
}

uint64_t SyncRes::getFailedServersSize()
{
  return s_fails.lock()->size();
}

void SyncRes::clearFailedServers()
{
  s_fails.lock()->clear();
}

void SyncRes::pruneFailedServers(time_t cutoff)
{
  s_fails.lock()->prune(cutoff);
}

unsigned long SyncRes::getServerFailsCount(const ComboAddress& server)
{
  return s_fails.lock()->value(server);
}

uint64_t SyncRes::doDumpFailedServers(int fileDesc)
{
  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    close(newfd);
    return 0;
  }
  fprintf(filePtr.get(), "; failed servers dump follows\n");
  fprintf(filePtr.get(), "; remote IP\tcount\ttimestamp\n");
  uint64_t count = 0;

  // We get a copy, so the I/O does not need to happen while holding the lock
  for (const auto& iter : s_fails.lock()->getMapCopy()) {
    count++;
    timebuf_t tmp;
    fprintf(filePtr.get(), "%s\t%" PRIu64 "\t%s\n", iter.key.toString().c_str(), iter.value, timestamp(iter.last, tmp));
  }

  return count;
}

uint64_t SyncRes::getNonResolvingNSSize()
{
  return s_nonresolving.lock()->size();
}

void SyncRes::clearNonResolvingNS()
{
  s_nonresolving.lock()->clear();
}

void SyncRes::pruneNonResolving(time_t cutoff)
{
  s_nonresolving.lock()->prune(cutoff);
}

uint64_t SyncRes::doDumpNonResolvingNS(int fileDesc)
{
  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    close(newfd);
    return 0;
  }
  fprintf(filePtr.get(), "; non-resolving nameserver dump follows\n");
  fprintf(filePtr.get(), "; name\tcount\ttimestamp\n");
  uint64_t count = 0;

  // We get a copy, so the I/O does not need to happen while holding the lock
  for (const auto& iter : s_nonresolving.lock()->getMapCopy()) {
    count++;
    timebuf_t tmp;
    fprintf(filePtr.get(), "%s\t%" PRIu64 "\t%s\n", iter.key.toString().c_str(), iter.value, timestamp(iter.last, tmp));
  }

  return count;
}

void SyncRes::clearSaveParentsNSSets()
{
  s_savedParentNSSet.lock()->clear();
}

size_t SyncRes::getSaveParentsNSSetsSize()
{
  return s_savedParentNSSet.lock()->size();
}

void SyncRes::pruneSaveParentsNSSets(time_t now)
{
  s_savedParentNSSet.lock()->prune(now);
}

uint64_t SyncRes::doDumpSavedParentNSSets(int fileDesc)
{
  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    close(newfd);
    return 0;
  }
  fprintf(filePtr.get(), "; dump of saved parent nameserver sets successfully used follows\n");
  fprintf(filePtr.get(), "; total entries: %zu\n", s_savedParentNSSet.lock()->size());
  fprintf(filePtr.get(), "; domain\tsuccess\tttd\n");
  uint64_t count = 0;

  // We get a copy, so the I/O does not need to happen while holding the lock
  for (const auto& iter : s_savedParentNSSet.lock()->getMapCopy()) {
    if (iter.d_count == 0) {
      continue;
    }
    count++;
    timebuf_t tmp;
    fprintf(filePtr.get(), "%s\t%" PRIu64 "\t%s\n", iter.d_domain.toString().c_str(), iter.d_count, timestamp(iter.d_ttd, tmp));
  }
  return count;
}

void SyncRes::pruneDoTProbeMap(time_t cutoff)
{
  auto lock = s_dotMap.lock();
  auto& ind = lock->d_map.get<time_t>();

  for (auto i = ind.begin(); i != ind.end();) {
    if (i->d_ttd >= cutoff) {
      // We're done as we loop ordered by d_ttd
      break;
    }
    if (i->d_status == DoTStatus::Status::Busy) {
      lock->d_numBusy--;
    }
    i = ind.erase(i);
  }
}

uint64_t SyncRes::doDumpDoTProbeMap(int fileDesc)
{
  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    close(newfd);
    return 0;
  }
  fprintf(filePtr.get(), "; DoT probing map follows\n");
  fprintf(filePtr.get(), "; ip\tdomain\tcount\tstatus\tttd\n");
  uint64_t count = 0;

  // We get a copy, so the I/O does not need to happen while holding the lock
  DoTMap copy;
  {
    copy = *s_dotMap.lock();
  }
  fprintf(filePtr.get(), "; %" PRIu64 " Busy entries\n", copy.d_numBusy);
  for (const auto& iter : copy.d_map) {
    count++;
    timebuf_t tmp;
    fprintf(filePtr.get(), "%s\t%s\t%" PRIu64 "\t%s\t%s\n", iter.d_address.toString().c_str(), iter.d_auth.toString().c_str(), iter.d_count, iter.toString().c_str(), timestamp(iter.d_ttd, tmp));
  }
  return count;
}

/* so here is the story. First we complete the full resolution process for a domain name. And only THEN do we decide
   to also do DNSSEC validation, which leads to new queries. To make this simple, we *always* ask for DNSSEC records
   so that if there are RRSIGs for a name, we'll have them.

   However, some hosts simply can't answer questions which ask for DNSSEC. This can manifest itself as:
   * No answer
   * FormErr
   * Nonsense answer

   The cause of "No answer" may be fragmentation, and it is tempting to probe if smaller answers would get through.
   Another cause of "No answer" may simply be a network condition.
   Nonsense answers are a clearer indication this host won't be able to do DNSSEC evah.

   Previous implementations have suffered from turning off DNSSEC questions for an authoritative server based on timeouts.
   A clever idea is to only turn off DNSSEC if we know a domain isn't signed anyhow. The problem with that really
   clever idea however is that at this point in PowerDNS, we may simply not know that yet. All the DNSSEC thinking happens
   elsewhere. It may not have happened yet.

   For now this means we can't be clever, but will turn off DNSSEC if you reply with FormError or gibberish.
*/

LWResult::Result SyncRes::asyncresolveWrapper(const OptLog& log, const ComboAddress& address, bool ednsMANDATORY, const DNSName& domain, [[maybe_unused]] const DNSName& auth, int type, bool doTCP, bool sendRDQuery, struct timeval* now, std::optional<Netmask>& srcmask, LWResult* res, bool* chained, const DNSName& nsName) const
{
  /* what is your QUEST?
     the goal is to get as many remotes as possible on the best level of EDNS support
     The levels are:

     1) EDNSOK: Honors EDNS0, absent from table
     2) EDNSIGNORANT: Ignores EDNS0, gives replies without EDNS0
     3) NOEDNS: Generates FORMERR on EDNS queries

     Everybody starts out assumed to be EDNSOK.
     If EDNSOK, send out EDNS0
        If you FORMERR us, go to NOEDNS,
        If no EDNS in response, go to EDNSIGNORANT
     If EDNSIGNORANT, keep on including EDNS0, see what happens
        Same behaviour as EDNSOK
     If NOEDNS, send bare queries
  */

  // Read current status, defaulting to OK
  SyncRes::EDNSStatus::EDNSMode mode = EDNSStatus::EDNSOK;
  {
    auto lock = s_ednsstatus.lock();
    auto ednsstatus = lock->find(address); // does this include port? YES
    if (ednsstatus != lock->end()) {
      if (ednsstatus->ttd != 0 && ednsstatus->ttd < d_now.tv_sec) {
        lock->erase(ednsstatus);
      }
      else {
        mode = ednsstatus->mode;
      }
    }
  }

  int EDNSLevel = 0;
  auto luaconfsLocal = g_luaconfs.getLocal();
  ResolveContext ctx(d_initialRequestId, nsName, auth);

  LWResult::Result ret{};

  for (int tries = 0; tries < 2; ++tries) {

    if (mode == EDNSStatus::NOEDNS) {
      t_Counters.at(rec::Counter::noEdnsOutQueries)++;
      EDNSLevel = 0; // level != mode
    }
    else if (ednsMANDATORY || mode != EDNSStatus::NOEDNS) {
      EDNSLevel = 1;
    }

    DNSName sendQname(domain);
    if (g_lowercaseOutgoing) {
      sendQname.makeUsLowerCase();
    }

    if (d_asyncResolve) {
      ret = d_asyncResolve(address, sendQname, type, doTCP, sendRDQuery, EDNSLevel, now, srcmask, ctx, res, chained);
    }
    else {
      ret = asyncresolve(log, address, sendQname, type, doTCP, sendRDQuery, EDNSLevel, now, srcmask, ctx, d_outgoingProtobufServers, d_frameStreamServers, luaconfsLocal->outgoingProtobufExportConfig.exportTypes, res, chained);
    }

    if (ret == LWResult::Result::PermanentError || LWResult::isLimitError(ret) || ret == LWResult::Result::Spoofed) {
      break; // transport error, nothing to learn here
    }

    if (ret == LWResult::Result::Timeout) { // timeout, not doing anything with it now
      break;
    }

    if (EDNSLevel == 1) {
      // We sent out with EDNS
      // ret is LWResult::Result::Success
      // ednsstatus in table might be pruned or changed by another request/thread, so do a new lookup/insert if needed
      auto lock = s_ednsstatus.lock(); // all three branches below need a lock

      // Determine new mode
      if (ret == LWResult::Result::BindError) {
        // BindError is only generated when cookies are active and we failed to bind to a local
        // address associated with a cookie, see RFC9018 section 3 last paragraph. We assume the
        // called code has already erased the cookie info.
        // This is the first path that re-iterates the loop
        continue;
      }
      if (res->d_validpacket && res->d_haveEDNS && ret == LWResult::Result::BadCookie) {
        // We assume the received cookie was stored and will be used in the second iteration
        // This is the second path that re-iterates the loop
        continue;
      }
      if (res->d_validpacket && !res->d_haveEDNS && res->d_rcode == RCode::FormErr) {
        mode = EDNSStatus::NOEDNS;
        auto ednsstatus = lock->insert(address).first;
        auto& ind = lock->get<ComboAddress>();
        lock->setMode(ind, ednsstatus, mode, d_now.tv_sec);
        // This is the third path that re-iterates the loop
        continue;
      }
      if (!res->d_haveEDNS) {
        auto ednsstatus = lock->insert(address).first;
        auto& ind = lock->get<ComboAddress>();
        lock->setMode(ind, ednsstatus, EDNSStatus::EDNSIGNORANT, d_now.tv_sec);
      }
      else {
        // New status is EDNSOK
        lock->erase(address);
      }
    }

    break;
  }
  return ret;
}

/* The parameters from rfc9156. */
/* maximum number of QNAME minimization iterations */
unsigned int SyncRes::s_max_minimize_count; // default is 10
/* number of iterations that should only have one label appended */
unsigned int SyncRes::s_minimize_one_label; // default is 4

static unsigned int qmStepLen(unsigned int labels, unsigned int qnamelen, unsigned int qmIteration)
{
  unsigned int step{};

  if (qmIteration < SyncRes::s_minimize_one_label) {
    step = 1;
  }
  else if (qmIteration < SyncRes::s_max_minimize_count) {
    step = std::max(1U, (qnamelen - labels) / (SyncRes::s_max_minimize_count - qmIteration));
  }
  else {
    step = qnamelen - labels;
  }
  unsigned int targetlen = std::min(labels + step, qnamelen);
  return targetlen;
}

static string resToString(int res)
{
  return res >= 0 ? RCode::to_s(res) : std::to_string(res);
}

int SyncRes::doResolve(const DNSName& qname, const QType qtype, vector<DNSRecord>& ret, unsigned int depth, set<GetBestNSAnswer>& beenthere, Context& context) // NOLINT(readability-function-cognitive-complexity)
{
  auto prefix = getPrefix(depth);
  auto luaconfsLocal = g_luaconfs.getLocal();

  /* Apply qname (including CNAME chain) filtering policies */
  if (d_wantsRPZ && !d_appliedPolicy.wasHit()) {
    if (luaconfsLocal->dfe.getQueryPolicy(qname, d_discardedPolicies, d_appliedPolicy)) {
      mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
      bool done = false;
      int rcode = RCode::NoError;
      handlePolicyHit(prefix, qname, qtype, ret, done, rcode, depth);
      if (done) {
        return rcode;
      }
    }
  }

  initZoneCutsFromTA(qname, prefix);

  // In the auth or recursive forward case, it does not make sense to do qname-minimization
  if (!getQNameMinimization() || isRecursiveForwardOrAuth(qname)) {
    return doResolveNoQNameMinimization(qname, qtype, ret, depth, beenthere, context);
  }

  // The qname minimization algorithm is a simplified version of the one in RFC 7816 (bis).
  // It could be simplified because the cache maintenance (both positive and negative)
  // is already done by doResolveNoQNameMinimization().
  //
  // Sketch of algorithm:
  // Check cache
  //  If result found: done
  //  Otherwise determine closes ancestor from cache data
  //    Repeat querying A, adding more labels of the original qname
  //    If we get a delegation continue at ancestor determination
  //    Until we have the full name.
  //
  // The algorithm starts with adding a single label per iteration, and
  // moves to three labels per iteration after three iterations.

  DNSName child;
  prefix.append(string("QM "));

  LOG(prefix << qname << ": doResolve" << endl);

  // Look in cache only
  vector<DNSRecord> retq;
  bool old = setCacheOnly(true);
  bool fromCache = false;
  // For cache peeking, we tell doResolveNoQNameMinimization not to consider the (non-recursive) forward case.
  // Otherwise all queries in a forward domain will be forwarded, while we want to consult the cache.
  int res{};
  try {
    // The cache lookup below can have three types of result:
    // Case 1: successful. In that case the records will be added to the end result below and we're done.
    // Case 2: unsuccessful. In that case the records in retq will be discarded. E.g. there
    // might be records as the lookup found a CNAME chain, but the target is missing from the cache.
    // Case 3: an exception is thrown, in that case we're still interested in the (partial) results in retq.
    // This can e.g. happen on a too-long CNAME chain.
    res = doResolveNoQNameMinimization(qname, qtype, retq, depth, beenthere, context, &fromCache, nullptr);
  }
  catch (...) {
    ret.insert(ret.end(), std::make_move_iterator(retq.begin()), std::make_move_iterator(retq.end()));
    throw;
  }
  setCacheOnly(old);
  if (fromCache) {
    LOG(prefix << qname << ": Step0 Found in cache" << endl);
    if (d_appliedPolicy.d_type != DNSFilterEngine::PolicyType::None && (d_appliedPolicy.d_kind == DNSFilterEngine::PolicyKind::NXDOMAIN || d_appliedPolicy.d_kind == DNSFilterEngine::PolicyKind::NODATA)) {
      ret.clear();
    }
    ret.insert(ret.end(), std::make_move_iterator(retq.begin()), std::make_move_iterator(retq.end()));
    return res;
  }
  LOG(prefix << qname << ": Step0 Not cached" << endl);

  const unsigned int qnamelen = qname.countLabels();

  DNSName fwdomain(qname);
  const bool forwarded = getBestAuthZone(&fwdomain) != t_sstorage.domainmap->end();
  if (forwarded) {
    LOG(prefix << qname << ": Step0 qname is in a forwarded domain " << fwdomain << endl);
  }

  for (unsigned int i = 0; i <= qnamelen; i++) {

    // Step 1
    vector<DNSRecord> bestns;
    DNSName nsdomain(qname);
    if (qtype == QType::DS) {
      nsdomain.chopOff();
    }
    // the two retries allow getBestNSFromCache&co to reprime the root
    // hints, in case they ever go missing
    for (int tries = 0; tries < 2 && bestns.empty(); ++tries) {
      bool flawedNSSet = false;
      set<GetBestNSAnswer> beenthereIgnored;
      getBestNSFromCache(nsdomain, qtype, bestns, &flawedNSSet, depth, prefix, beenthereIgnored, forwarded ? std::make_optional(fwdomain) : std::nullopt);
      if (forwarded) {
        break;
      }
    }

    if (bestns.empty()) {
      if (!forwarded) {
        // Something terrible is wrong
        LOG(prefix << qname << ": Step1 No ancestor found return ServFail" << endl);
        return RCode::ServFail;
      }
      child = fwdomain;
    }
    else {
      LOG(prefix << qname << ": Step1 Ancestor from cache is " << bestns[0].d_name << endl);
      if (forwarded) {
        child = bestns[0].d_name.isPartOf(fwdomain) ? bestns[0].d_name : fwdomain;
        LOG(prefix << qname << ": Step1 Final Ancestor (using forwarding info) is " << child << endl);
      }
      else {
        child = bestns[0].d_name;
      }
    }
    for (; i <= qnamelen; i++) {
      // Step 2
      unsigned int labels = child.countLabels();
      unsigned int targetlen = qmStepLen(labels, qnamelen, i);

      while (labels < targetlen) {
        child.prependRawLabel(qname.getRawLabel(qnamelen - labels - 1));
        labels++;
      }
      // rfc9156 section-2.3, append labels if they start with an underscore
      while (labels < qnamelen) {
        auto prependLabel = qname.getRawLabel(qnamelen - labels - 1);
        if (prependLabel.at(0) != '_') {
          break;
        }
        child.prependRawLabel(prependLabel);
        labels++;
      }

      LOG(prefix << qname << ": Step2 New child " << child << endl);

      // Step 3 resolve
      if (child == qname) {
        LOG(prefix << qname << ": Step3 Going to do final resolve" << endl);
        res = doResolveNoQNameMinimization(qname, qtype, ret, depth, beenthere, context);
        LOG(prefix << qname << ": Step3 Final resolve: " << resToString(res) << "/" << ret.size() << endl);
        return res;
      }

      // If we have seen this child during resolution already; we tried to QM it already or otherwise broken.
      // fall back to no-QM
      bool qmLoopDetected = false;
      for (const auto& visitedNS : beenthere) {
        if (visitedNS.qname == child) {
          qmLoopDetected = true;
          break;
        }
      }
      if (qmLoopDetected) {
        LOG(prefix << qname << ": Step4 loop detected as visited this child name already, fallback to no QM" << endl);
        res = doResolveNoQNameMinimization(qname, qtype, ret, depth, beenthere, context);
        LOG(prefix << qname << ": Step4 Final resolve: " << resToString(res) << "/" << ret.size() << endl);
        return res;
      }

      // Step 4
      LOG(prefix << qname << ": Step4 Resolve A for child " << child << endl);
      bool oldFollowCNAME = d_followCNAME;
      d_followCNAME = false;
      retq.clear();
      StopAtDelegation stopAtDelegation = Stop;
      res = doResolveNoQNameMinimization(child, QType::A, retq, depth, beenthere, context, nullptr, &stopAtDelegation);
      d_followCNAME = oldFollowCNAME;
      LOG(prefix << qname << ": Step4 Resolve " << child << "|A result is " << RCode::to_s(res) << "/" << retq.size() << "/" << stopAtDelegation << endl);
      if (stopAtDelegation == Stopped) {
        LOG(prefix << qname << ": Delegation seen, continue at step 1" << endl);
        break;
      }

      if (res != RCode::NoError) {
        // Case 5: unexpected answer
        LOG(prefix << qname << ": Step5: other rcode, last effort final resolve" << endl);
        setQNameMinimization(false);
        setQMFallbackMode(true);

        auto oldEDE = context.extendedError;
        res = doResolveNoQNameMinimization(qname, qtype, ret, depth + 1, beenthere, context);

        if (res == RCode::NoError) {
          t_Counters.at(rec::Counter::qnameminfallbacksuccess)++;
        }
        else {
          // as doResolveNoQNameMinimization clears the EDE, we put it back here, it is relevant but might not be set by the last effort attempt
          if (!context.extendedError) {
            context.extendedError = std::move(oldEDE);
          }
        }

        LOG(prefix << qname << ": Step5 End resolve: " << resToString(res) << "/" << ret.size() << endl);
        return res;
      }
    }
  }

  // Should not be reached
  LOG(prefix << qname << ": Max iterations reached, return ServFail" << endl);
  return RCode::ServFail;
}

unsigned int SyncRes::getAdjustedRecursionBound() const
{
  auto bound = s_maxdepth; // 40 is default value of s_maxdepth
  if (getQMFallbackMode()) {
    // We might have hit a depth level check, but we still want to allow some recursion levels in the fallback
    // no-qname-minimization case. This has the effect that a qname minimization fallback case might reach 150% of
    // maxdepth, taking care to not repeatedly increase the bound.
    bound += s_maxdepth / 2;
  }
  return bound;
}

static bool haveFinalAnswer(const DNSName& qname, QType qtype, int res, const vector<DNSRecord>& ret)
{
  if (res != RCode::NoError) {
    return false;
  }

  // This loop assumes the CNAME's records are in-order
  DNSName target(qname);
  for (const auto& record : ret) {
    if (record.d_place == DNSResourceRecord::ANSWER && record.d_name == target) {
      if (record.d_type == qtype) {
        return true;
      }
      if (record.d_type == QType::CNAME) {
        if (auto ptr = getRR<CNAMERecordContent>(record)) {
          target = ptr->getTarget();
        }
        else {
          return false;
        }
      }
    }
  }
  return false;
}

/*! This function will check the cache and go out to the internet if the answer is not in cache
 *
 * \param qname The name we need an answer for
 * \param qtype
 * \param ret The vector of DNSRecords we need to fill with the answers
 * \param depth The recursion depth we are in
 * \param beenthere
 * \param fromCache tells the caller the result came from the cache, may be nullptr
 * \param stopAtDelegation if non-nullptr and pointed-to value is Stop requests the callee to stop at a delegation, if so pointed-to value is set to Stopped
 * \return DNS RCODE or -1 (Error)
 */
int SyncRes::doResolveNoQNameMinimization(const DNSName& qname, const QType qtype, vector<DNSRecord>& ret, unsigned int depth, set<GetBestNSAnswer>& beenthere, Context& context, bool* fromCache, StopAtDelegation* stopAtDelegation) // NOLINT(readability-function-cognitive-complexity)
{
  context.extendedError.reset();
  auto prefix = getPrefix(depth);

  LOG(prefix << qname << ": Wants " << (d_doDNSSEC ? "" : "NO ") << "DNSSEC processing, " << (d_requireAuthData ? "" : "NO ") << "auth data required by query for " << qtype << endl);

  d_maxdepth = std::max(d_maxdepth, depth);
  if (s_maxdepth > 0) {
    auto bound = getAdjustedRecursionBound();
    // Use a stricter bound if throttling
    if (depth > bound || (d_outqueries > 10 && d_throttledqueries > 5 && depth > bound * 2 / 3)) {
      string msg = "More than " + std::to_string(bound) + " (adjusted max-recursion-depth) levels of recursion needed while resolving " + qname.toLogString();
      LOG(prefix << qname << ": " << msg << endl);
      throw ImmediateServFailException(std::move(msg));
    }
  }

  int res = 0;

  const int iterations = !d_refresh && MemRecursorCache::s_maxServedStaleExtensions > 0 ? 2 : 1;
  for (int loop = 0; loop < iterations; loop++) {

    d_serveStale = loop == 1;
    if (d_serveStale) {
      LOG(prefix << qname << ": Restart, with serve-stale enabled" << endl);
    }
    // This is a difficult way of expressing "this is a normal query", i.e. not getRootNS.
    if (!d_updatingRootNS || qtype.getCode() != QType::NS || !qname.isRoot()) {
      DNSName authname(qname);
      const auto iter = getBestAuthZone(&authname);

      if (d_cacheonly) {
        if (iter != t_sstorage.domainmap->end()) {
          if (iter->second.isAuth()) {
            LOG(prefix << qname << ": Cache only lookup for '" << qname << "|" << qtype << "', in auth zone" << endl);
            ret.clear();
            d_wasOutOfBand = doOOBResolve(qname, qtype, ret, depth, prefix, res);
            if (fromCache != nullptr) {
              *fromCache = d_wasOutOfBand;
            }
            return res;
          }
        }
      }

      bool wasForwardedOrAuthZone = false;
      bool wasAuthZone = false;
      bool wasForwardRecurse = false;

      if (iter != t_sstorage.domainmap->end()) {
        wasForwardedOrAuthZone = true;

        if (iter->second.isAuth()) {
          wasAuthZone = true;
        }
        else if (iter->second.shouldRecurse()) {
          wasForwardRecurse = true;
        }
      }

      /* When we are looking for a DS, we want to the non-CNAME cache check first
         because we can actually have a DS (from the parent zone) AND a CNAME (from
         the child zone), and what we really want is the DS */
      if (qtype != QType::DS && doCNAMECacheCheck(qname, qtype, ret, depth, prefix, res, context, wasAuthZone, wasForwardRecurse, loop == 1)) { // will reroute us if needed
        d_wasOutOfBand = wasAuthZone;
        // Here we have an issue. If we were prevented from going out to the network (cache-only was set, possibly because we
        // are in QM Step0) we might have a CNAME but not the corresponding target.
        // It means that we will sometimes go to the next steps when we are in fact done, but that's fine since
        // we will get the records from the cache, resulting in a small overhead.
        // This might be a real problem if we had a RPZ hit, though, because we do not want the processing to continue, since
        // RPZ rules will not be evaluated anymore (we already matched).
        bool stoppedByPolicyHit = d_appliedPolicy.wasHit();
        if (stoppedByPolicyHit && d_appliedPolicy.d_kind == DNSFilterEngine::PolicyKind::Custom && d_appliedPolicy.d_custom) {
          // if the custom RPZ record was a CNAME we still need a full chase
          // tested by unit test test_following_cname_chain_with_rpz
          if (!d_appliedPolicy.d_custom->empty() && d_appliedPolicy.d_custom->at(0)->getType() == QType::CNAME) {
            stoppedByPolicyHit = false;
          }
        }
        if (fromCache != nullptr && (!d_cacheonly || stoppedByPolicyHit)) {
          *fromCache = true;
        }
        /* Apply Post filtering policies */

        if (d_wantsRPZ && !d_appliedPolicy.wasHit()) {
          auto luaLocal = g_luaconfs.getLocal();
          if (luaLocal->dfe.getPostPolicy(ret, d_discardedPolicies, d_appliedPolicy)) {
            mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
            bool done = false;
            handlePolicyHit(prefix, qname, qtype, ret, done, res, depth);
            if (done && fromCache != nullptr) {
              *fromCache = true;
            }
          }
        }
        // This handles the case mentioned above: if the full CNAME chain leading to the answer was
        // constructed from the cache, indicate that.
        if (fromCache != nullptr && !*fromCache && haveFinalAnswer(qname, qtype, res, ret)) {
          *fromCache = true;
        }
        return res;
      }

      if (doCacheCheck(qname, authname, wasForwardedOrAuthZone, wasAuthZone, wasForwardRecurse, qtype, ret, depth, prefix, res, context)) {
        // we done
        d_wasOutOfBand = wasAuthZone;
        if (fromCache != nullptr) {
          *fromCache = true;
        }

        if (d_wantsRPZ && !d_appliedPolicy.wasHit()) {
          auto luaLocal = g_luaconfs.getLocal();
          if (luaLocal->dfe.getPostPolicy(ret, d_discardedPolicies, d_appliedPolicy)) {
            mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
            bool done = false;
            handlePolicyHit(prefix, qname, qtype, ret, done, res, depth);
          }
        }

        return res;
      }

      /* if we have not found a cached DS (or denial of), now is the time to look for a CNAME */
      if (qtype == QType::DS && doCNAMECacheCheck(qname, qtype, ret, depth, prefix, res, context, wasAuthZone, wasForwardRecurse, loop == 1)) { // will reroute us if needed
        d_wasOutOfBand = wasAuthZone;
        // Here we have an issue. If we were prevented from going out to the network (cache-only was set, possibly because we
        // are in QM Step0) we might have a CNAME but not the corresponding target.
        // It means that we will sometimes go to the next steps when we are in fact done, but that's fine since
        // we will get the records from the cache, resulting in a small overhead.
        // This might be a real problem if we had a RPZ hit, though, because we do not want the processing to continue, since
        // RPZ rules will not be evaluated anymore (we already matched).
        const bool stoppedByPolicyHit = d_appliedPolicy.wasHit();

        if (fromCache != nullptr && (!d_cacheonly || stoppedByPolicyHit)) {
          *fromCache = true;
        }
        /* Apply Post filtering policies */

        if (d_wantsRPZ && !stoppedByPolicyHit) {
          auto luaLocal = g_luaconfs.getLocal();
          if (luaLocal->dfe.getPostPolicy(ret, d_discardedPolicies, d_appliedPolicy)) {
            mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
            bool done = false;
            handlePolicyHit(prefix, qname, qtype, ret, done, res, depth);
            if (done && fromCache != nullptr) {
              *fromCache = true;
            }
          }
        }
        if (fromCache != nullptr && !*fromCache && haveFinalAnswer(qname, qtype, res, ret)) {
          *fromCache = true;
        }
        return res;
      }
    }

    if (d_cacheonly) {
      return 0;
    }

    // When trying to serve-stale, we also only look at the cache. Don't look at d_serveStale, it
    // might be changed by recursive calls (this should be fixed in a better way!).
    if (loop == 1) {
      return res;
    }

    LOG(prefix << qname << ": No cache hit for '" << qname << "|" << qtype << "', trying to find an appropriate NS record" << endl);

    DNSName subdomain(qname);
    if (qtype == QType::DS) {
      subdomain.chopOff();
    }

    NsSet nsset;
    bool flawedNSSet = false;

    // the two retries allow getBestNSNamesFromCache&co to reprime the root
    // hints, in case they ever go missing
    for (int tries = 0; tries < 2 && nsset.empty(); ++tries) {
      subdomain = getBestNSNamesFromCache(subdomain, qtype, nsset, &flawedNSSet, depth, prefix, beenthere); //  pass beenthere to both occasions
    }

    res = doResolveAt(nsset, subdomain, flawedNSSet, qname, qtype, ret, depth, prefix, beenthere, context, stopAtDelegation, nullptr);

    if (res == -1 && s_save_parent_ns_set) {
      // It did not work out, lets check if we have a saved parent NS set
      map<DNSName, vector<ComboAddress>> fallBack;
      {
        auto lock = s_savedParentNSSet.lock();
        auto domainData = lock->find(subdomain);
        if (domainData != lock->end() && !domainData->d_nsAddresses.empty()) {
          nsset.clear();
          // Build the nsset arg and fallBack data for the fallback doResolveAt() attempt
          // Take a copy to be able to release the lock, NsSet is actually a map, go figure
          for (const auto& nsAddress : domainData->d_nsAddresses) {
            nsset.emplace(nsAddress.first, pair(std::vector<ComboAddress>(), false));
            fallBack.emplace(nsAddress.first, nsAddress.second);
          }
        }
      }
      if (!fallBack.empty()) {
        LOG(prefix << qname << ": Failure, but we have a saved parent NS set, trying that one" << endl);
        res = doResolveAt(nsset, subdomain, flawedNSSet, qname, qtype, ret, depth, prefix, beenthere, context, stopAtDelegation, &fallBack);
        if (res == 0) {
          // It did work out
          s_savedParentNSSet.lock()->inc(subdomain);
        }
      }
    }
    /* Apply Post filtering policies */
    if (d_wantsRPZ && !d_appliedPolicy.wasHit()) {
      auto luaLocal = g_luaconfs.getLocal();
      if (luaLocal->dfe.getPostPolicy(ret, d_discardedPolicies, d_appliedPolicy)) {
        mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
        bool done = false;
        handlePolicyHit(prefix, qname, qtype, ret, done, res, depth);
      }
    }

    if (res == 0) {
      return 0;
    }

    LOG(prefix << qname << ": Failed (res=" << res << ")" << endl);
    if (res >= 0) {
      break;
    }
  }
  return res < 0 ? RCode::ServFail : res;
}

#if 0
// for testing purposes
static bool ipv6First(const ComboAddress& a, const ComboAddress& b)
{
  return !(a.sin4.sin_family < a.sin4.sin_family);
}
#endif

struct speedOrderCA
{
  speedOrderCA(std::map<ComboAddress, float>& speeds) :
    d_speeds(speeds) {}
  bool operator()(const ComboAddress& lhs, const ComboAddress& rhs) const
  {
    return d_speeds[lhs] < d_speeds[rhs];
  }
  std::map<ComboAddress, float>& d_speeds; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members): nothing wrong afaiks
};

void SyncRes::selectNSOnSpeed(const DNSName& qname, const string& prefix, vector<ComboAddress>& ret)
{
  /* we need to remove from the nsSpeeds collection the existing IPs
     for this nameserver that are no longer in the set, even if there
     is only one or none at all in the current set.
  */
  map<ComboAddress, float> speeds;
  {
    auto lock = s_nsSpeeds.lock();
    const auto& collection = lock->find_or_enter(qname, d_now);
    float factor = collection.getFactor(d_now);
    for (const auto& val : ret) {
      speeds[val] = collection.d_collection[val].get(factor);
    }
    collection.purge(speeds);
  }

  if (ret.size() > 1) {
    shuffle(ret.begin(), ret.end(), pdns::dns_random_engine());
    speedOrderCA speedOrder(speeds);
    stable_sort(ret.begin(), ret.end(), speedOrder);
  }

  if (doLog()) {
    LOG(prefix << qname << ": Nameserver " << qname << " IPs: ");
    bool first = true;
    for (const auto& addr : ret) {
      if (first) {
        first = false;
      }
      else {
        LOG(", ");
      }
      LOG((addr.toString()) << "(" << fmtfloat(speeds[addr] / 1000.0) << "ms)");
    }
    LOG(endl);
  }
}

template <typename T>
static bool collectAddresses(const vector<DNSRecord>& cset, vector<ComboAddress>& ret)
{
  bool pushed = false;
  for (const auto& record : cset) {
    if (auto rec = getRR<T>(record)) {
      ret.push_back(rec->getCA(53));
      pushed = true;
    }
  }
  return pushed;
}

/** This function explicitly goes out for A or AAAA addresses
 */
vector<ComboAddress> SyncRes::getAddrs(const DNSName& qname, unsigned int depth, const string& prefix, set<GetBestNSAnswer>& beenthere, bool cacheOnly, unsigned int& addressQueriesForNS)
{
  typedef vector<DNSRecord> res_t;
  typedef vector<ComboAddress> ret_t;
  ret_t ret;

  bool oldCacheOnly = setCacheOnly(cacheOnly);
  bool oldRequireAuthData = d_requireAuthData;
  bool oldValidationRequested = d_DNSSECValidationRequested;
  bool oldFollowCNAME = d_followCNAME;
  bool seenV6 = false;
  const unsigned int startqueries = d_outqueries;
  d_requireAuthData = false;
  d_DNSSECValidationRequested = false;
  d_followCNAME = false;

  MemRecursorCache::Flags flags = MemRecursorCache::None;
  if (d_serveStale) {
    flags |= MemRecursorCache::ServeStale;
  }
  try {
    // First look for both A and AAAA in the cache
    res_t cset;
    if (s_doIPv4 && g_recCache->get(d_now.tv_sec, qname, QType::A, flags, &cset, d_cacheRemote, d_routingTag) > 0) {
      collectAddresses<ARecordContent>(cset, ret);
    }
    if (s_doIPv6 && g_recCache->get(d_now.tv_sec, qname, QType::AAAA, flags, &cset, d_cacheRemote, d_routingTag) > 0) {
      if (collectAddresses<AAAARecordContent>(cset, ret)) {
        seenV6 = true;
      }
    }
    if (ret.empty()) {
      // Neither A nor AAAA in the cache...
      Context newContext1;
      cset.clear();
      // Go out to get A's
      if (s_doIPv4 && doResolveNoQNameMinimization(qname, QType::A, cset, depth + 1, beenthere, newContext1) == 0) { // this consults cache, OR goes out
        collectAddresses<ARecordContent>(cset, ret);
      }
      if (s_doIPv6) { // s_doIPv6 **IMPLIES** pdns::isQueryLocalAddressFamilyEnabled(AF_INET6) returned true
        if (ret.empty()) {
          // We only go out immediately to find IPv6 records if we did not find any IPv4 ones.
          Context newContext2;
          if (doResolveNoQNameMinimization(qname, QType::AAAA, cset, depth + 1, beenthere, newContext2) == 0) { // this consults cache, OR goes out
            if (collectAddresses<AAAARecordContent>(cset, ret)) {
              seenV6 = true;
            }
          }
        }
        else {
          // We have some IPv4 records, consult the cache, we might have encountered some IPv6 glue
          cset.clear();
          if (g_recCache->get(d_now.tv_sec, qname, QType::AAAA, flags, &cset, d_cacheRemote, d_routingTag) > 0) {
            if (collectAddresses<AAAARecordContent>(cset, ret)) {
              seenV6 = true;
            }
          }
        }
      }
    }
    if (s_doIPv6 && !seenV6 && !cacheOnly) {
      // No IPv6 records in cache, check negcache and submit async task if negache does not have the data
      // so that the next time the cache or the negcache will have data
      pushResolveIfNotInNegCache(qname, QType::AAAA, d_now);
    }
  }
  catch (const PolicyHitException&) {
    // We ignore a policy hit while trying to retrieve the addresses
    // of a NS and keep processing the current query
  }

  if (ret.empty() && d_outqueries > startqueries) {
    // We did 1 or more outgoing queries to resolve this NS name but returned empty handed
    addressQueriesForNS++;
  }
  d_requireAuthData = oldRequireAuthData;
  d_DNSSECValidationRequested = oldValidationRequested;
  setCacheOnly(oldCacheOnly);
  d_followCNAME = oldFollowCNAME;

  if (s_max_busy_dot_probes > 0 && s_dot_to_port_853) {
    for (auto& add : ret) {
      if (shouldDoDoT(add, d_now.tv_sec)) {
        add.setPort(853);
      }
    }
  }
  selectNSOnSpeed(qname, prefix, ret);
  return ret;
}

bool SyncRes::canUseRecords(const std::string& prefix, const DNSName& qname, const DNSName& name, QType qtype, vState state)
{
  if (vStateIsBogus(state)) {
    LOG(prefix << qname << ": Cannot use " << name << '/' << qtype << " records from cache: Bogus" << endl);
    return false;
  }
  // We could validate Indeterminate authoritative records here.
  return true;
}

void SyncRes::getBestNSFromCache(const DNSName& qname, const QType qtype, vector<DNSRecord>& bestns, bool* flawedNSSet, unsigned int depth, const string& prefix, set<GetBestNSAnswer>& beenthere, const std::optional<DNSName>& cutOffDomain) // NOLINT(readability-function-cognitive-complexity)
{
  DNSName subdomain(qname);
  bestns.clear();
  bool brokeloop = false;
  MemRecursorCache::Flags flags = MemRecursorCache::None;
  if (d_serveStale) {
    flags |= MemRecursorCache::ServeStale;
  }
  do {
    if (cutOffDomain && (subdomain == *cutOffDomain || !subdomain.isPartOf(*cutOffDomain))) {
      break;
    }
    brokeloop = false;
    LOG(prefix << qname << ": Checking if we have NS in cache for '" << subdomain << "'" << endl);
    vector<DNSRecord> nsVector;
    *flawedNSSet = false;

    vState state{vState::Indeterminate};
    if (bool isAuth = false; g_recCache->get(d_now.tv_sec, subdomain, QType::NS, flags, &nsVector, d_cacheRemote, d_routingTag, nullptr, nullptr, nullptr, &state, &isAuth) > 0 && canUseRecords(prefix, qname, subdomain, QType::NS, state)) {
      if (s_maxnsperresolve > 0 && nsVector.size() > s_maxnsperresolve) {
        vector<DNSRecord> selected;
        selected.reserve(s_maxnsperresolve);
        std::sample(nsVector.cbegin(), nsVector.cend(), std::back_inserter(selected), s_maxnsperresolve, pdns::dns_random_engine());
        nsVector = std::move(selected);
      }
      bestns.reserve(nsVector.size());

      vector<DNSName> missing;
      for (const auto& nsRecord : nsVector) {
        if (nsRecord.d_ttl > (unsigned int)d_now.tv_sec) {
          vector<DNSRecord> aset;
          QType nsqt{QType::ADDR};
          if (s_doIPv4 && !s_doIPv6) {
            nsqt = QType::A;
          }
          else if (!s_doIPv4 && s_doIPv6) {
            nsqt = QType::AAAA;
          }

          auto nrr = getRR<NSRecordContent>(nsRecord);
          state = vState::Indeterminate;
          if (nrr && (!nrr->getNS().isPartOf(subdomain) || g_recCache->get(d_now.tv_sec, nrr->getNS(), nsqt, flags, doLog() ? &aset : nullptr, d_cacheRemote, d_routingTag, nullptr, nullptr, nullptr, &state) > 0)) {
            // We make use of the fact that if get() is not called the state is still Indeterminate
            if (!canUseRecords(prefix, qname, nrr->getNS(), nsqt, state)) {
              continue;
            }
            bestns.push_back(nsRecord);
            LOG(prefix << qname << ": NS (with ip, or non-glue) in cache for '" << subdomain << "' -> '" << nrr->getNS() << "'");
            LOG(", within bailiwick: " << nrr->getNS().isPartOf(subdomain));
            if (!aset.empty()) {
              LOG(", in cache, ttl=" << (unsigned int)(((time_t)aset.begin()->d_ttl - d_now.tv_sec)) << endl);
            }
            else {
              LOG(", not in cache / did not look at cache" << endl);
            }
          }
          else if (nrr != nullptr) {
            *flawedNSSet = true;
            LOG(prefix << qname << ": NS in cache for '" << subdomain << "', but needs glue (" << nrr->getNS() << ") which we miss or is expired" << endl);
            missing.emplace_back(nrr->getNS());
          }
        }
      }
      if (*flawedNSSet && bestns.empty() && isAuth) {
        // The authoritative (child) NS records did not produce any usable addresses, wipe them, so
        // these useless records do not prevent parent records to be inserted into the cache
        LOG(prefix << qname << ": Wiping flawed authoritative NS records for " << subdomain << endl);
        g_recCache->doWipeCache(subdomain, false, QType::NS);
      }
      if (!missing.empty() && missing.size() < nsVector.size()) {
        // We miss glue, but we have a chance to resolve it
        // Pick a few and push async tasks to resolve them
        const unsigned int max = 2;
        unsigned int counter = 0;
        shuffle(missing.begin(), missing.end(), pdns::dns_random_engine());
        for (const auto& name : missing) {
          if (s_doIPv4 && pushResolveIfNotInNegCache(name, QType::A, d_now)) {
            LOG(prefix << qname << ": A glue for " << subdomain << " NS " << name << " missing, pushed task to resolve" << endl);
            counter++;
          }
          if (s_doIPv6 && pushResolveIfNotInNegCache(name, QType::AAAA, d_now)) {
            LOG(prefix << qname << ": AAAA glue for " << subdomain << " NS " << name << " missing, pushed task to resolve" << endl);
            counter++;
          }
          if (counter >= max) {
            break;
          }
        }
      }

      if (!bestns.empty()) {
        GetBestNSAnswer answer;
        answer.qname = qname;
        answer.qtype = qtype.getCode();
        for (const auto& bestNSRecord : bestns) {
          if (auto nsContent = getRR<NSRecordContent>(bestNSRecord)) {
            answer.bestns.emplace(bestNSRecord.d_name, nsContent->getNS());
          }
        }

        auto insertionPair = beenthere.insert(std::move(answer));
        if (!insertionPair.second) {
          brokeloop = true;
          LOG(prefix << qname << ": We have NS in cache for '" << subdomain << "' but part of LOOP (already seen " << insertionPair.first->qname << ")! Trying less specific NS" << endl);
          ;
          if (doLog()) {
            for (auto j = beenthere.begin(); j != beenthere.end(); ++j) {
              bool neo = (j == insertionPair.first);
              LOG(prefix << qname << ": Beenthere" << (neo ? "*" : "") << ": " << j->qname << "|" << DNSRecordContent::NumberToType(j->qtype) << " (" << (unsigned int)j->bestns.size() << ")" << endl);
            }
          }
          bestns.clear();
        }
        else {
          LOG(prefix << qname << ": We have NS in cache for '" << subdomain << "' (flawedNSSet=" << *flawedNSSet << ")" << endl);
          return;
        }
      }
    }
    LOG(prefix << qname << ": No valid/useful NS in cache for '" << subdomain << "'" << endl);

    if (subdomain.isRoot() && !brokeloop) {
      // We lost the root NS records
      primeHints();
      LOG(prefix << qname << ": Reprimed the root" << endl);
      /* let's prevent an infinite loop */
      if (!d_updatingRootNS) {
        auto log = g_slog->withName("housekeeping");
        getRootNS(d_now, d_asyncResolve, depth, log);
      }
    }
  } while (subdomain.chopOff());
}

SyncRes::domainmap_t::const_iterator SyncRes::getBestAuthZone(DNSName* qname)
{
  if (t_sstorage.domainmap->empty()) {
    return t_sstorage.domainmap->end();
  }

  SyncRes::domainmap_t::const_iterator ret;
  do {
    ret = t_sstorage.domainmap->find(*qname);
    if (ret != t_sstorage.domainmap->end()) {
      break;
    }
  } while (qname->chopOff());
  return ret;
}

/** doesn't actually do the work, leaves that to getBestNSFromCache */
DNSName SyncRes::getBestNSNamesFromCache(const DNSName& qname, const QType qtype, NsSet& nsset, bool* flawedNSSet, unsigned int depth, const string& prefix, set<GetBestNSAnswer>& beenthere)
{
  DNSName authOrForwDomain(qname);

  auto iter = getBestAuthZone(&authOrForwDomain);
  // We have an auth, forwarder of forwarder-recurse
  if (iter != t_sstorage.domainmap->end()) {
    if (iter->second.isAuth()) {
      // this gets picked up in doResolveAt, the empty DNSName, combined with the
      // empty vector means 'we are auth for this zone'
      nsset.insert({DNSName(), {{}, false}});
      return authOrForwDomain;
    }
    if (iter->second.shouldRecurse()) {
      // Again, picked up in doResolveAt. An empty DNSName, combined with a
      // non-empty vector of ComboAddresses means 'this is a forwarded domain'
      // This is actually picked up in retrieveAddressesForNS called from doResolveAt.
      nsset.insert({DNSName(), {iter->second.d_servers, true}});
      return authOrForwDomain;
    }
  }

  // We might have a (non-recursive) forwarder, but maybe the cache already contains
  // a better NS
  vector<DNSRecord> bestns;
  DNSName nsFromCacheDomain(g_rootdnsname);
  getBestNSFromCache(qname, qtype, bestns, flawedNSSet, depth, prefix, beenthere);

  // Pick up the auth domain
  for (const auto& nsRecord : bestns) {
    const auto nsContent = getRR<NSRecordContent>(nsRecord);
    if (nsContent) {
      nsFromCacheDomain = nsRecord.d_name;
      break;
    }
  }

  if (iter != t_sstorage.domainmap->end()) {
    if (doLog()) {
      LOG(prefix << qname << " authOrForwDomain: " << authOrForwDomain << " nsFromCacheDomain: " << nsFromCacheDomain << " isPartof: " << authOrForwDomain.isPartOf(nsFromCacheDomain) << endl);
    }

    // If the forwarder is better or equal to what's found in the cache, use forwarder. Note that name.isPartOf(name).
    // So queries that get NS for authOrForwDomain itself go to the forwarder
    if (authOrForwDomain.isPartOf(nsFromCacheDomain)) {
      if (doLog()) {
        LOG(prefix << qname << ": Using forwarder as NS" << endl);
      }
      nsset.insert({DNSName(), {iter->second.d_servers, false}});
      return authOrForwDomain;
    }
    if (doLog()) {
      LOG(prefix << qname << ": Using NS from cache" << endl);
    }
  }
  for (const auto& bestn : bestns) {
    // The actual resolver code will not even look at the ComboAddress or bool
    const auto nsContent = getRR<NSRecordContent>(bestn);
    if (nsContent) {
      nsset.insert({nsContent->getNS(), {{}, false}});
    }
  }
  return nsFromCacheDomain;
}

void SyncRes::updateValidationStatusInCache(const DNSName& qname, const QType qtype, bool aaFlag, vState newState) const
{
  if (qtype == QType::ANY || qtype == QType::ADDR) {
    // not doing that
    return;
  }

  if (vStateIsBogus(newState)) {
    g_recCache->updateValidationStatus(d_now.tv_sec, qname, qtype, d_cacheRemote, d_routingTag, aaFlag, newState, s_maxbogusttl + d_now.tv_sec);
  }
  else {
    g_recCache->updateValidationStatus(d_now.tv_sec, qname, qtype, d_cacheRemote, d_routingTag, aaFlag, newState, std::nullopt);
  }
}

static pair<bool, unsigned int> scanForCNAMELoop(const DNSName& name, const vector<DNSRecord>& records)
{
  unsigned int numCNames = 0;
  for (const auto& record : records) {
    if (record.d_type == QType::CNAME && record.d_place == DNSResourceRecord::ANSWER) {
      ++numCNames;
      if (name == record.d_name) {
        return {true, numCNames};
      }
    }
  }
  return {false, numCNames};
}

bool SyncRes::doCNAMECacheCheck(const DNSName& qname, const QType qtype, vector<DNSRecord>& ret, unsigned int depth, const string& prefix, int& res, Context& context, bool wasAuthZone, bool wasForwardRecurse, bool checkForDups) // NOLINT(readability-function-cognitive-complexity)
{
  vector<DNSRecord> cset;
  MemRecursorCache::SigRecs signatures = MemRecursorCache::s_emptySigRecs;
  MemRecursorCache::AuthRecs authorityRecs = MemRecursorCache::s_emptyAuthRecs;
  bool wasAuth = false;
  uint32_t capTTL = std::numeric_limits<uint32_t>::max();
  DNSName foundName;
  DNSName authZone;
  QType foundQT = QType::ENT;

  /* we don't require auth data for forward-recurse lookups */
  MemRecursorCache::Flags flags = MemRecursorCache::None;
  if (!wasForwardRecurse && d_requireAuthData) {
    flags |= MemRecursorCache::RequireAuth;
  }
  if (d_refresh) {
    flags |= MemRecursorCache::Refresh;
  }
  if (d_serveStale) {
    flags |= MemRecursorCache::ServeStale;
  }
  MemRecursorCache::Extra extra;
  if (g_recCache->get(d_now.tv_sec, qname, QType::CNAME, flags, &cset, d_cacheRemote, d_routingTag, d_doDNSSEC ? &signatures : nullptr, d_doDNSSEC ? &authorityRecs : nullptr, &d_wasVariable, &context.state, &wasAuth, &authZone, &extra) > 0) {
    foundName = qname;
    foundQT = QType::CNAME;
    d_fromAuthIP = extra.d_address;
  }

  if (foundName.empty() && qname != g_rootdnsname) {
    // look for a DNAME cache hit
    auto labels = qname.getRawLabels();
    DNSName dnameName(g_rootdnsname);

    do {
      dnameName.prependRawLabel(labels.back());
      labels.pop_back();
      if (dnameName == qname && qtype != QType::DNAME) { // The client does not want a DNAME, but we've reached the QNAME already. So there is no match
        break;
      }
      if (g_recCache->get(d_now.tv_sec, dnameName, QType::DNAME, flags, &cset, d_cacheRemote, d_routingTag, d_doDNSSEC ? &signatures : nullptr, d_doDNSSEC ? &authorityRecs : nullptr, &d_wasVariable, &context.state, &wasAuth, &authZone, &extra) > 0) {
        foundName = std::move(dnameName);
        foundQT = QType::DNAME;
        d_fromAuthIP = extra.d_address;
        break;
      }
    } while (!labels.empty());
  }

  if (foundName.empty()) {
    return false;
  }

  if (qtype == QType::DS && authZone == qname) {
    /* CNAME at APEX of the child zone, we can't use that to prove that
       there is no DS */
    LOG(prefix << qname << ": Found a " << foundQT.toString() << " cache hit of '" << qname << "' from " << authZone << ", but such a record at the apex of the child zone does not prove that there is no DS in the parent zone" << endl);
    return false;
  }

  for (auto const& record : cset) {
    if (record.d_class != QClass::IN) {
      continue;
    }

    if (record.d_ttl > (unsigned int)d_now.tv_sec) {

      if (!wasAuthZone && shouldValidate() && (wasAuth || wasForwardRecurse) && context.state == vState::Indeterminate && d_requireAuthData) {
        /* This means we couldn't figure out the state when this entry was cached */

        vState recordState = getValidationStatus(foundName, !signatures->empty(), qtype == QType::DS, depth, prefix);
        if (recordState == vState::Secure) {
          LOG(prefix << qname << ": Got vState::Indeterminate state from the " << foundQT.toString() << " cache, validating.." << endl);
          context.state = SyncRes::validateRecordsWithSigs(depth, prefix, qname, qtype, foundName, foundQT, cset, *signatures);
          if (context.state != vState::Indeterminate) {
            LOG(prefix << qname << ": Got vState::Indeterminate state from the " << foundQT.toString() << " cache, new validation result is " << context.state << endl);
            if (vStateIsBogus(context.state)) {
              capTTL = s_maxbogusttl;
            }
            updateValidationStatusInCache(foundName, foundQT, wasAuth, context.state);
          }
        }
      }

      LOG(prefix << qname << ": Found cache " << foundQT.toString() << " hit for '" << foundName << "|" << foundQT.toString() << "' to '" << record.getContent()->getZoneRepresentation() << "', validation state is " << context.state << endl);

      DNSRecord dnsRecord = record;
      auto alreadyPresent = false;

      if (checkForDups) {
        // This can happen on the 2nd iteration of the servestale loop, where the first iteration
        // added a C/DNAME record, but the target resolve failed
        for (const auto& dnsrec : ret) {
          if (dnsrec.d_type == foundQT && dnsrec.d_name == record.d_name) {
            alreadyPresent = true;
            break;
          }
        }
      }
      dnsRecord.d_ttl -= d_now.tv_sec;
      dnsRecord.d_ttl = std::min(dnsRecord.d_ttl, capTTL);
      const uint32_t ttl = dnsRecord.d_ttl;
      if (!alreadyPresent) {
        ret.reserve(ret.size() + 2 + signatures->size() + authorityRecs->size());
        ret.push_back(dnsRecord);

        for (const auto& signature : *signatures) {
          DNSRecord sigdr;
          sigdr.d_type = QType::RRSIG;
          sigdr.d_name = foundName;
          sigdr.d_ttl = ttl;
          sigdr.setContent(signature);
          sigdr.d_place = DNSResourceRecord::ANSWER;
          sigdr.d_class = QClass::IN;
          ret.push_back(std::move(sigdr));
        }

        for (const auto& rec : *authorityRecs) {
          DNSRecord authDR(rec);
          authDR.d_ttl = ttl;
          ret.push_back(std::move(authDR));
        }
      }

      DNSName newTarget;
      if (foundQT == QType::DNAME) {
        if (qtype == QType::DNAME && qname == foundName) { // client wanted the DNAME, no need to synthesize a CNAME
          res = RCode::NoError;
          return true;
        }
        // Synthesize a CNAME
        auto dnameRR = getRR<DNAMERecordContent>(record);
        if (dnameRR == nullptr) {
          throw ImmediateServFailException("Unable to get record content for " + foundName.toLogString() + "|DNAME cache entry");
        }
        const auto& dnameSuffix = dnameRR->getTarget();
        DNSName targetPrefix = qname.makeRelative(foundName);
        try {
          dnsRecord.d_type = QType::CNAME;
          dnsRecord.d_name = targetPrefix + foundName;
          newTarget = targetPrefix + dnameSuffix;
          dnsRecord.setContent(std::make_shared<CNAMERecordContent>(CNAMERecordContent(newTarget)));
          ret.push_back(dnsRecord);
        }
        catch (const std::exception& e) {
          // We should probably catch an std::range_error here and set the rcode to YXDOMAIN (RFC 6672, section 2.2)
          // But this is consistent with processRecords
          throw ImmediateServFailException("Unable to perform DNAME substitution(DNAME owner: '" + foundName.toLogString() + "', DNAME target: '" + dnameSuffix.toLogString() + "', substituted name: '" + targetPrefix.toLogString() + "." + dnameSuffix.toLogString() + "' : " + e.what());
        }

        LOG(prefix << qname << ": Synthesized " << dnsRecord.d_name << "|CNAME " << newTarget << endl);
      }

      if (qtype == QType::CNAME) { // perhaps they really wanted a CNAME!
        res = RCode::NoError;
        return true;
      }

      if (qtype == QType::DS || qtype == QType::DNSKEY) {
        res = RCode::NoError;
        return true;
      }

      // We have a DNAME _or_ CNAME cache hit and the client wants something else than those two.
      // Let's find the answer!
      if (foundQT == QType::CNAME) {
        const auto cnameContent = getRR<CNAMERecordContent>(record);
        if (cnameContent == nullptr) {
          throw ImmediateServFailException("Unable to get record content for " + foundName.toLogString() + "|CNAME cache entry");
        }
        newTarget = cnameContent->getTarget();
      }

      if (qname == newTarget) {
        string msg = "Got a CNAME referral (from cache) to self";
        LOG(prefix << qname << ": " << msg << endl);
        throw ImmediateServFailException(std::move(msg));
      }

      if (newTarget.isPartOf(qname)) {
        // a.b.c. CNAME x.a.b.c will go to great depths with QM on
        string msg = "Got a CNAME referral (from cache) to child, disabling QM";
        LOG(prefix << qname << ": " << msg << endl);
        setQNameMinimization(false);
      }

      if (!d_followCNAME) {
        res = RCode::NoError;
        return true;
      }

      // Check to see if we already have seen the new target as a previous target or that we have a very long CNAME chain
      const auto [CNAMELoop, numCNAMEs] = scanForCNAMELoop(newTarget, ret);
      if (CNAMELoop) {
        string msg = "got a CNAME referral (from cache) that causes a loop";
        LOG(prefix << qname << ": Status=" << msg << endl);
        throw ImmediateServFailException(std::move(msg));
      }
      if (numCNAMEs > s_max_CNAMES_followed) {
        string msg = "max number of CNAMEs exceeded";
        LOG(prefix << qname << ": Status=" << msg << endl);
        throw ImmediateServFailException(std::move(msg));
      }

      set<GetBestNSAnswer> beenthere;
      Context cnameContext;
      // Be aware that going out on the network might be disabled (cache-only), for example because we are in QM Step0,
      // so you can't trust that a real lookup will have been made.
      res = doResolve(newTarget, qtype, ret, depth + 1, beenthere, cnameContext);
      LOG(prefix << qname << ": Updating validation state for response to " << qname << " from " << context.state << " with the state from the DNAME/CNAME quest: " << cnameContext.state << endl);
      pdns::dedupRecords(ret); // multiple NSECS could have been added, #14120
      updateValidationState(qname, context.state, cnameContext.state, prefix);

      return true;
    }
  }
  throw ImmediateServFailException("Could not determine whether or not there was a CNAME or DNAME in cache for '" + qname.toLogString() + "'");
}

namespace
{
struct CacheEntry
{
  vector<DNSRecord> records;
  MemRecursorCache::SigRecsVec signatures;
  time_t d_ttl_time{0};
  uint32_t signaturesTTL{std::numeric_limits<uint32_t>::max()};
};
struct CacheKey
{
  DNSName name;
  QType type;
  DNSResourceRecord::Place place;
  bool operator<(const CacheKey& rhs) const
  {
    return std::tie(type, place, name) < std::tie(rhs.type, rhs.place, rhs.name);
  }
};
using tcache_t = map<CacheKey, CacheEntry>;
}

static void reapRecordsFromNegCacheEntryForValidation(tcache_t& tcache, const vector<DNSRecord>& records)
{
  for (const auto& rec : records) {
    if (rec.d_type == QType::RRSIG) {
      auto rrsig = getRR<RRSIGRecordContent>(rec);
      if (rrsig) {
        tcache[{rec.d_name, rrsig->d_type, rec.d_place}].signatures.push_back(rrsig);
      }
    }
    else {
      tcache[{rec.d_name, rec.d_type, rec.d_place}].records.push_back(rec);
    }
  }
}

static bool negativeCacheEntryHasSOA(const NegCache::NegCacheEntry& negEntry)
{
  return !negEntry.authoritySOA.records.empty();
}

static void reapRecordsForValidation(std::map<QType, CacheEntry>& entries, const vector<DNSRecord>& records)
{
  for (const auto& rec : records) {
    entries[rec.d_type].records.push_back(rec);
  }
}

static void reapSignaturesForValidation(std::map<QType, CacheEntry>& entries, const MemRecursorCache::SigRecs& signatures)
{
  for (const auto& sig : *signatures) {
    entries[sig->d_type].signatures.push_back(sig);
  }
}

/*!
 * Convenience function to push the records from records into ret with a new TTL
 *
 * \param records DNSRecords that need to go into ret
 * \param ttl     The new TTL for these records
 * \param ret     The vector of DNSRecords that should contain the records with the modified TTL
 */
static void addTTLModifiedRecords(vector<DNSRecord>& records, const uint32_t ttl, vector<DNSRecord>& ret)
{
  for (auto& rec : records) {
    rec.d_ttl = ttl;
    ret.push_back(std::move(rec));
  }
}

void SyncRes::computeNegCacheValidationStatus(const NegCache::NegCacheEntry& negEntry, const DNSName& qname, const QType qtype, const int res, vState& state, unsigned int depth, const string& prefix)
{
  tcache_t tcache;
  reapRecordsFromNegCacheEntryForValidation(tcache, negEntry.authoritySOA.records);
  reapRecordsFromNegCacheEntryForValidation(tcache, negEntry.authoritySOA.signatures);
  reapRecordsFromNegCacheEntryForValidation(tcache, negEntry.DNSSECRecords.records);
  reapRecordsFromNegCacheEntryForValidation(tcache, negEntry.DNSSECRecords.signatures);

  for (const auto& entry : tcache) {
    // this happens when we did store signatures, but passed on the records themselves
    if (entry.second.records.empty()) {
      continue;
    }

    const DNSName& owner = entry.first.name;

    vState recordState = getValidationStatus(owner, !entry.second.signatures.empty(), qtype == QType::DS, depth, prefix);
    if (state == vState::Indeterminate) {
      state = recordState;
    }

    if (recordState == vState::Secure) {
      recordState = SyncRes::validateRecordsWithSigs(depth, prefix, qname, qtype, owner, QType(entry.first.type), entry.second.records, entry.second.signatures);
    }

    if (recordState != vState::Indeterminate && recordState != state) {
      updateValidationState(qname, state, recordState, prefix);
      if (state != vState::Secure) {
        break;
      }
    }
  }

  if (state == vState::Secure) {
    vState neValidationState = negEntry.d_validationState;
    dState expectedState = res == RCode::NXDomain ? dState::NXDOMAIN : dState::NXQTYPE;
    dState denialState = getDenialValidationState(negEntry, expectedState, false, prefix);
    updateDenialValidationState(qname, neValidationState, negEntry.d_name, state, denialState, expectedState, qtype == QType::DS, depth, prefix);
  }
  if (state != vState::Indeterminate) {
    /* validation succeeded, let's update the cache entry so we don't have to validate again */
    std::optional<time_t> capTTD = std::nullopt;
    if (vStateIsBogus(state)) {
      capTTD = d_now.tv_sec + s_maxbogusttl;
    }
    g_negCache->updateValidationStatus(negEntry.d_name, negEntry.d_qtype, state, capTTD);
  }
}

bool SyncRes::doCacheCheck(const DNSName& qname, const DNSName& authname, bool wasForwardedOrAuthZone, bool wasAuthZone, bool wasForwardRecurse, QType qtype, vector<DNSRecord>& ret, unsigned int depth, const string& prefix, int& res, Context& context) // NOLINT(readability-function-cognitive-complexity)
{
  bool giveNegative = false;

  // sqname and sqtype are used contain 'higher' names if we have them (e.g. powerdns.com|SOA when we find a negative entry for doesnotexist.powerdns.com|A)
  DNSName sqname(qname);
  QType sqt(qtype);
  uint32_t sttl = 0;
  //  cout<<"Lookup for '"<<qname<<"|"<<qtype.toString()<<"' -> "<<getLastLabel(qname)<<endl;
  vState cachedState{};
  NegCache::NegCacheEntry negEntry;

  if (s_rootNXTrust && g_negCache->getRootNXTrust(qname, d_now, negEntry, d_serveStale, d_refresh) && negEntry.d_auth.isRoot() && (!wasForwardedOrAuthZone || authname.isRoot())) { // when forwarding, the root may only neg-cache if it was forwarded to.
    sttl = negEntry.d_ttd - d_now.tv_sec;
    LOG(prefix << qname << ": Entire name '" << qname << "', is negatively cached via '" << negEntry.d_auth << "' & '" << negEntry.d_name << "' for another " << sttl << " seconds" << endl);
    res = RCode::NXDomain;
    giveNegative = true;
    cachedState = negEntry.d_validationState;
    if (s_addExtendedResolutionDNSErrors) {
      context.extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::Synthesized), "Result synthesized by root-nx-trust"};
    }
  }
  else if (g_negCache->get(qname, qtype, d_now, negEntry, false, d_serveStale, d_refresh)) {
    /* If we are looking for a DS, discard NXD if auth == qname
       and ask for a specific denial instead */
    if (qtype != QType::DS || negEntry.d_qtype.getCode() != 0 || negEntry.d_auth != qname || g_negCache->get(qname, qtype, d_now, negEntry, true, d_serveStale, d_refresh)) {
      /* Careful! If the client is asking for a DS that does not exist, we need to provide the SOA along with the NSEC(3) proof
         and we might not have it if we picked up the proof from a delegation, in which case we need to keep on to do the actual DS
         query. */
      if (qtype == QType::DS && negEntry.d_qtype.getCode() != 0 && !d_externalDSQuery.empty() && qname == d_externalDSQuery && !negativeCacheEntryHasSOA(negEntry)) {
        giveNegative = false;
      }
      else {
        res = RCode::NXDomain;
        sttl = negEntry.d_ttd - d_now.tv_sec;
        giveNegative = true;
        cachedState = negEntry.d_validationState;
        if (negEntry.d_qtype.getCode() != 0) {
          LOG(prefix << qname << "|" << qtype << ": Is negatively cached via '" << negEntry.d_auth << "' for another " << sttl << " seconds" << endl);
          res = RCode::NoError;
          if (s_addExtendedResolutionDNSErrors) {
            context.extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::Synthesized), "Result from negative cache"};
          }
        }
        else {
          LOG(prefix << qname << ": Entire name '" << qname << "' is negatively cached via '" << negEntry.d_auth << "' for another " << sttl << " seconds" << endl);
          if (s_addExtendedResolutionDNSErrors) {
            context.extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::Synthesized), "Result from negative cache for entire name"};
          }
        }
      }
    }
  }
  else if (s_hardenNXD != HardenNXD::No && !qname.isRoot() && !wasForwardedOrAuthZone) {
    auto labels = qname.getRawLabels();
    DNSName negCacheName(g_rootdnsname);
    negCacheName.prependRawLabel(labels.back());
    labels.pop_back();
    while (!labels.empty()) {
      if (g_negCache->get(negCacheName, QType::ENT, d_now, negEntry, true, d_serveStale, d_refresh)) {
        if (negEntry.d_validationState == vState::Indeterminate && validationEnabled()) {
          // LOG(prefix << negCacheName <<  " negatively cached and vState::Indeterminate, trying to validate NXDOMAIN" << endl);
          // ...
          // And get the updated ne struct
          // t_sstorage.negcache.get(negCacheName, QType(0), d_now, ne, true);
        }
        if ((s_hardenNXD == HardenNXD::Yes && !vStateIsBogus(negEntry.d_validationState)) || negEntry.d_validationState == vState::Secure) {
          res = RCode::NXDomain;
          sttl = negEntry.d_ttd - d_now.tv_sec;
          giveNegative = true;
          cachedState = negEntry.d_validationState;
          LOG(prefix << qname << ": Name '" << negCacheName << "' and below, is negatively cached via '" << negEntry.d_auth << "' for another " << sttl << " seconds" << endl);
          if (s_addExtendedResolutionDNSErrors) {
            context.extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::Synthesized), "Result synthesized by nothing-below-nxdomain (RFC8020)"};
          }
          break;
        }
      }
      negCacheName.prependRawLabel(labels.back());
      labels.pop_back();
    }
  }

  if (giveNegative) {

    context.state = cachedState;

    if (!wasAuthZone && shouldValidate() && context.state == vState::Indeterminate) {
      LOG(prefix << qname << ": Got vState::Indeterminate state for records retrieved from the negative cache, validating.." << endl);
      computeNegCacheValidationStatus(negEntry, qname, qtype, res, context.state, depth, prefix);

      if (context.state != cachedState && vStateIsBogus(context.state)) {
        sttl = std::min(sttl, s_maxbogusttl);
      }
    }

    // Transplant SOA to the returned packet
    addTTLModifiedRecords(negEntry.authoritySOA.records, sttl, ret);
    if (d_doDNSSEC) {
      addTTLModifiedRecords(negEntry.authoritySOA.signatures, sttl, ret);
      addTTLModifiedRecords(negEntry.DNSSECRecords.records, sttl, ret);
      addTTLModifiedRecords(negEntry.DNSSECRecords.signatures, sttl, ret);
    }

    LOG(prefix << qname << ": Updating validation state with negative cache content for " << qname << " to " << context.state << endl);
    return true;
  }

  vector<DNSRecord> cset;
  bool found = false;
  bool expired = false;
  MemRecursorCache::SigRecs signatures = MemRecursorCache::s_emptySigRecs;
  MemRecursorCache::AuthRecs authorityRecs = MemRecursorCache::s_emptyAuthRecs;
  uint32_t ttl = 0;
  uint32_t capTTL = std::numeric_limits<uint32_t>::max();
  bool wasCachedAuth{};
  MemRecursorCache::Flags flags = MemRecursorCache::None;
  if (!wasForwardRecurse && d_requireAuthData) {
    flags |= MemRecursorCache::RequireAuth;
  }
  if (d_serveStale) {
    flags |= MemRecursorCache::ServeStale;
  }
  if (d_refresh) {
    flags |= MemRecursorCache::Refresh;
  }

  MemRecursorCache::Extra extra;
  if (g_recCache->get(d_now.tv_sec, sqname, sqt, flags, &cset, d_cacheRemote, d_routingTag, d_doDNSSEC ? &signatures : nullptr, d_doDNSSEC ? &authorityRecs : nullptr, &d_wasVariable, &cachedState, &wasCachedAuth, nullptr, &extra) > 0) {
    d_fromAuthIP = extra.d_address;

    LOG(prefix << sqname << ": Found cache hit for " << sqt.toString() << ": ");

    if (!wasAuthZone && shouldValidate() && (wasCachedAuth || wasForwardRecurse) && cachedState == vState::Indeterminate && d_requireAuthData) {

      /* This means we couldn't figure out the state when this entry was cached */
      vState recordState = getValidationStatus(qname, !signatures->empty(), qtype == QType::DS, depth, prefix);

      if (recordState == vState::Secure) {
        LOG(prefix << sqname << ": Got vState::Indeterminate state from the cache, validating.." << endl);
        if (sqt == QType::DNSKEY && sqname == getSigner(*signatures)) {
          cachedState = validateDNSKeys(sqname, cset, *signatures, depth, prefix);
        }
        else {
          if (sqt == QType::ANY) {
            std::map<QType, CacheEntry> types;
            reapRecordsForValidation(types, cset);
            reapSignaturesForValidation(types, signatures);

            for (const auto& type : types) {
              vState cachedRecordState{};
              if (type.first == QType::DNSKEY && sqname == getSigner(type.second.signatures)) {
                cachedRecordState = validateDNSKeys(sqname, type.second.records, type.second.signatures, depth, prefix);
              }
              else {
                cachedRecordState = SyncRes::validateRecordsWithSigs(depth, prefix, qname, qtype, sqname, type.first, type.second.records, type.second.signatures);
              }
              updateDNSSECValidationState(cachedState, cachedRecordState);
            }
          }
          else {
            cachedState = SyncRes::validateRecordsWithSigs(depth, prefix, qname, qtype, sqname, sqt, cset, *signatures);
          }
        }
      }
      else {
        cachedState = recordState;
      }

      if (cachedState != vState::Indeterminate) {
        LOG(prefix << qname << ": Got vState::Indeterminate state from the cache, validation result is " << cachedState << endl);
        if (vStateIsBogus(cachedState)) {
          capTTL = s_maxbogusttl;
        }
        if (sqt != QType::ANY && sqt != QType::ADDR) {
          updateValidationStatusInCache(sqname, sqt, wasCachedAuth, cachedState);
        }
      }
    }

    for (auto j = cset.cbegin(); j != cset.cend(); ++j) {

      LOG(j->getContent()->getZoneRepresentation());

      if (j->d_class != QClass::IN) {
        continue;
      }

      if (j->d_ttl > (unsigned int)d_now.tv_sec) {
        DNSRecord dnsRecord = *j;
        dnsRecord.d_ttl -= d_now.tv_sec;
        dnsRecord.d_ttl = std::min(dnsRecord.d_ttl, capTTL);
        ttl = dnsRecord.d_ttl;
        ret.push_back(dnsRecord);
        LOG("[ttl=" << dnsRecord.d_ttl << "] ");
        found = true;
      }
      else {
        LOG("[expired] ");
        expired = true;
      }
    }

    ret.reserve(ret.size() + signatures->size() + authorityRecs->size());

    for (const auto& signature : *signatures) {
      DNSRecord dnsRecord;
      dnsRecord.d_type = QType::RRSIG;
      dnsRecord.d_name = sqname;
      dnsRecord.d_ttl = ttl;
      dnsRecord.setContent(signature);
      dnsRecord.d_place = DNSResourceRecord::ANSWER;
      dnsRecord.d_class = QClass::IN;
      ret.push_back(std::move(dnsRecord));
    }

    for (const auto& rec : *authorityRecs) {
      DNSRecord dnsRecord(rec);
      dnsRecord.d_ttl = ttl;
      ret.push_back(std::move(dnsRecord));
    }

    LOG(endl);
    if (found && !expired) {
      if (!giveNegative) {
        res = 0;
      }
      LOG(prefix << qname << ": Updating validation state with cache content for " << qname << " to " << cachedState << endl);
      context.state = cachedState;
      return true;
    }
    LOG(prefix << qname << ": Cache had only stale entries" << endl);
  }

  /* let's check if we have a NSEC covering that record */
  if (g_aggressiveNSECCache && !wasForwardedOrAuthZone) {
    if (g_aggressiveNSECCache->getDenial(d_now.tv_sec, qname, qtype, ret, res, d_cacheRemote, d_routingTag, d_doDNSSEC, d_validationContext, LogObject(prefix))) {
      context.state = vState::Secure;
      if (s_addExtendedResolutionDNSErrors) {
        context.extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::Synthesized), "Result synthesized from aggressive NSEC cache (RFC8198)"};
      }
      return true;
    }
  }

  return false;
}

bool SyncRes::moreSpecificThan(const DNSName& lhs, const DNSName& rhs)
{
  return (lhs.isPartOf(rhs) && lhs.countLabels() > rhs.countLabels());
}

struct speedOrder
{
  bool operator()(const std::pair<DNSName, float>& lhs, const std::pair<DNSName, float>& rhs) const
  {
    return lhs.second < rhs.second;
  }
};

std::vector<std::pair<DNSName, float>> SyncRes::shuffleInSpeedOrder(const DNSName& qname, NsSet& tnameservers, const string& prefix)
{
  std::vector<std::pair<DNSName, float>> rnameservers;
  rnameservers.reserve(tnameservers.size());
  for (const auto& tns : tnameservers) {
    float speed = s_nsSpeeds.lock()->fastest(tns.first, d_now);
    rnameservers.emplace_back(tns.first, speed);
    if (tns.first.empty()) { // this was an authoritative OOB zone, don't pollute the nsSpeeds with that
      return rnameservers;
    }
  }

  shuffle(rnameservers.begin(), rnameservers.end(), pdns::dns_random_engine());
  speedOrder speedCompare;
  stable_sort(rnameservers.begin(), rnameservers.end(), speedCompare);

  if (doLog()) {
    LOG(prefix << qname << ": Nameservers: ");
    for (auto i = rnameservers.begin(); i != rnameservers.end(); ++i) {
      if (i != rnameservers.begin()) {
        LOG(", ");
        if (((i - rnameservers.begin()) % 3) == 0) {
          LOG(endl
              << prefix << "             ");
        }
      }
      LOG(i->first.toLogString() << "(" << fmtfloat(i->second / 1000.0) << "ms)");
    }
    LOG(endl);
  }
  return rnameservers;
}

vector<ComboAddress> SyncRes::shuffleForwardSpeed(const DNSName& qname, const vector<ComboAddress>& rnameservers, const string& prefix, const bool wasRd)
{
  vector<ComboAddress> nameservers = rnameservers;
  map<ComboAddress, float> speeds;

  for (const auto& val : nameservers) {
    DNSName nsName = DNSName(val.toStringWithPort());
    float speed = s_nsSpeeds.lock()->fastest(nsName, d_now);
    speeds[val] = speed;
  }
  shuffle(nameservers.begin(), nameservers.end(), pdns::dns_random_engine());
  speedOrderCA speedCompare(speeds);
  stable_sort(nameservers.begin(), nameservers.end(), speedCompare);

  if (doLog()) {
    LOG(prefix << qname << ": Nameservers: ");
    for (auto i = nameservers.cbegin(); i != nameservers.cend(); ++i) {
      if (i != nameservers.cbegin()) {
        LOG(", ");
        if (((i - nameservers.cbegin()) % 3) == 0) {
          LOG(endl
              << prefix << "             ");
        }
      }
      LOG((wasRd ? string("+") : string("-")) << i->toStringWithPort() << "(" << fmtfloat(speeds[*i] / 1000.0) << "ms)");
    }
    LOG(endl);
  }
  return nameservers;
}

static uint32_t getRRSIGTTL(const time_t now, const std::shared_ptr<const RRSIGRecordContent>& rrsig)
{
  uint32_t res = 0;
  if (now < rrsig->d_sigexpire) {
    // coverity[store_truncates_time_t]
    res = static_cast<uint32_t>(rrsig->d_sigexpire) - now;
  }
  return res;
}

static const set<QType> nsecTypes = {QType::NSEC, QType::NSEC3};

/* Fills the authoritySOA and DNSSECRecords fields from ne with those found in the records
 *
 * \param records The records to parse for the authority SOA and NSEC(3) records
 * \param ne      The NegCacheEntry to be filled out (will not be cleared, only appended to
 */
static void harvestNXRecords(const vector<DNSRecord>& records, NegCache::NegCacheEntry& negEntry, const time_t now, uint32_t* lowestTTL)
{
  for (const auto& rec : records) {
    if (rec.d_place != DNSResourceRecord::AUTHORITY) {
      // RFC 4035 section 3.1.3. indicates that NSEC records MUST be placed in
      // the AUTHORITY section. Section 3.1.1 indicates that RRSIGs for
      // records MUST be in the same section as the records they cover.
      // Hence, we ignore all records outside of the AUTHORITY section.
      continue;
    }

    if (rec.d_type == QType::RRSIG) {
      auto rrsig = getRR<RRSIGRecordContent>(rec);
      if (rrsig) {
        if (rrsig->d_type == QType::SOA) {
          negEntry.authoritySOA.signatures.push_back(rec);
          if (lowestTTL != nullptr && isRRSIGNotExpired(now, *rrsig)) {
            *lowestTTL = min(*lowestTTL, rec.d_ttl);
            *lowestTTL = min(*lowestTTL, getRRSIGTTL(now, rrsig));
          }
        }
        if (nsecTypes.count(rrsig->d_type) != 0) {
          negEntry.DNSSECRecords.signatures.push_back(rec);
          if (lowestTTL != nullptr && isRRSIGNotExpired(now, *rrsig)) {
            *lowestTTL = min(*lowestTTL, rec.d_ttl);
            *lowestTTL = min(*lowestTTL, getRRSIGTTL(now, rrsig));
          }
        }
      }
      continue;
    }
    if (rec.d_type == QType::SOA) {
      negEntry.authoritySOA.records.push_back(rec);
      if (lowestTTL != nullptr) {
        *lowestTTL = min(*lowestTTL, rec.d_ttl);
      }
      continue;
    }
    if (nsecTypes.count(rec.d_type) != 0) {
      negEntry.DNSSECRecords.records.push_back(rec);
      if (lowestTTL != nullptr) {
        *lowestTTL = min(*lowestTTL, rec.d_ttl);
      }
      continue;
    }
  }
}

static cspmap_t harvestCSPFromNE(const NegCache::NegCacheEntry& negEntry)
{
  cspmap_t cspmap;
  for (const auto& rec : negEntry.DNSSECRecords.signatures) {
    if (rec.d_type == QType::RRSIG) {
      auto rrc = getRR<RRSIGRecordContent>(rec);
      if (rrc) {
        cspmap[{rec.d_name, rrc->d_type}].signatures.push_back(rrc);
      }
    }
  }
  for (const auto& rec : negEntry.DNSSECRecords.records) {
    cspmap[{rec.d_name, rec.d_type}].records.insert(rec.getContent());
  }
  return cspmap;
}

// TODO remove after processRecords is fixed!
// Adds the RRSIG for the SOA and the NSEC(3) + RRSIGs to ret
static void addNXNSECS(vector<DNSRecord>& ret, const vector<DNSRecord>& records)
{
  NegCache::NegCacheEntry negEntry;
  harvestNXRecords(records, negEntry, 0, nullptr);
  ret.insert(ret.end(), negEntry.authoritySOA.signatures.begin(), negEntry.authoritySOA.signatures.end());
  ret.insert(ret.end(), negEntry.DNSSECRecords.records.begin(), negEntry.DNSSECRecords.records.end());
  ret.insert(ret.end(), negEntry.DNSSECRecords.signatures.begin(), negEntry.DNSSECRecords.signatures.end());
}

static bool rpzHitShouldReplaceContent(const DNSName& qname, const QType qtype, const std::vector<DNSRecord>& records)
{
  if (qtype == QType::CNAME) {
    return true;
  }

  for (const auto& record : records) { // NOLINT(readability-use-anyofallof): don't agree
    if (record.d_type == QType::CNAME) {
      if (auto content = getRR<CNAMERecordContent>(record)) {
        if (qname == content->getTarget()) {
          /* we have a CNAME whose target matches the entry we are about to
             generate, so it will complete the current records, not replace
             them
          */
          return false;
        }
      }
    }
  }

  return true;
}

static void removeConflictingRecord(std::vector<DNSRecord>& records, const DNSName& name, const QType dtype)
{
  for (auto it = records.begin(); it != records.end();) {
    bool remove = false;

    if (it->d_class == QClass::IN && (it->d_type == QType::CNAME || dtype == QType::CNAME || it->d_type == dtype) && it->d_name == name) {
      remove = true;
    }
    else if (it->d_class == QClass::IN && it->d_type == QType::RRSIG && it->d_name == name) {
      if (auto rrc = getRR<RRSIGRecordContent>(*it)) {
        if (rrc->d_type == QType::CNAME || rrc->d_type == dtype) {
          /* also remove any RRSIG that could conflict */
          remove = true;
        }
      }
    }

    if (remove) {
      it = records.erase(it);
    }
    else {
      ++it;
    }
  }
}

void SyncRes::handlePolicyHit(const std::string& prefix, const DNSName& qname, const QType qtype, std::vector<DNSRecord>& ret, bool& done, int& rcode, unsigned int depth)
{
  if (d_pdl && d_pdl->policyHitEventFilter(d_requestor, qname, qtype, d_queryReceivedOverTCP, d_appliedPolicy, d_policyTags, d_discardedPolicies)) {
    /* reset to no match */
    d_appliedPolicy = DNSFilterEngine::Policy();
    return;
  }

  /* don't account truncate actions for TCP queries, since they are not applied */
  if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::Truncate || !d_queryReceivedOverTCP) {
    ++t_Counters.at(rec::PolicyHistogram::policy).at(d_appliedPolicy.d_kind);
    ++t_Counters.at(rec::PolicyNameHits::policyName).counts[d_appliedPolicy.getName()];
  }

  if (d_appliedPolicy.d_type != DNSFilterEngine::PolicyType::None) {
    LOG(prefix << qname << "|" << qtype << ':' << d_appliedPolicy.getLogString() << endl);
  }

  switch (d_appliedPolicy.d_kind) {

  case DNSFilterEngine::PolicyKind::NoAction:
    return;

  case DNSFilterEngine::PolicyKind::Drop:
    ++t_Counters.at(rec::Counter::policyDrops);
    throw ImmediateQueryDropException();

  case DNSFilterEngine::PolicyKind::NXDOMAIN:
    ret.clear();
    d_appliedPolicy.addSOAtoRPZResult(ret);
    rcode = RCode::NXDomain;
    done = true;
    return;

  case DNSFilterEngine::PolicyKind::NODATA:
    ret.clear();
    d_appliedPolicy.addSOAtoRPZResult(ret);
    rcode = RCode::NoError;
    done = true;
    return;

  case DNSFilterEngine::PolicyKind::Truncate:
    if (!d_queryReceivedOverTCP) {
      ret.clear();
      rcode = RCode::NoError;
      // Exception handling code in pdns_recursor clears ret as well, so no use to
      // fill it here.
      throw SendTruncatedAnswerException();
    }
    return;

  case DNSFilterEngine::PolicyKind::Custom: {
    if (rpzHitShouldReplaceContent(qname, qtype, ret)) {
      ret.clear();
    }

    rcode = RCode::NoError;
    done = true;
    auto spoofed = d_appliedPolicy.getCustomRecords(qname, qtype.getCode());
    for (auto& dnsRecord : spoofed) {
      removeConflictingRecord(ret, dnsRecord.d_name, dnsRecord.d_type);
    }

    for (auto& dnsRecord : spoofed) {
      ret.push_back(dnsRecord);

      if (dnsRecord.d_name == qname && dnsRecord.d_type == QType::CNAME && qtype != QType::CNAME) {
        if (auto content = getRR<CNAMERecordContent>(dnsRecord)) {
          vState newTargetState = vState::Indeterminate;
          handleNewTarget(prefix, qname, content->getTarget(), qtype.getCode(), ret, rcode, depth, {}, newTargetState);
        }
      }
    }
    d_appliedPolicy.addSOAtoRPZResult(ret);
  }
  }
}

bool SyncRes::nameserversBlockedByRPZ(const DNSFilterEngine& dfe, const NsSet& nameservers)
{
  /* we skip RPZ processing if:
     - it was disabled (d_wantsRPZ is false) ;
     - we already got a RPZ hit (d_appliedPolicy.d_type != DNSFilterEngine::PolicyType::None) since
     the only way we can get back here is that it was a 'pass-thru' (NoAction) meaning that we should not
     process any further RPZ rules. Except that we need to process rules of higher priority..
  */
  if (d_wantsRPZ && !d_appliedPolicy.wasHit()) {
    for (auto const& nameserver : nameservers) {
      bool match = dfe.getProcessingPolicy(nameserver.first, d_discardedPolicies, d_appliedPolicy);
      if (match) {
        mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
        if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
          LOG(", however nameserver " << nameserver.first << " was blocked by RPZ policy '" << d_appliedPolicy.getName() << "'" << endl);
          return true;
        }
      }

      // Traverse all IP addresses for this NS to see if they have an RPN NSIP policy
      for (auto const& address : nameserver.second.first) {
        match = dfe.getProcessingPolicy(address, d_discardedPolicies, d_appliedPolicy);
        if (match) {
          mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
          if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
            LOG(", however nameserver " << nameserver.first << " IP address " << address.toString() << " was blocked by RPZ policy '" << d_appliedPolicy.getName() << "'" << endl);
            return true;
          }
        }
      }
    }
  }
  return false;
}

bool SyncRes::nameserverIPBlockedByRPZ(const DNSFilterEngine& dfe, const ComboAddress& remoteIP)
{
  /* we skip RPZ processing if:
     - it was disabled (d_wantsRPZ is false) ;
     - we already got a RPZ hit (d_appliedPolicy.d_type != DNSFilterEngine::PolicyType::None) since
     the only way we can get back here is that it was a 'pass-thru' (NoAction) meaning that we should not
     process any further RPZ rules. Except that we need to process rules of higher priority..
  */
  if (d_wantsRPZ && !d_appliedPolicy.wasHit()) {
    bool match = dfe.getProcessingPolicy(remoteIP, d_discardedPolicies, d_appliedPolicy);
    if (match) {
      mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
      if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) {
        LOG(" (blocked by RPZ policy '" + d_appliedPolicy.getName() + "')");
        return true;
      }
    }
  }
  return false;
}

static bool shouldNotThrottle(const DNSName* name, const ComboAddress* address)
{
  if (name != nullptr) {
    auto dontThrottleNames = g_dontThrottleNames.getLocal();
    if (dontThrottleNames->check(*name)) {
      return true;
    }
  }
  if (address != nullptr) {
    auto dontThrottleNetmasks = g_dontThrottleNetmasks.getLocal();
    if (dontThrottleNetmasks->match(*address)) {
      return true;
    }
  }
  return false;
}

vector<ComboAddress> SyncRes::retrieveAddressesForNS(const std::string& prefix, const DNSName& qname, std::vector<std::pair<DNSName, float>>::const_iterator& tns, const unsigned int depth, set<GetBestNSAnswer>& beenthere, const vector<std::pair<DNSName, float>>& rnameservers, NsSet& nameservers, bool& sendRDQuery, bool& pierceDontQuery, bool& /* flawedNSSet */, bool cacheOnly, unsigned int& nretrieveAddressesForNS)
{
  vector<ComboAddress> result;

  size_t nonresolvingfails = 0;
  if (!tns->first.empty()) {
    if (s_nonresolvingnsmaxfails > 0) {
      nonresolvingfails = s_nonresolving.lock()->value(tns->first);
      if (nonresolvingfails >= s_nonresolvingnsmaxfails) {
        LOG(prefix << qname << ": NS " << tns->first << " in non-resolving map, skipping" << endl);
        return result;
      }
    }

    LOG(prefix << qname << ": Trying to resolve NS '" << tns->first << "' (" << 1 + tns - rnameservers.begin() << "/" << (unsigned int)rnameservers.size() << ")" << endl);
    const unsigned int oldOutQueries = d_outqueries;
    try {
      result = getAddrs(tns->first, depth, prefix, beenthere, cacheOnly, nretrieveAddressesForNS);
    }
    // Other exceptions should likely not throttle...
    catch (const ImmediateServFailException& ex) {
      if (s_nonresolvingnsmaxfails > 0 && d_outqueries > oldOutQueries) {
        if (!shouldNotThrottle(&tns->first, nullptr)) {
          s_nonresolving.lock()->incr(tns->first, d_now);
        }
      }
      throw ex;
    }
    if (s_nonresolvingnsmaxfails > 0 && d_outqueries > oldOutQueries) {
      if (result.empty()) {
        if (!shouldNotThrottle(&tns->first, nullptr)) {
          s_nonresolving.lock()->incr(tns->first, d_now);
        }
      }
      else if (nonresolvingfails > 0) {
        // Succeeding resolve, clear memory of recent failures
        s_nonresolving.lock()->clear(tns->first);
      }
    }
    pierceDontQuery = false;
  }
  else {
    LOG(prefix << qname << ": Domain has hardcoded nameserver");

    if (nameservers[tns->first].first.size() > 1) {
      LOG("s");
    }
    LOG(endl);

    sendRDQuery = nameservers[tns->first].second;
    result = shuffleForwardSpeed(qname, nameservers[tns->first].first, prefix, sendRDQuery);
    pierceDontQuery = true;
  }
  return result;
}

void SyncRes::checkMaxQperQ(const DNSName& qname) const
{
  if (d_outqueries + d_throttledqueries > s_maxqperq) {
    throw ImmediateServFailException("more than " + std::to_string(s_maxqperq) + " (max-qperq) queries sent or throttled while resolving " + qname.toLogString());
  }
}

bool SyncRes::throttledOrBlocked(const std::string& prefix, const ComboAddress& remoteIP, const DNSName& qname, const QType qtype, bool pierceDontQuery)
{
  if (isThrottled(d_now.tv_sec, remoteIP)) {
    LOG(prefix << qname << ": Server throttled " << endl);
    t_Counters.at(rec::Counter::throttledqueries)++;
    d_throttledqueries++;
    return true;
  }
  if (isThrottled(d_now.tv_sec, remoteIP, qname, qtype)) {
    LOG(prefix << qname << ": Query throttled " << remoteIP.toString() << ", " << qname << "; " << qtype << endl);
    t_Counters.at(rec::Counter::throttledqueries)++;
    d_throttledqueries++;
    return true;
  }
  if (!pierceDontQuery && s_dontQuery && s_dontQuery->match(&remoteIP)) {
    // We could have retrieved an NS from the cache in a forwarding domain
    // Even in the case of !pierceDontQuery we still want to allow that NS
    DNSName forwardCandidate(qname);
    auto iter = getBestAuthZone(&forwardCandidate);
    if (iter == t_sstorage.domainmap->end()) {
      LOG(prefix << qname << ": Not sending query to " << remoteIP.toString() << ", blocked by 'dont-query' setting" << endl);
      t_Counters.at(rec::Counter::dontqueries)++;
      return true;
    }
    // The name (from the cache) is forwarded, but is it forwarded to an IP in known forwarders?
    const auto& ips = iter->second.d_servers;
    if (std::find(ips.cbegin(), ips.cend(), remoteIP) == ips.cend()) {
      LOG(prefix << qname << ": Not sending query to " << remoteIP.toString() << ", blocked by 'dont-query' setting" << endl);
      t_Counters.at(rec::Counter::dontqueries)++;
      return true;
    }
    LOG(prefix << qname << ": Sending query to " << remoteIP.toString() << ", blocked by 'dont-query' but a forwarding/auth case" << endl);
  }
  return false;
}

bool SyncRes::validationEnabled()
{
  return g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate;
}

uint32_t SyncRes::computeLowestTTD(const std::vector<DNSRecord>& records, const MemRecursorCache::SigRecsVec& signatures, uint32_t signaturesTTL, const MemRecursorCache::AuthRecsVec& authorityRecs) const
{
  uint32_t lowestTTD = std::numeric_limits<uint32_t>::max();
  for (const auto& record : records) {
    lowestTTD = min(lowestTTD, record.d_ttl);
  }

  /* even if it was not requested for that request (Process, and neither AD nor DO set),
     it might be requested at a later time so we need to be careful with the TTL. */
  if (validationEnabled() && !signatures.empty()) {
    /* if we are validating, we don't want to cache records after their signatures expire. */
    /* records TTL are now TTD, let's add 'now' to the signatures lowest TTL */
    lowestTTD = min(lowestTTD, static_cast<uint32_t>(signaturesTTL + d_now.tv_sec));

    for (const auto& sig : signatures) {
      if (isRRSIGNotExpired(d_now.tv_sec, *sig)) {
        // we don't decrement d_sigexpire by 'now' because we actually want a TTD, not a TTL */
        lowestTTD = min(lowestTTD, static_cast<uint32_t>(sig->d_sigexpire));
      }
    }
  }

  for (const auto& entry : authorityRecs) {
    /* be careful, this is still a TTL here */
    lowestTTD = min(lowestTTD, static_cast<uint32_t>(entry.d_ttl + d_now.tv_sec));

    if (entry.d_type == QType::RRSIG && validationEnabled()) {
      auto rrsig = getRR<RRSIGRecordContent>(entry);
      if (rrsig) {
        if (isRRSIGNotExpired(d_now.tv_sec, *rrsig)) {
          // we don't decrement d_sigexpire by 'now' because we actually want a TTD, not a TTL */
          lowestTTD = min(lowestTTD, static_cast<uint32_t>(rrsig->d_sigexpire));
        }
      }
    }
  }

  return lowestTTD;
}

void SyncRes::updateValidationState(const DNSName& qname, vState& state, const vState stateUpdate, const string& prefix)
{
  LOG(prefix << qname << ": Validation state was " << state << ", state update is " << stateUpdate);
  updateDNSSECValidationState(state, stateUpdate);
  LOG(", validation state is now " << state << endl);
}

vState SyncRes::getTA(const DNSName& zone, dsset_t& dsSet, const string& prefix)
{
  auto luaLocal = g_luaconfs.getLocal();

  if (luaLocal->dsAnchors.empty()) {
    LOG(prefix << zone << ": No trust anchors configured, everything is Insecure" << endl);
    /* We have no TA, everything is insecure */
    return vState::Insecure;
  }

  std::string reason;
  if (haveNegativeTrustAnchor(luaLocal->negAnchors, zone, reason)) {
    LOG(prefix << zone << ": Got NTA" << endl);
    return vState::NTA;
  }

  if (getTrustAnchor(luaLocal->dsAnchors, zone, dsSet)) {
    if (!zone.isRoot()) {
      LOG(prefix << zone << ": Got TA" << endl);
    }
    return vState::TA;
  }

  if (zone.isRoot()) {
    /* No TA for the root */
    return vState::Insecure;
  }

  return vState::Indeterminate;
}

size_t SyncRes::countSupportedDS(const dsset_t& dsset, const string& prefix)
{
  size_t count = 0;

  for (const auto& dsRecordContent : dsset) {
    if (isSupportedDS(dsRecordContent, LogObject(prefix))) {
      count++;
    }
  }

  return count;
}

void SyncRes::initZoneCutsFromTA(const DNSName& from, const string& prefix)
{
  DNSName zone(from);
  do {
    dsset_t dsSet;
    vState result = getTA(zone, dsSet, prefix);
    if (result != vState::Indeterminate) {
      if (result == vState::TA) {
        if (countSupportedDS(dsSet, prefix) == 0) {
          dsSet.clear();
          result = vState::Insecure;
        }
        else {
          result = vState::Secure;
        }
      }
      else if (result == vState::NTA) {
        result = vState::Insecure;
      }

      d_cutStates[zone] = result;
    }
  } while (zone.chopOff());
}

vState SyncRes::getDSRecords(const DNSName& zone, dsset_t& dsSet, bool onlyTA, unsigned int depth, const string& prefix, bool bogusOnNXD, bool* foundCut)
{
  vState result = getTA(zone, dsSet, prefix);

  if (result != vState::Indeterminate || onlyTA) {
    if (foundCut != nullptr) {
      *foundCut = (result != vState::Indeterminate);
    }

    if (result == vState::TA) {
      if (countSupportedDS(dsSet, prefix) == 0) {
        dsSet.clear();
        result = vState::Insecure;
      }
      else {
        result = vState::Secure;
      }
    }
    else if (result == vState::NTA) {
      result = vState::Insecure;
    }

    return result;
  }

  std::set<GetBestNSAnswer> beenthere;
  std::vector<DNSRecord> dsrecords;

  Context context;

  const bool oldCacheOnly = setCacheOnly(false);
  const bool oldQM = setQNameMinimization(!getQMFallbackMode());
  int rcode = doResolve(zone, QType::DS, dsrecords, depth + 1, beenthere, context);
  setCacheOnly(oldCacheOnly);
  setQNameMinimization(oldQM);

  if (rcode == RCode::ServFail) {
    throw ImmediateServFailException("Server Failure while retrieving DS records for " + zone.toLogString());
  }

  if (rcode != RCode::NoError && (rcode != RCode::NXDomain || bogusOnNXD)) {
    LOG(prefix << zone << ": Returning Bogus state from " << static_cast<const char*>(__func__) << "(" << zone << ")" << endl);
    return vState::BogusUnableToGetDSs;
  }

  uint8_t bestDigestType = 0;

  bool gotCNAME = false;
  for (const auto& record : dsrecords) {
    if (record.d_type == QType::DS) {
      const auto dscontent = getRR<DSRecordContent>(record);
      if (dscontent && isSupportedDS(*dscontent, LogObject(prefix))) {
        // Make GOST a lower prio than SHA256
        if (dscontent->d_digesttype == DNSSEC::DIGEST_GOST && bestDigestType == DNSSEC::DIGEST_SHA256) {
          continue;
        }
        if (dscontent->d_digesttype > bestDigestType || (bestDigestType == DNSSEC::DIGEST_GOST && dscontent->d_digesttype == DNSSEC::DIGEST_SHA256)) {
          bestDigestType = dscontent->d_digesttype;
        }
        dsSet.insert(*dscontent);
      }
    }
    else if (record.d_type == QType::CNAME && record.d_name == zone) {
      gotCNAME = true;
    }
  }

  /* RFC 4509 section 3: "Validator implementations SHOULD ignore DS RRs containing SHA-1
   * digests if DS RRs with SHA-256 digests are present in the DS RRset."
   * We interpret that as: do not use SHA-1 if SHA-256 or SHA-384 is available
   */
  for (auto dsrec = dsSet.begin(); dsrec != dsSet.end();) {
    if (dsrec->d_digesttype == DNSSEC::DIGEST_SHA1 && dsrec->d_digesttype != bestDigestType) {
      dsrec = dsSet.erase(dsrec);
    }
    else {
      ++dsrec;
    }
  }

  if (rcode == RCode::NoError) {
    if (dsSet.empty()) {
      /* we have no DS, it's either:
         - a delegation to a non-DNSSEC signed zone
         - no delegation, we stay in the same zone
      */
      if (gotCNAME || denialProvesNoDelegation(zone, dsrecords, d_validationContext)) {
        /* we are still inside the same zone */

        if (foundCut != nullptr) {
          *foundCut = false;
        }
        return context.state;
      }

      d_cutStates[zone] = context.state == vState::Secure ? vState::Insecure : context.state;
      /* delegation with no DS, might be Secure -> Insecure */
      if (foundCut != nullptr) {
        *foundCut = true;
      }

      /* a delegation with no DS is either:
         - a signed zone (Secure) to an unsigned one (Insecure)
         - an unsigned zone to another unsigned one (Insecure stays Insecure, Bogus stays Bogus)
      */
      return context.state == vState::Secure ? vState::Insecure : context.state;
    }
    /* we have a DS */
    d_cutStates[zone] = context.state;
    if (foundCut != nullptr) {
      *foundCut = true;
    }
  }

  return context.state;
}

vState SyncRes::getValidationStatus(const DNSName& name, bool wouldBeValid, bool typeIsDS, unsigned int depth, const string& prefix)
{
  vState result = vState::Indeterminate;

  if (!shouldValidate()) {
    return result;
  }

  DNSName subdomain(name);
  if (typeIsDS) {
    subdomain.chopOff();
  }

  {
    const auto& iter = d_cutStates.find(subdomain);
    if (iter != d_cutStates.cend()) {
      LOG(prefix << name << ": Got status " << iter->second << " for name " << subdomain << endl);
      return iter->second;
    }
  }

  /* look for the best match we have */
  DNSName best(subdomain);
  while (best.chopOff()) {
    const auto& iter = d_cutStates.find(best);
    if (iter != d_cutStates.cend()) {
      result = iter->second;
      if (vStateIsBogus(result) || result == vState::Insecure) {
        LOG(prefix << name << ": Got status " << result << " for name " << best << endl);
        return result;
      }
      break;
    }
  }

  /* by now we have the best match, it's likely Secure (otherwise we would not be there)
     but we don't know if we missed a cut (or several).
     We could see if we have DS (or denial of) in cache but let's not worry for now,
     we will if we don't have a signature, or if the signer doesn't match what we expect */
  if (!wouldBeValid && best != subdomain) {
    /* no signatures or Bogus, we likely missed a cut, let's try to find it */
    LOG(prefix << name << ": No or invalid signature/proof for " << name << ", we likely missed a cut between " << best << " and " << subdomain << ", looking for it" << endl);
    DNSName dsName(best);
    std::vector<string> labelsToAdd = subdomain.makeRelative(dsName).getRawLabels();

    while (!labelsToAdd.empty()) {

      dsName.prependRawLabel(labelsToAdd.back());
      labelsToAdd.pop_back();
      LOG(prefix << name << ": - Looking for a DS at " << dsName << endl);

      bool foundCut = false;
      dsset_t results;
      vState dsState = getDSRecords(dsName, results, false, depth, prefix, false, &foundCut);

      if (foundCut) {
        LOG(prefix << name << ": - Found cut at " << dsName << endl);
        LOG(prefix << name << ": New state for " << dsName << " is " << dsState << endl);
        d_cutStates[dsName] = dsState;

        if (dsState != vState::Secure) {
          return dsState;
        }
      }
    }

    /* we did not miss a cut, good luck */
    return result;
  }

#if 0
  /* we don't need this, we actually do the right thing later */
  DNSName signer = getSigner(signatures);

  if (!signer.empty() && name.isPartOf(signer)) {
    if (signer == best) {
      return result;
    }
    /* the zone cut is not the one we expected,
       this is fine because we will retrieve the needed DNSKEYs and DSs
       later, and even go Insecure if we missed a cut to Insecure (no DS)
       and the signatures do not validate (we should not go Bogus in that
       case) */
  }
  /* something is not right, but let's not worry about that for now.. */
#endif

  return result;
}

vState SyncRes::validateDNSKeys(const DNSName& zone, const std::vector<DNSRecord>& dnskeys, const MemRecursorCache::SigRecsVec& signatures, unsigned int depth, const string& prefix)
{
  dsset_t dsSet;
  if (signatures.empty()) {
    LOG(prefix << zone << ": We have " << std::to_string(dnskeys.size()) << " DNSKEYs but no signature, going Bogus!" << endl);
    return vState::BogusNoRRSIG;
  }

  DNSName signer = getSigner(signatures);

  if (!signer.empty() && zone.isPartOf(signer)) {
    vState state = getDSRecords(signer, dsSet, false, depth, prefix);

    if (state != vState::Secure) {
      return state;
    }
  }
  else {
    LOG(prefix << zone << ": We have " << std::to_string(dnskeys.size()) << " DNSKEYs but the zone (" << zone << ") is not part of the signer (" << signer << "), check that we did not miss a zone cut" << endl);
    /* try again to get the missed cuts, harder this time */
    auto zState = getValidationStatus(zone, false, false, depth, prefix);
    if (zState == vState::Secure) {
      /* too bad */
      LOG(prefix << zone << ": After checking the zone cuts again, we still have " << std::to_string(dnskeys.size()) << " DNSKEYs and the zone (" << zone << ") is still not part of the signer (" << signer << "), going Bogus!" << endl);
      return vState::BogusNoValidRRSIG;
    }
    return zState;
  }

  skeyset_t tentativeKeys;
  sortedRecords_t toSign;

  for (const auto& dnskey : dnskeys) {
    if (dnskey.d_type == QType::DNSKEY) {
      auto content = getRR<DNSKEYRecordContent>(dnskey);
      if (content) {
        tentativeKeys.insert(content);
        toSign.insert(content);
      }
    }
  }

  LOG(prefix << zone << ": Trying to validate " << std::to_string(tentativeKeys.size()) << " DNSKEYs with " << std::to_string(dsSet.size()) << " DS" << endl);
  skeyset_t validatedKeys;
  auto state = validateDNSKeysAgainstDS(d_now.tv_sec, zone, dsSet, tentativeKeys, toSign, signatures, validatedKeys, LogObject(prefix), d_validationContext);

  if (s_maxvalidationsperq != 0 && d_validationContext.d_validationsCounter > s_maxvalidationsperq) {
    throw ImmediateServFailException("Server Failure while validating DNSKEYs, too many signature validations for this query");
  }

  LOG(prefix << zone << ": We now have " << std::to_string(validatedKeys.size()) << " DNSKEYs" << endl);

  /* if we found at least one valid RRSIG covering the set,
     all tentative keys are validated keys. Otherwise it means
     we haven't found at least one DNSKEY and a matching RRSIG
     covering this set, this looks Bogus. */
  if (validatedKeys.size() != tentativeKeys.size()) {
    LOG(prefix << zone << ": Let's check whether we missed a zone cut before returning a Bogus state from " << static_cast<const char*>(__func__) << "(" << zone << ")" << endl);
    /* try again to get the missed cuts, harder this time */
    auto zState = getValidationStatus(zone, false, false, depth, prefix);
    if (zState == vState::Secure) {
      /* too bad */
      LOG(prefix << zone << ": After checking the zone cuts we are still in a Secure zone, returning Bogus state from " << static_cast<const char*>(__func__) << "(" << zone << ")" << endl);
      return state;
    }
    return zState;
  }

  return state;
}

vState SyncRes::getDNSKeys(const DNSName& signer, skeyset_t& keys, bool& servFailOccurred, unsigned int depth, const string& prefix)
{
  std::vector<DNSRecord> records;
  std::set<GetBestNSAnswer> beenthere;
  LOG(prefix << signer << ": Retrieving DNSKEYs" << endl);

  Context context;

  const bool oldCacheOnly = setCacheOnly(false);
  int rcode = doResolve(signer, QType::DNSKEY, records, depth + 1, beenthere, context);
  setCacheOnly(oldCacheOnly);

  if (rcode == RCode::ServFail) {
    servFailOccurred = true;
    return vState::BogusUnableToGetDNSKEYs;
  }

  if (rcode == RCode::NoError) {
    if (context.state == vState::Secure) {
      for (const auto& key : records) {
        if (key.d_type == QType::DNSKEY) {
          auto content = getRR<DNSKEYRecordContent>(key);
          if (content) {
            keys.insert(std::move(content));
          }
        }
      }
    }
    LOG(prefix << signer << ": Retrieved " << keys.size() << " DNSKeys, state is " << context.state << endl);
    return context.state;
  }

  if (context.state == vState::Insecure) {
    return context.state;
  }

  LOG(prefix << signer << ": Returning Bogus state from " << static_cast<const char*>(__func__) << "(" << signer << ")" << endl);
  return vState::BogusUnableToGetDNSKEYs;
}

vState SyncRes::validateRecordsWithSigs(unsigned int depth, const string& prefix, const DNSName& qname, const QType qtype, const DNSName& name, const QType type, const std::vector<DNSRecord>& records, const MemRecursorCache::SigRecsVec& signatures)
{
  skeyset_t keys;
  if (signatures.empty()) {
    LOG(prefix << qname << ": Bogus!" << endl);
    return vState::BogusNoRRSIG;
  }

  const DNSName signer = getSigner(signatures);
  bool dsFailed = false;
  if (!signer.empty() && name.isPartOf(signer)) {
    vState state = vState::Secure;

    if ((qtype == QType::DNSKEY || qtype == QType::DS) && signer == qname) {
      /* we are already retrieving those keys, sorry */
      if (type == QType::DS && signer == name && !signer.isRoot()) {
        /* Unless we are getting the DS of the root zone, we should never see a
           DS (or a denial of a DS) signed by the DS itself, since we should be
           requesting it from the parent zone. Something is very wrong */
        LOG(prefix << qname << ": The DS for " << qname << " is signed by itself" << endl);
        state = vState::BogusSelfSignedDS;
        dsFailed = true;
      }
      else if (qtype == QType::DS && signer == qname && !signer.isRoot()) {
        if (type == QType::SOA || type == QType::NSEC || type == QType::NSEC3) {
          /* if we are trying to validate the DS or more likely NSEC(3)s proving that it does not exist, we have a problem.
             In that case let's go Bogus (we will check later if we missed a cut)
          */
          state = vState::BogusSelfSignedDS;
          dsFailed = true;
        }
        else if (type == QType::CNAME) {
          state = vState::BogusUnableToGetDSs;
          dsFailed = true;
        }
      }
      else if (qtype == QType::DNSKEY && signer == qname) {
        /* that actually does happen when a server returns NS records in authority
           along with the DNSKEY, leading us to trying to validate the RRSIGs for
           the NS with the DNSKEY that we are about to process. */
        if ((name == signer && type == QType::NSEC) || type == QType::NSEC3) {
          /* if we are trying to validate the DNSKEY (should not happen here),
             or more likely NSEC(3)s proving that it does not exist, we have a problem.
             In that case let's see if the DS does exist, and if it does let's go Bogus
          */
          dsset_t results;
          vState dsState = getDSRecords(signer, results, false, depth, prefix, true);
          if (vStateIsBogus(dsState) || dsState == vState::Insecure) {
            state = dsState;
            if (vStateIsBogus(dsState)) {
              dsFailed = true;
            }
          }
          else {
            LOG(prefix << qname << ": Unable to get the DS for " << signer << endl);
            state = vState::BogusUnableToGetDNSKEYs;
            dsFailed = true;
          }
        }
        else {
          /* return immediately since looking at the cuts is not going to change the
             fact that we are looking at a signature done with the key we are trying to
             obtain */
          LOG(prefix << qname << ": We are looking at a signature done with the key we are trying to obtain " << signer << endl);
          return vState::Indeterminate;
        }
      }
    }
    bool servFailOccurred = false;
    if (state == vState::Secure) {
      state = getDNSKeys(signer, keys, servFailOccurred, depth, prefix);
    }

    if (state != vState::Secure) {
      if (!vStateIsBogus(state)) {
        return state;
      }
      /* try again to get the missed cuts, harder this time */
      LOG(prefix << signer << ": Checking whether we missed a zone cut for " << signer << " before returning a Bogus state for " << name << "|" << type.toString() << endl);
      auto zState = getValidationStatus(signer, false, dsFailed, depth, prefix);
      if (zState == vState::Secure) {
        if (state == vState::BogusUnableToGetDNSKEYs && servFailOccurred) {
          throw ImmediateServFailException("Server Failure while retrieving DNSKEY records for " + signer.toLogString());
        }
        /* too bad */
        LOG(prefix << signer << ": We are still in a Secure zone, returning " << vStateToString(state) << endl);
        return state;
      }
      return zState;
    }
  }

  sortedRecords_t recordcontents;
  for (const auto& record : records) {
    recordcontents.insert(record.getContent());
  }

  LOG(prefix << name << ": Going to validate " << recordcontents.size() << " record contents with " << signatures.size() << " sigs and " << keys.size() << " keys for " << name << "|" << type.toString() << endl);
  vState state = validateWithKeySet(d_now.tv_sec, name, recordcontents, signatures, keys, LogObject(prefix), d_validationContext, false);
  if (s_maxvalidationsperq != 0 && d_validationContext.d_validationsCounter > s_maxvalidationsperq) {
    throw ImmediateServFailException("Server Failure while validating records, too many signature validations for this query");
  }

  if (state == vState::Secure) {
    LOG(prefix << name << ": Secure!" << endl);
    return vState::Secure;
  }

  LOG(prefix << vStateToString(state) << "!" << endl);

  bool skipThisLevelWhenLookingForMissedCuts = false;
  if (name == qname && qtype == QType::DS && (type == QType::NSEC || type == QType::NSEC3)) {
    /* so we have a NSEC(3) record likely proving that the DS we were looking for does not exist,
       but we cannot validate it:
       - if there actually is a cut at this level, we will not be able to validate it anyway
       - if there is no cut at this level, the only thing that can save us is a cut above
    */
    LOG(prefix << name << ": We are trying to validate a " << type << " record for " << name << " likely proving that the DS we were initially looking for (" << qname << ") does not exist, no need to check a zone cut at this exact level" << endl);
    skipThisLevelWhenLookingForMissedCuts = true;
  }

  /* try again to get the missed cuts, harder this time */
  auto zState = getValidationStatus(name, false, type == QType::DS || skipThisLevelWhenLookingForMissedCuts, depth, prefix);
  LOG(prefix << name << ": Checking whether we missed a zone cut before returning a Bogus state" << endl);
  if (zState == vState::Secure) {
    /* too bad */
    LOG(prefix << name << ": We are still in a Secure zone, returning " << vStateToString(state) << endl);
    return state;
  }
  return zState;
}

/* This function will check whether the answer should have the AA bit set, and will set if it should be set and isn't.
   This is unfortunately needed to deal with very crappy so-called DNS servers */
void SyncRes::fixupAnswer(const std::string& prefix, LWResult& lwr, const DNSName& qname, const QType qtype, const DNSName& auth, bool wasForwarded, bool rdQuery)
{
  const bool wasForwardRecurse = wasForwarded && rdQuery;

  if (wasForwardRecurse || lwr.d_aabit) {
    /* easy */
    return;
  }

  for (const auto& rec : lwr.d_records) {

    if (rec.d_type == QType::OPT) {
      continue;
    }

    if (rec.d_class != QClass::IN) {
      continue;
    }

    if (rec.d_type == QType::ANY) {
      continue;
    }

    if (rec.d_place == DNSResourceRecord::ANSWER && (rec.d_type == qtype || rec.d_type == QType::CNAME || qtype == QType::ANY) && rec.d_name == qname && rec.d_name.isPartOf(auth)) {
      /* This is clearly an answer to the question we were asking, from an authoritative server that is allowed to send it.
         We are going to assume this server is broken and does not know it should set the AA bit, even though it is DNS 101 */
      LOG(prefix << qname << ": Received a record for " << rec.d_name << "|" << DNSRecordContent::NumberToType(rec.d_type) << " in the answer section from " << auth << ", without the AA bit set. Assuming this server is clueless and setting the AA bit." << endl);
      lwr.d_aabit = true;
      return;
    }

    if (rec.d_place != DNSResourceRecord::ANSWER) {
      /* we have scanned all the records in the answer section, if any, we are done */
      return;
    }
  }
}

static void allowAdditionalEntry(std::unordered_set<DNSName>& allowedAdditionals, const DNSRecord& rec)
{
  // As we only use a limited amount of NS names for resolving, limit number of additional names as
  // well.  s_maxnsperresolve is a proper limit for the NS case and is also reasonable for other
  // qtypes.  Allow one extra for qname itself, which is always in allowedAdditionals.
  if (SyncRes::s_maxnsperresolve > 0 && allowedAdditionals.size() > SyncRes::s_maxnsperresolve + 1) {
    return;
  }
  switch (rec.d_type) {
  case QType::MX:
    if (auto mxContent = getRR<MXRecordContent>(rec)) {
      allowedAdditionals.insert(mxContent->d_mxname);
    }
    break;
  case QType::NS:
    if (auto nsContent = getRR<NSRecordContent>(rec)) {
      allowedAdditionals.insert(nsContent->getNS());
    }
    break;
  case QType::SRV:
    if (auto srvContent = getRR<SRVRecordContent>(rec)) {
      allowedAdditionals.insert(srvContent->d_target);
    }
    break;
  case QType::SVCB: /* fall-through */
  case QType::HTTPS:
    if (auto svcbContent = getRR<SVCBBaseRecordContent>(rec)) {
      if (svcbContent->getPriority() > 0) {
        DNSName target = svcbContent->getTarget();
        if (target.isRoot()) {
          target = rec.d_name;
        }
        allowedAdditionals.insert(std::move(target));
      }
      else {
        // FIXME: Alias mode not implemented yet
      }
    }
    break;
  case QType::NAPTR:
    if (auto naptrContent = getRR<NAPTRRecordContent>(rec)) {
      auto flags = naptrContent->getFlags();
      toLowerInPlace(flags);
      if (flags.find('a') != string::npos || flags.find('s') != string::npos) {
        allowedAdditionals.insert(naptrContent->getReplacement());
      }
    }
    break;
  default:
    break;
  }
}

static bool isRedirection(QType qtype)
{
  return qtype == QType::CNAME || qtype == QType::DNAME;
}

void SyncRes::sanitizeRecords(const std::string& prefix, LWResult& lwr, const DNSName& qname, const QType qtype, const DNSName& auth, bool wasForwarded, bool rdQuery)
{
  const bool wasForwardRecurse = wasForwarded && rdQuery;
  /* list of names for which we will allow A and AAAA records in the additional section
     to remain */
  std::unordered_set<DNSName> allowedAdditionals = {qname};
  std::unordered_set<DNSName> allowedAnswerNames = {qname};
  bool cnameSeen = false;
  bool haveAnswers = false;
  bool acceptDelegation = false;
  bool soaInAuth = false;

  std::vector<bool> skipvec(lwr.d_records.size(), false);
  unsigned int counter = 0;
  unsigned int skipCount = 0;

  for (auto rec = lwr.d_records.cbegin(); rec != lwr.d_records.cend(); ++rec, ++counter) {

    // Allow OPT record containing EDNS(0) data
    if (rec->d_type == QType::OPT) {
      continue;
    }

    // Disallow QClass != IN
    if (rec->d_class != QClass::IN) {
      LOG(prefix << qname << ": Removing non internet-classed data received from " << auth << endl);
      skipvec[counter] = true;
      ++skipCount;
      continue;
    }

    // Disallow QType ANY in responses
    if (rec->d_type == QType::ANY) {
      LOG(prefix << qname << ": Removing 'ANY'-typed data received from " << auth << endl);
      skipvec[counter] = true;
      ++skipCount;
      continue;
    }

    // Disallow any name not part of auth requested (i.e. disallow x.y.z if asking a NS authoritative for x.w.z)
    if (!rec->d_name.isPartOf(auth)) {
      LOG(prefix << qname << ": Removing record '" << rec->toString() << "' in the " << DNSResourceRecord::placeString(rec->d_place) << " section received from " << auth << endl);
      skipvec[counter] = true;
      ++skipCount;
      continue;
    }

    // Disallow QType DNAME in non-answer section or containing an answer that is not a parent of or equal to the question name
    // i.e. disallowed bar.example.com. DNAME bar.example.net. when asking foo.example.com
    // But allow it when asking for foo.bar.example.com.
    if (rec->d_type == QType::DNAME && (rec->d_place != DNSResourceRecord::ANSWER || !qname.isPartOf(rec->d_name))) {
      LOG(prefix << qname << ": Removing invalid DNAME record '" << rec->toString() << "' in the " << DNSResourceRecord::placeString(rec->d_place) << " section received from " << auth << endl);
      skipvec[counter] = true;
      ++skipCount;
      continue;
    }

    /* dealing with the records in answer */
    if (rec->d_place == DNSResourceRecord::ANSWER) {
      // Special case for Amazon CNAME records
      if (!(lwr.d_aabit || wasForwardRecurse)) {
        /* for now we allow a CNAME for the exact qname in ANSWER with AA=0, because Amazon DNS servers
           are sending such responses */
        if (rec->d_type != QType::CNAME || qname != rec->d_name) {
          LOG(prefix << qname << ": Removing record '" << rec->toString() << "' in the ANSWER section without the AA bit set received from " << auth << endl);
          skipvec[counter] = true;
          ++skipCount;
          continue;
        }
      }
      // Disallow answer records not answering the QType requested. ANY, CNAME, DNAME, RRSIG complicate matters here
      if (qtype != QType::ANY && rec->d_type != qtype.getCode() && !isRedirection(rec->d_type) && rec->d_type != QType::RRSIG) {
        LOG(prefix << qname << ": Removing irrelevant record '" << rec->toString() << "' in the ANSWER section received from " << auth << endl);
        skipvec[counter] = true;
        ++skipCount;
        continue;
      }

      haveAnswers = true;
      if (rec->d_type == QType::CNAME) {
        if (auto cnametarget = getRR<CNAMERecordContent>(*rec); cnametarget != nullptr) {
          allowedAnswerNames.insert(cnametarget->getTarget());
        }
        cnameSeen = cnameSeen || qname == rec->d_name;
      }
      else if (rec->d_type == QType::DNAME) {
        // We have checked the DNAME rec->d_name above, the actual answer will be synthesized in a later step
        allowedAnswerNames.insert(rec->d_name);
      }
      allowAdditionalEntry(allowedAdditionals, *rec);
    }

    /* dealing with the records in authority */
    // Only allow NS, DS, SOA, RRSIG, NSEC, NSEC3 in AUTHORITY section
    else if (rec->d_place == DNSResourceRecord::AUTHORITY) {
      if (rec->d_type != QType::NS && rec->d_type != QType::DS && rec->d_type != QType::SOA && rec->d_type != QType::RRSIG && rec->d_type != QType::NSEC && rec->d_type != QType::NSEC3) {
        LOG(prefix << qname << ": Removing irrelevant record '" << rec->toString() << "' in the AUTHORITY section received from " << auth << endl);
        skipvec[counter] = true;
        ++skipCount;
        continue;
      }
      if (rec->d_type == QType::NS && (!rec->d_name.isPartOf(auth) || (rec->d_name == auth && !d_updatingRootNS) || !qname.isPartOf(rec->d_name))) {
        /*
         * We don't want to pick up irrelevant NS records in AUTHORITY and their associated ADDITIONAL sections.
         * So remove them and don't add them to allowedAdditionals.
         */
        LOG(prefix << qname << ": Removing NS record '" << rec->toString() << "' in the AUTHORITY section of a response received from " << auth << endl);
        skipvec[counter] = true;
        ++skipCount;
        continue;
      }

      if (rec->d_type == QType::SOA) {
        // Disallow a SOA record with a name that is not a parent of or equal to the name we asked
        if (!qname.isPartOf(rec->d_name)) {
          LOG(prefix << qname << ": Removing irrelevant SOA record '" << rec->toString() << "' in the AUTHORITY section received from " << auth << endl);
          skipvec[counter] = true;
          ++skipCount;
          continue;
        }
        // Disallow SOA without AA bit (except for forward with RD=1)
        if (!(lwr.d_aabit || wasForwardRecurse)) {
          LOG(prefix << qname << ": Removing irrelevant record (AA not set) '" << rec->toString() << "' in the AUTHORITY section received from " << auth << endl);
          skipvec[counter] = true;
          ++skipCount;
          continue;
        }
        soaInAuth = true;
      }
    }
    /* dealing with records in additional */
    else if (rec->d_place == DNSResourceRecord::ADDITIONAL) {
      if (rec->d_type != QType::A && rec->d_type != QType::AAAA && rec->d_type != QType::RRSIG) {
        LOG(prefix << qname << ": Removing irrelevant record '" << rec->toString() << "' in the ADDITIONAL section received from " << auth << endl);
        skipvec[counter] = true;
        ++skipCount;
        continue;
      }
    }
  } // end of first loop, handled answer and most of authority section

  if (!haveAnswers && lwr.d_rcode == RCode::NoError) {
    acceptDelegation = true;
  }

  sanitizeRecordsPass2(prefix, lwr, qname, qtype, auth, allowedAnswerNames, allowedAdditionals, cnameSeen, acceptDelegation && !soaInAuth, skipvec, skipCount);
}

void SyncRes::sanitizeRecordsPass2(const std::string& prefix, LWResult& lwr, const DNSName& qname, const QType qtype, const DNSName& auth, std::unordered_set<DNSName>& allowedAnswerNames, std::unordered_set<DNSName>& allowedAdditionals, bool cnameSeen, bool acceptDelegation, std::vector<bool>& skipvec, unsigned int& skipCount)
{
  // Second loop, we know now if the answer was NxDomain or NoData
  unsigned int counter = 0;
  for (auto rec = lwr.d_records.cbegin(); rec != lwr.d_records.cend(); ++rec, ++counter) {

    if (skipvec[counter]) {
      continue;
    }
    // Allow OPT record containing EDNS(0) data
    if (rec->d_type == QType::OPT) {
      continue;
    }

    if (rec->d_place == DNSResourceRecord::ANSWER) {
      if (allowedAnswerNames.count(rec->d_name) == 0) {
        LOG(prefix << qname << ": Removing irrelevent record '" << rec->toString() << "' in the ANSWER section received from " << auth << endl);
        skipvec[counter] = true;
        ++skipCount;
      }
      // If we have a CNAME, skip answer records for the requested type
      if (cnameSeen && rec->d_type == qtype && rec->d_name == qname && qtype != QType::CNAME) {
        LOG(prefix << qname << ": Removing answer record in presence of CNAME record '" << rec->toString() << "' in the ANSWER section received from " << auth << endl);
        skipvec[counter] = true;
        ++skipCount;
        continue;
      }
    }
    if (rec->d_place == DNSResourceRecord::AUTHORITY && rec->d_type == QType::NS) {
      if (!acceptDelegation) {
        /*
         * We don't want to pick up NS records in AUTHORITY and their ADDITIONAL sections of NXDomain answers and answers with answer records
         * because they are somewhat easy to insert into a large, fragmented UDP response
         * for an off-path attacker by injecting spoofed UDP fragments. So do not add these to allowedAdditionals.
         */
        LOG(prefix << qname << ": Removing NS record '" << rec->toString() << "' in the AUTHORITY section of a response received from " << auth << endl);
        skipvec[counter] = true;
        ++skipCount;
        continue;
      }
      allowAdditionalEntry(allowedAdditionals, *rec);
    }
    /* dealing with the records in additional */
    else if (rec->d_place == DNSResourceRecord::ADDITIONAL) {
      if (allowedAdditionals.count(rec->d_name) == 0) {
        LOG(prefix << qname << ": Removing irrelevant record '" << rec->toString() << "' in the ADDITIONAL section received from " << auth << endl);
        skipvec[counter] = true;
        ++skipCount;
        continue;
      }
    }
  }
  if (skipCount > 0) {
    std::vector<DNSRecord> vec;
    vec.reserve(lwr.d_records.size() - skipCount);
    for (counter = 0; counter < lwr.d_records.size(); ++counter) {
      if (!skipvec[counter]) {
        vec.emplace_back(std::move(lwr.d_records[counter]));
      }
    }
    lwr.d_records = std::move(vec);
  }
#ifdef notyet
  // As dedupping is relatively expensive and having dup records not really hurts as far as we have seen, do not dedup.
  if (auto count = pdns::dedupRecords(lwr.d_records); count > 0) {
    LOG(prefix << qname << ": Removed " << count << " duplicate records from response received from " << auth << endl);
  }
#endif
}

void SyncRes::rememberParentSetIfNeeded(const DNSName& domain, const vector<DNSRecord>& newRecords, unsigned int depth, const string& prefix)
{
  vector<DNSRecord> existing;
  bool wasAuth = false;
  auto ttl = g_recCache->get(d_now.tv_sec, domain, QType::NS, MemRecursorCache::None, &existing, d_cacheRemote, d_routingTag, nullptr, nullptr, nullptr, nullptr, &wasAuth);

  if (ttl <= 0 || wasAuth) {
    return;
  }
  {
    auto lock = s_savedParentNSSet.lock();
    if (lock->find(domain) != lock->end()) {
      // no relevant data, or we already stored the parent data
      return;
    }
  }

  set<DNSName> authSet;
  for (const auto& dnsRecord : newRecords) {
    auto content = getRR<NSRecordContent>(dnsRecord);
    authSet.insert(content->getNS());
  }
  // The glue IPs could also differ, but we're not checking that yet, we're only looking for parent NS records not
  // in the child set
  bool shouldSave = false;
  for (const auto& dnsRecord : existing) {
    auto content = getRR<NSRecordContent>(dnsRecord);
    if (authSet.count(content->getNS()) == 0) {
      LOG(prefix << domain << ": At least one parent-side NS was not in the child-side NS set, remembering parent NS set and cached IPs" << endl);
      shouldSave = true;
      break;
    }
  }

  if (shouldSave) {
    map<DNSName, vector<ComboAddress>> entries;
    for (const auto& dnsRecord : existing) {
      auto content = getRR<NSRecordContent>(dnsRecord);
      const DNSName& name = content->getNS();
      set<GetBestNSAnswer> beenthereIgnored;
      unsigned int nretrieveAddressesForNSIgnored{};
      auto addresses = getAddrs(name, depth, prefix, beenthereIgnored, true, nretrieveAddressesForNSIgnored);
      entries.emplace(name, addresses);
    }
    s_savedParentNSSet.lock()->emplace(domain, std::move(entries), d_now.tv_sec + ttl);
  }
}

RCode::rcodes_ SyncRes::updateCacheFromRecords(unsigned int depth, const string& prefix, LWResult& lwr, const DNSName& qname, const QType qtype, const DNSName& auth, bool wasForwarded, const std::optional<Netmask>& ednsmask, vState& state, bool& needWildcardProof, bool& gatherWildcardProof, unsigned int& wildcardLabelsCount, bool rdQuery, const ComboAddress& remoteIP, bool overTCP) // NOLINT(readability-function-cognitive-complexity)
{
  bool wasForwardRecurse = wasForwarded && rdQuery;
  tcache_t tcache;

  fixupAnswer(prefix, lwr, qname, qtype, auth, wasForwarded, rdQuery);
  sanitizeRecords(prefix, lwr, qname, qtype, auth, wasForwarded, rdQuery);

  MemRecursorCache::AuthRecsVec authorityRecs;
  bool isCNAMEAnswer = false;
  bool isDNAMEAnswer = false;
  DNSName seenAuth;

  // names that might be expanded from a wildcard, and thus require denial of existence proof
  // this is the queried name and any part of the CNAME chain from the queried name
  // the key is the name itself, the value is initially false and is set to true once we have
  // confirmed it was actually expanded from a wildcard
  std::map<DNSName, bool> wildcardCandidates{{qname, false}};

  if (rdQuery) {
    std::unordered_map<DNSName, DNSName> cnames;
    for (const auto& rec : lwr.d_records) {
      if (rec.d_type != QType::CNAME || rec.d_class != QClass::IN) {
        continue;
      }
      if (auto content = getRR<CNAMERecordContent>(rec)) {
        cnames[rec.d_name] = DNSName(content->getTarget());
      }
    }
    auto initial = qname;
    while (true) {
      auto cnameIt = cnames.find(initial);
      if (cnameIt == cnames.end()) {
        break;
      }
      initial = cnameIt->second;
      if (!wildcardCandidates.emplace(initial, false).second) {
        // CNAME Loop
        break;
      }
    }
  }

  for (auto& rec : lwr.d_records) {
    if (rec.d_type == QType::OPT || rec.d_class != QClass::IN) {
      continue;
    }

    rec.d_ttl = min(s_maxcachettl, rec.d_ttl);

    if (!isCNAMEAnswer && rec.d_place == DNSResourceRecord::ANSWER && rec.d_type == QType::CNAME && (!(qtype == QType::CNAME)) && rec.d_name == qname && !isDNAMEAnswer) {
      isCNAMEAnswer = true;
    }
    if (!isDNAMEAnswer && rec.d_place == DNSResourceRecord::ANSWER && rec.d_type == QType::DNAME && qtype != QType::DNAME && qname.isPartOf(rec.d_name)) {
      isDNAMEAnswer = true;
      isCNAMEAnswer = false;
    }

    if (rec.d_type == QType::SOA && rec.d_place == DNSResourceRecord::AUTHORITY && qname.isPartOf(rec.d_name)) {
      seenAuth = rec.d_name;
    }

    const auto labelCount = rec.d_name.countLabels();
    if (rec.d_type == QType::RRSIG) {
      auto rrsig = getRR<RRSIGRecordContent>(rec);
      if (rrsig) {
        /* As illustrated in rfc4035's Appendix B.6, the RRSIG label
           count can be lower than the name's label count if it was
           synthesized from the wildcard. Note that the difference might
           be > 1. */
        if (auto wcIt = wildcardCandidates.find(rec.d_name); wcIt != wildcardCandidates.end() && isWildcardExpanded(labelCount, *rrsig)) {
          wcIt->second = true;
          gatherWildcardProof = true;
          if (!isWildcardExpandedOntoItself(rec.d_name, labelCount, *rrsig)) {
            /* if we have a wildcard expanded onto itself, we don't need to prove
               that the exact name doesn't exist because it actually does.
               We still want to gather the corresponding NSEC/NSEC3 records
               to pass them to our client in case it wants to validate by itself.
            */
            LOG(prefix << qname << ": RRSIG indicates the name was synthesized from a wildcard, we need a wildcard proof" << endl);
            needWildcardProof = true;
          }
          else {
            LOG(prefix << qname << ": RRSIG indicates the name was synthesized from a wildcard expanded onto itself, we need to gather wildcard proof" << endl);
          }
          wildcardLabelsCount = rrsig->d_labels;
        }

        // cerr<<"Got an RRSIG for "<<DNSRecordContent::NumberToType(rrsig->d_type)<<" with name '"<<rec.d_name<<"' and place "<<rec.d_place<<endl;
        tcache[{rec.d_name, rrsig->d_type, rec.d_place}].signatures.push_back(rrsig);
        tcache[{rec.d_name, rrsig->d_type, rec.d_place}].signaturesTTL = std::min(tcache[{rec.d_name, rrsig->d_type, rec.d_place}].signaturesTTL, rec.d_ttl);
      }
    }
  }

  /* if we have a positive answer synthesized from a wildcard,
     we need to store the corresponding NSEC/NSEC3 records proving
     that the exact name did not exist in the negative cache */
  if (gatherWildcardProof) {
    for (const auto& rec : lwr.d_records) {
      if (rec.d_type == QType::OPT || rec.d_class != QClass::IN) {
        continue;
      }

      if (nsecTypes.count(rec.d_type) != 0) {
        authorityRecs.emplace_back(rec);
      }
      else if (rec.d_type == QType::RRSIG) {
        auto rrsig = getRR<RRSIGRecordContent>(rec);
        if (rrsig && nsecTypes.count(rrsig->d_type) != 0) {
          authorityRecs.emplace_back(rec);
        }
      }
    }
  }

  // reap all answers from this packet that are acceptable
  for (auto& rec : lwr.d_records) {
    if (rec.d_type == QType::OPT) {
      LOG(prefix << qname << ": OPT answer '" << rec.d_name << "' from '" << auth << "' nameservers" << endl);
      continue;
    }

    LOG(prefix << qname << ": Accept answer '" << rec.d_name << "|" << DNSRecordContent::NumberToType(rec.d_type) << "|" << rec.getContent()->getZoneRepresentation() << "' from '" << auth << "' nameservers? ttl=" << rec.d_ttl << ", place=" << (int)rec.d_place << " ");

    // We called sanitizeRecords before, so all ANY, non-IN and non-aa/non-forwardrecurse answer records are already removed

    if (rec.d_name.isPartOf(auth)) {
      if (rec.d_type == QType::RRSIG) {
        LOG("RRSIG - separate" << endl);
      }
      else if (rec.d_type == QType::DS && rec.d_name == auth) {
        LOG("NO - DS provided by child zone" << endl);
      }
      else {
        bool haveLogged = false;
        if (isDNAMEAnswer && rec.d_type == QType::CNAME) {
          LOG("NO - we already have a DNAME answer for this domain" << endl);
          continue;
        }
        if (!t_sstorage.domainmap->empty()) {
          // Check if we are authoritative for a zone in this answer
          DNSName tmp_qname(rec.d_name);
          // We may be auth for domain example.com, but the DS record needs to come from the parent (.com) nameserver
          if (rec.d_type == QType::DS) {
            tmp_qname.chopOff();
          }
          auto auth_domain_iter = getBestAuthZone(&tmp_qname);
          if (auth_domain_iter != t_sstorage.domainmap->end() && auth.countLabels() <= auth_domain_iter->first.countLabels()) {
            if (auth_domain_iter->first != auth) {
              LOG("NO! - we are authoritative for the zone " << auth_domain_iter->first << endl);
              continue;
            }
            LOG("YES! - This answer was ");
            if (!wasForwarded) {
              LOG("retrieved from the local auth store.");
            }
            else {
              LOG("received from a server we forward to.");
            }
            haveLogged = true;
            LOG(endl);
          }
        }
        if (!haveLogged) {
          LOG("YES!" << endl);
        }

        rec.d_ttl = min(s_maxcachettl, rec.d_ttl);

        DNSRecord dnsRecord(rec);
        tcache[{rec.d_name, rec.d_type, rec.d_place}].d_ttl_time = d_now.tv_sec;
        dnsRecord.d_ttl += d_now.tv_sec;
        dnsRecord.d_place = DNSResourceRecord::ANSWER;
        tcache[{rec.d_name, rec.d_type, rec.d_place}].records.push_back(std::move(dnsRecord));
      }
    }
    else
      LOG("NO!" << endl);
  }

  // supplant
  for (auto& entry : tcache) {
    if ((entry.second.records.size() + entry.second.signatures.size() + authorityRecs.size()) > 1) { // need to group the ttl to be the minimum of the RRSET (RFC 2181, 5.2)
      uint32_t lowestTTD = computeLowestTTD(entry.second.records, entry.second.signatures, entry.second.signaturesTTL, authorityRecs);

      for (auto& record : entry.second.records) {
        record.d_ttl = lowestTTD; // boom
      }
    }
  }

  bool seenBogusRRSet = false;
  for (auto tCacheEntry = tcache.begin(); tCacheEntry != tcache.end(); ++tCacheEntry) {

    if (tCacheEntry->second.records.empty()) { // this happens when we did store signatures, but passed on the records themselves
      continue;
    }

    /* Even if the AA bit is set, additional data cannot be considered
       as authoritative. This is especially important during validation
       because keeping records in the additional section is allowed even
       if the corresponding RRSIGs are not included, without setting the TC
       bit, as stated in rfc4035's section 3.1.1.  Including RRSIG RRs in a Response:
       "When placing a signed RRset in the Additional section, the name
       server MUST also place its RRSIG RRs in the Additional section.
       If space does not permit inclusion of both the RRset and its
       associated RRSIG RRs, the name server MAY retain the RRset while
       dropping the RRSIG RRs.  If this happens, the name server MUST NOT
       set the TC bit solely because these RRSIG RRs didn't fit."
    */
    bool isAA = lwr.d_aabit && tCacheEntry->first.place != DNSResourceRecord::ADDITIONAL;
    /* if we forwarded the query to a recursor, we can expect the answer to be signed,
       even if the answer is not AA. Of course that's not only true inside a Secure
       zone, but we check that below. */
    bool expectSignature = tCacheEntry->first.place == DNSResourceRecord::ANSWER || ((lwr.d_aabit || wasForwardRecurse) && tCacheEntry->first.place != DNSResourceRecord::ADDITIONAL);
    /* in a non authoritative answer, we only care about the DS record (or lack of)  */
    if (!isAA && (tCacheEntry->first.type == QType::DS || tCacheEntry->first.type == QType::NSEC || tCacheEntry->first.type == QType::NSEC3) && tCacheEntry->first.place == DNSResourceRecord::AUTHORITY) {
      expectSignature = true;
    }

    if (isCNAMEAnswer && (tCacheEntry->first.place != DNSResourceRecord::ANSWER || tCacheEntry->first.type != QType::CNAME || tCacheEntry->first.name != qname)) {
      /*
        rfc2181 states:
        Note that the answer section of an authoritative answer normally
        contains only authoritative data.  However when the name sought is an
        alias (see section 10.1.1) only the record describing that alias is
        necessarily authoritative.  Clients should assume that other records
        may have come from the server's cache.  Where authoritative answers
        are required, the client should query again, using the canonical name
        associated with the alias.
      */
      isAA = false;
      expectSignature = false;
    }
    if (isDNAMEAnswer && (tCacheEntry->first.place != DNSResourceRecord::ANSWER || tCacheEntry->first.type != QType::DNAME || !qname.isPartOf(tCacheEntry->first.name))) {
      /* see above */
      isAA = false;
      expectSignature = false;
    }

    if ((isCNAMEAnswer || isDNAMEAnswer) && tCacheEntry->first.place == DNSResourceRecord::AUTHORITY && tCacheEntry->first.type == QType::NS && auth == tCacheEntry->first.name) {
      /* These NS can't be authoritative since we have a CNAME/DNAME answer for which (see above) only the
         record describing that alias is necessarily authoritative.
         But if we allow the current auth, which might be serving the child zone, to raise the TTL
         of non-authoritative NS in the cache, they might be able to keep a "ghost" zone alive forever,
         even after the delegation is gone from the parent.
         So let's just do nothing with them, we can fetch them directly if we need them.
      */
      LOG(prefix << qname << ": Skipping authority NS from '" << auth << "' nameservers in CNAME/DNAME answer " << tCacheEntry->first.name << "|" << DNSRecordContent::NumberToType(tCacheEntry->first.type) << endl);
      continue;
    }

    /*
     * RFC 6672 section 5.3.1
     *  In any response, a signed DNAME RR indicates a non-terminal
     *  redirection of the query.  There might or might not be a server-
     *  synthesized CNAME in the answer section; if there is, the CNAME will
     *  never be signed.  For a DNSSEC validator, verification of the DNAME
     *  RR and then that the CNAME was properly synthesized is sufficient
     *  proof.
     *
     * We do the synthesis check in processRecords, here we make sure we
     * don't validate the CNAME.
     */
    if (isDNAMEAnswer && tCacheEntry->first.type == QType::CNAME) {
      expectSignature = false;
    }

    vState recordState = vState::Indeterminate;

    if (expectSignature && shouldValidate()) {
      vState initialState = getValidationStatus(tCacheEntry->first.name, !tCacheEntry->second.signatures.empty(), tCacheEntry->first.type == QType::DS, depth, prefix);
      LOG(prefix << qname << ": Got initial zone status " << initialState << " for record " << tCacheEntry->first.name << "|" << DNSRecordContent::NumberToType(tCacheEntry->first.type) << endl);

      if (initialState == vState::Secure) {
        if (tCacheEntry->first.type == QType::DNSKEY && tCacheEntry->first.place == DNSResourceRecord::ANSWER && tCacheEntry->first.name == getSigner(tCacheEntry->second.signatures)) {
          LOG(prefix << qname << ": Validating DNSKEY for " << tCacheEntry->first.name << endl);
          recordState = validateDNSKeys(tCacheEntry->first.name, tCacheEntry->second.records, tCacheEntry->second.signatures, depth, prefix);
        }
        else {
          LOG(prefix << qname << ": Validating non-additional " << QType(tCacheEntry->first.type).toString() << " record for " << tCacheEntry->first.name << endl);
          recordState = validateRecordsWithSigs(depth, prefix, qname, qtype, tCacheEntry->first.name, QType(tCacheEntry->first.type), tCacheEntry->second.records, tCacheEntry->second.signatures);
        }
      }
      else {
        recordState = initialState;
        LOG(prefix << qname << ": Skipping validation because the current state is " << recordState << endl);
      }

      LOG(prefix << qname << ": Validation result is " << recordState << ", current state is " << state << endl);
      if (state != recordState) {
        updateValidationState(qname, state, recordState, prefix);
      }
    }

    if (vStateIsBogus(recordState)) {
      seenBogusRRSet = true;
      /* this is a TTD by now, be careful */
      for (auto& record : tCacheEntry->second.records) {
        auto newval = std::min(record.d_ttl, static_cast<uint32_t>(s_maxbogusttl + d_now.tv_sec));
        record.d_ttl = newval;
      }
      tCacheEntry->second.d_ttl_time = d_now.tv_sec;
    }

    /* We don't need to store NSEC3 records in the positive cache because:
       - we don't allow direct NSEC3 queries
       - denial of existence proofs in wildcard expanded positive responses are stored in authorityRecs
       - denial of existence proofs for negative responses are stored in the negative cache
       We also don't want to cache non-authoritative data except for:
       - records coming from non forward-recurse servers (those will never be AA)
       - DS (special case)
       - NS, A and AAAA (used for infra queries)
    */
    if (tCacheEntry->first.type != QType::NSEC3 && (tCacheEntry->first.type == QType::DS || tCacheEntry->first.type == QType::NS || tCacheEntry->first.type == QType::A || tCacheEntry->first.type == QType::AAAA || isAA || wasForwardRecurse)) {

      bool doCache = true;
      if (!isAA && seenBogusRRSet) {
        LOG(prefix << qname << ": Not caching non-authoritative rrsets received with Bogus answer" << endl);
        doCache = false;
      }
      if (doCache && tCacheEntry->first.place == DNSResourceRecord::ANSWER && ednsmask) {
        const bool isv4 = ednsmask->isIPv4();
        if ((isv4 && s_ecsipv4nevercache) || (!isv4 && s_ecsipv6nevercache)) {
          doCache = false;
        }
        // If ednsmask is relevant, we do not want to cache if the scope prefix length is large and TTL is small
        if (doCache && s_ecscachelimitttl > 0) {
          bool manyMaskBits = (isv4 && ednsmask->getBits() > s_ecsipv4cachelimit) || (!isv4 && ednsmask->getBits() > s_ecsipv6cachelimit);

          if (manyMaskBits) {
            uint32_t minttl = UINT32_MAX;
            for (const auto& iter : tCacheEntry->second.records) {
              if (iter.d_ttl < minttl) {
                minttl = iter.d_ttl;
              }
            }
            bool ttlIsSmall = minttl < s_ecscachelimitttl + d_now.tv_sec;
            if (ttlIsSmall) {
              // Case: many bits and ttlIsSmall
              doCache = false;
            }
          }
        }
      }

      d_fromAuthIP = remoteIP;

      if (doCache) {
        // Check if we are going to replace a non-auth (parent) NS recordset
        if (isAA && tCacheEntry->first.type == QType::NS && s_save_parent_ns_set) {
          rememberParentSetIfNeeded(tCacheEntry->first.name, tCacheEntry->second.records, depth, prefix);
        }
        bool thisRRNeedsWildcardProof = false;
        if (gatherWildcardProof) {
          if (auto wcIt = wildcardCandidates.find(tCacheEntry->first.name); wcIt != wildcardCandidates.end() && wcIt->second) {
            thisRRNeedsWildcardProof = true;
          }
        }
        g_recCache->replace(d_now.tv_sec, tCacheEntry->first.name, tCacheEntry->first.type, tCacheEntry->second.records, tCacheEntry->second.signatures, thisRRNeedsWildcardProof ? authorityRecs : *MemRecursorCache::s_emptyAuthRecs, tCacheEntry->first.type == QType::DS ? true : isAA, auth, tCacheEntry->first.place == DNSResourceRecord::ANSWER ? ednsmask : std::nullopt, d_routingTag, recordState, MemRecursorCache::Extra{remoteIP, overTCP}, d_refresh, tCacheEntry->second.d_ttl_time);

        // Delete potential negcache entry. When a record recovers with serve-stale the negcache entry can cause the wrong entry to
        // be served, as negcache entries are checked before record cache entries
        if (NegCache::s_maxServedStaleExtensions > 0) {
          g_negCache->wipeTyped(tCacheEntry->first.name, tCacheEntry->first.type);
        }

        if (g_aggressiveNSECCache && thisRRNeedsWildcardProof && recordState == vState::Secure && tCacheEntry->first.place == DNSResourceRecord::ANSWER && !tCacheEntry->second.signatures.empty() && !d_routingTag && !ednsmask) {
          /* we have an answer synthesized from a wildcard and aggressive NSEC is enabled, we need to store the
             wildcard in its non-expanded form in the cache to be able to synthesize wildcard answers later */
          const auto& rrsig = tCacheEntry->second.signatures.at(0);
          const auto labelCount = tCacheEntry->first.name.countLabels();

          if (isWildcardExpanded(labelCount, *rrsig) && !isWildcardExpandedOntoItself(tCacheEntry->first.name, labelCount, *rrsig)) {
            DNSName realOwner = getNSECOwnerName(tCacheEntry->first.name, tCacheEntry->second.signatures);

            std::vector<DNSRecord> content;
            content.reserve(tCacheEntry->second.records.size());
            for (const auto& record : tCacheEntry->second.records) {
              DNSRecord nonExpandedRecord(record);
              nonExpandedRecord.d_name = realOwner;
              content.push_back(std::move(nonExpandedRecord));
            }

            g_recCache->replace(d_now.tv_sec, realOwner, QType(tCacheEntry->first.type), content, tCacheEntry->second.signatures, /* no additional records in that case */ {}, tCacheEntry->first.type == QType::DS ? true : isAA, auth, std::nullopt, boost::none, recordState, MemRecursorCache::Extra{remoteIP, overTCP}, d_refresh, tCacheEntry->second.d_ttl_time);
          }
        }
      }
    }

    if (seenAuth.empty() && !tCacheEntry->second.signatures.empty()) {
      seenAuth = getSigner(tCacheEntry->second.signatures);
    }

    if (g_aggressiveNSECCache && (tCacheEntry->first.type == QType::NSEC || tCacheEntry->first.type == QType::NSEC3) && recordState == vState::Secure && !seenAuth.empty()) {
      // Good candidate for NSEC{,3} caching
      g_aggressiveNSECCache->insertNSEC(seenAuth, tCacheEntry->first.name, tCacheEntry->second.records.at(0), tCacheEntry->second.signatures, tCacheEntry->first.type == QType::NSEC3, qname, qtype);
    }

    if (tCacheEntry->first.place == DNSResourceRecord::ANSWER && ednsmask) {
      d_wasVariable = true;
    }
  }

  if (gatherWildcardProof) {
    if (auto wcIt = wildcardCandidates.find(qname); wcIt != wildcardCandidates.end() && !wcIt->second) {
      // the queried name was not expanded from a wildcard, a record in the CNAME chain was, so we don't need to gather wildcard proof now: we will do that when looking up the CNAME chain
      gatherWildcardProof = false;
    }
  }

  return RCode::NoError;
}

void SyncRes::updateDenialValidationState(const DNSName& qname, vState& neValidationState, const DNSName& neName, vState& state, const dState denialState, const dState expectedState, bool isDS, unsigned int depth, const string& prefix)
{
  if (denialState == expectedState) {
    neValidationState = vState::Secure;
  }
  else {
    if (denialState == dState::OPTOUT) {
      LOG(prefix << qname << ": OPT-out denial found for " << neName << endl);
      /* rfc5155 states:
         "The AD bit, as defined by [RFC4035], MUST NOT be set when returning a
         response containing a closest (provable) encloser proof in which the
         NSEC3 RR that covers the "next closer" name has the Opt-Out bit set.

         This rule is based on what this closest encloser proof actually
         proves: names that would be covered by the Opt-Out NSEC3 RR may or
         may not exist as insecure delegations.  As such, not all the data in
         responses containing such closest encloser proofs will have been
         cryptographically verified, so the AD bit cannot be set."

         At best the Opt-Out NSEC3 RR proves that there is no signed DS (so no
         secure delegation).
      */
      neValidationState = vState::Insecure;
    }
    else if (denialState == dState::INSECURE) {
      LOG(prefix << qname << ": Insecure denial found for " << neName << ", returning Insecure" << endl);
      neValidationState = vState::Insecure;
    }
    else {
      LOG(prefix << qname << ": Invalid denial found for " << neName << ", res=" << denialState << ", expectedState=" << expectedState << ", checking whether we have missed a zone cut before returning a Bogus state" << endl);
      /* try again to get the missed cuts, harder this time */
      auto zState = getValidationStatus(neName, false, isDS, depth, prefix);
      if (zState != vState::Secure) {
        neValidationState = zState;
      }
      else {
        LOG(prefix << qname << ": Still in a secure zone with an invalid denial for " << neName << ", returning " << vStateToString(vState::BogusInvalidDenial) << endl);
        neValidationState = vState::BogusInvalidDenial;
      }
    }
  }
  updateValidationState(qname, state, neValidationState, prefix);
}

dState SyncRes::getDenialValidationState(const NegCache::NegCacheEntry& negEntry, const dState expectedState, bool referralToUnsigned, const string& prefix)
{
  cspmap_t csp = harvestCSPFromNE(negEntry);
  return getDenial(csp, negEntry.d_name, negEntry.d_qtype.getCode(), referralToUnsigned, expectedState == dState::NXQTYPE, d_validationContext, LogObject(prefix));
}

void SyncRes::checkWildcardProof(const DNSName& qname, const QType& qtype, DNSRecord& rec, const LWResult& lwr, vState& state, unsigned int depth, const std::string& prefix, unsigned int wildcardLabelsCount)
{
  /* positive answer synthesized from a wildcard */
  NegCache::NegCacheEntry negEntry;
  negEntry.d_name = qname;
  negEntry.d_qtype = QType::ENT; // this encodes 'whole record'
  uint32_t lowestTTL = rec.d_ttl;
  harvestNXRecords(lwr.d_records, negEntry, d_now.tv_sec, &lowestTTL);

  if (vStateIsBogus(state)) {
    negEntry.d_validationState = state;
  }
  else {
    auto recordState = getValidationStatus(qname, !negEntry.authoritySOA.signatures.empty() || !negEntry.DNSSECRecords.signatures.empty(), false, depth, prefix);

    if (recordState == vState::Secure) {
      /* We have a positive answer synthesized from a wildcard, we need to check that we have
         proof that the exact name doesn't exist so the wildcard can be used,
         as described in section 5.3.4 of RFC 4035 and 5.3 of RFC 7129.
      */
      cspmap_t csp = harvestCSPFromNE(negEntry);
      dState res = getDenial(csp, qname, negEntry.d_qtype.getCode(), false, false, d_validationContext, LogObject(prefix), false, wildcardLabelsCount);
      if (res != dState::NXDOMAIN) {
        vState tmpState = vState::BogusInvalidDenial;
        if (res == dState::INSECURE || res == dState::OPTOUT) {
          /* Some part could not be validated, for example a NSEC3 record with a too large number of iterations,
             this is not enough to warrant a Bogus, but go Insecure. */
          tmpState = vState::Insecure;
          LOG(prefix << qname << ": Unable to validate denial in wildcard expanded positive response found for " << qname << ", returning Insecure, res=" << res << endl);
        }
        else {
          LOG(prefix << qname << ": Invalid denial in wildcard expanded positive response found for " << qname << ", returning Bogus, res=" << res << endl);
          rec.d_ttl = std::min(rec.d_ttl, s_maxbogusttl);
        }

        updateValidationState(qname, state, tmpState, prefix);
        /* we already stored the record with a different validation status, let's fix it */
        updateValidationStatusInCache(qname, qtype, lwr.d_aabit, tmpState);
      }
    }
  }
}

bool SyncRes::processRecords(const std::string& prefix, const DNSName& qname, const QType qtype, const DNSName& auth, LWResult& lwr, const bool sendRDQuery, vector<DNSRecord>& ret, set<DNSName>& nsset, DNSName& newtarget, DNSName& newauth, bool& realreferral, bool& negindic, vState& state, const bool needWildcardProof, const bool gatherWildcardProof, const unsigned int wildcardLabelsCount, int& rcode, bool& negIndicHasSignatures, unsigned int depth) // // NOLINT(readability-function-cognitive-complexity)
{
  bool done = false;
  DNSName dnameTarget;
  DNSName dnameOwner;
  uint32_t dnameTTL = 0;
  bool referralOnDS = false;

  for (auto& rec : lwr.d_records) {
    if (rec.d_type == QType::OPT || rec.d_class != QClass::IN) {
      continue;
    }

    if (rec.d_place == DNSResourceRecord::ANSWER && !(lwr.d_aabit || sendRDQuery)) {
      /* for now we allow a CNAME for the exact qname in ANSWER with AA=0, because Amazon DNS servers
         are sending such responses */
      if (rec.d_type != QType::CNAME || rec.d_name != qname) {
        continue;
      }
    }
    const bool negCacheIndication = rec.d_place == DNSResourceRecord::AUTHORITY && rec.d_type == QType::SOA && lwr.d_rcode == RCode::NXDomain && qname.isPartOf(rec.d_name) && rec.d_name.isPartOf(auth);

    bool putInNegCache = true;
    if (negCacheIndication && qtype == QType::DS && isForwardOrAuth(qname)) {
      // #10189, a NXDOMAIN to a DS query for a forwarded or auth domain should not NXDOMAIN the whole domain
      putInNegCache = false;
    }

    if (negCacheIndication) {
      LOG(prefix << qname << ": Got negative caching indication for name '" << qname << "' (accept=" << rec.d_name.isPartOf(auth) << "), newtarget='" << newtarget << "'" << endl);

      rec.d_ttl = min(rec.d_ttl, s_maxnegttl);
      // only add a SOA if we're not going anywhere after this
      if (newtarget.empty()) {
        ret.push_back(rec);
      }

      NegCache::NegCacheEntry negEntry;

      uint32_t lowestTTL = rec.d_ttl;
      /* if we get an NXDomain answer with a CNAME, the name
         does exist but the target does not */
      negEntry.d_name = newtarget.empty() ? qname : newtarget;
      negEntry.d_qtype = QType::ENT; // this encodes 'whole record'
      negEntry.d_auth = rec.d_name;
      harvestNXRecords(lwr.d_records, negEntry, d_now.tv_sec, &lowestTTL);

      if (vStateIsBogus(state)) {
        negEntry.d_validationState = state;
      }
      else {
        /* here we need to get the validation status of the zone telling us that the domain does not
           exist, ie the owner of the SOA */
        auto recordState = getValidationStatus(rec.d_name, !negEntry.authoritySOA.signatures.empty() || !negEntry.DNSSECRecords.signatures.empty(), false, depth, prefix);
        if (recordState == vState::Secure) {
          dState denialState = getDenialValidationState(negEntry, dState::NXDOMAIN, false, prefix);
          updateDenialValidationState(qname, negEntry.d_validationState, negEntry.d_name, state, denialState, dState::NXDOMAIN, false, depth, prefix);
        }
        else {
          negEntry.d_validationState = recordState;
          updateValidationState(qname, state, negEntry.d_validationState, prefix);
        }
      }

      if (vStateIsBogus(negEntry.d_validationState)) {
        lowestTTL = min(lowestTTL, s_maxbogusttl);
      }

      negEntry.d_ttd = d_now.tv_sec + lowestTTL;
      negEntry.d_orig_ttl = lowestTTL;
      /* if we get an NXDomain answer with a CNAME, let's not cache the
         target, even the server was authoritative for it,
         and do an additional query for the CNAME target.
         We have a regression test making sure we do exactly that.
      */
      if (newtarget.empty() && putInNegCache) {
        g_negCache->add(negEntry);
        // doCNAMECacheCheck() checks record cache and does not look into negcache. That means that an old record might be found if
        // serve-stale is active. Avoid that by explicitly zapping that CNAME record.
        if (qtype == QType::CNAME && MemRecursorCache::s_maxServedStaleExtensions > 0) {
          g_recCache->doWipeCache(qname, false, qtype);
        }
        if (s_rootNXTrust && negEntry.d_auth.isRoot() && auth.isRoot() && lwr.d_aabit) {
          negEntry.d_name = negEntry.d_name.getLastLabel();
          g_negCache->add(negEntry);
        }
      }

      negIndicHasSignatures = !negEntry.authoritySOA.signatures.empty() || !negEntry.DNSSECRecords.signatures.empty();
      negindic = true;
    }
    else if (rec.d_place == DNSResourceRecord::ANSWER && isRedirection(rec.d_type) && // CNAME or DNAME answer
             !isRedirection(qtype.getCode())) { // But not in response to a CNAME or DNAME query
      if (rec.d_type == QType::CNAME && rec.d_name == qname) {
        if (!dnameOwner.empty()) { // We synthesize ourselves
          continue;
        }
        ret.push_back(rec);
        if (auto content = getRR<CNAMERecordContent>(rec)) {
          newtarget = DNSName(content->getTarget());
        }
        if (needWildcardProof) {
          checkWildcardProof(qname, QType::CNAME, rec, lwr, state, depth, prefix, wildcardLabelsCount);
        }
      }
      else if (rec.d_type == QType::DNAME && qname.isPartOf(rec.d_name)) { // DNAME
        ret.push_back(rec);
        if (auto content = getRR<DNAMERecordContent>(rec)) {
          dnameOwner = rec.d_name;
          dnameTarget = content->getTarget();
          dnameTTL = rec.d_ttl;
          if (!newtarget.empty()) { // We had a CNAME before, remove it from ret so we don't cache it
            ret.erase(std::remove_if(
                        ret.begin(),
                        ret.end(),
                        [&qname](DNSRecord& dnsrecord) {
                          return (dnsrecord.d_place == DNSResourceRecord::ANSWER && dnsrecord.d_type == QType::CNAME && dnsrecord.d_name == qname);
                        }),
                      ret.end());
          }
          try {
            newtarget = qname.makeRelative(dnameOwner) + dnameTarget;
            if (needWildcardProof) {
              checkWildcardProof(qname, QType::DNAME, rec, lwr, state, depth, prefix, wildcardLabelsCount);
            }
          }
          catch (const std::exception& e) {
            // We should probably catch an std::range_error here and set the rcode to YXDOMAIN (RFC 6672, section 2.2)
            // But there is no way to set the RCODE from this function
            throw ImmediateServFailException("Unable to perform DNAME substitution(DNAME owner: '" + dnameOwner.toLogString() + "', DNAME target: '" + dnameTarget.toLogString() + "', substituted name: '" + qname.makeRelative(dnameOwner).toLogString() + "." + dnameTarget.toLogString() + "' : " + e.what());
          }
        }
      }
    }
    /* if we have a positive answer synthesized from a wildcard, we need to
       return the corresponding NSEC/NSEC3 records from the AUTHORITY section
       proving that the exact name did not exist.
       Except if this is a NODATA answer because then we will gather the NXNSEC records later */
    else if (gatherWildcardProof && !negindic && (rec.d_type == QType::RRSIG || rec.d_type == QType::NSEC || rec.d_type == QType::NSEC3) && rec.d_place == DNSResourceRecord::AUTHORITY) {
      ret.push_back(rec); // enjoy your DNSSEC
    }
    // for ANY answers we *must* have an authoritative answer, unless we are forwarding recursively
    else if (rec.d_place == DNSResourceRecord::ANSWER && rec.d_name == qname && (rec.d_type == qtype.getCode() || ((lwr.d_aabit || sendRDQuery) && qtype == QType::ANY))) {
      LOG(prefix << qname << ": Answer is in: resolved to '" << rec.getContent()->getZoneRepresentation() << "|" << DNSRecordContent::NumberToType(rec.d_type) << "'" << endl);

      done = true;
      rcode = RCode::NoError;

      if (needWildcardProof) {
        checkWildcardProof(qname, qtype, rec, lwr, state, depth, prefix, wildcardLabelsCount);
      }

      ret.push_back(rec);
    }
    else if ((rec.d_type == QType::RRSIG || rec.d_type == QType::NSEC || rec.d_type == QType::NSEC3) && rec.d_place == DNSResourceRecord::ANSWER) {
      if (rec.d_type != QType::RRSIG || rec.d_name == qname) {
        ret.push_back(rec); // enjoy your DNSSEC
      }
      else if (rec.d_type == QType::RRSIG && qname.isPartOf(rec.d_name)) {
        auto rrsig = getRR<RRSIGRecordContent>(rec);
        if (rrsig != nullptr && rrsig->d_type == QType::DNAME) {
          ret.push_back(rec);
        }
      }
    }
    else if (rec.d_place == DNSResourceRecord::AUTHORITY && rec.d_type == QType::NS && qname.isPartOf(rec.d_name)) {
      if (moreSpecificThan(rec.d_name, auth)) {
        newauth = rec.d_name;
        LOG(prefix << qname << ": Got NS record '" << rec.d_name << "' -> '" << rec.getContent()->getZoneRepresentation() << "'" << endl);

        /* check if we have a referral from the parent zone to a child zone for a DS query, which is not right */
        if (qtype == QType::DS && (newauth.isPartOf(qname) || qname == newauth)) {
          /* just got a referral from the parent zone when asking for a DS, looks like this server did not get the DNSSEC memo.. */
          referralOnDS = true;
        }
        else {
          realreferral = true;
          if (auto content = getRR<NSRecordContent>(rec)) {
            nsset.insert(content->getNS());
          }
        }
      }
      else {
        LOG(prefix << qname << ": Got upwards/level NS record '" << rec.d_name << "' -> '" << rec.getContent()->getZoneRepresentation() << "', had '" << auth << "'" << endl);
        if (auto content = getRR<NSRecordContent>(rec)) {
          nsset.insert(content->getNS());
        }
      }
    }
    else if (rec.d_place == DNSResourceRecord::AUTHORITY && rec.d_type == QType::DS && qname.isPartOf(rec.d_name)) {
      LOG(prefix << qname << ": Got DS record '" << rec.d_name << "' -> '" << rec.getContent()->getZoneRepresentation() << "'" << endl);
    }
    else if (realreferral && rec.d_place == DNSResourceRecord::AUTHORITY && (rec.d_type == QType::NSEC || rec.d_type == QType::NSEC3) && newauth.isPartOf(auth)) {
      /* we might have received a denial of the DS, let's check */
      NegCache::NegCacheEntry negEntry;
      uint32_t lowestTTL = rec.d_ttl;
      harvestNXRecords(lwr.d_records, negEntry, d_now.tv_sec, &lowestTTL);

      if (!vStateIsBogus(state)) {
        auto recordState = getValidationStatus(newauth, !negEntry.authoritySOA.signatures.empty() || !negEntry.DNSSECRecords.signatures.empty(), true, depth, prefix);

        if (recordState == vState::Secure) {
          negEntry.d_auth = auth;
          negEntry.d_name = newauth;
          negEntry.d_qtype = QType::DS;
          rec.d_ttl = min(s_maxnegttl, rec.d_ttl);

          dState denialState = getDenialValidationState(negEntry, dState::NXQTYPE, true, prefix);

          if (denialState == dState::NXQTYPE || denialState == dState::OPTOUT || denialState == dState::INSECURE) {
            negEntry.d_ttd = lowestTTL + d_now.tv_sec;
            negEntry.d_orig_ttl = lowestTTL;
            negEntry.d_validationState = vState::Secure;
            if (denialState == dState::OPTOUT) {
              negEntry.d_validationState = vState::Insecure;
            }
            LOG(prefix << qname << ": Got negative indication of DS record for '" << newauth << "'" << endl);

            g_negCache->add(negEntry);

            /* Careful! If the client is asking for a DS that does not exist, we need to provide the SOA along with the NSEC(3) proof
               and we might not have it if we picked up the proof from a delegation, in which case we need to keep on to do the actual DS
               query. */
            if (qtype == QType::DS && qname == newauth && (d_externalDSQuery.empty() || qname != d_externalDSQuery)) {
              /* we are actually done! */
              negindic = true;
              negIndicHasSignatures = !negEntry.authoritySOA.signatures.empty() || !negEntry.DNSSECRecords.signatures.empty();
              nsset.clear();
            }
          }
        }
      }
    }
    else if (!done && rec.d_place == DNSResourceRecord::AUTHORITY && rec.d_type == QType::SOA && lwr.d_rcode == RCode::NoError && qname.isPartOf(rec.d_name)) {
      LOG(prefix << qname << ": Got negative caching indication for '" << qname << "|" << qtype << "'" << endl);

      if (!newtarget.empty()) {
        LOG(prefix << qname << ": Hang on! Got a redirect to '" << newtarget << "' already" << endl);
      }
      else {
        rec.d_ttl = min(s_maxnegttl, rec.d_ttl);

        NegCache::NegCacheEntry negEntry;
        negEntry.d_auth = rec.d_name;
        uint32_t lowestTTL = rec.d_ttl;
        negEntry.d_name = qname;
        negEntry.d_qtype = qtype;
        harvestNXRecords(lwr.d_records, negEntry, d_now.tv_sec, &lowestTTL);

        if (vStateIsBogus(state)) {
          negEntry.d_validationState = state;
        }
        else {
          auto recordState = getValidationStatus(qname, !negEntry.authoritySOA.signatures.empty() || !negEntry.DNSSECRecords.signatures.empty(), qtype == QType::DS, depth, prefix);
          if (recordState == vState::Secure) {
            dState denialState = getDenialValidationState(negEntry, dState::NXQTYPE, false, prefix);
            updateDenialValidationState(qname, negEntry.d_validationState, negEntry.d_name, state, denialState, dState::NXQTYPE, qtype == QType::DS, depth, prefix);
          }
          else {
            negEntry.d_validationState = recordState;
            updateValidationState(qname, state, negEntry.d_validationState, prefix);
          }
        }

        if (vStateIsBogus(negEntry.d_validationState)) {
          lowestTTL = min(lowestTTL, s_maxbogusttl);
          rec.d_ttl = min(rec.d_ttl, s_maxbogusttl);
        }
        negEntry.d_ttd = d_now.tv_sec + lowestTTL;
        negEntry.d_orig_ttl = lowestTTL;
        if (qtype.getCode() != 0) { // prevents us from NXDOMAIN'ing a whole domain
          // doCNAMECacheCheck() checks record cache and does not look into negcache. That means that an old record might be found if
          // serve-stale is active. Avoid that by explicitly zapping that CNAME record.
          if (qtype == QType::CNAME && MemRecursorCache::s_maxServedStaleExtensions > 0) {
            g_recCache->doWipeCache(qname, false, qtype);
          }
          g_negCache->add(negEntry);
        }

        ret.push_back(rec);
        negindic = true;
        negIndicHasSignatures = !negEntry.authoritySOA.signatures.empty() || !negEntry.DNSSECRecords.signatures.empty();
      }
    }
  }

  if (!dnameTarget.empty()) {
    // Synthesize a CNAME
    auto cnamerec = DNSRecord();
    cnamerec.d_name = qname;
    cnamerec.d_type = QType::CNAME;
    cnamerec.d_ttl = dnameTTL;
    cnamerec.setContent(std::make_shared<CNAMERecordContent>(CNAMERecordContent(newtarget)));
    ret.push_back(std::move(cnamerec));
  }

  /* If we have seen a proper denial, let's forget that we also had a referral for a DS query.
     Otherwise we need to deal with it. */
  if (referralOnDS && !negindic) {
    LOG(prefix << qname << ": Got a referral to the child zone for a DS query without a negative indication (missing SOA in authority), treating that as a NODATA" << endl);
    if (!vStateIsBogus(state)) {
      auto recordState = getValidationStatus(qname, false, true, depth, prefix);
      if (recordState == vState::Secure) {
        /* we are in a secure zone, got a referral to the child zone on a DS query, no denial, that's wrong */
        LOG(prefix << qname << ": NODATA without a negative indication (missing SOA in authority) in a DNSSEC secure zone, going Bogus" << endl);
        updateValidationState(qname, state, vState::BogusMissingNegativeIndication, prefix);
      }
    }
    negindic = true;
    negIndicHasSignatures = false;
  }

  return done;
}

static void submitTryDotTask(ComboAddress address, const DNSName& auth, const DNSName& nsname, time_t now)
{
  if (address.getPort() == 853) {
    return;
  }
  address.setPort(853);
  auto lock = s_dotMap.lock();
  if (lock->d_numBusy >= SyncRes::s_max_busy_dot_probes) {
    return;
  }
  auto iter = lock->d_map.emplace(DoTStatus{address, auth, now + dotFailWait}).first;
  if (iter->d_status == DoTStatus::Busy) {
    return;
  }
  if (iter->d_ttd > now) {
    if (iter->d_status == DoTStatus::Bad) {
      return;
    }
    if (iter->d_status == DoTStatus::Good) {
      return;
    }
    // We only want to probe auths that we have seen before, auth that only come around once are not interesting
    if (iter->d_status == DoTStatus::Unknown && iter->d_count == 0) {
      return;
    }
  }
  lock->d_map.modify(iter, [=](DoTStatus& status) { status.d_ttd = now + dotFailWait; });
  bool pushed = pushTryDoTTask(auth, QType::SOA, address, std::numeric_limits<time_t>::max(), nsname);
  if (pushed) {
    iter->d_status = DoTStatus::Busy;
    ++lock->d_numBusy;
  }
}

static bool shouldDoDoT(ComboAddress address, time_t now)
{
  address.setPort(853);
  auto lock = s_dotMap.lock();
  auto iter = lock->d_map.find(address);
  if (iter == lock->d_map.end()) {
    return false;
  }
  iter->d_count++;
  return iter->d_status == DoTStatus::Good && iter->d_ttd > now;
}

static void updateDoTStatus(ComboAddress address, DoTStatus::Status status, time_t time, bool updateBusy = false)
{
  address.setPort(853);
  auto lock = s_dotMap.lock();
  auto iter = lock->d_map.find(address);
  if (iter != lock->d_map.end()) {
    iter->d_status = status;
    lock->d_map.modify(iter, [=](DoTStatus& statusToModify) { statusToModify.d_ttd = time; });
    if (updateBusy) {
      --lock->d_numBusy;
    }
  }
}

bool SyncRes::tryDoT(const DNSName& qname, const QType qtype, const DNSName& nsName, ComboAddress address, time_t now)
{
  auto log = g_slog->withName("taskq")->withValues("method", Logging::Loggable("tryDoT"), "name", Logging::Loggable(qname), "qtype", Logging::Loggable(QType(qtype).toString()), "ip", Logging::Loggable(address));

  auto logHelper1 = [&log](const string& ename) {
    log->info(Logr::Debug, "Failed to probe DoT records, got an exception", "exception", Logging::Loggable(ename));
  };
  auto logHelper2 = [&log](const string& msg, const string& ename) {
    log->error(Logr::Debug, msg, "Failed to probe DoT records, got an exception", "exception", Logging::Loggable(ename));
  };
  LWResult lwr;
  bool truncated{};
  bool spoofed{};
  std::optional<Netmask> netmask;
  address.setPort(853);
  // We use the fact that qname equals auth
  bool isOK = false;
  try {
    std::optional<EDNSExtendedError> extendedError;
    isOK = doResolveAtThisIP("", qname, qtype, lwr, netmask, qname, false, false, nsName, address, true, true, truncated, spoofed, extendedError, true);
    isOK = isOK && lwr.d_rcode == RCode::NoError && !lwr.d_records.empty();
  }
  catch (const PDNSException& e) {
    logHelper2(e.reason, "PDNSException");
  }
  catch (const ImmediateServFailException& e) {
    logHelper2(e.reason, "ImmediateServFailException");
  }
  catch (const PolicyHitException& e) {
    logHelper1("PolicyHitException");
  }
  catch (const std::exception& e) {
    logHelper2(e.what(), "std::exception");
  }
  catch (...) {
    logHelper1("other");
  }
  updateDoTStatus(address, isOK ? DoTStatus::Good : DoTStatus::Bad, now + (isOK ? dotSuccessWait : dotFailWait), true);
  return isOK;
}

void SyncRes::ednsStats(std::optional<Netmask>& ednsmask, const DNSName& qname, const string& prefix)
{
  if (!ednsmask) {
    return;
  }
  s_ecsresponses++;
  LOG(prefix << qname << ": Received EDNS Client Subnet Mask " << ednsmask->toString() << " on response" << endl);

  if (ednsmask->getBits() > 0) {
    if (ednsmask->isIPv4()) {
      ++SyncRes::s_ecsResponsesBySubnetSize4.at(ednsmask->getBits() - 1);
    }
    else {
      ++SyncRes::s_ecsResponsesBySubnetSize6.at(ednsmask->getBits() - 1);
    }
  }
}

void SyncRes::updateQueryCounts(const string& prefix, const DNSName& qname, const ComboAddress& address, bool doTCP, bool doDoT)
{
  t_Counters.at(rec::Counter::outqueries)++;
  d_outqueries++;
  checkMaxQperQ(qname);
  if (address.sin4.sin_family == AF_INET6) {
    t_Counters.at(rec::Counter::ipv6queries)++;
  }
  if (doTCP) {
    if (doDoT) {
      LOG(prefix << qname << ": Using DoT with " << address.toStringWithPort() << endl);
      t_Counters.at(rec::Counter::dotoutqueries)++;
      d_dotoutqueries++;
    }
    else {
      LOG(prefix << qname << ": Using TCP with " << address.toStringWithPort() << endl);
      t_Counters.at(rec::Counter::tcpoutqueries)++;
      d_tcpoutqueries++;
    }
  }
}

void SyncRes::incTimeoutStats(const ComboAddress& remoteIP)
{
  d_timeouts++;
  t_Counters.at(rec::Counter::outgoingtimeouts)++;

  if (remoteIP.sin4.sin_family == AF_INET) {
    t_Counters.at(rec::Counter::outgoing4timeouts)++;
  }
  else {
    t_Counters.at(rec::Counter::outgoing6timeouts)++;
  }

  if (t_timeouts) {
    t_timeouts->push_back(remoteIP);
  }
}

void SyncRes::checkTotalTime(const DNSName& qname, QType qtype, std::optional<EDNSExtendedError>& extendedError) const
{
  if (s_maxtotusec != 0 && d_totUsec > s_maxtotusec) {
    if (s_addExtendedResolutionDNSErrors) {
      extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::NoReachableAuthority), "Timeout waiting for answer(s)"};
    }
    throw ImmediateServFailException("Too much time waiting for " + qname.toLogString() + "|" + qtype.toString() + ", timeouts: " + std::to_string(d_timeouts) + ", throttles: " + std::to_string(d_throttledqueries) + ", queries: " + std::to_string(d_outqueries) + ", " + std::to_string(d_totUsec / 1000) + " ms");
  }
}

bool SyncRes::doResolveAtThisIP(const std::string& prefix, const DNSName& qname, const QType qtype, LWResult& lwr, std::optional<Netmask>& ednsmask, const DNSName& auth, bool const sendRDQuery, const bool wasForwarded, const DNSName& nsName, const ComboAddress& remoteIP, bool doTCP, bool doDoT, bool& truncated, bool& spoofed, std::optional<EDNSExtendedError>& extendedError, bool dontThrottle)
{
  checkTotalTime(qname, qtype, extendedError);

  bool chained = false;
  LWResult::Result resolveret = LWResult::Result::Success;
  int preOutQueryRet = RCode::NoError;

  if (d_pdl && d_pdl->preoutquery(remoteIP, d_requestor, qname, qtype, doTCP, lwr.d_records, preOutQueryRet, d_eventTrace, timeval{0, 0})) {
    LOG(prefix << qname << ": Query handled by Lua" << endl);
  }
  else {
    ednsmask = getEDNSSubnetMask(qname, remoteIP);
    if (ednsmask) {
      LOG(prefix << qname << ": Adding EDNS Client Subnet Mask " << ednsmask->toString() << " to query" << endl);
      s_ecsqueries++;
    }
    auto match = d_eventTrace.add(RecEventTrace::AuthRequest, qname.toLogString(), true, 0);
    d_eventTrace.setValueName(match, "query.qname");
    d_eventTrace.addExtraValues(match, {{"query.qtype", qtype.toString()}, {"auth.address", remoteIP.toStringWithPortExcept(53)}, {"auth.nsname", nsName.toLogString()}});
    updateQueryCounts(prefix, qname, remoteIP, doTCP, doDoT);
    resolveret = asyncresolveWrapper(LogObject(prefix), remoteIP, d_doDNSSEC, qname, auth, qtype.getCode(),
                                     doTCP, sendRDQuery, &d_now, ednsmask, &lwr, &chained, nsName); // <- we go out on the wire!
    d_eventTrace.add(RecEventTrace::AuthRequest, static_cast<int64_t>(lwr.d_rcode), false, match);
    ednsStats(ednsmask, qname, prefix);
    if (resolveret == LWResult::Result::ECSMissing) {
      ednsmask = std::nullopt;
      LOG(prefix << qname << ": Answer has no ECS, trying again without EDNS Client Subnet Mask" << endl);
      updateQueryCounts(prefix, qname, remoteIP, doTCP, doDoT);
      match = d_eventTrace.add(RecEventTrace::AuthRequest, qname.toLogString() + '/' + qtype.toString(), true, 0);
      resolveret = asyncresolveWrapper(LogObject(prefix), remoteIP, d_doDNSSEC, qname, auth, qtype.getCode(),
                                       doTCP, sendRDQuery, &d_now, ednsmask, &lwr, &chained, nsName); // <- we go out on the wire!
      d_eventTrace.add(RecEventTrace::AuthRequest, static_cast<int64_t>(lwr.d_rcode), false, match);
    }
  }

  /* preoutquery killed the query by setting dq.rcode to -3 */
  if (preOutQueryRet == -3) {
    throw ImmediateServFailException("Query killed by policy");
  }

  d_totUsec += lwr.d_usec;

  if (resolveret == LWResult::Result::Spoofed || resolveret == LWResult::Result::BadCookie) {
    spoofed = true;
    return false;
  }

  accountAuthLatency(lwr.d_usec, remoteIP.sin4.sin_family);
  if (lwr.d_rcode >= 0 && lwr.d_rcode < static_cast<decltype(lwr.d_rcode)>(t_Counters.at(rec::RCode::auth).rcodeCounters.size())) {
    ++t_Counters.at(rec::RCode::auth).rcodeCounters.at(static_cast<uint8_t>(lwr.d_rcode));
  }

  if (!dontThrottle) {
    dontThrottle = shouldNotThrottle(&nsName, &remoteIP);
  }

  if (resolveret != LWResult::Result::Success) {
    /* Error while resolving */
    switch (resolveret) {
    case LWResult::Result::Timeout:
      LOG(prefix << qname << ": Timeout resolving after " << lwr.d_usec / 1000.0 << " ms " << (doTCP ? "over TCP" : "") << endl);
      incTimeoutStats(remoteIP);
      break;
    case LWResult::Result::OSLimitError:
      /* OS resource limit reached */
      LOG(prefix << qname << ": Hit a local resource limit resolving" << (doTCP ? " over TCP" : "") << ", probable error: " << stringerror() << endl);
      t_Counters.at(rec::Counter::resourceLimits)++;
      break;
    case LWResult::Result::ChainLimitError:
      /* Chain resource limit reached */
      LOG(prefix << qname << ": Hit a chain limit resolving" << (doTCP ? " over TCP" : ""));
      t_Counters.at(rec::Counter::chainLimits)++;
      break;
    default:
      /* LWResult::Result::PermanentError */
      t_Counters.at(rec::Counter::unreachables)++;
      d_unreachables++;
      // XXX questionable use of errno
      LOG(prefix << qname << ": Error resolving from " << remoteIP.toString() << (doTCP ? " over TCP" : "") << ", possible error: " << stringerror() << endl);
      break;
    }

    // don't account for resource limits, they are our own fault
    // And don't throttle when the IP address is on the dontThrottleNetmasks list or the name is part of dontThrottleNames
    if (!LWResult::isLimitError(resolveret) && !chained && !dontThrottle) {
      uint32_t responseUsec = 1000000; // 1 sec for non-timeout cases
      // Use the actual time if we saw a timeout
      if (resolveret == LWResult::Result::Timeout) {
        responseUsec = lwr.d_usec;
      }

      s_nsSpeeds.lock()->find_or_enter(nsName.empty() ? DNSName(remoteIP.toStringWithPort()) : nsName, d_now).submit(remoteIP, static_cast<int>(responseUsec), d_now);

      // make sure we don't throttle the root
      if (s_serverdownmaxfails > 0 && auth != g_rootdnsname && s_fails.lock()->incr(remoteIP, d_now) >= s_serverdownmaxfails) {
        LOG(prefix << qname << ": Max fails reached resolving on " << remoteIP.toString() << ". Going full throttle for " << s_serverdownthrottletime << " seconds" << endl);
        // mark server as down
        doThrottle(d_now.tv_sec, remoteIP, s_serverdownthrottletime, 10000, Throttle::Reason::ServerDown);
      }
      else if (resolveret == LWResult::Result::PermanentError) {
        // unreachable, 1 minute or 100 queries
        doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 60, 100, Throttle::Reason::PermanentError);
      }
      else {
        // If the actual response time was more than 80% of the default timeout, we throttle. On a
        // busy rec we reduce the time we are willing to wait for an auth, it is unfair to throttle on
        // such a shortened timeout.
        if (responseUsec > g_networkTimeoutMsec * 800) {
          // timeout, 10 seconds or 5 queries
          doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 10, 5, Throttle::Reason::Timeout);
        }
      }
    }

    return false;
  }

  if (!lwr.d_validpacket) {
    LOG(prefix << qname << ": " << nsName << " (" << remoteIP.toString() << ") returned a packet we could not parse over " << (doTCP ? "TCP" : "UDP") << ", trying sibling IP or NS" << endl);
    if (!chained && !dontThrottle) {

      // let's make sure we prefer a different server for some time, if there is one available
      s_nsSpeeds.lock()->find_or_enter(nsName.empty() ? DNSName(remoteIP.toStringWithPort()) : nsName, d_now).submit(remoteIP, 1000000, d_now); // 1 sec

      if (doTCP) {
        // we can be more heavy-handed over TCP
        doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 60, 10, Throttle::Reason::ParseError);
      }
      else {
        doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 10, 2, Throttle::Reason::ParseError);
      }
    }
    return false;
  }
  /* we got an answer */
  if (lwr.d_rcode != RCode::NoError && lwr.d_rcode != RCode::NXDomain) {
    LOG(prefix << qname << ": " << nsName << " (" << remoteIP.toString() << ") returned a " << RCode::to_s(lwr.d_rcode) << ", trying sibling IP or NS" << endl);
    if (!chained && !dontThrottle) {
      if (wasForwarded && lwr.d_rcode == RCode::ServFail) {
        // rather than throttling what could be the only server we have for this destination, let's make sure we try a different one if there is one available
        // on the other hand, we might keep hammering a server under attack if there is no other alternative, or the alternative is overwhelmed as well, but
        // at the very least we will detect that if our packets stop being answered
        s_nsSpeeds.lock()->find_or_enter(nsName.empty() ? DNSName(remoteIP.toStringWithPort()) : nsName, d_now).submit(remoteIP, 1000000, d_now); // 1 sec
      }
      else {
        Throttle::Reason reason{};
        switch (lwr.d_rcode) {
        case RCode::ServFail:
          reason = Throttle::Reason::RCodeServFail;
          break;
        case RCode::Refused:
          reason = Throttle::Reason::RCodeRefused;
          break;
        default:
          reason = Throttle::Reason::RCodeOther;
          break;
        }
        doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 60, 3, reason);
      }
    }
    return false;
  }

  /* this server sent a valid answer, mark it backup up if it was down */
  if (s_serverdownmaxfails > 0) {
    s_fails.lock()->clear(remoteIP);
  }
  // Clear all throttles for this IP, both general and specific throttles for qname-qtype
  unThrottle(remoteIP, qname, qtype);

  if (lwr.d_tcbit) {
    truncated = true;

    if (doTCP) {
      LOG(prefix << qname << ": Truncated bit set, over TCP?" << endl);
      if (!dontThrottle) {
        /* let's treat that as a ServFail answer from this server */
        doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 60, 3, Throttle::Reason::TCPTruncate);
      }
      return false;
    }
    LOG(prefix << qname << ": Truncated bit set, over UDP" << endl);

    return true;
  }

  return true;
}

void SyncRes::handleNewTarget(const std::string& prefix, const DNSName& qname, const DNSName& newtarget, const QType qtype, std::vector<DNSRecord>& ret, int& rcode, unsigned int depth, const std::vector<DNSRecord>& recordsFromAnswer, vState& state)
{
  if (newtarget == qname) {
    LOG(prefix << qname << ": Status=got a CNAME referral to self, returning SERVFAIL" << endl);
    ret.clear();
    rcode = RCode::ServFail;
    return;
  }
  if (newtarget.isPartOf(qname)) {
    // a.b.c. CNAME x.a.b.c will go to great depths with QM on
    LOG(prefix << qname << ": Status=got a CNAME referral to child, disabling QM" << endl);
    setQNameMinimization(false);
  }

  if (!d_followCNAME) {
    rcode = RCode::NoError;
    return;
  }

  // Check to see if we already have seen the new target as a previous target or that the chain is too long
  const auto [CNAMELoop, numCNAMEs] = scanForCNAMELoop(newtarget, ret);
  if (CNAMELoop) {
    LOG(prefix << qname << ": Status=got a CNAME referral that causes a loop, returning SERVFAIL" << endl);
    ret.clear();
    rcode = RCode::ServFail;
    return;
  }
  if (numCNAMEs > s_max_CNAMES_followed) {
    LOG(prefix << qname << ": Status=got a CNAME referral, but chain too long, returning SERVFAIL" << endl);
    rcode = RCode::ServFail;
    return;
  }

  if (qtype == QType::DS || qtype == QType::DNSKEY) {
    LOG(prefix << qname << ": Status=got a CNAME referral, but we are looking for a DS or DNSKEY" << endl);

    if (d_doDNSSEC) {
      addNXNSECS(ret, recordsFromAnswer);
    }

    rcode = RCode::NoError;
    return;
  }

  LOG(prefix << qname << ": Status=got a CNAME referral, starting over with " << newtarget << endl);

  set<GetBestNSAnswer> beenthere;
  Context cnameContext;
  rcode = doResolve(newtarget, qtype, ret, depth + 1, beenthere, cnameContext);
  LOG(prefix << qname << ": Updating validation state for response to " << qname << " from " << state << " with the state from the CNAME quest: " << cnameContext.state << endl);
  updateValidationState(qname, state, cnameContext.state, prefix);
}

bool SyncRes::processAnswer(unsigned int depth, const string& prefix, LWResult& lwr, const DNSName& qname, const QType qtype, DNSName& auth, bool wasForwarded, const std::optional<Netmask>& ednsmask, bool sendRDQuery, NsSet& nameservers, std::vector<DNSRecord>& ret, const DNSFilterEngine& dfe, bool* gotNewServers, int* rcode, vState& state, const ComboAddress& remoteIP, bool overTCP)
{
  if (s_minimumTTL != 0) {
    for (auto& rec : lwr.d_records) {
      rec.d_ttl = max(rec.d_ttl, s_minimumTTL);
    }
  }

  /* if the answer is ECS-specific, a minimum TTL is set for this kind of answers
     and it's higher than the global minimum TTL */
  if (ednsmask && s_minimumECSTTL > 0 && (s_minimumTTL == 0 || s_minimumECSTTL > s_minimumTTL)) {
    for (auto& rec : lwr.d_records) {
      if (rec.d_place == DNSResourceRecord::ANSWER) {
        rec.d_ttl = max(rec.d_ttl, s_minimumECSTTL);
      }
    }
  }

  bool needWildcardProof = false;
  bool gatherWildcardProof = false;
  unsigned int wildcardLabelsCount = 0;
  *rcode = updateCacheFromRecords(depth, prefix, lwr, qname, qtype, auth, wasForwarded, ednsmask, state, needWildcardProof, gatherWildcardProof, wildcardLabelsCount, sendRDQuery, remoteIP, overTCP);
  if (*rcode != RCode::NoError) {
    return true;
  }

  LOG(prefix << qname << ": Determining status after receiving this packet" << endl);

  set<DNSName> nsset;
  bool realreferral = false;
  bool negindic = false;
  bool negIndicHasSignatures = false;
  DNSName newauth;
  DNSName newtarget;

  bool done = processRecords(prefix, qname, qtype, auth, lwr, sendRDQuery, ret, nsset, newtarget, newauth, realreferral, negindic, state, needWildcardProof, gatherWildcardProof, wildcardLabelsCount, *rcode, negIndicHasSignatures, depth);

  // If we both have a CNAME and an answer, let the CNAME take precedence. This *should* not happen
  // (because CNAMEs cannot co-exist with other records), but reality says otherwise. Other
  // resolvers choose to follow the CNAME in this case as well. We removed the answer record from
  // the records received from the auth when sanitizing, so `done' should not be set when a CNAME is
  // present.
  if (done) {
    LOG(prefix << qname << ": Status=got results, this level of recursion done" << endl);
    LOG(prefix << qname << ": Validation status is " << state << endl);
    return true;
  }

  if (!newtarget.empty()) {
    handleNewTarget(prefix, qname, newtarget, qtype.getCode(), ret, *rcode, depth, lwr.d_records, state);
    return true;
  }

  if (lwr.d_rcode == RCode::NXDomain) {
    LOG(prefix << qname << ": Status=NXDOMAIN, we are done " << (negindic ? "(have negative SOA)" : "") << endl);

    auto tempState = getValidationStatus(qname, negIndicHasSignatures, qtype == QType::DS, depth, prefix);
    if (tempState == vState::Secure && (lwr.d_aabit || sendRDQuery) && !negindic) {
      LOG(prefix << qname << ": NXDOMAIN without a negative indication (missing SOA in authority) in a DNSSEC secure zone, going Bogus" << endl);
      updateValidationState(qname, state, vState::BogusMissingNegativeIndication, prefix);
    }
    else {
      /* we might not have validated any record, because we did get a NXDOMAIN without any SOA
         from an insecure zone, for example */
      updateValidationState(qname, state, tempState, prefix);
    }

    if (d_doDNSSEC) {
      addNXNSECS(ret, lwr.d_records);
    }

    *rcode = RCode::NXDomain;
    return true;
  }

  if (nsset.empty() && lwr.d_rcode == 0 && (negindic || lwr.d_aabit || sendRDQuery)) {
    LOG(prefix << qname << ": Status=noerror, other types may exist, but we are done " << (negindic ? "(have negative SOA) " : "") << (lwr.d_aabit ? "(have aa bit) " : "") << endl);

    auto tempState = getValidationStatus(qname, negIndicHasSignatures, qtype == QType::DS, depth, prefix);
    if (tempState == vState::Secure && (lwr.d_aabit || sendRDQuery) && !negindic) {
      LOG(prefix << qname << ": NODATA without a negative indication (missing SOA in authority) in a DNSSEC secure zone, going Bogus" << endl);
      updateValidationState(qname, state, vState::BogusMissingNegativeIndication, prefix);
    }
    else {
      /* we might not have validated any record, because we did get a NODATA without any SOA
         from an insecure zone, for example */
      updateValidationState(qname, state, tempState, prefix);
    }

    if (d_doDNSSEC) {
      addNXNSECS(ret, lwr.d_records);
    }

    *rcode = RCode::NoError;
    return true;
  }

  if (realreferral) {
    LOG(prefix << qname << ": Status=did not resolve, got " << (unsigned int)nsset.size() << " NS, ");

    nameservers.clear();
    for (auto const& nameserver : nsset) {
      if (d_wantsRPZ && !d_appliedPolicy.wasHit()) {
        bool match = dfe.getProcessingPolicy(nameserver, d_discardedPolicies, d_appliedPolicy);
        if (match) {
          mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
          if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
            if (d_pdl && d_pdl->policyHitEventFilter(d_requestor, qname, qtype, d_queryReceivedOverTCP, d_appliedPolicy, d_policyTags, d_discardedPolicies)) {
              /* reset to no match */
              d_appliedPolicy = DNSFilterEngine::Policy();
            }
            else {
              LOG("however " << nameserver << " was blocked by RPZ policy '" << d_appliedPolicy.getName() << "'" << endl);
              throw PolicyHitException();
            }
          }
        }
      }
      nameservers.insert({nameserver, {{}, false}});
    }
    LOG("looping to them" << endl);
    *gotNewServers = true;
    auth = std::move(newauth);

    return false;
  }

  return false;
}

bool SyncRes::doDoTtoAuth(const DNSName& nameServer)
{
  return g_DoTToAuthNames.getLocal()->check(nameServer);
}

/** returns:
 *  -1 in case of no results
 *  rcode otherwise
 */
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
int SyncRes::doResolveAt(NsSet& nameservers, DNSName auth, bool flawedNSSet, const DNSName& qname, const QType qtype,
                         vector<DNSRecord>& ret,
                         unsigned int depth, const string& prefix, set<GetBestNSAnswer>& beenthere, Context& context, StopAtDelegation* stopAtDelegation,
                         map<DNSName, vector<ComboAddress>>* fallBack)
{
  auto luaconfsLocal = g_luaconfs.getLocal();

  LOG(prefix << qname << ": Cache consultations done, have " << (unsigned int)nameservers.size() << " NS to contact");

  if (nameserversBlockedByRPZ(luaconfsLocal->dfe, nameservers)) {
    /* RPZ hit */
    if (d_pdl && d_pdl->policyHitEventFilter(d_requestor, qname, qtype, d_queryReceivedOverTCP, d_appliedPolicy, d_policyTags, d_discardedPolicies)) {
      /* reset to no match */
      d_appliedPolicy = DNSFilterEngine::Policy();
    }
    else {
      throw PolicyHitException();
    }
  }

  LOG(endl);

  unsigned int addressQueriesForNS = 0;
  for (;;) { // we may get more specific nameservers
    auto rnameservers = shuffleInSpeedOrder(qname, nameservers, prefix);

    // We allow s_maxnsaddressqperq (default 10) queries with empty responses when resolving NS names.
    // If a zone publishes many (more than s_maxnsaddressqperq) NS records, we allow less.
    // This is to "punish" zones that publish many non-resolving NS names.
    // We always allow 5 NS name resolving attempts with empty results.
    unsigned int nsLimit = s_maxnsaddressqperq;
    if (rnameservers.size() > nsLimit) {
      int newLimit = static_cast<int>(nsLimit - (rnameservers.size() - nsLimit));
      nsLimit = std::max(5, newLimit);
    }

    for (auto tns = rnameservers.cbegin();; ++tns) {
      if (addressQueriesForNS >= nsLimit) {
        throw ImmediateServFailException(std::to_string(nsLimit) + " (adjusted max-ns-address-qperq) or more queries with empty results for NS addresses sent resolving " + qname.toLogString());
      }
      if (tns == rnameservers.cend()) {
        LOG(prefix << qname << ": Failed to resolve via any of the " << (unsigned int)rnameservers.size() << " offered NS at level '" << auth << "'" << endl);
        if (s_addExtendedResolutionDNSErrors) {
          context.extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::NoReachableAuthority), "delegation " + auth.toLogString()};
        }
        if (!auth.isRoot() && flawedNSSet) {
          LOG(prefix << qname << ": Ageing nameservers for level '" << auth << "', next query might succeed" << endl);
          if (g_recCache->doAgeCache(d_now.tv_sec, auth, QType::NS, 10)) {
            t_Counters.at(rec::Counter::nsSetInvalidations)++;
          }
        }
        return -1;
      }

      bool cacheOnly = false;
      // this line needs to identify the 'self-resolving' behaviour
      if (qname == tns->first && (qtype.getCode() == QType::A || qtype.getCode() == QType::AAAA)) {
        /* we might have a glue entry in cache so let's try this NS
           but only if we have enough in the cache to know how to reach it */
        LOG(prefix << qname << ": Using NS to resolve itself, but only using what we have in cache (" << (1 + tns - rnameservers.cbegin()) << "/" << rnameservers.size() << ")" << endl);
        cacheOnly = true;
      }

      typedef vector<ComboAddress> remoteIPs_t;
      remoteIPs_t remoteIPs;
      remoteIPs_t::iterator remoteIP;
      bool pierceDontQuery = false;
      bool sendRDQuery = false;
      std::optional<Netmask> ednsmask;
      LWResult lwr;
      const bool wasForwarded = tns->first.empty() && (!nameservers[tns->first].first.empty());
      int rcode = RCode::NoError;
      bool gotNewServers = false;

      if (tns->first.empty() && !wasForwarded) {
        static ComboAddress const s_oobRemote("255.255.255.255");
        LOG(prefix << qname << ": Domain is out-of-band" << endl);
        /* setting state to indeterminate since validation is disabled for local auth zone,
           and Insecure would be misleading. */
        context.state = vState::Indeterminate;
        d_wasOutOfBand = doOOBResolve(qname, qtype, lwr.d_records, depth, prefix, lwr.d_rcode);
        lwr.d_tcbit = false;
        lwr.d_aabit = true;

        /* we have received an answer, are we done ? */
        bool done = processAnswer(depth, prefix, lwr, qname, qtype, auth, false, ednsmask, sendRDQuery, nameservers, ret, luaconfsLocal->dfe, &gotNewServers, &rcode, context.state, s_oobRemote, false);
        if (done) {
          return rcode;
        }
        if (gotNewServers) {
          if (stopAtDelegation != nullptr && *stopAtDelegation == Stop) {
            *stopAtDelegation = Stopped;
            return rcode;
          }
          break;
        }
      }
      else {
        if (fallBack != nullptr) {
          if (auto iter = fallBack->find(tns->first); iter != fallBack->end()) {
            remoteIPs = iter->second;
          }
        }
        if (remoteIPs.empty()) {
          remoteIPs = retrieveAddressesForNS(prefix, qname, tns, depth, beenthere, rnameservers, nameservers, sendRDQuery, pierceDontQuery, flawedNSSet, cacheOnly, addressQueriesForNS);
        }

        if (remoteIPs.empty()) {
          LOG(prefix << qname << ": Failed to get IP for NS " << tns->first << ", trying next if available" << endl);
          flawedNSSet = true;
          continue;
        }
        bool hitPolicy{false};
        LOG(prefix << qname << ": Resolved '" << auth << "' NS " << tns->first << " to: ");
        for (remoteIP = remoteIPs.begin(); remoteIP != remoteIPs.end(); ++remoteIP) {
          if (remoteIP != remoteIPs.begin()) {
            LOG(", ");
          }
          LOG(remoteIP->toString());
          if (nameserverIPBlockedByRPZ(luaconfsLocal->dfe, *remoteIP)) {
            hitPolicy = true;
          }
        }
        LOG(endl);
        if (hitPolicy) { // implies d_wantsRPZ
          /* RPZ hit */
          if (d_pdl && d_pdl->policyHitEventFilter(d_requestor, qname, qtype, d_queryReceivedOverTCP, d_appliedPolicy, d_policyTags, d_discardedPolicies)) {
            /* reset to no match */
            d_appliedPolicy = DNSFilterEngine::Policy();
          }
          else {
            throw PolicyHitException();
          }
        }

        for (remoteIP = remoteIPs.begin(); remoteIP != remoteIPs.end(); ++remoteIP) {
          LOG(prefix << qname << ": Trying IP " << remoteIP->toStringWithPort() << ", asking '" << qname << "|" << qtype << "'" << endl);

          if (throttledOrBlocked(prefix, *remoteIP, qname, qtype, pierceDontQuery)) {
            // As d_throttledqueries might be increased, check the max-qperq condition
            checkMaxQperQ(qname);
            continue;
          }

          bool truncated = false;
          bool spoofed = false;
          bool gotAnswer = false;
          bool doDoT = false;

          if (doDoTtoAuth(tns->first)) {
            remoteIP->setPort(853);
            doDoT = true;
          }
          if (SyncRes::s_dot_to_port_853 && remoteIP->getPort() == 853) {
            doDoT = true;
          }
          bool forceTCP = doDoT || (qtype == QType::ANY && s_outAnyToTcp);

          if (!doDoT && s_max_busy_dot_probes > 0) {
            submitTryDotTask(*remoteIP, auth, tns->first, d_now.tv_sec);
          }
          bool overTCP = false;
          if (!forceTCP) {
            gotAnswer = doResolveAtThisIP(prefix, qname, qtype, lwr, ednsmask, auth, sendRDQuery, wasForwarded,
                                          tns->first, *remoteIP, false, false, truncated, spoofed, context.extendedError);
          }
          if (spoofed) {
            LOG(prefix << qname << ": potentially spoofed, retrying over TCP" << endl);
          }
          if (forceTCP || (spoofed || (gotAnswer && truncated))) {
            /* retry, over TCP this time */
            gotAnswer = doResolveAtThisIP(prefix, qname, qtype, lwr, ednsmask, auth, sendRDQuery, wasForwarded,
                                          tns->first, *remoteIP, true, doDoT, truncated, spoofed, context.extendedError);
            overTCP = true;
          }

          if (!gotAnswer) {
            if (doDoT && s_max_busy_dot_probes > 0) {
              // This is quite pessimistic...
              updateDoTStatus(*remoteIP, DoTStatus::Bad, d_now.tv_sec + dotFailWait);
            }
            continue;
          }

          LOG(prefix << qname << ": Got " << (unsigned int)lwr.d_records.size() << " answers from " << tns->first << " (" << remoteIP->toString() << "), rcode=" << lwr.d_rcode << " (" << RCode::to_s(lwr.d_rcode) << "), aa=" << lwr.d_aabit << ", in " << lwr.d_usec / 1000 << "ms" << endl);

          if (doDoT && s_max_busy_dot_probes > 0) {
            updateDoTStatus(*remoteIP, DoTStatus::Good, d_now.tv_sec + dotSuccessWait);
          }
          /*  // for you IPv6 fanatics :-)
              if(remoteIP->sin4.sin_family==AF_INET6)
              lwr.d_usec/=3;
          */
          //        cout<<"ms: "<<lwr.d_usec/1000.0<<", "<<g_avgLatency/1000.0<<'\n';

          s_nsSpeeds.lock()->find_or_enter(tns->first.empty() ? DNSName(remoteIP->toStringWithPort()) : tns->first, d_now).submit(*remoteIP, static_cast<int>(lwr.d_usec), d_now);

          /* we have received an answer, are we done ? */
          bool done = processAnswer(depth, prefix, lwr, qname, qtype, auth, wasForwarded, ednsmask, sendRDQuery, nameservers, ret, luaconfsLocal->dfe, &gotNewServers, &rcode, context.state, *remoteIP, overTCP);
          if (done) {
            return rcode;
          }
          if (gotNewServers) {
            if (stopAtDelegation != nullptr && *stopAtDelegation == Stop) {
              *stopAtDelegation = Stopped;
              return rcode;
            }
            break;
          }
          /* was lame */
          if (!shouldNotThrottle(&tns->first, &*remoteIP)) {
            doThrottle(d_now.tv_sec, *remoteIP, qname, qtype, 60, 100, Throttle::Reason::Lame);
          }
        }

        if (gotNewServers) {
          break;
        }

        if (remoteIP == remoteIPs.cend()) { // we tried all IP addresses, none worked
          continue;
        }
      }
    }
  }
  return -1;
}

void SyncRes::setQuerySource(const Netmask& netmask)
{
  if (!netmask.empty()) {
    d_outgoingECSNetwork = netmask;
  }
  else {
    d_outgoingECSNetwork = std::nullopt;
  }
}

void SyncRes::setQuerySource(const ComboAddress& requestor, const boost::optional<const EDNSSubnetOpts&>& incomingECS)
{
  d_requestor = requestor;

  if (incomingECS && incomingECS->getSourcePrefixLength() > 0) {
    d_cacheRemote = incomingECS->getSource().getMaskedNetwork();
    uint8_t bits = std::min(incomingECS->getSourcePrefixLength(), (incomingECS->getSource().isIPv4() ? s_ecsipv4limit : s_ecsipv6limit));
    ComboAddress trunc = incomingECS->getSource().getNetwork();
    trunc.truncate(bits);
    d_outgoingECSNetwork = std::optional<Netmask>(Netmask(trunc, bits));
  }
  else {
    d_cacheRemote = d_requestor;
    if (!incomingECS && s_ednslocalsubnets.match(d_requestor)) {
      ComboAddress trunc = d_requestor;
      uint8_t bits = d_requestor.isIPv4() ? 32 : 128;
      bits = std::min(bits, (trunc.isIPv4() ? s_ecsipv4limit : s_ecsipv6limit));
      trunc.truncate(bits);
      d_outgoingECSNetwork = std::optional<Netmask>(Netmask(trunc, bits));
    }
    else if (s_ecsScopeZero.getSourcePrefixLength() > 0) {
      /* RFC7871 says we MUST NOT send any ECS if the source scope is 0.
         But using an empty ECS in that case would mean inserting
         a non ECS-specific entry into the cache, preventing any further
         ECS-specific query to be sent.
         So instead we use the trick described in section 7.1.2:
         "The subsequent Recursive Resolver query to the Authoritative Nameserver
         will then either not include an ECS option or MAY optionally include
         its own address information, which is what the Authoritative
         Nameserver will almost certainly use to generate any Tailored
         Response in lieu of an option.  This allows the answer to be handled
         by the same caching mechanism as other queries, with an explicit
         indicator of the applicable scope.  Subsequent Stub Resolver queries
         for /0 can then be answered from this cached response.
      */
      d_outgoingECSNetwork = std::optional<Netmask>(s_ecsScopeZero.getSource().getMaskedNetwork());
      d_cacheRemote = s_ecsScopeZero.getSource().getNetwork();
    }
    else {
      // ECS disabled because no scope-zero address could be derived.
      d_outgoingECSNetwork = std::nullopt;
    }
  }
}

std::optional<Netmask> SyncRes::getEDNSSubnetMask(const DNSName& name, const ComboAddress& rem)
{
  if (d_outgoingECSNetwork && (s_ednsdomains.check(name) || s_ednsremotesubnets.match(rem))) {
    return d_outgoingECSNetwork;
  }
  return std::nullopt;
}

void SyncRes::parseEDNSSubnetAllowlist(const std::string& alist)
{
  vector<string> parts;
  stringtok(parts, alist, ",; ");
  for (const auto& allow : parts) {
    try {
      s_ednsremotesubnets.addMask(Netmask(allow));
    }
    catch (...) {
      s_ednsdomains.add(DNSName(allow));
    }
  }
}

void SyncRes::parseEDNSSubnetAddFor(const std::string& subnetlist)
{
  vector<string> parts;
  stringtok(parts, subnetlist, ",; ");
  for (const auto& allow : parts) {
    s_ednslocalsubnets.addMask(allow);
  }
}

// used by PowerDNSLua - note that this neglects to add the packet count & statistics back to pdns_recursor.cc
int directResolve(const DNSName& qname, const QType qtype, const QClass qclass, vector<DNSRecord>& ret, const shared_ptr<RecursorLua4>& pdl, Logr::log_t log)
{
  return directResolve(qname, qtype, qclass, ret, pdl, SyncRes::s_qnameminimization, log);
}

int directResolve(const DNSName& qname, const QType qtype, const QClass qclass, vector<DNSRecord>& ret, const shared_ptr<RecursorLua4>& pdl, bool qnamemin, Logr::log_t slog)
{
  auto log = slog->withValues("qname", Logging::Loggable(qname), "qtype", Logging::Loggable(qtype));

  struct timeval now{};
  gettimeofday(&now, nullptr);

  SyncRes resolver(now);
  resolver.setQNameMinimization(qnamemin);
  if (pdl) {
    resolver.setLuaEngine(pdl);
  }

  int res = -1;
  const std::string msg = "Exception while resolving";
  try {
    res = resolver.beginResolve(qname, qtype, qclass, ret, 0);
  }
  catch (const PDNSException& e) {
    log->error(Logr::Warning, e.reason, msg, "exception", Logging::Loggable("PDNSException"));
    ret.clear();
  }
  catch (const ImmediateServFailException& e) {
    log->error(Logr::Warning, e.reason, msg, "exception", Logging::Loggable("ImmediateServFailException"));
    ret.clear();
  }
  catch (const PolicyHitException& e) {
    log->info(Logr::Warning, msg, "exception", Logging::Loggable("PolicyHitException"));
    ret.clear();
  }
  catch (const std::exception& e) {
    log->error(Logr::Warning, e.what(), msg, "exception", Logging::Loggable("std::exception"));
    ret.clear();
  }
  catch (...) {
    log->info(Logr::Warning, msg);
    ret.clear();
  }

  return res;
}

int SyncRes::getRootNS(struct timeval now, asyncresolve_t asyncCallback, unsigned int depth, Logr::log_t log)
{
  if (::arg()["hint-file"] == "no-refresh") {
    return 0;
  }
  SyncRes resolver(now);
  resolver.d_prefix = "[getRootNS]";
  resolver.setDoEDNS0(true);
  resolver.setUpdatingRootNS();
  resolver.setDoDNSSEC(g_dnssecmode != DNSSECMode::Off);
  resolver.setDNSSECValidationRequested(g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate);
  resolver.setAsyncCallback(std::move(asyncCallback));
  resolver.setRefreshAlmostExpired(true);

  const string msg = "Failed to update . records";
  vector<DNSRecord> ret;
  int res = -1;
  try {
    res = resolver.beginResolve(g_rootdnsname, QType::NS, 1, ret, depth + 1);
    if (g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate) {
      auto state = resolver.getValidationState();
      if (vStateIsBogus(state)) {
        throw PDNSException("Got Bogus validation result for .|NS");
      }
    }
  }
  catch (const PDNSException& e) {
    log->error(Logr::Error, e.reason, msg, "exception", Logging::Loggable("PDNSException"));
  }
  catch (const ImmediateServFailException& e) {
    log->error(Logr::Error, e.reason, msg, "exception", Logging::Loggable("ImmediateServFailException"));
  }
  catch (const PolicyHitException& policyHit) {
    log->info(Logr::Error, msg, "exception", Logging::Loggable("PolicyHitException"),
              "policyName", Logging::Loggable(resolver.d_appliedPolicy.getName()));
    ret.clear();
  }
  catch (const std::exception& e) {
    log->error(Logr::Error, e.what(), msg, "exception", Logging::Loggable("std::exception"));
  }
  catch (...) {
    log->info(Logr::Error, msg);
  }

  if (res == 0) {
    log->info(Logr::Debug, "Refreshed . records");
  }
  else {
    log->info(Logr::Warning, msg, "rcode", Logging::Loggable(res));
  }
  return res;
}

bool SyncRes::answerIsNOData(uint16_t requestedType, int rcode, const std::vector<DNSRecord>& records)
{
  if (rcode != RCode::NoError) {
    return false;
  }

  // NOLINTNEXTLINE(readability-use-anyofallof)
  for (const auto& rec : records) {
    if (rec.d_place == DNSResourceRecord::ANSWER && rec.d_type == requestedType) {
      /* we have a record, of the right type, in the right section */
      return false;
    }
  }
  return true;
#if 0
  // This code should be equivalent to the code above, clang-tidy prefers any_of()
  // I have doubts if that is easier to read
  return !std::any_of(records.begin(), records.end(), [=](const DNSRecord& rec) {
    return rec.d_place == DNSResourceRecord::ANSWER && rec.d_type == requestedType;
  });
#endif
}
