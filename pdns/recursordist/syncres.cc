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
#ifdef HAVE_CONFIG_H
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
#include "dnsseckeeper.hh"
#include "validate-recursor.hh"
#include "rec-taskqueue.hh"

rec::GlobalCounters g_Counters;
thread_local rec::TCounters t_Counters(g_Counters);

template <class T>
class fails_t : public boost::noncopyable
{
public:
  typedef uint64_t counter_t;
  struct value_t
  {
    value_t(const T& a) :
      key(a) {}
    T key;
    mutable counter_t value{0};
    time_t last{0};
  };

  typedef multi_index_container<value_t,
                                indexed_by<
                                  ordered_unique<tag<T>, member<value_t, T, &value_t::key>>,
                                  ordered_non_unique<tag<time_t>, member<value_t, time_t, &value_t::last>>>>
    cont_t;

  cont_t getMapCopy() const
  {
    return d_cont;
  }

  counter_t value(const T& t) const
  {
    auto i = d_cont.find(t);

    if (i == d_cont.end()) {
      return 0;
    }
    return i->value;
  }

  counter_t incr(const T& key, const struct timeval& now)
  {
    auto i = d_cont.insert(key).first;

    if (i->value < std::numeric_limits<counter_t>::max()) {
      i->value++;
    }
    auto& ind = d_cont.template get<T>();
    time_t tm = now.tv_sec;
    ind.modify(i, [tm](value_t& val) { val.last = tm; });
    return i->value;
  }

  void clear(const T& a)
  {
    d_cont.erase(a);
  }

  void clear()
  {
    d_cont.clear();
  }

  size_t size() const
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

/** Class that implements a decaying EWMA.
    This class keeps an exponentially weighted moving average which, additionally, decays over time.
    The decaying is only done on get.
*/

//! This represents a number of decaying Ewmas, used to store performance per nameserver-name.
/** Modelled to work mostly like the underlying DecayingEwma */
class DecayingEwmaCollection
{
private:
  struct DecayingEwma
  {
  public:
    void submit(int arg, const struct timeval& last, const struct timeval& now)
    {
      d_last = arg;
      auto val = static_cast<float>(arg);
      if (d_val == 0) {
        d_val = val;
      }
      else {
        auto diff = makeFloat(last - now);
        auto factor = expf(diff) / 2.0f; // might be '0.5', or 0.0001
        d_val = (1.0f - factor) * val + factor * d_val;
      }
    }

    float get(float factor)
    {
      return d_val *= factor;
    }

    float peek(void) const
    {
      return d_val;
    }

    int last(void) const
    {
      return d_last;
    }

    float d_val{0};
    int d_last{0};
  };

public:
  DecayingEwmaCollection(const DNSName& name, const struct timeval ts = {0, 0}) :
    d_name(name), d_lastget(ts)
  {
  }

  void submit(const ComboAddress& remote, int usecs, const struct timeval& now) const
  {
    d_collection[remote].submit(usecs, d_lastget, now);
  }

  float getFactor(const struct timeval& now) const
  {
    float diff = makeFloat(d_lastget - now);
    return expf(diff / 60.0f); // is 1.0 or less
  }

  bool stale(time_t limit) const
  {
    return limit > d_lastget.tv_sec;
  }

  void purge(const std::map<ComboAddress, float>& keep) const
  {
    for (auto iter = d_collection.begin(); iter != d_collection.end();) {
      if (keep.find(iter->first) != keep.end()) {
        ++iter;
      }
      else {
        iter = d_collection.erase(iter);
      }
    }
  }

  // d_collection is the modifyable part of the record, we index on DNSName and timeval, and DNSName never changes
  mutable std::map<ComboAddress, DecayingEwma> d_collection;
  const DNSName d_name;
  struct timeval d_lastget;
};

class nsspeeds_t : public multi_index_container<DecayingEwmaCollection,
                                                indexed_by<
                                                  hashed_unique<tag<DNSName>, member<DecayingEwmaCollection, const DNSName, &DecayingEwmaCollection::d_name>>,
                                                  ordered_non_unique<tag<timeval>, member<DecayingEwmaCollection, timeval, &DecayingEwmaCollection::d_lastget>>>>
{
public:
  const auto& find_or_enter(const DNSName& name, const struct timeval& now)
  {
    const auto it = insert(DecayingEwmaCollection{name, now}).first;
    return *it;
  }

  const auto& find_or_enter(const DNSName& name)
  {
    const auto it = insert(DecayingEwmaCollection{name}).first;
    return *it;
  }

  float fastest(const DNSName& name, const struct timeval& now)
  {
    auto& ind = get<DNSName>();
    auto it = insert(DecayingEwmaCollection{name, now}).first;
    if (it->d_collection.empty()) {
      return 0;
    }
    // This could happen if find(DNSName) entered an entry; it's used only by test code
    if (it->d_lastget.tv_sec == 0 && it->d_lastget.tv_usec == 0) {
      ind.modify(it, [&](DecayingEwmaCollection& d) { d.d_lastget = now; });
    }

    float ret = std::numeric_limits<float>::max();
    const float factor = it->getFactor(now);
    for (auto& entry : it->d_collection) {
      if (float tmp = entry.second.get(factor); tmp < ret) {
        ret = tmp;
      }
    }
    ind.modify(it, [&](DecayingEwmaCollection& d) { d.d_lastget = now; });
    return ret;
  }
};

static LockGuarded<nsspeeds_t> s_nsSpeeds;

template <class Thing>
class Throttle : public boost::noncopyable
{
public:
  struct entry_t
  {
    entry_t(const Thing& thing_, time_t ttd_, unsigned int count_) :
      thing(thing_), ttd(ttd_), count(count_)
    {
    }
    Thing thing;
    time_t ttd;
    mutable unsigned int count;
  };
  typedef multi_index_container<entry_t,
                                indexed_by<
                                  ordered_unique<tag<Thing>, member<entry_t, Thing, &entry_t::thing>>,
                                  ordered_non_unique<tag<time_t>, member<entry_t, time_t, &entry_t::ttd>>>>
    cont_t;

  bool shouldThrottle(time_t now, const Thing& t)
  {
    auto i = d_cont.find(t);
    if (i == d_cont.end()) {
      return false;
    }
    if (now > i->ttd || i->count == 0) {
      d_cont.erase(i);
      return false;
    }
    i->count--;

    return true; // still listed, still blocked
  }

  void throttle(time_t now, const Thing& t, time_t ttl, unsigned int count)
  {
    auto i = d_cont.find(t);
    time_t ttd = now + ttl;
    if (i == d_cont.end()) {
      d_cont.emplace(t, ttd, count);
    }
    else if (ttd > i->ttd || count > i->count) {
      ttd = std::max(i->ttd, ttd);
      count = std::max(i->count, count);
      auto& ind = d_cont.template get<Thing>();
      ind.modify(i, [ttd, count](entry_t& e) { e.ttd = ttd; e.count = count; });
    }
  }

  size_t size() const
  {
    return d_cont.size();
  }

  cont_t getThrottleMap() const
  {
    return d_cont;
  }

  void clear()
  {
    d_cont.clear();
  }

  void prune(time_t now)
  {
    auto& ind = d_cont.template get<time_t>();
    ind.erase(ind.begin(), ind.upper_bound(now));
  }

private:
  cont_t d_cont;
};

static LockGuarded<Throttle<std::tuple<ComboAddress, DNSName, QType>>> s_throttle;

struct SavedParentEntry
{
  SavedParentEntry(const DNSName& name, map<DNSName, vector<ComboAddress>>&& nsAddresses, time_t ttd) :
    d_domain(name), d_nsAddresses(nsAddresses), d_ttd(ttd)
  {
  }
  DNSName d_domain;
  map<DNSName, vector<ComboAddress>> d_nsAddresses;
  time_t d_ttd;
  mutable uint64_t d_count{0};
};

typedef multi_index_container<
  SavedParentEntry,
  indexed_by<ordered_unique<tag<DNSName>, member<SavedParentEntry, DNSName, &SavedParentEntry::d_domain>>,
             ordered_non_unique<tag<time_t>, member<SavedParentEntry, time_t, &SavedParentEntry::d_ttd>>>>
  SavedParentNSSetBase;

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
    auto it = find(name);
    if (it != end()) {
      ++(*it).d_count;
    }
  }
  SavedParentNSSet getMapCopy() const
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
const std::unordered_set<QType> SyncRes::s_redirectionQTypes = {QType::CNAME, QType::DNAME};
static LockGuarded<fails_t<ComboAddress>> s_fails;
static LockGuarded<fails_t<DNSName>> s_nonresolving;

struct DoTStatus
{
  DoTStatus(const ComboAddress& ip, const DNSName& auth, time_t ttd) :
    d_address(ip), d_auth(auth), d_ttd(ttd)
  {
  }
  enum Status : uint8_t
  {
    Unknown,
    Busy,
    Bad,
    Good
  };
  const ComboAddress d_address;
  const DNSName d_auth;
  time_t d_ttd;
  mutable uint64_t d_count{0};
  mutable Status d_status{Unknown};
  std::string toString() const
  {
    const std::array<std::string, 4> n{"Unknown", "Busy", "Bad", "Good"};
    unsigned int v = static_cast<unsigned int>(d_status);
    return v >= n.size() ? "?" : n[v];
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

static const time_t dotFailWait = 24 * 3600;
static const time_t dotSuccessWait = 3 * 24 * 3600;
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
unsigned int SyncRes::s_nonresolvingnsmaxfails;
unsigned int SyncRes::s_nonresolvingnsthrottletime;
unsigned int SyncRes::s_ecscachelimitttl;
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
SyncRes::HardenNXD SyncRes::s_hardenNXD;
unsigned int SyncRes::s_refresh_ttlperc;
unsigned int SyncRes::s_locked_ttlperc;
int SyncRes::s_tcp_fast_open;
bool SyncRes::s_tcp_fast_open_connect;
bool SyncRes::s_dot_to_port_853;
int SyncRes::s_event_trace_enabled;
bool SyncRes::s_save_parent_ns_set;
unsigned int SyncRes::s_max_busy_dot_probes;
bool SyncRes::s_addExtendedResolutionDNSErrors;

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
    ret = {prefix, d_fixednow, &g_log};
  }
  else if (d_lm == Store) {
    ret = {prefix, d_fixednow, &d_trace};
  }
  return ret;
}

// A helper function to print a double with specific printf format.
// Not using boost::format since it is not thread safe while calling
// into locale handling code according to tsan.
// This allocates a string, but that's nothing compared to what
// boost::format is doing and may even be optimized away anyway.
static inline std::string fmtfloat(double f)
{
  char buf[20];
  int ret = snprintf(buf, sizeof(buf), "%0.2f", f);
  if (ret < 0 || ret >= static_cast<int>(sizeof(buf))) {
    return "?";
  }
  return std::string(buf, ret);
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
    if (res == 0 && addRecords.size() > 0) {
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
    NegCache::NegCacheEntry ne;
    bool inNegCache = g_negCache->get(qname, qtype, d_now, ne, false);
    if (!inNegCache) {
      // There are a few cases where an answer is neither stored in the record cache nor in the neg cache.
      // An example is a SOA-less NODATA response. Rate limiting will kick in if those tasks are pushed too often.
      // We might want to fix these cases (and always either store positive or negative) some day.
      pushResolveTask(qname, qtype, d_now.tv_sec, d_now.tv_sec + 60);
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
  const auto it = luaLocal->allowAdditionalQTypes.find(qtype);
  if (it == luaLocal->allowAdditionalQTypes.end()) {
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

  auto mode = it->second.second;
  for (const auto& targettype : it->second.first) {
    for (const auto& addname : addnames) {
      std::vector<DNSRecord> records;
      bool inserted = uniqueCalls.emplace(addname, targettype).second;
      if (inserted) {
        resolveAdditionals(addname, targettype, mode, records, depth, additionalsNotInCache);
      }
      if (!records.empty()) {
        for (auto r = records.begin(); r != records.end();) {
          QType covered = QType::ENT;
          if (r->d_type == QType::RRSIG) {
            if (auto rsig = getRR<RRSIGRecordContent>(*r); rsig != nullptr) {
              covered = rsig->d_type;
            }
          }
          if (uniqueResults.count(std::tuple(r->d_name, QType(r->d_type), covered)) > 0) {
            // A bit expensive for vectors, but they are small
            r = records.erase(r);
          }
          else {
            ++r;
          }
        }
        for (const auto& r : records) {
          additionals.push_back(r);
          QType covered = QType::ENT;
          if (r.d_type == QType::RRSIG) {
            if (auto rsig = getRR<RRSIGRecordContent>(r); rsig != nullptr) {
              covered = rsig->d_type;
            }
          }
          uniqueResults.emplace(r.d_name, r.d_type, covered);
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
  d_eventTrace.add(RecEventTrace::SyncRes);
  t_Counters.at(rec::Counter::syncresqueries)++;
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

  if (qclass == QClass::ANY)
    qclass = QClass::IN;
  else if (qclass != QClass::IN)
    return -1;

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
  d_eventTrace.add(RecEventTrace::SyncRes, res, false);
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
  static const DNSName arpa("1.0.0.127.in-addr.arpa."), ip6_arpa("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."),
    localhost("localhost."), versionbind("version.bind."), idserver("id.server."), versionpdns("version.pdns."), trustanchorserver("trustanchor.server."),
    negativetrustanchorserver("negativetrustanchor.server.");

  bool handled = false;
  vector<pair<QType::typeenum, string>> answers;

  if ((qname == arpa || qname == ip6_arpa) && qclass == QClass::IN) {
    handled = true;
    if (qtype == QType::PTR || qtype == QType::ANY)
      answers.emplace_back(QType::PTR, "localhost.");
  }

  if (qname.isPartOf(localhost) && qclass == QClass::IN) {
    handled = true;
    if (qtype == QType::A || qtype == QType::ANY)
      answers.emplace_back(QType::A, "127.0.0.1");
    if (qtype == QType::AAAA || qtype == QType::ANY)
      answers.emplace_back(QType::AAAA, "::1");
  }

  if ((qname == versionbind || qname == idserver || qname == versionpdns) && qclass == QClass::CHAOS) {
    handled = true;
    if (qtype == QType::TXT || qtype == QType::ANY) {
      if (qname == versionbind || qname == versionpdns)
        answers.emplace_back(QType::TXT, "\"" + ::arg()["version-string"] + "\"");
      else if (s_serverID != "disabled")
        answers.emplace_back(QType::TXT, "\"" + s_serverID + "\"");
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
        if (negAnchor.second.length())
          ans << " " << negAnchor.second;
        ans << "\"";
        answers.emplace_back(QType::TXT, ans.str());
      }
    }
  }

  if (handled && !answers.empty()) {
    ret.clear();
    d_wasOutOfBand = true;

    DNSRecord dr;
    dr.d_name = qname;
    dr.d_place = DNSResourceRecord::ANSWER;
    dr.d_class = qclass;
    dr.d_ttl = 86400;
    for (const auto& ans : answers) {
      dr.d_type = ans.first;
      dr.setContent(DNSRecordContent::mastermake(ans.first, qclass, ans.second));
      ret.push_back(dr);
    }
  }

  return handled;
}

//! This is the 'out of band resolver', in other words, the authoritative server
void SyncRes::AuthDomain::addSOA(std::vector<DNSRecord>& records) const
{
  SyncRes::AuthDomain::records_t::const_iterator ziter = d_records.find(std::make_tuple(getName(), QType::SOA));
  if (ziter != d_records.end()) {
    DNSRecord dr = *ziter;
    dr.d_place = DNSResourceRecord::AUTHORITY;
    records.push_back(dr);
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
  std::stringstream s;
  s << indent << "DNSName = " << d_name << std::endl;
  s << indent << "rdForward = " << d_rdForward << std::endl;
  s << indent << "Records {" << std::endl;
  auto recordContentIndentation = indent;
  recordContentIndentation += indentLevel;
  recordContentIndentation += indentLevel;
  for (const auto& record : d_records) {
    s << indent << indentLevel << "Record `" << record.d_name << "` {" << std::endl;
    s << record.print(recordContentIndentation);
    s << indent << indentLevel << "}" << std::endl;
  }
  s << indent << "}" << std::endl;
  s << indent << "Servers {" << std::endl;
  for (const auto& server : d_servers) {
    s << indent << indentLevel << server.toString() << std::endl;
  }
  s << indent << "}" << std::endl;
  return s.str();
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
      DNSRecord dr = *ziter;
      dr.d_place = DNSResourceRecord::AUTHORITY;
      records.push_back(dr);
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
    range = d_records.equal_range(std::make_tuple(g_wildcarddnsname + wcarddomain));
    if (range.first == range.second)
      continue;

    for (ziter = range.first; ziter != range.second; ++ziter) {
      DNSRecord dr = *ziter;
      // if we hit a CNAME, just answer that - rest of recursor will do the needful & follow
      if (dr.d_type == qtype || qtype == QType::ANY || dr.d_type == QType::CNAME) {
        dr.d_name = qname;
        dr.d_place = DNSResourceRecord::ANSWER;
        records.push_back(dr);
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
    range = d_records.equal_range(std::make_tuple(nsdomain, QType::NS));
    if (range.first == range.second)
      continue;

    for (ziter = range.first; ziter != range.second; ++ziter) {
      DNSRecord dr = *ziter;
      dr.d_place = DNSResourceRecord::AUTHORITY;
      records.push_back(dr);
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
  domainmap_t::const_iterator iter = getBestAuthZone(&authdomain);
  if (iter == t_sstorage.domainmap->end() || !iter->second.isAuth()) {
    LOG(prefix << qname << ": Auth storage has no zone for this query!" << endl);
    return false;
  }

  LOG(prefix << qname << ": Auth storage has data, zone='" << authdomain << "'" << endl);
  return doOOBResolve(iter->second, qname, qtype, ret, res);
}

bool SyncRes::isRecursiveForwardOrAuth(const DNSName& qname) const
{
  DNSName authname(qname);
  domainmap_t::const_iterator iter = getBestAuthZone(&authname);
  return iter != t_sstorage.domainmap->end() && (iter->second.isAuth() || iter->second.shouldRecurse());
}

bool SyncRes::isForwardOrAuth(const DNSName& qname) const
{
  DNSName authname(qname);
  domainmap_t::const_iterator iter = getBestAuthZone(&authname);
  return iter != t_sstorage.domainmap->end();
}

const char* isoDateTimeMillis(const struct timeval& tv, char* buf, size_t sz)
{
  const std::string s_timestampFormat = "%Y-%m-%dT%T";
  struct tm tm;
  size_t len = strftime(buf, sz, s_timestampFormat.c_str(), localtime_r(&tv.tv_sec, &tm));
  if (len == 0) {
    int ret = snprintf(buf, sz, "%lld", static_cast<long long>(tv.tv_sec));
    if (ret < 0 || static_cast<size_t>(ret) >= sz) {
      if (sz > 0) {
        buf[0] = '\0';
      }
      return buf;
    }
    len = ret;
  }

  if (sz > len + 4) {
    snprintf(buf + len, sz - len, ".%03ld", static_cast<long>(tv.tv_usec) / 1000);
  }
  return buf;
}

static const char* timestamp(time_t t, char* buf, size_t sz)
{
  const std::string s_timestampFormat = "%Y-%m-%dT%T";
  struct tm tm;
  size_t len = strftime(buf, sz, s_timestampFormat.c_str(), localtime_r(&t, &tm));
  if (len == 0) {
    int ret = snprintf(buf, sz, "%lld", static_cast<long long>(t));
    if (ret < 0 || static_cast<size_t>(ret) >= sz) {
      if (sz > 0) {
        buf[0] = '\0';
      }
    }
  }
  return buf;
}

struct ednsstatus_t : public multi_index_container<SyncRes::EDNSStatus,
                                                   indexed_by<
                                                     ordered_unique<tag<ComboAddress>, member<SyncRes::EDNSStatus, ComboAddress, &SyncRes::EDNSStatus::address>>,
                                                     ordered_non_unique<tag<time_t>, member<SyncRes::EDNSStatus, time_t, &SyncRes::EDNSStatus::ttd>>>>
{
  // Get a copy
  ednsstatus_t getMap() const
  {
    return *this;
  }

  void setMode(index<ComboAddress>::type& ind, iterator it, SyncRes::EDNSStatus::EDNSMode mode, time_t ts)
  {
    if (it->mode != mode || it->ttd == 0) {
      ind.modify(it, [=](SyncRes::EDNSStatus& s) { s.mode = mode; s.ttd = ts + Expire; });
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
  const auto& it = lock->find(server);
  if (it == lock->end()) {
    return EDNSStatus::EDNSOK;
  }
  return it->mode;
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

uint64_t SyncRes::doEDNSDump(int fd)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if (!fp) {
    close(newfd);
    return 0;
  }
  uint64_t count = 0;

  fprintf(fp.get(), "; edns dump follows\n; ip\tstatus\tttd\n");
  const auto copy = s_ednsstatus.lock()->getMap();
  for (const auto& eds : copy) {
    count++;
    char tmp[26];
    fprintf(fp.get(), "%s\t%s\t%s\n", eds.address.toString().c_str(), eds.toString().c_str(), timestamp(eds.ttd, tmp, sizeof(tmp)));
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

void SyncRes::submitNSSpeed(const DNSName& server, const ComboAddress& ca, uint32_t usec, const struct timeval& now)
{
  auto lock = s_nsSpeeds.lock();
  lock->find_or_enter(server, now).submit(ca, usec, now);
}

void SyncRes::clearNSSpeeds()
{
  s_nsSpeeds.lock()->clear();
}

float SyncRes::getNSSpeed(const DNSName& server, const ComboAddress& ca)
{
  auto lock = s_nsSpeeds.lock();
  return lock->find_or_enter(server).d_collection[ca].peek();
}

uint64_t SyncRes::doDumpNSSpeeds(int fd)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if (!fp) {
    close(newfd);
    return 0;
  }

  fprintf(fp.get(), "; nsspeed dump follows\n; nsname\ttimestamp\t[ip/decaying-ms/last-ms...]\n");
  uint64_t count = 0;

  // Create a copy to avoid holding the lock while doing I/O
  for (const auto& i : *s_nsSpeeds.lock()) {
    count++;

    // an <empty> can appear hear in case of authoritative (hosted) zones
    char tmp[26];
    fprintf(fp.get(), "%s\t%s\t", i.d_name.toLogString().c_str(), isoDateTimeMillis(i.d_lastget, tmp, sizeof(tmp)));
    bool first = true;
    for (const auto& j : i.d_collection) {
      fprintf(fp.get(), "%s%s/%.3f/%.3f", first ? "" : "\t", j.first.toStringWithPortExcept(53).c_str(), j.second.peek() / 1000.0f, j.second.last() / 1000.0f);
      first = false;
    }
    fprintf(fp.get(), "\n");
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
  return s_throttle.lock()->shouldThrottle(now, std::make_tuple(server, target, qtype));
}

bool SyncRes::isThrottled(time_t now, const ComboAddress& server)
{
  return s_throttle.lock()->shouldThrottle(now, std::make_tuple(server, g_rootdnsname, 0));
}

void SyncRes::doThrottle(time_t now, const ComboAddress& server, time_t duration, unsigned int tries)
{
  s_throttle.lock()->throttle(now, std::make_tuple(server, g_rootdnsname, 0), duration, tries);
}

void SyncRes::doThrottle(time_t now, const ComboAddress& server, const DNSName& name, QType qtype, time_t duration, unsigned int tries)
{
  s_throttle.lock()->throttle(now, std::make_tuple(server, name, qtype), duration, tries);
}

uint64_t SyncRes::doDumpThrottleMap(int fd)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if (!fp) {
    close(newfd);
    return 0;
  }
  fprintf(fp.get(), "; throttle map dump follows\n");
  fprintf(fp.get(), "; remote IP\tqname\tqtype\tcount\tttd\n");
  uint64_t count = 0;

  // Get a copy to avoid holding the lock while doing I/O
  const auto throttleMap = s_throttle.lock()->getThrottleMap();
  for (const auto& i : throttleMap) {
    count++;
    char tmp[26];
    // remote IP, dns name, qtype, count, ttd
    fprintf(fp.get(), "%s\t%s\t%s\t%u\t%s\n", std::get<0>(i.thing).toString().c_str(), std::get<1>(i.thing).toLogString().c_str(), std::get<2>(i.thing).toString().c_str(), i.count, timestamp(i.ttd, tmp, sizeof(tmp)));
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

uint64_t SyncRes::doDumpFailedServers(int fd)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if (!fp) {
    close(newfd);
    return 0;
  }
  fprintf(fp.get(), "; failed servers dump follows\n");
  fprintf(fp.get(), "; remote IP\tcount\ttimestamp\n");
  uint64_t count = 0;

  // We get a copy, so the I/O does not need to happen while holding the lock
  for (const auto& i : s_fails.lock()->getMapCopy()) {
    count++;
    char tmp[26];
    fprintf(fp.get(), "%s\t%" PRIu64 "\t%s\n", i.key.toString().c_str(), i.value, timestamp(i.last, tmp, sizeof(tmp)));
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

uint64_t SyncRes::doDumpNonResolvingNS(int fd)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if (!fp) {
    close(newfd);
    return 0;
  }
  fprintf(fp.get(), "; non-resolving nameserver dump follows\n");
  fprintf(fp.get(), "; name\tcount\ttimestamp\n");
  uint64_t count = 0;

  // We get a copy, so the I/O does not need to happen while holding the lock
  for (const auto& i : s_nonresolving.lock()->getMapCopy()) {
    count++;
    char tmp[26];
    fprintf(fp.get(), "%s\t%" PRIu64 "\t%s\n", i.key.toString().c_str(), i.value, timestamp(i.last, tmp, sizeof(tmp)));
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

uint64_t SyncRes::doDumpSavedParentNSSets(int fd)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if (!fp) {
    close(newfd);
    return 0;
  }
  fprintf(fp.get(), "; dump of saved parent nameserver sets succesfully used follows\n");
  fprintf(fp.get(), "; total entries: %zu\n", s_savedParentNSSet.lock()->size());
  fprintf(fp.get(), "; domain\tsuccess\tttd\n");
  uint64_t count = 0;

  // We get a copy, so the I/O does not need to happen while holding the lock
  for (const auto& i : s_savedParentNSSet.lock()->getMapCopy()) {
    if (i.d_count == 0) {
      continue;
    }
    count++;
    char tmp[26];
    fprintf(fp.get(), "%s\t%" PRIu64 "\t%s\n", i.d_domain.toString().c_str(), i.d_count, timestamp(i.d_ttd, tmp, sizeof(tmp)));
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

uint64_t SyncRes::doDumpDoTProbeMap(int fd)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if (!fp) {
    close(newfd);
    return 0;
  }
  fprintf(fp.get(), "; DoT probing map follows\n");
  fprintf(fp.get(), "; ip\tdomain\tcount\tstatus\tttd\n");
  uint64_t count = 0;

  // We get a copy, so the I/O does not need to happen while holding the lock
  DoTMap copy;
  {
    copy = *s_dotMap.lock();
  }
  fprintf(fp.get(), "; %" PRIu64 " Busy entries\n", copy.d_numBusy);
  for (const auto& i : copy.d_map) {
    count++;
    char tmp[26];
    fprintf(fp.get(), "%s\t%s\t%" PRIu64 "\t%s\t%s\n", i.d_address.toString().c_str(), i.d_auth.toString().c_str(), i.d_count, i.toString().c_str(), timestamp(i.d_ttd, tmp, sizeof(tmp)));
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

LWResult::Result SyncRes::asyncresolveWrapper(const ComboAddress& ip, bool ednsMANDATORY, const DNSName& domain, const DNSName& auth, int type, bool doTCP, bool sendRDQuery, struct timeval* now, boost::optional<Netmask>& srcmask, LWResult* res, bool* chained, const DNSName& nsName) const
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
    auto ednsstatus = lock->find(ip); // does this include port? YES
    if (ednsstatus != lock->end()) {
      if (ednsstatus->ttd && ednsstatus->ttd < d_now.tv_sec) {
        lock->erase(ednsstatus);
      }
      else {
        mode = ednsstatus->mode;
      }
    }
  }

  int EDNSLevel = 0;
  auto luaconfsLocal = g_luaconfs.getLocal();
  ResolveContext ctx;
  ctx.d_initialRequestId = d_initialRequestId;
  ctx.d_nsName = nsName;
#ifdef HAVE_FSTRM
  ctx.d_auth = auth;
#endif

  LWResult::Result ret;

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
      ret = d_asyncResolve(ip, sendQname, type, doTCP, sendRDQuery, EDNSLevel, now, srcmask, ctx, res, chained);
    }
    else {
      ret = asyncresolve(ip, sendQname, type, doTCP, sendRDQuery, EDNSLevel, now, srcmask, ctx, d_outgoingProtobufServers, d_frameStreamServers, luaconfsLocal->outgoingProtobufExportConfig.exportTypes, res, chained);
    }

    if (ret == LWResult::Result::PermanentError || ret == LWResult::Result::OSLimitError || ret == LWResult::Result::Spoofed) {
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
      if (res->d_validpacket && !res->d_haveEDNS && res->d_rcode == RCode::FormErr) {
        mode = EDNSStatus::NOEDNS;
        auto ednsstatus = lock->insert(ip).first;
        auto& ind = lock->get<ComboAddress>();
        lock->setMode(ind, ednsstatus, mode, d_now.tv_sec);
        // This is the only path that re-iterates the loop
        continue;
      }
      else if (!res->d_haveEDNS) {
        auto ednsstatus = lock->insert(ip).first;
        auto& ind = lock->get<ComboAddress>();
        lock->setMode(ind, ednsstatus, EDNSStatus::EDNSIGNORANT, d_now.tv_sec);
      }
      else {
        // New status is EDNSOK
        lock->erase(ip);
      }
    }

    break;
  }
  return ret;
}

/* The parameters from rfc9156. */
/* maximum number of QNAME minimisation iterations */
static const unsigned int s_max_minimise_count = 10;
/* number of queries that should only have one label appended */
static const unsigned int s_minimise_one_lab = 4;

static unsigned int qmStepLen(unsigned int labels, unsigned int qnamelen, unsigned int i)
{
  unsigned int step;

  if (i < s_minimise_one_lab) {
    step = 1;
  }
  else if (i < s_max_minimise_count) {
    step = std::max(1U, (qnamelen - labels) / (10 - i));
  }
  else {
    step = qnamelen - labels;
  }
  unsigned int targetlen = std::min(labels + step, qnamelen);
  return targetlen;
}

int SyncRes::doResolve(const DNSName& qname, const QType qtype, vector<DNSRecord>& ret, unsigned int depth, set<GetBestNSAnswer>& beenthere, Context& context)
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
  int res = doResolveNoQNameMinimization(qname, qtype, retq, depth, beenthere, context, &fromCache, nullptr);
  setCacheOnly(old);
  if (fromCache) {
    LOG(prefix << qname << ": Step0 Found in cache" << endl);
    if (d_appliedPolicy.d_type != DNSFilterEngine::PolicyType::None && (d_appliedPolicy.d_kind == DNSFilterEngine::PolicyKind::NXDOMAIN || d_appliedPolicy.d_kind == DNSFilterEngine::PolicyKind::NODATA)) {
      ret.clear();
    }
    ret.insert(ret.end(), retq.begin(), retq.end());

    return res;
  }
  LOG(prefix << qname << ": Step0 Not cached" << endl);

  const unsigned int qnamelen = qname.countLabels();

  DNSName fwdomain(qname);
  const bool forwarded = getBestAuthZone(&fwdomain) != t_sstorage.domainmap->end();
  if (forwarded) {
    LOG(prefix << qname << ": Step0 qname is in a forwarded domain " << fwdomain << endl);
  }

  for (unsigned int i = 0; i <= qnamelen;) {

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
      getBestNSFromCache(nsdomain, qtype, bestns, &flawedNSSet, depth, prefix, beenthereIgnored, boost::make_optional(forwarded, fwdomain));
      if (forwarded) {
        break;
      }
    }

    if (bestns.size() == 0) {
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
        LOG(prefix << qname << ": Step3 Final resolve: " << RCode::to_s(res) << "/" << ret.size() << endl);
        return res;
      }

      // If we have seen this child during resolution already; just skip it. We tried to QM it already or otherwise broken.
      bool skipStep4 = false;
      for (const auto& visitedNS : beenthere) {
        if (visitedNS.qname == child) {
          skipStep4 = true;
          break;
        }
      }
      if (skipStep4) {
        LOG(prefix << ": Step4 Being skipped as visited this child name already" << endl);
        continue;
      }

      // Step 4
      LOG(prefix << qname << ": Step4 Resolve A for child " << child << endl);
      bool oldFollowCNAME = d_followCNAME;
      d_followCNAME = false;
      retq.resize(0);
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
            context.extendedError = oldEDE;
          }
        }

        LOG(prefix << qname << ": Step5 End resolve: " << RCode::to_s(res) << "/" << ret.size() << endl);
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
int SyncRes::doResolveNoQNameMinimization(const DNSName& qname, const QType qtype, vector<DNSRecord>& ret, unsigned int depth, set<GetBestNSAnswer>& beenthere, Context& context, bool* fromCache, StopAtDelegation* stopAtDelegation)
{
  context.extendedError.reset();
  auto prefix = getPrefix(depth);

  LOG(prefix << qname << ": Wants " << (d_doDNSSEC ? "" : "NO ") << "DNSSEC processing, " << (d_requireAuthData ? "" : "NO ") << "auth data required by query for " << qtype << endl);

  if (s_maxdepth > 0) {
    auto bound = getAdjustedRecursionBound();
    if (depth > bound) {
      string msg = "More than " + std::to_string(bound) + " (adjusted max-recursion-depth) levels of recursion needed while resolving " + qname.toLogString();
      LOG(prefix << qname << ": " << msg << endl);
      throw ImmediateServFailException(msg);
    }
  }

  int res = 0;

  const int iterations = !d_refresh && MemRecursorCache::s_maxServedStaleExtensions > 0 ? 2 : 1;
  for (int loop = 0; loop < iterations; loop++) {

    d_serveStale = loop == 1;

    // This is a difficult way of expressing "this is a normal query", i.e. not getRootNS.
    if (!(d_updatingRootNS && qtype.getCode() == QType::NS && qname.isRoot())) {
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
      if (qtype != QType::DS && doCNAMECacheCheck(qname, qtype, ret, depth, prefix, res, context, wasAuthZone, wasForwardRecurse)) { // will reroute us if needed
        d_wasOutOfBand = wasAuthZone;
        // Here we have an issue. If we were prevented from going out to the network (cache-only was set, possibly because we
        // are in QM Step0) we might have a CNAME but not the corresponding target.
        // It means that we will sometimes go to the next steps when we are in fact done, but that's fine since
        // we will get the records from the cache, resulting in a small overhead.
        // This might be a real problem if we had a RPZ hit, though, because we do not want the processing to continue, since
        // RPZ rules will not be evaluated anymore (we already matched).
        const bool stoppedByPolicyHit = d_appliedPolicy.wasHit();

        if (fromCache && (!d_cacheonly || stoppedByPolicyHit)) {
          *fromCache = true;
        }
        /* Apply Post filtering policies */

        if (d_wantsRPZ && !stoppedByPolicyHit) {
          auto luaLocal = g_luaconfs.getLocal();
          if (luaLocal->dfe.getPostPolicy(ret, d_discardedPolicies, d_appliedPolicy)) {
            mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
            bool done = false;
            handlePolicyHit(prefix, qname, qtype, ret, done, res, depth);
            if (done && fromCache) {
              *fromCache = true;
            }
          }
        }
        return res;
      }

      if (doCacheCheck(qname, authname, wasForwardedOrAuthZone, wasAuthZone, wasForwardRecurse, qtype, ret, depth, prefix, res, context)) {
        // we done
        d_wasOutOfBand = wasAuthZone;
        if (fromCache) {
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
      if (qtype == QType::DS && doCNAMECacheCheck(qname, qtype, ret, depth, prefix, res, context, wasAuthZone, wasForwardRecurse)) { // will reroute us if needed
        d_wasOutOfBand = wasAuthZone;
        // Here we have an issue. If we were prevented from going out to the network (cache-only was set, possibly because we
        // are in QM Step0) we might have a CNAME but not the corresponding target.
        // It means that we will sometimes go to the next steps when we are in fact done, but that's fine since
        // we will get the records from the cache, resulting in a small overhead.
        // This might be a real problem if we had a RPZ hit, though, because we do not want the processing to continue, since
        // RPZ rules will not be evaluated anymore (we already matched).
        const bool stoppedByPolicyHit = d_appliedPolicy.wasHit();

        if (fromCache && (!d_cacheonly || stoppedByPolicyHit)) {
          *fromCache = true;
        }
        /* Apply Post filtering policies */

        if (d_wantsRPZ && !stoppedByPolicyHit) {
          auto luaLocal = g_luaconfs.getLocal();
          if (luaLocal->dfe.getPostPolicy(ret, d_discardedPolicies, d_appliedPolicy)) {
            mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
            bool done = false;
            handlePolicyHit(prefix, qname, qtype, ret, done, res, depth);
            if (done && fromCache) {
              *fromCache = true;
            }
          }
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
    if (qtype == QType::DS)
      subdomain.chopOff();

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
        if (domainData != lock->end() && domainData->d_nsAddresses.size() > 0) {
          nsset.clear();
          // Build the nsset arg and fallBack data for the fallback doResolveAt() attempt
          // Take a copy to be able to release the lock, NsSet is actually a map, go figure
          for (const auto& ns : domainData->d_nsAddresses) {
            nsset.emplace(ns.first, pair(std::vector<ComboAddress>(), false));
            fallBack.emplace(ns.first, ns.second);
          }
        }
      }
      if (fallBack.size() > 0) {
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

    if (!res) {
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
  bool operator()(const ComboAddress& a, const ComboAddress& b) const
  {
    return d_speeds[a] < d_speeds[b];
  }
  std::map<ComboAddress, float>& d_speeds;
};

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
  d_followCNAME = true;

  MemRecursorCache::Flags flags = MemRecursorCache::None;
  if (d_serveStale) {
    flags |= MemRecursorCache::ServeStale;
  }
  try {
    // First look for both A and AAAA in the cache
    res_t cset;
    if (s_doIPv4 && g_recCache->get(d_now.tv_sec, qname, QType::A, flags, &cset, d_cacheRemote, d_routingTag) > 0) {
      for (const auto& i : cset) {
        if (auto rec = getRR<ARecordContent>(i)) {
          ret.push_back(rec->getCA(53));
        }
      }
    }
    if (s_doIPv6 && g_recCache->get(d_now.tv_sec, qname, QType::AAAA, flags, &cset, d_cacheRemote, d_routingTag) > 0) {
      for (const auto& i : cset) {
        if (auto rec = getRR<AAAARecordContent>(i)) {
          seenV6 = true;
          ret.push_back(rec->getCA(53));
        }
      }
    }
    if (ret.empty()) {
      // Neither A nor AAAA in the cache...
      Context newContext1;
      cset.clear();
      // Go out to get A's
      if (s_doIPv4 && doResolve(qname, QType::A, cset, depth + 1, beenthere, newContext1) == 0) { // this consults cache, OR goes out
        for (auto const& i : cset) {
          if (i.d_type == QType::A) {
            if (auto rec = getRR<ARecordContent>(i)) {
              ret.push_back(rec->getCA(53));
            }
          }
        }
      }
      if (s_doIPv6) { // s_doIPv6 **IMPLIES** pdns::isQueryLocalAddressFamilyEnabled(AF_INET6) returned true
        if (ret.empty()) {
          // We only go out immediately to find IPv6 records if we did not find any IPv4 ones.
          Context newContext2;
          if (doResolve(qname, QType::AAAA, cset, depth + 1, beenthere, newContext2) == 0) { // this consults cache, OR goes out
            for (const auto& i : cset) {
              if (i.d_type == QType::AAAA) {
                if (auto rec = getRR<AAAARecordContent>(i)) {
                  seenV6 = true;
                  ret.push_back(rec->getCA(53));
                }
              }
            }
          }
        }
        else {
          // We have some IPv4 records, consult the cache, we might have encountered some IPv6 glue
          cset.clear();
          if (g_recCache->get(d_now.tv_sec, qname, QType::AAAA, flags, &cset, d_cacheRemote, d_routingTag) > 0) {
            for (const auto& i : cset) {
              if (auto rec = getRR<AAAARecordContent>(i)) {
                seenV6 = true;
                ret.push_back(rec->getCA(53));
              }
            }
          }
        }
      }
    }
    if (s_doIPv6 && !seenV6 && !cacheOnly) {
      // No IPv6 records in cache, check negcache and submit async task if negache does not have the data
      // so that the next time the cache or the negcache will have data
      NegCache::NegCacheEntry ne;
      bool inNegCache = g_negCache->get(qname, QType::AAAA, d_now, ne, false);
      if (!inNegCache) {
        pushResolveTask(qname, QType::AAAA, d_now.tv_sec, d_now.tv_sec + 60);
      }
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
  /* we need to remove from the nsSpeeds collection the existing IPs
     for this nameserver that are no longer in the set, even if there
     is only one or none at all in the current set.
  */
  map<ComboAddress, float> speeds;
  {
    auto lock = s_nsSpeeds.lock();
    auto& collection = lock->find_or_enter(qname, d_now);
    float factor = collection.getFactor(d_now);
    for (const auto& val : ret) {
      speeds[val] = collection.d_collection[val].get(factor);
    }
    collection.purge(speeds);
  }

  if (ret.size() > 1) {
    shuffle(ret.begin(), ret.end(), pdns::dns_random_engine());
    speedOrderCA so(speeds);
    stable_sort(ret.begin(), ret.end(), so);
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

  return ret;
}

void SyncRes::getBestNSFromCache(const DNSName& qname, const QType qtype, vector<DNSRecord>& bestns, bool* flawedNSSet, unsigned int depth, const string& prefix, set<GetBestNSAnswer>& beenthere, const boost::optional<DNSName>& cutOffDomain)
{
  DNSName subdomain(qname);
  bestns.clear();
  bool brokeloop;
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
    vector<DNSRecord> ns;
    *flawedNSSet = false;

    if (g_recCache->get(d_now.tv_sec, subdomain, QType::NS, flags, &ns, d_cacheRemote, d_routingTag) > 0) {
      if (s_maxnsperresolve > 0 && ns.size() > s_maxnsperresolve) {
        vector<DNSRecord> selected;
        selected.reserve(s_maxnsperresolve);
        std::sample(ns.cbegin(), ns.cend(), std::back_inserter(selected), s_maxnsperresolve, pdns::dns_random_engine());
        ns = selected;
      }
      bestns.reserve(ns.size());

      for (auto k = ns.cbegin(); k != ns.cend(); ++k) {
        if (k->d_ttl > (unsigned int)d_now.tv_sec) {
          vector<DNSRecord> aset;
          QType nsqt{QType::ADDR};
          if (s_doIPv4 && !s_doIPv6) {
            nsqt = QType::A;
          }
          else if (!s_doIPv4 && s_doIPv6) {
            nsqt = QType::AAAA;
          }

          const DNSRecord& dr = *k;
          auto nrr = getRR<NSRecordContent>(dr);
          if (nrr && (!nrr->getNS().isPartOf(subdomain) || g_recCache->get(d_now.tv_sec, nrr->getNS(), nsqt, flags, doLog() ? &aset : 0, d_cacheRemote, d_routingTag) > 0)) {
            bestns.push_back(dr);
            LOG(prefix << qname << ": NS (with ip, or non-glue) in cache for '" << subdomain << "' -> '" << nrr->getNS() << "'");
            LOG(", within bailiwick: " << nrr->getNS().isPartOf(subdomain));
            if (!aset.empty()) {
              LOG(", in cache, ttl=" << (unsigned int)(((time_t)aset.begin()->d_ttl - d_now.tv_sec)) << endl);
            }
            else {
              LOG(", not in cache / did not look at cache" << endl);
            }
          }
          else {
            *flawedNSSet = true;
            LOG(prefix << qname << ": NS in cache for '" << subdomain << "', but needs glue (" << nrr->getNS() << ") which we miss or is expired" << endl);
          }
        }
      }

      if (!bestns.empty()) {
        GetBestNSAnswer answer;
        answer.qname = qname;
        answer.qtype = qtype.getCode();
        for (const auto& dr : bestns) {
          if (auto nsContent = getRR<NSRecordContent>(dr)) {
            answer.bestns.emplace(dr.d_name, nsContent->getNS());
          }
        }

        auto insertionPair = beenthere.insert(std::move(answer));
        if (!insertionPair.second) {
          brokeloop = true;
          LOG(prefix << qname << ": We have NS in cache for '" << subdomain << "' but part of LOOP (already seen " << answer.qname << ")! Trying less specific NS" << endl);
          ;
          if (doLog())
            for (set<GetBestNSAnswer>::const_iterator j = beenthere.begin(); j != beenthere.end(); ++j) {
              bool neo = (j == insertionPair.first);
              LOG(prefix << qname << ": Beenthere" << (neo ? "*" : "") << ": " << j->qname << "|" << DNSRecordContent::NumberToType(j->qtype) << " (" << (unsigned int)j->bestns.size() << ")" << endl);
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

SyncRes::domainmap_t::const_iterator SyncRes::getBestAuthZone(DNSName* qname) const
{
  if (t_sstorage.domainmap->empty()) {
    return t_sstorage.domainmap->end();
  }

  SyncRes::domainmap_t::const_iterator ret;
  do {
    ret = t_sstorage.domainmap->find(*qname);
    if (ret != t_sstorage.domainmap->end())
      break;
  } while (qname->chopOff());
  return ret;
}

/** doesn't actually do the work, leaves that to getBestNSFromCache */
DNSName SyncRes::getBestNSNamesFromCache(const DNSName& qname, const QType qtype, NsSet& nsset, bool* flawedNSSet, unsigned int depth, const string& prefix, set<GetBestNSAnswer>& beenthere)
{
  DNSName authOrForwDomain(qname);

  domainmap_t::const_iterator iter = getBestAuthZone(&authOrForwDomain);
  // We have an auth, forwarder of forwarder-recurse
  if (iter != t_sstorage.domainmap->end()) {
    if (iter->second.isAuth()) {
      // this gets picked up in doResolveAt, the empty DNSName, combined with the
      // empty vector means 'we are auth for this zone'
      nsset.insert({DNSName(), {{}, false}});
      return authOrForwDomain;
    }
    else {
      if (iter->second.shouldRecurse()) {
        // Again, picked up in doResolveAt. An empty DNSName, combined with a
        // non-empty vector of ComboAddresses means 'this is a forwarded domain'
        // This is actually picked up in retrieveAddressesForNS called from doResolveAt.
        nsset.insert({DNSName(), {iter->second.d_servers, true}});
        return authOrForwDomain;
      }
    }
  }

  // We might have a (non-recursive) forwarder, but maybe the cache already contains
  // a better NS
  vector<DNSRecord> bestns;
  DNSName nsFromCacheDomain(g_rootdnsname);
  getBestNSFromCache(qname, qtype, bestns, flawedNSSet, depth, prefix, beenthere);

  // Pick up the auth domain
  for (const auto& k : bestns) {
    const auto nsContent = getRR<NSRecordContent>(k);
    if (nsContent) {
      nsFromCacheDomain = k.d_name;
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
    else {
      if (doLog()) {
        LOG(prefix << qname << ": Using NS from cache" << endl);
      }
    }
  }
  for (auto k = bestns.cbegin(); k != bestns.cend(); ++k) {
    // The actual resolver code will not even look at the ComboAddress or bool
    const auto nsContent = getRR<NSRecordContent>(*k);
    if (nsContent) {
      nsset.insert({nsContent->getNS(), {{}, false}});
    }
  }
  return nsFromCacheDomain;
}

void SyncRes::updateValidationStatusInCache(const DNSName& qname, const QType qt, bool aa, vState newState) const
{
  if (qt == QType::ANY || qt == QType::ADDR) {
    // not doing that
    return;
  }

  if (vStateIsBogus(newState)) {
    g_recCache->updateValidationStatus(d_now.tv_sec, qname, qt, d_cacheRemote, d_routingTag, aa, newState, s_maxbogusttl + d_now.tv_sec);
  }
  else {
    g_recCache->updateValidationStatus(d_now.tv_sec, qname, qt, d_cacheRemote, d_routingTag, aa, newState, boost::none);
  }
}

static bool scanForCNAMELoop(const DNSName& name, const vector<DNSRecord>& records)
{
  for (const auto& record : records) {
    if (record.d_type == QType::CNAME && record.d_place == DNSResourceRecord::ANSWER) {
      if (name == record.d_name) {
        return true;
      }
    }
  }
  return false;
}

bool SyncRes::doCNAMECacheCheck(const DNSName& qname, const QType qtype, vector<DNSRecord>& ret, unsigned int depth, const string& prefix, int& res, Context& context, bool wasAuthZone, bool wasForwardRecurse)
{
  // Even if s_maxdepth is zero, we want to have this check
  auto bound = std::max(40U, getAdjustedRecursionBound());
  // Bounds were > 9 and > 15 originally, now they are derived from s_maxdepth (default 40)
  // Apply more strict bound if we see throttling
  if ((depth >= bound / 4 && d_outqueries > 10 && d_throttledqueries > 5) || depth > bound * 3 / 8) {
    LOG(prefix << qname << ": Recursing (CNAME or other indirection) too deep, depth=" << depth << endl);
    res = RCode::ServFail;
    return true;
  }

  vector<DNSRecord> cset;
  vector<std::shared_ptr<const RRSIGRecordContent>> signatures;
  vector<std::shared_ptr<DNSRecord>> authorityRecs;
  bool wasAuth;
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
  if (g_recCache->get(d_now.tv_sec, qname, QType::CNAME, flags, &cset, d_cacheRemote, d_routingTag, d_doDNSSEC ? &signatures : nullptr, d_doDNSSEC ? &authorityRecs : nullptr, &d_wasVariable, &context.state, &wasAuth, &authZone, &d_fromAuthIP) > 0) {
    foundName = qname;
    foundQT = QType::CNAME;
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
      if (g_recCache->get(d_now.tv_sec, dnameName, QType::DNAME, flags, &cset, d_cacheRemote, d_routingTag, d_doDNSSEC ? &signatures : nullptr, d_doDNSSEC ? &authorityRecs : nullptr, &d_wasVariable, &context.state, &wasAuth, &authZone, &d_fromAuthIP) > 0) {
        foundName = dnameName;
        foundQT = QType::DNAME;
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

        vState recordState = getValidationStatus(foundName, !signatures.empty(), qtype == QType::DS, depth, prefix);
        if (recordState == vState::Secure) {
          LOG(prefix << qname << ": Got vState::Indeterminate state from the " << foundQT.toString() << " cache, validating.." << endl);
          context.state = SyncRes::validateRecordsWithSigs(depth, prefix, qname, qtype, foundName, foundQT, cset, signatures);
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

      DNSRecord dr = record;
      dr.d_ttl -= d_now.tv_sec;
      dr.d_ttl = std::min(dr.d_ttl, capTTL);
      const uint32_t ttl = dr.d_ttl;
      ret.reserve(ret.size() + 2 + signatures.size() + authorityRecs.size());
      ret.push_back(dr);

      for (const auto& signature : signatures) {
        DNSRecord sigdr;
        sigdr.d_type = QType::RRSIG;
        sigdr.d_name = foundName;
        sigdr.d_ttl = ttl;
        sigdr.setContent(signature);
        sigdr.d_place = DNSResourceRecord::ANSWER;
        sigdr.d_class = QClass::IN;
        ret.push_back(sigdr);
      }

      for (const auto& rec : authorityRecs) {
        DNSRecord authDR(*rec);
        authDR.d_ttl = ttl;
        ret.push_back(authDR);
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
          dr.d_type = QType::CNAME;
          dr.d_name = targetPrefix + foundName;
          newTarget = targetPrefix + dnameSuffix;
          dr.setContent(std::make_shared<CNAMERecordContent>(CNAMERecordContent(newTarget)));
          ret.push_back(dr);
        }
        catch (const std::exception& e) {
          // We should probably catch an std::range_error here and set the rcode to YXDOMAIN (RFC 6672, section 2.2)
          // But this is consistent with processRecords
          throw ImmediateServFailException("Unable to perform DNAME substitution(DNAME owner: '" + foundName.toLogString() + "', DNAME target: '" + dnameSuffix.toLogString() + "', substituted name: '" + targetPrefix.toLogString() + "." + dnameSuffix.toLogString() + "' : " + e.what());
        }

        LOG(prefix << qname << ": Synthesized " << dr.d_name << "|CNAME " << newTarget << endl);
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
        throw ImmediateServFailException(msg);
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

      // Check to see if we already have seen the new target as a previous target
      if (scanForCNAMELoop(newTarget, ret)) {
        string msg = "got a CNAME referral (from cache) that causes a loop";
        LOG(prefix << qname << ": Status=" << msg << endl);
        throw ImmediateServFailException(msg);
      }

      set<GetBestNSAnswer> beenthere;
      Context cnameContext;
      // Be aware that going out on the network might be disabled (cache-only), for example because we are in QM Step0,
      // so you can't trust that a real lookup will have been made.
      res = doResolve(newTarget, qtype, ret, depth + 1, beenthere, cnameContext);
      LOG(prefix << qname << ": Updating validation state for response to " << qname << " from " << context.state << " with the state from the DNAME/CNAME quest: " << cnameContext.state << endl);
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
  vector<shared_ptr<const RRSIGRecordContent>> signatures;
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

static bool negativeCacheEntryHasSOA(const NegCache::NegCacheEntry& ne)
{
  return !ne.authoritySOA.records.empty();
}

static void reapRecordsForValidation(std::map<QType, CacheEntry>& entries, const vector<DNSRecord>& records)
{
  for (const auto& rec : records) {
    entries[rec.d_type].records.push_back(rec);
  }
}

static void reapSignaturesForValidation(std::map<QType, CacheEntry>& entries, const vector<std::shared_ptr<const RRSIGRecordContent>>& signatures)
{
  for (const auto& sig : signatures) {
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

void SyncRes::computeNegCacheValidationStatus(const NegCache::NegCacheEntry& ne, const DNSName& qname, const QType qtype, const int res, vState& state, unsigned int depth, const string& prefix)
{
  tcache_t tcache;
  reapRecordsFromNegCacheEntryForValidation(tcache, ne.authoritySOA.records);
  reapRecordsFromNegCacheEntryForValidation(tcache, ne.authoritySOA.signatures);
  reapRecordsFromNegCacheEntryForValidation(tcache, ne.DNSSECRecords.records);
  reapRecordsFromNegCacheEntryForValidation(tcache, ne.DNSSECRecords.signatures);

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
    vState neValidationState = ne.d_validationState;
    dState expectedState = res == RCode::NXDomain ? dState::NXDOMAIN : dState::NXQTYPE;
    dState denialState = getDenialValidationState(ne, expectedState, false, prefix);
    updateDenialValidationState(qname, neValidationState, ne.d_name, state, denialState, expectedState, qtype == QType::DS, depth, prefix);
  }
  if (state != vState::Indeterminate) {
    /* validation succeeded, let's update the cache entry so we don't have to validate again */
    boost::optional<time_t> capTTD = boost::none;
    if (vStateIsBogus(state)) {
      capTTD = d_now.tv_sec + s_maxbogusttl;
    }
    g_negCache->updateValidationStatus(ne.d_name, ne.d_qtype, state, capTTD);
  }
}

bool SyncRes::doCacheCheck(const DNSName& qname, const DNSName& authname, bool wasForwardedOrAuthZone, bool wasAuthZone, bool wasForwardRecurse, QType qtype, vector<DNSRecord>& ret, unsigned int depth, const string& prefix, int& res, Context& context)
{
  bool giveNegative = false;

  // sqname and sqtype are used contain 'higher' names if we have them (e.g. powerdns.com|SOA when we find a negative entry for doesnotexist.powerdns.com|A)
  DNSName sqname(qname);
  QType sqt(qtype);
  uint32_t sttl = 0;
  //  cout<<"Lookup for '"<<qname<<"|"<<qtype.toString()<<"' -> "<<getLastLabel(qname)<<endl;
  vState cachedState;
  NegCache::NegCacheEntry ne;

  if (s_rootNXTrust && g_negCache->getRootNXTrust(qname, d_now, ne, d_serveStale, d_refresh) && ne.d_auth.isRoot() && !(wasForwardedOrAuthZone && !authname.isRoot())) { // when forwarding, the root may only neg-cache if it was forwarded to.
    sttl = ne.d_ttd - d_now.tv_sec;
    LOG(prefix << qname << ": Entire name '" << qname << "', is negatively cached via '" << ne.d_auth << "' & '" << ne.d_name << "' for another " << sttl << " seconds" << endl);
    res = RCode::NXDomain;
    giveNegative = true;
    cachedState = ne.d_validationState;
    if (s_addExtendedResolutionDNSErrors) {
      context.extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::Synthesized), "Result synthesized by root-nx-trust"};
    }
  }
  else if (g_negCache->get(qname, qtype, d_now, ne, false, d_serveStale, d_refresh)) {
    /* If we are looking for a DS, discard NXD if auth == qname
       and ask for a specific denial instead */
    if (qtype != QType::DS || ne.d_qtype.getCode() || ne.d_auth != qname || g_negCache->get(qname, qtype, d_now, ne, true, d_serveStale, d_refresh)) {
      /* Careful! If the client is asking for a DS that does not exist, we need to provide the SOA along with the NSEC(3) proof
         and we might not have it if we picked up the proof from a delegation, in which case we need to keep on to do the actual DS
         query. */
      if (qtype == QType::DS && ne.d_qtype.getCode() && !d_externalDSQuery.empty() && qname == d_externalDSQuery && !negativeCacheEntryHasSOA(ne)) {
        giveNegative = false;
      }
      else {
        res = RCode::NXDomain;
        sttl = ne.d_ttd - d_now.tv_sec;
        giveNegative = true;
        cachedState = ne.d_validationState;
        if (ne.d_qtype.getCode()) {
          LOG(prefix << qname << "|" << qtype << ": Is negatively cached via '" << ne.d_auth << "' for another " << sttl << " seconds" << endl);
          res = RCode::NoError;
          if (s_addExtendedResolutionDNSErrors) {
            context.extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::Synthesized), "Result from negative cache"};
          }
        }
        else {
          LOG(prefix << qname << ": Entire name '" << qname << "' is negatively cached via '" << ne.d_auth << "' for another " << sttl << " seconds" << endl);
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
      if (g_negCache->get(negCacheName, QType::ENT, d_now, ne, true, d_serveStale, d_refresh)) {
        if (ne.d_validationState == vState::Indeterminate && validationEnabled()) {
          // LOG(prefix << negCacheName <<  " negatively cached and vState::Indeterminate, trying to validate NXDOMAIN" << endl);
          // ...
          // And get the updated ne struct
          // t_sstorage.negcache.get(negCacheName, QType(0), d_now, ne, true);
        }
        if ((s_hardenNXD == HardenNXD::Yes && !vStateIsBogus(ne.d_validationState)) || ne.d_validationState == vState::Secure) {
          res = RCode::NXDomain;
          sttl = ne.d_ttd - d_now.tv_sec;
          giveNegative = true;
          cachedState = ne.d_validationState;
          LOG(prefix << qname << ": Name '" << negCacheName << "' and below, is negatively cached via '" << ne.d_auth << "' for another " << sttl << " seconds" << endl);
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
      computeNegCacheValidationStatus(ne, qname, qtype, res, context.state, depth, prefix);

      if (context.state != cachedState && vStateIsBogus(context.state)) {
        sttl = std::min(sttl, s_maxbogusttl);
      }
    }

    // Transplant SOA to the returned packet
    addTTLModifiedRecords(ne.authoritySOA.records, sttl, ret);
    if (d_doDNSSEC) {
      addTTLModifiedRecords(ne.authoritySOA.signatures, sttl, ret);
      addTTLModifiedRecords(ne.DNSSECRecords.records, sttl, ret);
      addTTLModifiedRecords(ne.DNSSECRecords.signatures, sttl, ret);
    }

    LOG(prefix << qname << ": Updating validation state with negative cache content for " << qname << " to " << context.state << endl);
    return true;
  }

  vector<DNSRecord> cset;
  bool found = false, expired = false;
  vector<std::shared_ptr<const RRSIGRecordContent>> signatures;
  vector<std::shared_ptr<DNSRecord>> authorityRecs;
  uint32_t ttl = 0;
  uint32_t capTTL = std::numeric_limits<uint32_t>::max();
  bool wasCachedAuth;
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
  if (g_recCache->get(d_now.tv_sec, sqname, sqt, flags, &cset, d_cacheRemote, d_routingTag, d_doDNSSEC ? &signatures : nullptr, d_doDNSSEC ? &authorityRecs : nullptr, &d_wasVariable, &cachedState, &wasCachedAuth, nullptr, &d_fromAuthIP) > 0) {

    LOG(prefix << sqname << ": Found cache hit for " << sqt.toString() << ": ");

    if (!wasAuthZone && shouldValidate() && (wasCachedAuth || wasForwardRecurse) && cachedState == vState::Indeterminate && d_requireAuthData) {

      /* This means we couldn't figure out the state when this entry was cached */
      vState recordState = getValidationStatus(qname, !signatures.empty(), qtype == QType::DS, depth, prefix);

      if (recordState == vState::Secure) {
        LOG(prefix << sqname << ": Got vState::Indeterminate state from the cache, validating.." << endl);
        if (sqt == QType::DNSKEY && sqname == getSigner(signatures)) {
          cachedState = validateDNSKeys(sqname, cset, signatures, depth, prefix);
        }
        else {
          if (sqt == QType::ANY) {
            std::map<QType, CacheEntry> types;
            reapRecordsForValidation(types, cset);
            reapSignaturesForValidation(types, signatures);

            for (const auto& type : types) {
              vState cachedRecordState;
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
            cachedState = SyncRes::validateRecordsWithSigs(depth, prefix, qname, qtype, sqname, sqt, cset, signatures);
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
        DNSRecord dr = *j;
        dr.d_ttl -= d_now.tv_sec;
        dr.d_ttl = std::min(dr.d_ttl, capTTL);
        ttl = dr.d_ttl;
        ret.push_back(dr);
        LOG("[ttl=" << dr.d_ttl << "] ");
        found = true;
      }
      else {
        LOG("[expired] ");
        expired = true;
      }
    }

    ret.reserve(ret.size() + signatures.size() + authorityRecs.size());

    for (const auto& signature : signatures) {
      DNSRecord dr;
      dr.d_type = QType::RRSIG;
      dr.d_name = sqname;
      dr.d_ttl = ttl;
      dr.setContent(signature);
      dr.d_place = DNSResourceRecord::ANSWER;
      dr.d_class = QClass::IN;
      ret.push_back(dr);
    }

    for (const auto& rec : authorityRecs) {
      DNSRecord dr(*rec);
      dr.d_ttl = ttl;
      ret.push_back(dr);
    }

    LOG(endl);
    if (found && !expired) {
      if (!giveNegative)
        res = 0;
      LOG(prefix << qname << ": Updating validation state with cache content for " << qname << " to " << cachedState << endl);
      context.state = cachedState;
      return true;
    }
    else
      LOG(prefix << qname << ": Cache had only stale entries" << endl);
  }

  /* let's check if we have a NSEC covering that record */
  if (g_aggressiveNSECCache && !wasForwardedOrAuthZone) {
    if (g_aggressiveNSECCache->getDenial(d_now.tv_sec, qname, qtype, ret, res, d_cacheRemote, d_routingTag, d_doDNSSEC, LogObject(prefix))) {
      context.state = vState::Secure;
      if (s_addExtendedResolutionDNSErrors) {
        context.extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::Synthesized), "Result synthesized from aggressive NSEC cache (RFC8198)"};
      }
      return true;
    }
  }

  return false;
}

bool SyncRes::moreSpecificThan(const DNSName& a, const DNSName& b) const
{
  return (a.isPartOf(b) && a.countLabels() > b.countLabels());
}

struct speedOrder
{
  bool operator()(const std::pair<DNSName, float>& a, const std::pair<DNSName, float>& b) const
  {
    return a.second < b.second;
  }
};

std::vector<std::pair<DNSName, float>> SyncRes::shuffleInSpeedOrder(const DNSName& qname, NsSet& tnameservers, const string& prefix)
{
  std::vector<std::pair<DNSName, float>> rnameservers;
  rnameservers.reserve(tnameservers.size());
  for (const auto& tns : tnameservers) {
    float speed = s_nsSpeeds.lock()->fastest(tns.first, d_now);
    rnameservers.emplace_back(tns.first, speed);
    if (tns.first.empty()) // this was an authoritative OOB zone, don't pollute the nsSpeeds with that
      return rnameservers;
  }

  shuffle(rnameservers.begin(), rnameservers.end(), pdns::dns_random_engine());
  speedOrder so;
  stable_sort(rnameservers.begin(), rnameservers.end(), so);

  if (doLog()) {
    LOG(prefix << qname << ": Nameservers: ");
    for (auto i = rnameservers.begin(); i != rnameservers.end(); ++i) {
      if (i != rnameservers.begin()) {
        LOG(", ");
        if (!((i - rnameservers.begin()) % 3)) {
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
  speedOrderCA so(speeds);
  stable_sort(nameservers.begin(), nameservers.end(), so);

  if (doLog()) {
    LOG(prefix << qname << ": Nameservers: ");
    for (vector<ComboAddress>::const_iterator i = nameservers.cbegin(); i != nameservers.cend(); ++i) {
      if (i != nameservers.cbegin()) {
        LOG(", ");
        if (!((i - nameservers.cbegin()) % 3)) {
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
static void harvestNXRecords(const vector<DNSRecord>& records, NegCache::NegCacheEntry& ne, const time_t now, uint32_t* lowestTTL)
{
  for (const auto& rec : records) {
    if (rec.d_place != DNSResourceRecord::AUTHORITY) {
      // RFC 4035 section 3.1.3. indicates that NSEC records MUST be placed in
      // the AUTHORITY section. Section 3.1.1 indicates that that RRSIGs for
      // records MUST be in the same section as the records they cover.
      // Hence, we ignore all records outside of the AUTHORITY section.
      continue;
    }

    if (rec.d_type == QType::RRSIG) {
      auto rrsig = getRR<RRSIGRecordContent>(rec);
      if (rrsig) {
        if (rrsig->d_type == QType::SOA) {
          ne.authoritySOA.signatures.push_back(rec);
          if (lowestTTL && isRRSIGNotExpired(now, *rrsig)) {
            *lowestTTL = min(*lowestTTL, rec.d_ttl);
            *lowestTTL = min(*lowestTTL, getRRSIGTTL(now, rrsig));
          }
        }
        if (nsecTypes.count(rrsig->d_type)) {
          ne.DNSSECRecords.signatures.push_back(rec);
          if (lowestTTL && isRRSIGNotExpired(now, *rrsig)) {
            *lowestTTL = min(*lowestTTL, rec.d_ttl);
            *lowestTTL = min(*lowestTTL, getRRSIGTTL(now, rrsig));
          }
        }
      }
      continue;
    }
    if (rec.d_type == QType::SOA) {
      ne.authoritySOA.records.push_back(rec);
      if (lowestTTL) {
        *lowestTTL = min(*lowestTTL, rec.d_ttl);
      }
      continue;
    }
    if (nsecTypes.count(rec.d_type)) {
      ne.DNSSECRecords.records.push_back(rec);
      if (lowestTTL) {
        *lowestTTL = min(*lowestTTL, rec.d_ttl);
      }
      continue;
    }
  }
}

static cspmap_t harvestCSPFromNE(const NegCache::NegCacheEntry& ne)
{
  cspmap_t cspmap;
  for (const auto& rec : ne.DNSSECRecords.signatures) {
    if (rec.d_type == QType::RRSIG) {
      auto rrc = getRR<RRSIGRecordContent>(rec);
      if (rrc) {
        cspmap[{rec.d_name, rrc->d_type}].signatures.push_back(rrc);
      }
    }
  }
  for (const auto& rec : ne.DNSSECRecords.records) {
    cspmap[{rec.d_name, rec.d_type}].records.insert(rec.getContent());
  }
  return cspmap;
}

// TODO remove after processRecords is fixed!
// Adds the RRSIG for the SOA and the NSEC(3) + RRSIGs to ret
static void addNXNSECS(vector<DNSRecord>& ret, const vector<DNSRecord>& records)
{
  NegCache::NegCacheEntry ne;
  harvestNXRecords(records, ne, 0, nullptr);
  ret.insert(ret.end(), ne.authoritySOA.signatures.begin(), ne.authoritySOA.signatures.end());
  ret.insert(ret.end(), ne.DNSSECRecords.records.begin(), ne.DNSSECRecords.records.end());
  ret.insert(ret.end(), ne.DNSSECRecords.signatures.begin(), ne.DNSSECRecords.signatures.end());
}

static bool rpzHitShouldReplaceContent(const DNSName& qname, const QType qtype, const std::vector<DNSRecord>& records)
{
  if (qtype == QType::CNAME) {
    return true;
  }

  for (const auto& record : records) {
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
    rcode = RCode::NXDomain;
    done = true;
    return;

  case DNSFilterEngine::PolicyKind::NODATA:
    ret.clear();
    rcode = RCode::NoError;
    done = true;
    return;

  case DNSFilterEngine::PolicyKind::Truncate:
    if (!d_queryReceivedOverTCP) {
      ret.clear();
      rcode = RCode::NoError;
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
    for (auto& dr : spoofed) {
      removeConflictingRecord(ret, dr.d_name, dr.d_type);
    }

    for (auto& dr : spoofed) {
      ret.push_back(dr);

      if (dr.d_name == qname && dr.d_type == QType::CNAME && qtype != QType::CNAME) {
        if (auto content = getRR<CNAMERecordContent>(dr)) {
          vState newTargetState = vState::Indeterminate;
          handleNewTarget(prefix, qname, content->getTarget(), qtype.getCode(), ret, rcode, depth, {}, newTargetState);
        }
      }
    }
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
    for (auto const& ns : nameservers) {
      bool match = dfe.getProcessingPolicy(ns.first, d_discardedPolicies, d_appliedPolicy);
      if (match) {
        mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
        if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
          LOG(", however nameserver " << ns.first << " was blocked by RPZ policy '" << d_appliedPolicy.getName() << "'" << endl);
          return true;
        }
      }

      // Traverse all IP addresses for this NS to see if they have an RPN NSIP policy
      for (auto const& address : ns.second.first) {
        match = dfe.getProcessingPolicy(address, d_discardedPolicies, d_appliedPolicy);
        if (match) {
          mergePolicyTags(d_policyTags, d_appliedPolicy.getTags());
          if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
            LOG(", however nameserver " << ns.first << " IP address " << address.toString() << " was blocked by RPZ policy '" << d_appliedPolicy.getName() << "'" << endl);
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
        auto dontThrottleNames = g_dontThrottleNames.getLocal();
        if (!dontThrottleNames->check(tns->first)) {
          s_nonresolving.lock()->incr(tns->first, d_now);
        }
      }
      throw ex;
    }
    if (s_nonresolvingnsmaxfails > 0 && d_outqueries > oldOutQueries) {
      if (result.empty()) {
        auto dontThrottleNames = g_dontThrottleNames.getLocal();
        if (!dontThrottleNames->check(tns->first)) {
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
  else if (isThrottled(d_now.tv_sec, remoteIP, qname, qtype)) {
    LOG(prefix << qname << ": Query throttled " << remoteIP.toString() << ", " << qname << "; " << qtype << endl);
    t_Counters.at(rec::Counter::throttledqueries)++;
    d_throttledqueries++;
    return true;
  }
  else if (!pierceDontQuery && s_dontQuery && s_dontQuery->match(&remoteIP)) {
    // We could have retrieved an NS from the cache in a forwarding domain
    // Even in the case of !pierceDontQuery we still want to allow that NS
    DNSName forwardCandidate(qname);
    auto it = getBestAuthZone(&forwardCandidate);
    if (it == t_sstorage.domainmap->end()) {
      LOG(prefix << qname << ": Not sending query to " << remoteIP.toString() << ", blocked by 'dont-query' setting" << endl);
      t_Counters.at(rec::Counter::dontqueries)++;
      return true;
    }
    else {
      // The name (from the cache) is forwarded, but is it forwarded to an IP in known forwarders?
      const auto& ips = it->second.d_servers;
      if (std::find(ips.cbegin(), ips.cend(), remoteIP) == ips.cend()) {
        LOG(prefix << qname << ": Not sending query to " << remoteIP.toString() << ", blocked by 'dont-query' setting" << endl);
        t_Counters.at(rec::Counter::dontqueries)++;
        return true;
      }
      else {
        LOG(prefix << qname << ": Sending query to " << remoteIP.toString() << ", blocked by 'dont-query' but a forwarding/auth case" << endl);
      }
    }
  }
  return false;
}

bool SyncRes::validationEnabled() const
{
  return g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate;
}

uint32_t SyncRes::computeLowestTTD(const std::vector<DNSRecord>& records, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures, uint32_t signaturesTTL, const std::vector<std::shared_ptr<DNSRecord>>& authorityRecs) const
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
    lowestTTD = min(lowestTTD, static_cast<uint32_t>(entry->d_ttl + d_now.tv_sec));

    if (entry->d_type == QType::RRSIG && validationEnabled()) {
      auto rrsig = getRR<RRSIGRecordContent>(*entry);
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

vState SyncRes::getTA(const DNSName& zone, dsmap_t& ds, const string& prefix)
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

  if (getTrustAnchor(luaLocal->dsAnchors, zone, ds)) {
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

size_t SyncRes::countSupportedDS(const dsmap_t& dsmap, const string& prefix)
{
  size_t count = 0;

  for (const auto& ds : dsmap) {
    if (isSupportedDS(ds, LogObject(prefix))) {
      count++;
    }
  }

  return count;
}

void SyncRes::initZoneCutsFromTA(const DNSName& from, const string& prefix)
{
  DNSName zone(from);
  do {
    dsmap_t ds;
    vState result = getTA(zone, ds, prefix);
    if (result != vState::Indeterminate) {
      if (result == vState::TA) {
        if (countSupportedDS(ds, prefix) == 0) {
          ds.clear();
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

vState SyncRes::getDSRecords(const DNSName& zone, dsmap_t& ds, bool taOnly, unsigned int depth, const string& prefix, bool bogusOnNXD, bool* foundCut)
{
  vState result = getTA(zone, ds, prefix);

  if (result != vState::Indeterminate || taOnly) {
    if (foundCut) {
      *foundCut = (result != vState::Indeterminate);
    }

    if (result == vState::TA) {
      if (countSupportedDS(ds, prefix) == 0) {
        ds.clear();
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

  if (rcode == RCode::NoError || (rcode == RCode::NXDomain && !bogusOnNXD)) {
    uint8_t bestDigestType = 0;

    bool gotCNAME = false;
    for (const auto& record : dsrecords) {
      if (record.d_type == QType::DS) {
        const auto dscontent = getRR<DSRecordContent>(record);
        if (dscontent && isSupportedDS(*dscontent, LogObject(prefix))) {
          // Make GOST a lower prio than SHA256
          if (dscontent->d_digesttype == DNSSECKeeper::DIGEST_GOST && bestDigestType == DNSSECKeeper::DIGEST_SHA256) {
            continue;
          }
          if (dscontent->d_digesttype > bestDigestType || (bestDigestType == DNSSECKeeper::DIGEST_GOST && dscontent->d_digesttype == DNSSECKeeper::DIGEST_SHA256)) {
            bestDigestType = dscontent->d_digesttype;
          }
          ds.insert(*dscontent);
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
    for (auto dsrec = ds.begin(); dsrec != ds.end();) {
      if (dsrec->d_digesttype == DNSSECKeeper::DIGEST_SHA1 && dsrec->d_digesttype != bestDigestType) {
        dsrec = ds.erase(dsrec);
      }
      else {
        ++dsrec;
      }
    }

    if (rcode == RCode::NoError) {
      if (ds.empty()) {
        /* we have no DS, it's either:
           - a delegation to a non-DNSSEC signed zone
           - no delegation, we stay in the same zone
        */
        if (gotCNAME || denialProvesNoDelegation(zone, dsrecords)) {
          /* we are still inside the same zone */

          if (foundCut) {
            *foundCut = false;
          }
          return context.state;
        }

        d_cutStates[zone] = context.state == vState::Secure ? vState::Insecure : context.state;
        /* delegation with no DS, might be Secure -> Insecure */
        if (foundCut) {
          *foundCut = true;
        }

        /* a delegation with no DS is either:
           - a signed zone (Secure) to an unsigned one (Insecure)
           - an unsigned zone to another unsigned one (Insecure stays Insecure, Bogus stays Bogus)
        */
        return context.state == vState::Secure ? vState::Insecure : context.state;
      }
      else {
        /* we have a DS */
        d_cutStates[zone] = context.state;
        if (foundCut) {
          *foundCut = true;
        }
      }
    }

    return context.state;
  }

  LOG(prefix << zone << ": Returning Bogus state from " << __func__ << "(" << zone << ")" << endl);
  return vState::BogusUnableToGetDSs;
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
    const auto& it = d_cutStates.find(subdomain);
    if (it != d_cutStates.cend()) {
      LOG(prefix << name << ": Got status " << it->second << " for name " << subdomain << endl);
      return it->second;
    }
  }

  /* look for the best match we have */
  DNSName best(subdomain);
  while (best.chopOff()) {
    const auto& it = d_cutStates.find(best);
    if (it != d_cutStates.cend()) {
      result = it->second;
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
    DNSName ds(best);
    std::vector<string> labelsToAdd = subdomain.makeRelative(ds).getRawLabels();

    while (!labelsToAdd.empty()) {

      ds.prependRawLabel(labelsToAdd.back());
      labelsToAdd.pop_back();
      LOG(prefix << name << ": - Looking for a DS at " << ds << endl);

      bool foundCut = false;
      dsmap_t results;
      vState dsState = getDSRecords(ds, results, false, depth, prefix, false, &foundCut);

      if (foundCut) {
        LOG(prefix << name << ": - Found cut at " << ds << endl);
        LOG(prefix << name << ": New state for " << ds << " is " << dsState << endl);
        d_cutStates[ds] = dsState;

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

vState SyncRes::validateDNSKeys(const DNSName& zone, const std::vector<DNSRecord>& dnskeys, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures, unsigned int depth, const string& prefix)
{
  dsmap_t ds;
  if (signatures.empty()) {
    LOG(prefix << zone << ": We have " << std::to_string(dnskeys.size()) << " DNSKEYs but no signature, going Bogus!" << endl);
    return vState::BogusNoRRSIG;
  }

  DNSName signer = getSigner(signatures);

  if (!signer.empty() && zone.isPartOf(signer)) {
    vState state = getDSRecords(signer, ds, false, depth, prefix);

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
    else {
      return zState;
    }
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

  LOG(prefix << zone << ": Trying to validate " << std::to_string(tentativeKeys.size()) << " DNSKEYs with " << std::to_string(ds.size()) << " DS" << endl);
  skeyset_t validatedKeys;
  auto state = validateDNSKeysAgainstDS(d_now.tv_sec, zone, ds, tentativeKeys, toSign, signatures, validatedKeys, LogObject(prefix));

  LOG(prefix << zone << ": We now have " << std::to_string(validatedKeys.size()) << " DNSKEYs" << endl);

  /* if we found at least one valid RRSIG covering the set,
     all tentative keys are validated keys. Otherwise it means
     we haven't found at least one DNSKEY and a matching RRSIG
     covering this set, this looks Bogus. */
  if (validatedKeys.size() != tentativeKeys.size()) {
    LOG(prefix << zone << ": Let's check whether we missed a zone cut before returning a Bogus state from " << __func__ << "(" << zone << ")" << endl);
    /* try again to get the missed cuts, harder this time */
    auto zState = getValidationStatus(zone, false, false, depth, prefix);
    if (zState == vState::Secure) {
      /* too bad */
      LOG(prefix << zone << ": After checking the zone cuts we are still in a Secure zone, returning Bogus state from " << __func__ << "(" << zone << ")" << endl);
      return state;
    }
    else {
      return zState;
    }
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
            keys.insert(content);
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

  LOG(prefix << signer << ": Returning Bogus state from " << __func__ << "(" << signer << ")" << endl);
  return vState::BogusUnableToGetDNSKEYs;
}

vState SyncRes::validateRecordsWithSigs(unsigned int depth, const string& prefix, const DNSName& qname, const QType qtype, const DNSName& name, const QType type, const std::vector<DNSRecord>& records, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures)
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
          dsmap_t results;
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
      else {
        return zState;
      }
    }
  }

  sortedRecords_t recordcontents;
  for (const auto& record : records) {
    recordcontents.insert(record.getContent());
  }

  LOG(prefix << name << ": Going to validate " << recordcontents.size() << " record contents with " << signatures.size() << " sigs and " << keys.size() << " keys for " << name << "|" << type.toString() << endl);
  vState state = validateWithKeySet(d_now.tv_sec, name, recordcontents, signatures, keys, LogObject(prefix), false);
  if (state == vState::Secure) {
    LOG(prefix << name << ": Secure!" << endl);
    return vState::Secure;
  }

  LOG(prefix << vStateToString(state) << "!" << endl);
  /* try again to get the missed cuts, harder this time */
  auto zState = getValidationStatus(name, false, type == QType::DS, depth, prefix);
  LOG(prefix << name << ": Checking whether we missed a zone cut before returning a Bogus state" << endl);
  if (zState == vState::Secure) {
    /* too bad */
    LOG(prefix << name << ": We are still in a Secure zone, returning " << vStateToString(state) << endl);
    return state;
  }
  else {
    return zState;
  }
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
        allowedAdditionals.insert(target);
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

void SyncRes::sanitizeRecords(const std::string& prefix, LWResult& lwr, const DNSName& qname, const QType qtype, const DNSName& auth, bool wasForwarded, bool rdQuery)
{
  const bool wasForwardRecurse = wasForwarded && rdQuery;
  /* list of names for which we will allow A and AAAA records in the additional section
     to remain */
  std::unordered_set<DNSName> allowedAdditionals = {qname};
  bool haveAnswers = false;
  bool isNXDomain = false;
  bool isNXQType = false;

  for (auto rec = lwr.d_records.begin(); rec != lwr.d_records.end();) {

    if (rec->d_type == QType::OPT) {
      ++rec;
      continue;
    }

    if (rec->d_class != QClass::IN) {
      LOG(prefix << qname << ": Removing non internet-classed data received from " << auth << endl);
      rec = lwr.d_records.erase(rec);
      continue;
    }

    if (rec->d_type == QType::ANY) {
      LOG(prefix << qname << ": Removing 'ANY'-typed data received from " << auth << endl);
      rec = lwr.d_records.erase(rec);
      continue;
    }

    if (!rec->d_name.isPartOf(auth)) {
      LOG(prefix << qname << ": Removing record '" << rec->d_name << "|" << DNSRecordContent::NumberToType(rec->d_type) << "|" << rec->getContent()->getZoneRepresentation() << "' in the " << (int)rec->d_place << " section received from " << auth << endl);
      rec = lwr.d_records.erase(rec);
      continue;
    }

    /* dealing with the records in answer */
    if (!(lwr.d_aabit || wasForwardRecurse) && rec->d_place == DNSResourceRecord::ANSWER) {
      /* for now we allow a CNAME for the exact qname in ANSWER with AA=0, because Amazon DNS servers
         are sending such responses */
      if (!(rec->d_type == QType::CNAME && qname == rec->d_name)) {
        LOG(prefix << qname << ": Removing record '" << rec->d_name << "|" << DNSRecordContent::NumberToType(rec->d_type) << "|" << rec->getContent()->getZoneRepresentation() << "' in the answer section without the AA bit set received from " << auth << endl);
        rec = lwr.d_records.erase(rec);
        continue;
      }
    }

    if (rec->d_type == QType::DNAME && (rec->d_place != DNSResourceRecord::ANSWER || !qname.isPartOf(rec->d_name))) {
      LOG(prefix << qname << ": Removing invalid DNAME record '" << rec->d_name << "|" << DNSRecordContent::NumberToType(rec->d_type) << "|" << rec->getContent()->getZoneRepresentation() << "' in the " << (int)rec->d_place << " section received from " << auth << endl);
      rec = lwr.d_records.erase(rec);
      continue;
    }

    if (rec->d_place == DNSResourceRecord::ANSWER && (qtype != QType::ANY && rec->d_type != qtype.getCode() && s_redirectionQTypes.count(rec->d_type) == 0 && rec->d_type != QType::SOA && rec->d_type != QType::RRSIG)) {
      LOG(prefix << qname << ": Removing irrelevant record '" << rec->d_name << "|" << DNSRecordContent::NumberToType(rec->d_type) << "|" << rec->getContent()->getZoneRepresentation() << "' in the ANSWER section received from " << auth << endl);
      rec = lwr.d_records.erase(rec);
      continue;
    }

    if (rec->d_place == DNSResourceRecord::ANSWER && !haveAnswers) {
      haveAnswers = true;
    }

    if (rec->d_place == DNSResourceRecord::ANSWER) {
      allowAdditionalEntry(allowedAdditionals, *rec);
    }

    /* dealing with the records in authority */
    if (rec->d_place == DNSResourceRecord::AUTHORITY && rec->d_type != QType::NS && rec->d_type != QType::DS && rec->d_type != QType::SOA && rec->d_type != QType::RRSIG && rec->d_type != QType::NSEC && rec->d_type != QType::NSEC3) {
      LOG(prefix << qname << ": Removing irrelevant record '" << rec->d_name << "|" << DNSRecordContent::NumberToType(rec->d_type) << "|" << rec->getContent()->getZoneRepresentation() << "' in the AUTHORITY section received from " << auth << endl);
      rec = lwr.d_records.erase(rec);
      continue;
    }

    if (rec->d_place == DNSResourceRecord::AUTHORITY && rec->d_type == QType::SOA) {
      if (!qname.isPartOf(rec->d_name)) {
        LOG(prefix << qname << ": Removing irrelevant SOA record '" << rec->d_name << "|" << rec->getContent()->getZoneRepresentation() << "' in the AUTHORITY section received from " << auth << endl);
        rec = lwr.d_records.erase(rec);
        continue;
      }

      if (!(lwr.d_aabit || wasForwardRecurse)) {
        LOG(prefix << qname << ": Removing irrelevant record '" << rec->d_name << "|" << DNSRecordContent::NumberToType(rec->d_type) << "|" << rec->getContent()->getZoneRepresentation() << "' in the AUTHORITY section received from " << auth << endl);
        rec = lwr.d_records.erase(rec);
        continue;
      }

      if (!haveAnswers) {
        if (lwr.d_rcode == RCode::NXDomain) {
          isNXDomain = true;
        }
        else if (lwr.d_rcode == RCode::NoError) {
          isNXQType = true;
        }
      }
    }

    if (rec->d_place == DNSResourceRecord::AUTHORITY && rec->d_type == QType::NS && (isNXDomain || isNXQType)) {
      /*
       * We don't want to pick up NS records in AUTHORITY and their ADDITIONAL sections of NXDomain answers
       * because they are somewhat easy to insert into a large, fragmented UDP response
       * for an off-path attacker by injecting spoofed UDP fragments. So do not add these to allowedAdditionals.
       */
      LOG(prefix << qname << ": Removing NS record '" << rec->d_name << "|" << DNSRecordContent::NumberToType(rec->d_type) << "|" << rec->getContent()->getZoneRepresentation() << "' in the " << (int)rec->d_place << " section of a " << (isNXDomain ? "NXD" : "NXQTYPE") << " response received from " << auth << endl);
      rec = lwr.d_records.erase(rec);
      continue;
    }

    if (rec->d_place == DNSResourceRecord::AUTHORITY && rec->d_type == QType::NS && !d_updatingRootNS && rec->d_name == g_rootdnsname) {
      /*
       * We don't want to pick up root NS records in AUTHORITY and their associated ADDITIONAL sections of random queries.
       * So don't add them to allowedAdditionals.
       */
      LOG(prefix << qname << ": Removing NS record '" << rec->d_name << "|" << DNSRecordContent::NumberToType(rec->d_type) << "|" << rec->getContent()->getZoneRepresentation() << "' in the " << (int)rec->d_place << " section of a response received from " << auth << endl);
      rec = lwr.d_records.erase(rec);
      continue;
    }

    if (rec->d_place == DNSResourceRecord::AUTHORITY && rec->d_type == QType::NS) {
      allowAdditionalEntry(allowedAdditionals, *rec);
    }

    /* dealing with the records in additional */
    if (rec->d_place == DNSResourceRecord::ADDITIONAL && rec->d_type != QType::A && rec->d_type != QType::AAAA && rec->d_type != QType::RRSIG) {
      LOG(prefix << qname << ": Removing irrelevant record '" << rec->d_name << "|" << DNSRecordContent::NumberToType(rec->d_type) << "|" << rec->getContent()->getZoneRepresentation() << "' in the ADDITIONAL section received from " << auth << endl);
      rec = lwr.d_records.erase(rec);
      continue;
    }

    if (rec->d_place == DNSResourceRecord::ADDITIONAL && allowedAdditionals.count(rec->d_name) == 0) {
      LOG(prefix << qname << ": Removing irrelevant additional record '" << rec->d_name << "|" << DNSRecordContent::NumberToType(rec->d_type) << "|" << rec->getContent()->getZoneRepresentation() << "' in the ADDITIONAL section received from " << auth << endl);
      rec = lwr.d_records.erase(rec);
      continue;
    }

    ++rec;
  }
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
  for (const auto& ns : newRecords) {
    auto content = getRR<NSRecordContent>(ns);
    authSet.insert(content->getNS());
  }
  // The glue IPs could also differ, but we're not checking that yet, we're only looking for parent NS records not
  // in the child set
  bool shouldSave = false;
  for (const auto& ns : existing) {
    auto content = getRR<NSRecordContent>(ns);
    if (authSet.count(content->getNS()) == 0) {
      LOG(prefix << domain << ": At least one parent-side NS was not in the child-side NS set, remembering parent NS set and cached IPs" << endl);
      shouldSave = true;
      break;
    }
  }

  if (shouldSave) {
    map<DNSName, vector<ComboAddress>> entries;
    for (const auto& ns : existing) {
      auto content = getRR<NSRecordContent>(ns);
      const DNSName& name = content->getNS();
      set<GetBestNSAnswer> beenthereIgnored;
      unsigned int nretrieveAddressesForNSIgnored;
      auto addresses = getAddrs(name, depth, prefix, beenthereIgnored, true, nretrieveAddressesForNSIgnored);
      entries.emplace(name, addresses);
    }
    s_savedParentNSSet.lock()->emplace(domain, std::move(entries), d_now.tv_sec + ttl);
  }
}

RCode::rcodes_ SyncRes::updateCacheFromRecords(unsigned int depth, const string& prefix, LWResult& lwr, const DNSName& qname, const QType qtype, const DNSName& auth, bool wasForwarded, const boost::optional<Netmask> ednsmask, vState& state, bool& needWildcardProof, bool& gatherWildcardProof, unsigned int& wildcardLabelsCount, bool rdQuery, const ComboAddress& remoteIP)
{
  bool wasForwardRecurse = wasForwarded && rdQuery;
  tcache_t tcache;

  fixupAnswer(prefix, lwr, qname, qtype, auth, wasForwarded, rdQuery);
  sanitizeRecords(prefix, lwr, qname, qtype, auth, wasForwarded, rdQuery);

  std::vector<std::shared_ptr<DNSRecord>> authorityRecs;
  const unsigned int labelCount = qname.countLabels();
  bool isCNAMEAnswer = false;
  bool isDNAMEAnswer = false;
  DNSName seenAuth;

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

    if (rec.d_type == QType::RRSIG) {
      auto rrsig = getRR<RRSIGRecordContent>(rec);
      if (rrsig) {
        /* As illustrated in rfc4035's Appendix B.6, the RRSIG label
           count can be lower than the name's label count if it was
           synthesized from the wildcard. Note that the difference might
           be > 1. */
        if (rec.d_name == qname && isWildcardExpanded(labelCount, *rrsig)) {
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

      if (nsecTypes.count(rec.d_type)) {
        authorityRecs.push_back(std::make_shared<DNSRecord>(rec));
      }
      else if (rec.d_type == QType::RRSIG) {
        auto rrsig = getRR<RRSIGRecordContent>(rec);
        if (rrsig && nsecTypes.count(rrsig->d_type)) {
          authorityRecs.push_back(std::make_shared<DNSRecord>(rec));
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
            else {
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
        }
        if (!haveLogged) {
          LOG("YES!" << endl);
        }

        rec.d_ttl = min(s_maxcachettl, rec.d_ttl);

        DNSRecord dr(rec);
        dr.d_ttl += d_now.tv_sec;
        dr.d_place = DNSResourceRecord::ANSWER;
        tcache[{rec.d_name, rec.d_type, rec.d_place}].records.push_back(dr);
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

  for (tcache_t::iterator i = tcache.begin(); i != tcache.end(); ++i) {

    if (i->second.records.empty()) // this happens when we did store signatures, but passed on the records themselves
      continue;

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
    bool isAA = lwr.d_aabit && i->first.place != DNSResourceRecord::ADDITIONAL;
    /* if we forwarded the query to a recursor, we can expect the answer to be signed,
       even if the answer is not AA. Of course that's not only true inside a Secure
       zone, but we check that below. */
    bool expectSignature = i->first.place == DNSResourceRecord::ANSWER || ((lwr.d_aabit || wasForwardRecurse) && i->first.place != DNSResourceRecord::ADDITIONAL);
    /* in a non authoritative answer, we only care about the DS record (or lack of)  */
    if (!isAA && (i->first.type == QType::DS || i->first.type == QType::NSEC || i->first.type == QType::NSEC3) && i->first.place == DNSResourceRecord::AUTHORITY) {
      expectSignature = true;
    }

    if (isCNAMEAnswer && (i->first.place != DNSResourceRecord::ANSWER || i->first.type != QType::CNAME || i->first.name != qname)) {
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
    else if (isDNAMEAnswer && (i->first.place != DNSResourceRecord::ANSWER || i->first.type != QType::DNAME || !qname.isPartOf(i->first.name))) {
      /* see above */
      isAA = false;
      expectSignature = false;
    }

    if ((isCNAMEAnswer || isDNAMEAnswer) && i->first.place == DNSResourceRecord::AUTHORITY && i->first.type == QType::NS && auth == i->first.name) {
      /* These NS can't be authoritative since we have a CNAME/DNAME answer for which (see above) only the
         record describing that alias is necessarily authoritative.
         But if we allow the current auth, which might be serving the child zone, to raise the TTL
         of non-authoritative NS in the cache, they might be able to keep a "ghost" zone alive forever,
         even after the delegation is gone from the parent.
         So let's just do nothing with them, we can fetch them directly if we need them.
      */
      LOG(prefix << qname << ": Skipping authority NS from '" << auth << "' nameservers in CNAME/DNAME answer " << i->first.name << "|" << DNSRecordContent::NumberToType(i->first.type) << endl);
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
    if (isDNAMEAnswer && i->first.type == QType::CNAME) {
      expectSignature = false;
    }

    vState recordState = vState::Indeterminate;

    if (expectSignature && shouldValidate()) {
      vState initialState = getValidationStatus(i->first.name, !i->second.signatures.empty(), i->first.type == QType::DS, depth, prefix);
      LOG(prefix << qname << ": Got initial zone status " << initialState << " for record " << i->first.name << "|" << DNSRecordContent::NumberToType(i->first.type) << endl);

      if (initialState == vState::Secure) {
        if (i->first.type == QType::DNSKEY && i->first.place == DNSResourceRecord::ANSWER && i->first.name == getSigner(i->second.signatures)) {
          LOG(prefix << qname << ": Validating DNSKEY for " << i->first.name << endl);
          recordState = validateDNSKeys(i->first.name, i->second.records, i->second.signatures, depth, prefix);
        }
        else {
          LOG(prefix << qname << ": Validating non-additional " << QType(i->first.type).toString() << " record for " << i->first.name << endl);
          recordState = validateRecordsWithSigs(depth, prefix, qname, qtype, i->first.name, QType(i->first.type), i->second.records, i->second.signatures);
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
      /* this is a TTD by now, be careful */
      for (auto& record : i->second.records) {
        record.d_ttl = std::min(record.d_ttl, static_cast<uint32_t>(s_maxbogusttl + d_now.tv_sec));
      }
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
    if (i->first.type != QType::NSEC3 && (i->first.type == QType::DS || i->first.type == QType::NS || i->first.type == QType::A || i->first.type == QType::AAAA || isAA || wasForwardRecurse)) {

      bool doCache = true;
      if (i->first.place == DNSResourceRecord::ANSWER && ednsmask) {
        const bool isv4 = ednsmask->isIPv4();
        if ((isv4 && s_ecsipv4nevercache) || (!isv4 && s_ecsipv6nevercache)) {
          doCache = false;
        }
        // If ednsmask is relevant, we do not want to cache if the scope prefix length is large and TTL is small
        if (doCache && s_ecscachelimitttl > 0) {
          bool manyMaskBits = (isv4 && ednsmask->getBits() > s_ecsipv4cachelimit) || (!isv4 && ednsmask->getBits() > s_ecsipv6cachelimit);

          if (manyMaskBits) {
            uint32_t minttl = UINT32_MAX;
            for (const auto& it : i->second.records) {
              if (it.d_ttl < minttl)
                minttl = it.d_ttl;
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
        if (isAA && i->first.type == QType::NS && s_save_parent_ns_set) {
          rememberParentSetIfNeeded(i->first.name, i->second.records, depth, prefix);
        }
        g_recCache->replace(d_now.tv_sec, i->first.name, i->first.type, i->second.records, i->second.signatures, authorityRecs, i->first.type == QType::DS ? true : isAA, auth, i->first.place == DNSResourceRecord::ANSWER ? ednsmask : boost::none, d_routingTag, recordState, remoteIP, d_refresh);

        // Delete potential negcache entry. When a record recovers with serve-stale the negcache entry can cause the wrong entry to
        // be served, as negcache entries are checked before record cache entries
        if (NegCache::s_maxServedStaleExtensions > 0) {
          g_negCache->wipeTyped(i->first.name, i->first.type);
        }

        if (g_aggressiveNSECCache && needWildcardProof && recordState == vState::Secure && i->first.place == DNSResourceRecord::ANSWER && i->first.name == qname && !i->second.signatures.empty() && !d_routingTag && !ednsmask) {
          /* we have an answer synthesized from a wildcard and aggressive NSEC is enabled, we need to store the
             wildcard in its non-expanded form in the cache to be able to synthesize wildcard answers later */
          const auto& rrsig = i->second.signatures.at(0);

          if (isWildcardExpanded(labelCount, *rrsig) && !isWildcardExpandedOntoItself(i->first.name, labelCount, *rrsig)) {
            DNSName realOwner = getNSECOwnerName(i->first.name, i->second.signatures);

            std::vector<DNSRecord> content;
            content.reserve(i->second.records.size());
            for (const auto& record : i->second.records) {
              DNSRecord nonExpandedRecord(record);
              nonExpandedRecord.d_name = realOwner;
              content.push_back(std::move(nonExpandedRecord));
            }

            g_recCache->replace(d_now.tv_sec, realOwner, QType(i->first.type), content, i->second.signatures, /* no additional records in that case */ {}, i->first.type == QType::DS ? true : isAA, auth, boost::none, boost::none, recordState, remoteIP, d_refresh);
          }
        }
      }
    }

    if (seenAuth.empty() && !i->second.signatures.empty()) {
      seenAuth = getSigner(i->second.signatures);
    }

    if (g_aggressiveNSECCache && (i->first.type == QType::NSEC || i->first.type == QType::NSEC3) && recordState == vState::Secure && !seenAuth.empty()) {
      // Good candidate for NSEC{,3} caching
      g_aggressiveNSECCache->insertNSEC(seenAuth, i->first.name, i->second.records.at(0), i->second.signatures, i->first.type == QType::NSEC3);
    }

    if (i->first.place == DNSResourceRecord::ANSWER && ednsmask) {
      d_wasVariable = true;
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

dState SyncRes::getDenialValidationState(const NegCache::NegCacheEntry& ne, const dState expectedState, bool referralToUnsigned, const string& prefix)
{
  cspmap_t csp = harvestCSPFromNE(ne);
  return getDenial(csp, ne.d_name, ne.d_qtype.getCode(), referralToUnsigned, expectedState == dState::NXQTYPE, LogObject(prefix));
}

bool SyncRes::processRecords(const std::string& prefix, const DNSName& qname, const QType qtype, const DNSName& auth, LWResult& lwr, const bool sendRDQuery, vector<DNSRecord>& ret, set<DNSName>& nsset, DNSName& newtarget, DNSName& newauth, bool& realreferral, bool& negindic, vState& state, const bool needWildcardProof, const bool gatherWildcardProof, const unsigned int wildcardLabelsCount, int& rcode, bool& negIndicHasSignatures, unsigned int depth)
{
  bool done = false;
  DNSName dnameTarget, dnameOwner;
  uint32_t dnameTTL = 0;
  bool referralOnDS = false;

  for (auto& rec : lwr.d_records) {
    if (rec.d_type == QType::OPT || rec.d_class != QClass::IN) {
      continue;
    }

    if (rec.d_place == DNSResourceRecord::ANSWER && !(lwr.d_aabit || sendRDQuery)) {
      /* for now we allow a CNAME for the exact qname in ANSWER with AA=0, because Amazon DNS servers
         are sending such responses */
      if (!(rec.d_type == QType::CNAME && rec.d_name == qname)) {
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

      NegCache::NegCacheEntry ne;

      uint32_t lowestTTL = rec.d_ttl;
      /* if we get an NXDomain answer with a CNAME, the name
         does exist but the target does not */
      ne.d_name = newtarget.empty() ? qname : newtarget;
      ne.d_qtype = QType::ENT; // this encodes 'whole record'
      ne.d_auth = rec.d_name;
      harvestNXRecords(lwr.d_records, ne, d_now.tv_sec, &lowestTTL);

      if (vStateIsBogus(state)) {
        ne.d_validationState = state;
      }
      else {
        /* here we need to get the validation status of the zone telling us that the domain does not
           exist, ie the owner of the SOA */
        auto recordState = getValidationStatus(rec.d_name, !ne.authoritySOA.signatures.empty() || !ne.DNSSECRecords.signatures.empty(), false, depth, prefix);
        if (recordState == vState::Secure) {
          dState denialState = getDenialValidationState(ne, dState::NXDOMAIN, false, prefix);
          updateDenialValidationState(qname, ne.d_validationState, ne.d_name, state, denialState, dState::NXDOMAIN, false, depth, prefix);
        }
        else {
          ne.d_validationState = recordState;
          updateValidationState(qname, state, ne.d_validationState, prefix);
        }
      }

      if (vStateIsBogus(ne.d_validationState)) {
        lowestTTL = min(lowestTTL, s_maxbogusttl);
      }

      ne.d_ttd = d_now.tv_sec + lowestTTL;
      ne.d_orig_ttl = lowestTTL;
      /* if we get an NXDomain answer with a CNAME, let's not cache the
         target, even the server was authoritative for it,
         and do an additional query for the CNAME target.
         We have a regression test making sure we do exactly that.
      */
      if (newtarget.empty() && putInNegCache) {
        g_negCache->add(ne);
        // doCNAMECacheCheck() checks record cache and does not look into negcache. That means that an old record might be found if
        // serve-stale is active. Avoid that by explicitly zapping that CNAME record.
        if (qtype == QType::CNAME && MemRecursorCache::s_maxServedStaleExtensions > 0) {
          g_recCache->doWipeCache(qname, false, qtype);
        }
        if (s_rootNXTrust && ne.d_auth.isRoot() && auth.isRoot() && lwr.d_aabit) {
          ne.d_name = ne.d_name.getLastLabel();
          g_negCache->add(ne);
        }
      }

      negIndicHasSignatures = !ne.authoritySOA.signatures.empty() || !ne.DNSSECRecords.signatures.empty();
      negindic = true;
    }
    else if (rec.d_place == DNSResourceRecord::ANSWER && s_redirectionQTypes.count(rec.d_type) > 0 && // CNAME or DNAME answer
             s_redirectionQTypes.count(qtype.getCode()) == 0) { // But not in response to a CNAME or DNAME query
      if (rec.d_type == QType::CNAME && rec.d_name == qname) {
        if (!dnameOwner.empty()) { // We synthesize ourselves
          continue;
        }
        ret.push_back(rec);
        if (auto content = getRR<CNAMERecordContent>(rec)) {
          newtarget = DNSName(content->getTarget());
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
                        [&qname](DNSRecord& rr) {
                          return (rr.d_place == DNSResourceRecord::ANSWER && rr.d_type == QType::CNAME && rr.d_name == qname);
                        }),
                      ret.end());
          }
          try {
            newtarget = qname.makeRelative(dnameOwner) + dnameTarget;
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
        /* positive answer synthesized from a wildcard */
        NegCache::NegCacheEntry ne;
        ne.d_name = qname;
        ne.d_qtype = QType::ENT; // this encodes 'whole record'
        uint32_t lowestTTL = rec.d_ttl;
        harvestNXRecords(lwr.d_records, ne, d_now.tv_sec, &lowestTTL);

        if (vStateIsBogus(state)) {
          ne.d_validationState = state;
        }
        else {
          auto recordState = getValidationStatus(qname, !ne.authoritySOA.signatures.empty() || !ne.DNSSECRecords.signatures.empty(), false, depth, prefix);

          if (recordState == vState::Secure) {
            /* We have a positive answer synthesized from a wildcard, we need to check that we have
               proof that the exact name doesn't exist so the wildcard can be used,
               as described in section 5.3.4 of RFC 4035 and 5.3 of RFC 7129.
            */
            cspmap_t csp = harvestCSPFromNE(ne);
            dState res = getDenial(csp, qname, ne.d_qtype.getCode(), false, false, LogObject(prefix), false, wildcardLabelsCount);
            if (res != dState::NXDOMAIN) {
              vState st = vState::BogusInvalidDenial;
              if (res == dState::INSECURE || res == dState::OPTOUT) {
                /* Some part could not be validated, for example a NSEC3 record with a too large number of iterations,
                   this is not enough to warrant a Bogus, but go Insecure. */
                st = vState::Insecure;
                LOG(prefix << qname << ": Unable to validate denial in wildcard expanded positive response found for " << qname << ", returning Insecure, res=" << res << endl);
              }
              else {
                LOG(prefix << qname << ": Invalid denial in wildcard expanded positive response found for " << qname << ", returning Bogus, res=" << res << endl);
                rec.d_ttl = std::min(rec.d_ttl, s_maxbogusttl);
              }

              updateValidationState(qname, state, st, prefix);
              /* we already stored the record with a different validation status, let's fix it */
              updateValidationStatusInCache(qname, qtype, lwr.d_aabit, st);
            }
          }
        }
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
      NegCache::NegCacheEntry ne;
      uint32_t lowestTTL = rec.d_ttl;
      harvestNXRecords(lwr.d_records, ne, d_now.tv_sec, &lowestTTL);

      if (!vStateIsBogus(state)) {
        auto recordState = getValidationStatus(newauth, !ne.authoritySOA.signatures.empty() || !ne.DNSSECRecords.signatures.empty(), true, depth, prefix);

        if (recordState == vState::Secure) {
          ne.d_auth = auth;
          ne.d_name = newauth;
          ne.d_qtype = QType::DS;
          rec.d_ttl = min(s_maxnegttl, rec.d_ttl);

          dState denialState = getDenialValidationState(ne, dState::NXQTYPE, true, prefix);

          if (denialState == dState::NXQTYPE || denialState == dState::OPTOUT || denialState == dState::INSECURE) {
            ne.d_ttd = lowestTTL + d_now.tv_sec;
            ne.d_orig_ttl = lowestTTL;
            ne.d_validationState = vState::Secure;
            if (denialState == dState::OPTOUT) {
              ne.d_validationState = vState::Insecure;
            }
            LOG(prefix << qname << ": Got negative indication of DS record for '" << newauth << "'" << endl);

            g_negCache->add(ne);

            /* Careful! If the client is asking for a DS that does not exist, we need to provide the SOA along with the NSEC(3) proof
               and we might not have it if we picked up the proof from a delegation, in which case we need to keep on to do the actual DS
               query. */
            if (qtype == QType::DS && qname == newauth && (d_externalDSQuery.empty() || qname != d_externalDSQuery)) {
              /* we are actually done! */
              negindic = true;
              negIndicHasSignatures = !ne.authoritySOA.signatures.empty() || !ne.DNSSECRecords.signatures.empty();
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

        NegCache::NegCacheEntry ne;
        ne.d_auth = rec.d_name;
        uint32_t lowestTTL = rec.d_ttl;
        ne.d_name = qname;
        ne.d_qtype = qtype;
        harvestNXRecords(lwr.d_records, ne, d_now.tv_sec, &lowestTTL);

        if (vStateIsBogus(state)) {
          ne.d_validationState = state;
        }
        else {
          auto recordState = getValidationStatus(qname, !ne.authoritySOA.signatures.empty() || !ne.DNSSECRecords.signatures.empty(), qtype == QType::DS, depth, prefix);
          if (recordState == vState::Secure) {
            dState denialState = getDenialValidationState(ne, dState::NXQTYPE, false, prefix);
            updateDenialValidationState(qname, ne.d_validationState, ne.d_name, state, denialState, dState::NXQTYPE, qtype == QType::DS, depth, prefix);
          }
          else {
            ne.d_validationState = recordState;
            updateValidationState(qname, state, ne.d_validationState, prefix);
          }
        }

        if (vStateIsBogus(ne.d_validationState)) {
          lowestTTL = min(lowestTTL, s_maxbogusttl);
          rec.d_ttl = min(rec.d_ttl, s_maxbogusttl);
        }
        ne.d_ttd = d_now.tv_sec + lowestTTL;
        ne.d_orig_ttl = lowestTTL;
        if (qtype.getCode()) { // prevents us from NXDOMAIN'ing a whole domain
          g_negCache->add(ne);
        }

        ret.push_back(rec);
        negindic = true;
        negIndicHasSignatures = !ne.authoritySOA.signatures.empty() || !ne.DNSSECRecords.signatures.empty();
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

static void submitTryDotTask(ComboAddress address, const DNSName& auth, const DNSName nsname, time_t now)
{
  if (address.getPort() == 853) {
    return;
  }
  address.setPort(853);
  auto lock = s_dotMap.lock();
  if (lock->d_numBusy >= SyncRes::s_max_busy_dot_probes) {
    return;
  }
  auto it = lock->d_map.emplace(DoTStatus{address, auth, now + dotFailWait}).first;
  if (it->d_status == DoTStatus::Busy) {
    return;
  }
  if (it->d_ttd > now) {
    if (it->d_status == DoTStatus::Bad) {
      return;
    }
    if (it->d_status == DoTStatus::Good) {
      return;
    }
    // We only want to probe auths that we have seen before, auth that only come around once are not interesting
    if (it->d_status == DoTStatus::Unknown && it->d_count == 0) {
      return;
    }
  }
  lock->d_map.modify(it, [=](DoTStatus& st) { st.d_ttd = now + dotFailWait; });
  bool pushed = pushTryDoTTask(auth, QType::SOA, address, std::numeric_limits<time_t>::max(), nsname);
  if (pushed) {
    it->d_status = DoTStatus::Busy;
    ++lock->d_numBusy;
  }
}

static bool shouldDoDoT(ComboAddress address, time_t now)
{
  address.setPort(853);
  auto lock = s_dotMap.lock();
  auto it = lock->d_map.find(address);
  if (it == lock->d_map.end()) {
    return false;
  }
  it->d_count++;
  if (it->d_status == DoTStatus::Good && it->d_ttd > now) {
    return true;
  }
  return false;
}

static void updateDoTStatus(ComboAddress address, DoTStatus::Status status, time_t time, bool updateBusy = false)
{
  address.setPort(853);
  auto lock = s_dotMap.lock();
  auto it = lock->d_map.find(address);
  if (it != lock->d_map.end()) {
    it->d_status = status;
    lock->d_map.modify(it, [=](DoTStatus& st) { st.d_ttd = time; });
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
  bool truncated;
  bool spoofed;
  boost::optional<Netmask> nm;
  address.setPort(853);
  // We use the fact that qname equals auth
  bool ok = false;
  try {
    boost::optional<EDNSExtendedError> extendedError;
    ok = doResolveAtThisIP("", qname, qtype, lwr, nm, qname, false, false, nsName, address, true, true, truncated, spoofed, extendedError, true);
    ok = ok && lwr.d_rcode == RCode::NoError && lwr.d_records.size() > 0;
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
  updateDoTStatus(address, ok ? DoTStatus::Good : DoTStatus::Bad, now + (ok ? dotSuccessWait : dotFailWait), true);
  return ok;
}

bool SyncRes::doResolveAtThisIP(const std::string& prefix, const DNSName& qname, const QType qtype, LWResult& lwr, boost::optional<Netmask>& ednsmask, const DNSName& auth, bool const sendRDQuery, const bool wasForwarded, const DNSName& nsName, const ComboAddress& remoteIP, bool doTCP, bool doDoT, bool& truncated, bool& spoofed, boost::optional<EDNSExtendedError>& extendedError, bool dontThrottle)
{
  bool chained = false;
  LWResult::Result resolveret = LWResult::Result::Success;
  t_Counters.at(rec::Counter::outqueries)++;
  d_outqueries++;
  checkMaxQperQ(qname);

  if (s_maxtotusec && d_totUsec > s_maxtotusec) {
    if (s_addExtendedResolutionDNSErrors) {
      extendedError = EDNSExtendedError{static_cast<uint16_t>(EDNSExtendedError::code::NoReachableAuthority), "Timeout waiting for answer(s)"};
    }
    throw ImmediateServFailException("Too much time waiting for " + qname.toLogString() + "|" + qtype.toString() + ", timeouts: " + std::to_string(d_timeouts) + ", throttles: " + std::to_string(d_throttledqueries) + ", queries: " + std::to_string(d_outqueries) + ", " + std::to_string(d_totUsec / 1000) + " ms");
  }

  if (doTCP) {
    if (doDoT) {
      LOG(prefix << qname << ": Using DoT with " << remoteIP.toStringWithPort() << endl);
      t_Counters.at(rec::Counter::dotoutqueries)++;
      d_dotoutqueries++;
    }
    else {
      LOG(prefix << qname << ": Using TCP with " << remoteIP.toStringWithPort() << endl);
      t_Counters.at(rec::Counter::tcpoutqueries)++;
      d_tcpoutqueries++;
    }
  }

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
    resolveret = asyncresolveWrapper(remoteIP, d_doDNSSEC, qname, auth, qtype.getCode(),
                                     doTCP, sendRDQuery, &d_now, ednsmask, &lwr, &chained, nsName); // <- we go out on the wire!
    if (ednsmask) {
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
  }

  /* preoutquery killed the query by setting dq.rcode to -3 */
  if (preOutQueryRet == -3) {
    throw ImmediateServFailException("Query killed by policy");
  }

  d_totUsec += lwr.d_usec;

  if (resolveret == LWResult::Result::Spoofed) {
    spoofed = true;
    return false;
  }

  accountAuthLatency(lwr.d_usec, remoteIP.sin4.sin_family);
  ++t_Counters.at(rec::RCode::auth).rcodeCounters.at(static_cast<uint8_t>(lwr.d_rcode));

  if (!dontThrottle) {
    auto dontThrottleNames = g_dontThrottleNames.getLocal();
    auto dontThrottleNetmasks = g_dontThrottleNetmasks.getLocal();
    dontThrottle = dontThrottleNames->check(nsName) || dontThrottleNetmasks->match(remoteIP);
  }

  if (resolveret != LWResult::Result::Success) {
    /* Error while resolving */
    if (resolveret == LWResult::Result::Timeout) {
      /* Time out */

      LOG(prefix << qname << ": Timeout resolving after " << lwr.d_usec / 1000.0 << " ms " << (doTCP ? "over TCP" : "") << endl);
      d_timeouts++;
      t_Counters.at(rec::Counter::outgoingtimeouts)++;

      if (remoteIP.sin4.sin_family == AF_INET)
        t_Counters.at(rec::Counter::outgoing4timeouts)++;
      else
        t_Counters.at(rec::Counter::outgoing6timeouts)++;

      if (t_timeouts)
        t_timeouts->push_back(remoteIP);
    }
    else if (resolveret == LWResult::Result::OSLimitError) {
      /* OS resource limit reached */
      LOG(prefix << qname << ": Hit a local resource limit resolving" << (doTCP ? " over TCP" : "") << ", probable error: " << stringerror() << endl);
      t_Counters.at(rec::Counter::resourceLimits)++;
    }
    else {
      /* LWResult::Result::PermanentError */
      t_Counters.at(rec::Counter::unreachables)++;
      d_unreachables++;
      // XXX questionable use of errno
      LOG(prefix << qname << ": Error resolving from " << remoteIP.toString() << (doTCP ? " over TCP" : "") << ", possible error: " << stringerror() << endl);
    }

    if (resolveret != LWResult::Result::OSLimitError && !chained && !dontThrottle) {
      // don't account for resource limits, they are our own fault
      // And don't throttle when the IP address is on the dontThrottleNetmasks list or the name is part of dontThrottleNames
      s_nsSpeeds.lock()->find_or_enter(nsName.empty() ? DNSName(remoteIP.toStringWithPort()) : nsName, d_now).submit(remoteIP, 1000000, d_now); // 1 sec

      // code below makes sure we don't filter COM or the root
      if (s_serverdownmaxfails > 0 && (auth != g_rootdnsname) && s_fails.lock()->incr(remoteIP, d_now) >= s_serverdownmaxfails) {
        LOG(prefix << qname << ": Max fails reached resolving on " << remoteIP.toString() << ". Going full throttle for " << s_serverdownthrottletime << " seconds" << endl);
        // mark server as down
        doThrottle(d_now.tv_sec, remoteIP, s_serverdownthrottletime, 10000);
      }
      else if (resolveret == LWResult::Result::PermanentError) {
        // unreachable, 1 minute or 100 queries
        doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 60, 100);
      }
      else {
        // timeout, 10 seconds or 5 queries
        doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 10, 5);
      }
    }

    return false;
  }

  if (lwr.d_validpacket == false) {
    LOG(prefix << qname << ": " << nsName << " (" << remoteIP.toString() << ") returned a packet we could not parse over " << (doTCP ? "TCP" : "UDP") << ", trying sibling IP or NS" << endl);
    if (!chained && !dontThrottle) {

      // let's make sure we prefer a different server for some time, if there is one available
      s_nsSpeeds.lock()->find_or_enter(nsName.empty() ? DNSName(remoteIP.toStringWithPort()) : nsName, d_now).submit(remoteIP, 1000000, d_now); // 1 sec

      if (doTCP) {
        // we can be more heavy-handed over TCP
        doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 60, 10);
      }
      else {
        doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 10, 2);
      }
    }
    return false;
  }
  else {
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
          doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 60, 3);
        }
      }
      return false;
    }
  }

  /* this server sent a valid answer, mark it backup up if it was down */
  if (s_serverdownmaxfails > 0) {
    s_fails.lock()->clear(remoteIP);
  }

  if (lwr.d_tcbit) {
    truncated = true;

    if (doTCP) {
      LOG(prefix << qname << ": Truncated bit set, over TCP?" << endl);
      if (!dontThrottle) {
        /* let's treat that as a ServFail answer from this server */
        doThrottle(d_now.tv_sec, remoteIP, qname, qtype, 60, 3);
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

  // Was 10 originally, default s_maxdepth is 40, but even if it is zero we want to apply a bound
  auto bound = std::max(40U, getAdjustedRecursionBound()) / 4;
  if (depth > bound) {
    LOG(prefix << qname << ": Status=got a CNAME referral, but recursing too deep, returning SERVFAIL" << endl);
    rcode = RCode::ServFail;
    return;
  }

  if (!d_followCNAME) {
    rcode = RCode::NoError;
    return;
  }

  // Check to see if we already have seen the new target as a previous target
  if (scanForCNAMELoop(newtarget, ret)) {
    LOG(prefix << qname << ": Status=got a CNAME referral that causes a loop, returning SERVFAIL" << endl);
    ret.clear();
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

bool SyncRes::processAnswer(unsigned int depth, const string& prefix, LWResult& lwr, const DNSName& qname, const QType qtype, DNSName& auth, bool wasForwarded, const boost::optional<Netmask> ednsmask, bool sendRDQuery, NsSet& nameservers, std::vector<DNSRecord>& ret, const DNSFilterEngine& dfe, bool* gotNewServers, int* rcode, vState& state, const ComboAddress& remoteIP)
{
  if (s_minimumTTL) {
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
  *rcode = updateCacheFromRecords(depth, prefix, lwr, qname, qtype, auth, wasForwarded, ednsmask, state, needWildcardProof, gatherWildcardProof, wildcardLabelsCount, sendRDQuery, remoteIP);
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

  if (nsset.empty() && !lwr.d_rcode && (negindic || lwr.d_aabit || sendRDQuery)) {
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
    auth = newauth;

    return false;
  }

  return false;
}

bool SyncRes::doDoTtoAuth(const DNSName& ns) const
{
  return g_DoTToAuthNames.getLocal()->check(ns);
}

/** returns:
 *  -1 in case of no results
 *  rcode otherwise
 */
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
      int newLimit = static_cast<int>(nsLimit) - (rnameservers.size() - nsLimit);
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
      boost::optional<Netmask> ednsmask;
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
        bool done = processAnswer(depth, prefix, lwr, qname, qtype, auth, false, ednsmask, sendRDQuery, nameservers, ret, luaconfsLocal->dfe, &gotNewServers, &rcode, context.state, s_oobRemote);
        if (done) {
          return rcode;
        }
        if (gotNewServers) {
          if (stopAtDelegation && *stopAtDelegation == Stop) {
            *stopAtDelegation = Stopped;
            return rcode;
          }
          break;
        }
      }
      else {
        if (fallBack != nullptr) {
          if (auto it = fallBack->find(tns->first); it != fallBack->end()) {
            remoteIPs = it->second;
          }
        }
        if (remoteIPs.size() == 0) {
          remoteIPs = retrieveAddressesForNS(prefix, qname, tns, depth, beenthere, rnameservers, nameservers, sendRDQuery, pierceDontQuery, flawedNSSet, cacheOnly, addressQueriesForNS);
        }

        if (remoteIPs.empty()) {
          LOG(prefix << qname << ": Failed to get IP for NS " << tns->first << ", trying next if available" << endl);
          flawedNSSet = true;
          continue;
        }
        else {
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
          bool forceTCP = doDoT;

          if (!doDoT && s_max_busy_dot_probes > 0) {
            submitTryDotTask(*remoteIP, auth, tns->first, d_now.tv_sec);
          }
          if (!forceTCP) {
            gotAnswer = doResolveAtThisIP(prefix, qname, qtype, lwr, ednsmask, auth, sendRDQuery, wasForwarded,
                                          tns->first, *remoteIP, false, false, truncated, spoofed, context.extendedError);
          }
          if (forceTCP || (spoofed || (gotAnswer && truncated))) {
            /* retry, over TCP this time */
            gotAnswer = doResolveAtThisIP(prefix, qname, qtype, lwr, ednsmask, auth, sendRDQuery, wasForwarded,
                                          tns->first, *remoteIP, true, doDoT, truncated, spoofed, context.extendedError);
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

          s_nsSpeeds.lock()->find_or_enter(tns->first.empty() ? DNSName(remoteIP->toStringWithPort()) : tns->first, d_now).submit(*remoteIP, lwr.d_usec, d_now);

          /* we have received an answer, are we done ? */
          bool done = processAnswer(depth, prefix, lwr, qname, qtype, auth, wasForwarded, ednsmask, sendRDQuery, nameservers, ret, luaconfsLocal->dfe, &gotNewServers, &rcode, context.state, *remoteIP);
          if (done) {
            return rcode;
          }
          if (gotNewServers) {
            if (stopAtDelegation && *stopAtDelegation == Stop) {
              *stopAtDelegation = Stopped;
              return rcode;
            }
            break;
          }
          /* was lame */
          doThrottle(d_now.tv_sec, *remoteIP, qname, qtype, 60, 100);
        }

        if (gotNewServers) {
          break;
        }

        if (remoteIP == remoteIPs.cend()) // we tried all IP addresses, none worked
          continue;
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
    d_outgoingECSNetwork = boost::none;
  }
}

void SyncRes::setQuerySource(const ComboAddress& requestor, boost::optional<const EDNSSubnetOpts&> incomingECS)
{
  d_requestor = requestor;

  if (incomingECS && incomingECS->source.getBits() > 0) {
    d_cacheRemote = incomingECS->source.getMaskedNetwork();
    uint8_t bits = std::min(incomingECS->source.getBits(), (incomingECS->source.isIPv4() ? s_ecsipv4limit : s_ecsipv6limit));
    ComboAddress trunc = incomingECS->source.getNetwork();
    trunc.truncate(bits);
    d_outgoingECSNetwork = boost::optional<Netmask>(Netmask(trunc, bits));
  }
  else {
    d_cacheRemote = d_requestor;
    if (!incomingECS && s_ednslocalsubnets.match(d_requestor)) {
      ComboAddress trunc = d_requestor;
      uint8_t bits = d_requestor.isIPv4() ? 32 : 128;
      bits = std::min(bits, (trunc.isIPv4() ? s_ecsipv4limit : s_ecsipv6limit));
      trunc.truncate(bits);
      d_outgoingECSNetwork = boost::optional<Netmask>(Netmask(trunc, bits));
    }
    else if (s_ecsScopeZero.source.getBits() > 0) {
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
      d_outgoingECSNetwork = boost::optional<Netmask>(s_ecsScopeZero.source.getMaskedNetwork());
      d_cacheRemote = s_ecsScopeZero.source.getNetwork();
    }
    else {
      // ECS disabled because no scope-zero address could be derived.
      d_outgoingECSNetwork = boost::none;
    }
  }
}

boost::optional<Netmask> SyncRes::getEDNSSubnetMask(const DNSName& dn, const ComboAddress& rem)
{
  if (d_outgoingECSNetwork && (s_ednsdomains.check(dn) || s_ednsremotesubnets.match(rem))) {
    return d_outgoingECSNetwork;
  }
  return boost::none;
}

void SyncRes::parseEDNSSubnetAllowlist(const std::string& alist)
{
  vector<string> parts;
  stringtok(parts, alist, ",; ");
  for (const auto& a : parts) {
    try {
      s_ednsremotesubnets.addMask(Netmask(a));
    }
    catch (...) {
      s_ednsdomains.add(DNSName(a));
    }
  }
}

void SyncRes::parseEDNSSubnetAddFor(const std::string& subnetlist)
{
  vector<string> parts;
  stringtok(parts, subnetlist, ",; ");
  for (const auto& a : parts) {
    s_ednslocalsubnets.addMask(a);
  }
}

// used by PowerDNSLua - note that this neglects to add the packet count & statistics back to pdns_recursor.cc
int directResolve(const DNSName& qname, const QType qtype, const QClass qclass, vector<DNSRecord>& ret, shared_ptr<RecursorLua4> pdl, Logr::log_t log)
{
  return directResolve(qname, qtype, qclass, ret, pdl, SyncRes::s_qnameminimization, log);
}

int directResolve(const DNSName& qname, const QType qtype, const QClass qclass, vector<DNSRecord>& ret, shared_ptr<RecursorLua4> pdl, bool qm, Logr::log_t slog)
{
  auto log = slog->withValues("qname", Logging::Loggable(qname), "qtype", Logging::Loggable(qtype));

  struct timeval now;
  gettimeofday(&now, 0);

  SyncRes sr(now);
  sr.setQNameMinimization(qm);
  if (pdl) {
    sr.setLuaEngine(pdl);
  }

  int res = -1;
  const std::string msg = "Exception while resolving";
  try {
    res = sr.beginResolve(qname, qtype, qclass, ret, 0);
  }
  catch (const PDNSException& e) {
    SLOG(g_log << Logger::Error << "Failed to resolve " << qname << ", got pdns exception: " << e.reason << endl,
         log->error(Logr::Error, e.reason, msg, "exception", Logging::Loggable("PDNSException")));
    ret.clear();
  }
  catch (const ImmediateServFailException& e) {
    SLOG(g_log << Logger::Error << "Failed to resolve " << qname << ", got ImmediateServFailException: " << e.reason << endl,
         log->error(Logr::Error, e.reason, msg, "exception", Logging::Loggable("ImmediateServFailException")));
    ret.clear();
  }
  catch (const PolicyHitException& e) {
    SLOG(g_log << Logger::Error << "Failed to resolve " << qname << ", got a policy hit" << endl,
         log->info(Logr::Error, msg, "exception", Logging::Loggable("PolicyHitException")));
    ret.clear();
  }
  catch (const std::exception& e) {
    SLOG(g_log << Logger::Error << "Failed to resolve " << qname << ", got STL error: " << e.what() << endl,
         log->error(Logr::Error, e.what(), msg, "exception", Logging::Loggable("std::exception")));
    ret.clear();
  }
  catch (...) {
    SLOG(g_log << Logger::Error << "Failed to resolve " << qname << ", got an exception" << endl,
         log->info(Logr::Error, msg));
    ret.clear();
  }

  return res;
}

int SyncRes::getRootNS(struct timeval now, asyncresolve_t asyncCallback, unsigned int depth, Logr::log_t log)
{
  SyncRes sr(now);
  sr.d_prefix = "[getRootNS]";
  sr.setDoEDNS0(true);
  sr.setUpdatingRootNS();
  sr.setDoDNSSEC(g_dnssecmode != DNSSECMode::Off);
  sr.setDNSSECValidationRequested(g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate);
  sr.setAsyncCallback(asyncCallback);
  sr.setRefreshAlmostExpired(true);

  const string msg = "Failed to update . records";
  vector<DNSRecord> ret;
  int res = -1;
  try {
    res = sr.beginResolve(g_rootdnsname, QType::NS, 1, ret, depth + 1);
    if (g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate) {
      auto state = sr.getValidationState();
      if (vStateIsBogus(state)) {
        throw PDNSException("Got Bogus validation result for .|NS");
      }
    }
  }
  catch (const PDNSException& e) {
    SLOG(g_log << Logger::Error << "Failed to update . records, got an exception: " << e.reason << endl,
         log->error(Logr::Error, e.reason, msg, "exception", Logging::Loggable("PDNSException")));
  }
  catch (const ImmediateServFailException& e) {
    SLOG(g_log << Logger::Error << "Failed to update . records, got an exception: " << e.reason << endl,
         log->error(Logr::Error, e.reason, msg, "exception", Logging::Loggable("ImmediateServFailException")));
  }
  catch (const PolicyHitException& e) {
    SLOG(g_log << Logger::Error << "Failed to update . records, got a policy hit" << endl,
         log->info(Logr::Error, msg, "exception", Logging::Loggable("PolicyHitException")));
    ret.clear();
  }
  catch (const std::exception& e) {
    SLOG(g_log << Logger::Error << "Failed to update . records, got an exception: " << e.what() << endl,
         log->error(Logr::Error, e.what(), msg, "exception", Logging::Loggable("std::exception")));
  }
  catch (...) {
    SLOG(g_log << Logger::Error << "Failed to update . records, got an exception" << endl,
         log->info(Logr::Error, msg));
  }

  if (res == 0) {
    SLOG(g_log << Logger::Debug << "Refreshed . records" << endl,
         log->info(Logr::Debug, "Refreshed . records"));
  }
  else {
    SLOG(g_log << Logger::Warning << "Failed to update root NS records, RCODE=" << res << endl,
         log->info(Logr::Warning, msg, "rcode", Logging::Loggable(res)));
  }
  return res;
}
