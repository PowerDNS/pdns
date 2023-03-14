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

#include "dnsdist.hh"
#include "dnsdist-lbpolicies.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-ffi.hh"
#include "dolog.hh"

GlobalStateHolder<ServerPolicy> g_policy;
bool g_roundrobinFailOnNoServer{false};

static constexpr size_t s_staticArrayCutOff = 16;
template <typename T> using DynamicIndexArray = std::vector<std::pair<T, size_t>>;
template <typename T> using StaticIndexArray = std::array<std::pair<T, size_t>, s_staticArrayCutOff>;

template <class T> static std::shared_ptr<DownstreamState> getLeastOutstanding(const ServerPolicy::NumberedServerVector& servers, T& poss)
{
  /* so you might wonder, why do we go through this trouble? The data on which we sort could change during the sort,
     which would suck royally and could even lead to crashes. So first we snapshot on what we sort, and then we sort */
  size_t usableServers = 0;
  for (const auto& d : servers) {
    if (d.second->isUp()) {
      poss[usableServers] = std::make_pair(std::make_tuple(d.second->outstanding.load(), d.second->d_config.order, d.second->getRelevantLatencyUsec()), d.first);
      usableServers++;
    }
  }

  if (usableServers == 0) {
    return shared_ptr<DownstreamState>();
  }

  std::nth_element(poss.begin(), poss.begin(), poss.begin() + usableServers, [](const typename T::value_type& a, const typename T::value_type& b) { return a.first < b.first; });
  // minus 1 because the NumberedServerVector starts at 1 for Lua
  return servers.at(poss.begin()->second - 1).second;
}

// get server with least outstanding queries, and within those, with the lowest order, and within those: the fastest
shared_ptr<DownstreamState> leastOutstanding(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq)
{
  using LeastOutstandingType = std::tuple<int,int,double>;

  if (servers.size() == 1 && servers[0].second->isUp()) {
    return servers[0].second;
  }

  if (servers.size() <= s_staticArrayCutOff) {
    StaticIndexArray<LeastOutstandingType> poss;
    return getLeastOutstanding(servers, poss);
  }

  DynamicIndexArray<LeastOutstandingType> poss;
  poss.resize(servers.size());
  return getLeastOutstanding(servers, poss);
}

shared_ptr<DownstreamState> firstAvailable(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq)
{
  for (auto& d : servers) {
    if (d.second->isUp() && d.second->qps.checkOnly()) {
      return d.second;
    }
  }
  return leastOutstanding(servers, dq);
}

double g_weightedBalancingFactor = 0;

template <class T> static std::shared_ptr<DownstreamState> getValRandom(const ServerPolicy::NumberedServerVector& servers, T& poss, const unsigned int val, const double targetLoad)
{
  constexpr int max = std::numeric_limits<int>::max();
  int sum = 0;

  size_t usableServers = 0;
  for (const auto& d : servers) {      // w=1, w=10 -> 1, 11
    if (d.second->isUp() && (g_weightedBalancingFactor == 0 || (d.second->outstanding <= (targetLoad * d.second->d_config.d_weight)))) {
      // Don't overflow sum when adding high weights
      if (d.second->d_config.d_weight > max - sum) {
        sum = max;
      } else {
        sum += d.second->d_config.d_weight;
      }

      poss[usableServers]  = std::make_pair(sum, d.first);
      usableServers++;
    }
  }

  // Catch the case where usableServers or sum are equal to 0 to avoid a SIGFPE
  if (usableServers == 0 || sum == 0) {
    return shared_ptr<DownstreamState>();
  }

  int r = val % sum;
  auto p = std::upper_bound(poss.begin(), poss.begin() + usableServers, r, [](int r_, const typename T::value_type& a) { return  r_ < a.first;});
  if (p == poss.begin() + usableServers) {
    return shared_ptr<DownstreamState>();
  }

  // minus 1 because the NumberedServerVector starts at 1 for Lua
  return servers.at(p->second - 1).second;
}

static shared_ptr<DownstreamState> valrandom(const unsigned int val, const ServerPolicy::NumberedServerVector& servers)
{
  using ValRandomType = int;
  double targetLoad = std::numeric_limits<double>::max();

  if (g_weightedBalancingFactor > 0) {
    /* we start with one, representing the query we are currently handling */
    double currentLoad = 1;
    size_t totalWeight = 0;
    for (const auto& pair : servers) {
      if (pair.second->isUp()) {
        currentLoad += pair.second->outstanding;
        totalWeight += pair.second->d_config.d_weight;
      }
    }

    if (totalWeight > 0) {
      targetLoad = (currentLoad / totalWeight) * g_weightedBalancingFactor;
    }
  }

  if (servers.size() <= s_staticArrayCutOff) {
    StaticIndexArray<ValRandomType> poss;
    return getValRandom(servers, poss, val, targetLoad);
  }

  DynamicIndexArray<ValRandomType> poss;
  poss.resize(servers.size());
  return getValRandom(servers, poss, val, targetLoad);
}

shared_ptr<DownstreamState> wrandom(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq)
{
  return valrandom(random(), servers);
}

uint32_t g_hashperturb;
double g_consistentHashBalancingFactor = 0;

shared_ptr<DownstreamState> whashedFromHash(const ServerPolicy::NumberedServerVector& servers, size_t hash)
{
  return valrandom(hash, servers);
}

shared_ptr<DownstreamState> whashed(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq)
{
  return whashedFromHash(servers, dq->ids.qname.hash(g_hashperturb));
}

shared_ptr<DownstreamState> chashedFromHash(const ServerPolicy::NumberedServerVector& servers, size_t qhash)
{
  unsigned int sel = std::numeric_limits<unsigned int>::max();
  unsigned int min = std::numeric_limits<unsigned int>::max();
  shared_ptr<DownstreamState> ret = nullptr, first = nullptr;

  double targetLoad = std::numeric_limits<double>::max();
  if (g_consistentHashBalancingFactor > 0) {
    /* we start with one, representing the query we are currently handling */
    double currentLoad = 1;
    size_t totalWeight = 0;
    for (const auto& pair : servers) {
      if (pair.second->isUp()) {
        currentLoad += pair.second->outstanding;
        totalWeight += pair.second->d_config.d_weight;
      }
    }

    if (totalWeight > 0) {
      targetLoad = (currentLoad / totalWeight) * g_consistentHashBalancingFactor;
    }
  }

  for (const auto& d: servers) {
    if (d.second->isUp() && (g_consistentHashBalancingFactor == 0 || d.second->outstanding <= (targetLoad * d.second->d_config.d_weight))) {
      // make sure hashes have been computed
      if (!d.second->hashesComputed) {
        d.second->hash();
      }
      {
        const auto& server = d.second;
        auto hashes = server->hashes.read_lock();
        // we want to keep track of the last hash
        if (min > *(hashes->begin())) {
          min = *(hashes->begin());
          first = server;
        }

        auto hash_it = std::lower_bound(hashes->begin(), hashes->end(), qhash);
        if (hash_it != hashes->end()) {
          if (*hash_it < sel) {
            sel = *hash_it;
            ret = server;
          }
        }
      }
    }
  }
  if (ret != nullptr) {
    return ret;
  }
  if (first != nullptr) {
    return first;
  }
  return shared_ptr<DownstreamState>();
}

shared_ptr<DownstreamState> chashed(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq)
{
  return chashedFromHash(servers, dq->ids.qname.hash(g_hashperturb));
}

shared_ptr<DownstreamState> roundrobin(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq)
{
  if (servers.empty()) {
    return shared_ptr<DownstreamState>();
  }

  vector<size_t> candidates;
  candidates.reserve(servers.size());

  for (auto& d : servers) {
    if (d.second->isUp()) {
      candidates.push_back(d.first);
    }
  }

  if (candidates.empty()) {
    if (g_roundrobinFailOnNoServer) {
      return shared_ptr<DownstreamState>();
    }
    for (auto& d : servers) {
      candidates.push_back(d.first);
    }
  }

  static unsigned int counter;
  return servers.at(candidates.at((counter++) % candidates.size()) - 1).second;
}

const std::shared_ptr<const ServerPolicy::NumberedServerVector> getDownstreamCandidates(const pools_t& pools, const std::string& poolName)
{
  std::shared_ptr<ServerPool> pool = getPool(pools, poolName);
  return pool->getServers();
}

std::shared_ptr<ServerPool> createPoolIfNotExists(pools_t& pools, const string& poolName)
{
  std::shared_ptr<ServerPool> pool;
  pools_t::iterator it = pools.find(poolName);
  if (it != pools.end()) {
    pool = it->second;
  }
  else {
    if (!poolName.empty())
      vinfolog("Creating pool %s", poolName);
    pool = std::make_shared<ServerPool>();
    pools.insert(std::pair<std::string, std::shared_ptr<ServerPool> >(poolName, pool));
  }
  return pool;
}

void setPoolPolicy(pools_t& pools, const string& poolName, std::shared_ptr<ServerPolicy> policy)
{
  std::shared_ptr<ServerPool> pool = createPoolIfNotExists(pools, poolName);
  if (!poolName.empty()) {
    vinfolog("Setting pool %s server selection policy to %s", poolName, policy->getName());
  } else {
    vinfolog("Setting default pool server selection policy to %s", policy->getName());
  }
  pool->policy = policy;
}

void addServerToPool(pools_t& pools, const string& poolName, std::shared_ptr<DownstreamState> server)
{
  std::shared_ptr<ServerPool> pool = createPoolIfNotExists(pools, poolName);
  if (!poolName.empty()) {
    vinfolog("Adding server to pool %s", poolName);
  } else {
    vinfolog("Adding server to default pool");
  }
  pool->addServer(server);
}

void removeServerFromPool(pools_t& pools, const string& poolName, std::shared_ptr<DownstreamState> server)
{
  std::shared_ptr<ServerPool> pool = getPool(pools, poolName);

  if (!poolName.empty()) {
    vinfolog("Removing server from pool %s", poolName);
  }
  else {
    vinfolog("Removing server from default pool");
  }

  pool->removeServer(server);
}

std::shared_ptr<ServerPool> getPool(const pools_t& pools, const std::string& poolName)
{
  pools_t::const_iterator it = pools.find(poolName);

  if (it == pools.end()) {
    throw std::out_of_range("No pool named " + poolName);
  }

  return it->second;
}

ServerPolicy::ServerPolicy(const std::string& name_, const std::string& code): d_name(name_), d_perThreadPolicyCode(code), d_isLua(true), d_isFFI(true), d_isPerThread(true)
{
  LuaContext tmpContext;
  setupLuaLoadBalancingContext(tmpContext);
  auto ret = tmpContext.executeCode<ServerPolicy::ffipolicyfunc_t>(code);
}

thread_local ServerPolicy::PerThreadState ServerPolicy::t_perThreadState;

const ServerPolicy::ffipolicyfunc_t& ServerPolicy::getPerThreadPolicy() const
{
  auto& state = t_perThreadState;
  if (!state.d_initialized) {
    setupLuaLoadBalancingContext(state.d_luaContext);
    state.d_initialized = true;
  }

  const auto& it = state.d_policies.find(d_name);
  if (it != state.d_policies.end()) {
    return it->second;
  }

  auto newPolicy = state.d_luaContext.executeCode<ServerPolicy::ffipolicyfunc_t>(d_perThreadPolicyCode);
  state.d_policies[d_name] = std::move(newPolicy);
  return state.d_policies.at(d_name);
}

std::shared_ptr<DownstreamState> ServerPolicy::getSelectedBackend(const ServerPolicy::NumberedServerVector& servers, DNSQuestion& dq) const
{
  std::shared_ptr<DownstreamState> selectedBackend{nullptr};

  if (d_isLua) {
    if (!d_isFFI) {
      auto lock = g_lua.lock();
      selectedBackend = d_policy(servers, &dq);
    }
    else {
      dnsdist_ffi_dnsquestion_t dnsq(&dq);
      dnsdist_ffi_servers_list_t serversList(servers);
      unsigned int selected = 0;

      if (!d_isPerThread) {
        auto lock = g_lua.lock();
        selected = d_ffipolicy(&serversList, &dnsq);
      }
      else {
        const auto& policy = getPerThreadPolicy();
        selected = policy(&serversList, &dnsq);
      }

      selectedBackend = servers.at(selected).second;
    }
  }
  else {
    selectedBackend = d_policy(servers, &dq);
  }

  return selectedBackend;
}
