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
#include "dns_random.hh"

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
      poss.at(usableServers) = std::pair(std::tuple(d.second->outstanding.load(), d.second->d_config.order, d.second->getRelevantLatencyUsec()), d.first);
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
  (void)dq;
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

template <class T> static std::shared_ptr<DownstreamState> getValRandom(const ServerPolicy::NumberedServerVector& servers, T& poss, const unsigned int val, const double targetLoad)
{
  constexpr int max = std::numeric_limits<int>::max();
  int sum = 0;

  size_t usableServers = 0;
  const auto weightedBalancingFactor = dnsdist::configuration::getImmutableConfiguration().d_weightedBalancingFactor;
  for (const auto& d : servers) {      // w=1, w=10 -> 1, 11
    if (d.second->isUp() && (weightedBalancingFactor == 0 || (static_cast<double>(d.second->outstanding.load()) <= (targetLoad * d.second->d_config.d_weight)))) {
      // Don't overflow sum when adding high weights
      if (d.second->d_config.d_weight > max - sum) {
        sum = max;
      } else {
        sum += d.second->d_config.d_weight;
      }

      poss.at(usableServers) = std::pair(sum, d.first);
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
  const auto weightedBalancingFactor = dnsdist::configuration::getImmutableConfiguration().d_weightedBalancingFactor;
  if (weightedBalancingFactor > 0) {
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
      targetLoad = (currentLoad / static_cast<double>(totalWeight)) * weightedBalancingFactor;
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
  (void)dq;
  return valrandom(dns_random_uint32(), servers);
}

shared_ptr<DownstreamState> whashedFromHash(const ServerPolicy::NumberedServerVector& servers, size_t hash)
{
  return valrandom(hash, servers);
}

shared_ptr<DownstreamState> whashed(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq)
{
  const auto hashPerturbation = dnsdist::configuration::getImmutableConfiguration().d_hashPerturbation;
  return whashedFromHash(servers, dq->ids.qname.hash(hashPerturbation));
}

shared_ptr<DownstreamState> chashedFromHash(const ServerPolicy::NumberedServerVector& servers, size_t qhash)
{
  unsigned int sel = std::numeric_limits<unsigned int>::max();
  unsigned int min = std::numeric_limits<unsigned int>::max();
  shared_ptr<DownstreamState> ret = nullptr, first = nullptr;

  double targetLoad = std::numeric_limits<double>::max();
  const auto consistentHashBalancingFactor = dnsdist::configuration::getImmutableConfiguration().d_consistentHashBalancingFactor;
  if (consistentHashBalancingFactor > 0) {
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
      targetLoad = (currentLoad / static_cast<double>(totalWeight)) * consistentHashBalancingFactor;
    }
  }

  for (const auto& d: servers) {
    if (d.second->isUp() && (consistentHashBalancingFactor == 0 || static_cast<double>(d.second->outstanding.load()) <= (targetLoad * d.second->d_config.d_weight))) {
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
  const auto hashPerturbation = dnsdist::configuration::getImmutableConfiguration().d_hashPerturbation;
  return chashedFromHash(servers, dq->ids.qname.hash(hashPerturbation));
}

shared_ptr<DownstreamState> roundrobin(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq)
{
  (void)dq;
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
    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_roundrobinFailOnNoServer) {
      return shared_ptr<DownstreamState>();
    }
    for (auto& d : servers) {
      candidates.push_back(d.first);
    }
  }

  static unsigned int counter;
  return servers.at(candidates.at((counter++) % candidates.size()) - 1).second;
}

shared_ptr<DownstreamState> orderedWrandUntag(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsq)
{
  if (servers.empty()) {
    return {};
  }

  ServerPolicy::NumberedServerVector candidates;
  candidates.reserve(servers.size());

  int curOrder = std::numeric_limits<int>::max();
  unsigned int startIndex = 0;
  unsigned int curNumber = 1;

  for (const auto& svr : servers) {
    if (svr.second->isUp() && svr.second->d_config.order <= curOrder && (!dnsq->ids.qTag || dnsq->ids.qTag->count(svr.second->getNameWithAddr()) == 0)) {
      if (svr.second->d_config.order < curOrder) {
          curOrder = svr.second->d_config.order;
          startIndex = candidates.end() - candidates.begin();
          curNumber = 1;
      }
      candidates.push_back(ServerPolicy::NumberedServer(curNumber++, svr.second));
    }
  }

  if (candidates.empty()) {
    return {};
  }

  ServerPolicy::NumberedServerVector selected(candidates.begin() + startIndex, candidates.end());
  return wrandom(selected, dnsq);
}

std::shared_ptr<const ServerPolicy::NumberedServerVector> getDownstreamCandidates(const std::string& poolName)
{
  std::shared_ptr<ServerPool> pool = getPool(poolName);
  return pool->getServers();
}

std::shared_ptr<ServerPool> createPoolIfNotExists(const string& poolName)
{
  {
    const auto& pools = dnsdist::configuration::getCurrentRuntimeConfiguration().d_pools;
    const auto poolIt = pools.find(poolName);
    if (poolIt != pools.end()) {
      return poolIt->second;
    }
  }

  if (!poolName.empty()) {
    vinfolog("Creating pool %s", poolName);
  }

  auto pool = std::make_shared<ServerPool>();
  dnsdist::configuration::updateRuntimeConfiguration([&poolName,&pool](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_pools.emplace(poolName, pool);
  });

  return pool;
}

void setPoolPolicy(const string& poolName, std::shared_ptr<ServerPolicy> policy)
{
  std::shared_ptr<ServerPool> pool = createPoolIfNotExists(poolName);
  if (!poolName.empty()) {
    vinfolog("Setting pool %s server selection policy to %s", poolName, policy->getName());
  } else {
    vinfolog("Setting default pool server selection policy to %s", policy->getName());
  }
  pool->policy = std::move(policy);
}

void addServerToPool(const string& poolName, std::shared_ptr<DownstreamState> server)
{
  std::shared_ptr<ServerPool> pool = createPoolIfNotExists(poolName);
  if (!poolName.empty()) {
    vinfolog("Adding server to pool %s", poolName);
  } else {
    vinfolog("Adding server to default pool");
  }
  pool->addServer(server);
}

void removeServerFromPool(const string& poolName, std::shared_ptr<DownstreamState> server)
{
  std::shared_ptr<ServerPool> pool = getPool(poolName);

  if (!poolName.empty()) {
    vinfolog("Removing server from pool %s", poolName);
  }
  else {
    vinfolog("Removing server from default pool");
  }

  pool->removeServer(server);
}

std::shared_ptr<ServerPool> getPool(const std::string& poolName)
{
  const auto& pools = dnsdist::configuration::getCurrentRuntimeConfiguration().d_pools;
  auto poolIt = pools.find(poolName);
  if (poolIt == pools.end()) {
    throw std::out_of_range("No pool named " + poolName);
  }

  return poolIt->second;
}

ServerPolicy::ServerPolicy(const std::string& name_, const std::string& code): d_name(name_), d_perThreadPolicyCode(code), d_isLua(true), d_isFFI(true), d_isPerThread(true)
{
  LuaContext tmpContext;
  setupLuaLoadBalancingContext(tmpContext);
  auto ret = tmpContext.executeCode<ServerPolicy::ffipolicyfunc_t>(code);
}

struct ServerPolicy::PerThreadState
{
  LuaContext d_luaContext;
  std::unordered_map<std::string, ffipolicyfunc_t> d_policies;
};

thread_local std::unique_ptr<ServerPolicy::PerThreadState> ServerPolicy::t_perThreadState;

const ServerPolicy::ffipolicyfunc_t& ServerPolicy::getPerThreadPolicy() const
{
  auto& state = t_perThreadState;
  if (!state) {
    state = std::make_unique<ServerPolicy::PerThreadState>();
    setupLuaLoadBalancingContext(state->d_luaContext);
  }

  const auto& policyIt = state->d_policies.find(d_name);
  if (policyIt != state->d_policies.end()) {
    return policyIt->second;
  }

  auto newPolicy = state->d_luaContext.executeCode<ServerPolicy::ffipolicyfunc_t>(d_perThreadPolicyCode);
  state->d_policies[d_name] = std::move(newPolicy);
  return state->d_policies.at(d_name);
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

      if (selected >= servers.size()) {
        /* invalid offset, meaning that there is no server available */
        return {};
      }

      selectedBackend = servers.at(selected).second;
    }
  }
  else {
    selectedBackend = d_policy(servers, &dq);
  }

  return selectedBackend;
}

namespace dnsdist::lbpolicies
{
const std::vector<std::shared_ptr<ServerPolicy>>& getBuiltInPolicies()
{
  static const std::vector<std::shared_ptr<ServerPolicy>> s_policies{
    std::make_shared<ServerPolicy>("firstAvailable", firstAvailable, false),
    std::make_shared<ServerPolicy>("roundrobin", roundrobin, false),
    std::make_shared<ServerPolicy>("wrandom", wrandom, false),
    std::make_shared<ServerPolicy>("whashed", whashed, false),
    std::make_shared<ServerPolicy>("chashed", chashed, false),
    std::make_shared<ServerPolicy>("orderedWrandUntag", orderedWrandUntag, false),
    std::make_shared<ServerPolicy>("leastOutstanding", leastOutstanding, false)};
  return s_policies;
}
}
