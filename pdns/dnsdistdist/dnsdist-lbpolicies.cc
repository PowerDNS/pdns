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

static std::optional<ServerPolicy::SelectedServerPosition> getLeastOutstanding(const ServerPolicy::NumberedServerVector& servers)
{
  std::optional<ServerPolicy::SelectedServerPosition> best;
  uint64_t leastOutstandingSeen = std::numeric_limits<uint64_t>::max();
  int lowestOrderSeen = std::numeric_limits<int>::max();
  double lowestLatencySeen = std::numeric_limits<double>::max();

  for (const auto& server : servers) {
    if (!server.second->isUp()) {
      continue;
    }

    auto outstanding = server.second->outstanding.load();
    auto order = server.second->d_config.order;
    if (outstanding > leastOutstandingSeen) {
      continue;
    }
    if (outstanding < leastOutstandingSeen) {
      best = server.first;
      leastOutstandingSeen = outstanding;
      lowestOrderSeen = order;
      lowestLatencySeen = server.second->getRelevantLatencyUsec();
      continue;
    }
    if (order > lowestOrderSeen) {
      continue;
    }
    auto latency = server.second->getRelevantLatencyUsec();
    if (latency < lowestLatencySeen) {
      best = server.first;
      leastOutstandingSeen = outstanding;
      lowestOrderSeen = order;
      lowestLatencySeen = server.second->getRelevantLatencyUsec();
    }
  }

  return best;
}

// get server with least outstanding queries, and within those, with the lowest order, and within those: the fastest
std::optional<ServerPolicy::SelectedServerPosition> leastOutstanding(const ServerPolicy::NumberedServerVector& servers, [[maybe_unused]] const DNSQuestion* dnsQuestion)
{
  if (servers.size() == 1 && servers[0].second->isUp()) {
    return 1;
  }

  return getLeastOutstanding(servers);
}

std::optional<ServerPolicy::SelectedServerPosition> firstAvailable(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion)
{
  for (const auto& server : servers) {
    if (server.second->isUp() && (!server.second->d_qpsLimiter || server.second->d_qpsLimiter->checkOnly())) {
      return server.first;
    }
  }
  return leastOutstanding(servers, dnsQuestion);
}

template <class T> static std::optional<ServerPolicy::SelectedServerPosition> getValRandom(const ServerPolicy::NumberedServerVector& servers, T& poss, const unsigned int val, const double targetLoad)
{
  constexpr int max = std::numeric_limits<int>::max();
  int sum = 0;

  size_t usableServers = 0;
  const auto weightedBalancingFactor = dnsdist::configuration::getImmutableConfiguration().d_weightedBalancingFactor;
  for (const auto& server : servers) {      // w=1, w=10 -> 1, 11
    if (server.second->isUp() && (weightedBalancingFactor == 0 || (static_cast<double>(server.second->outstanding.load()) <= (targetLoad * server.second->d_config.d_weight)))) {
      // Don't overflow sum when adding high weights
      if (server.second->d_config.d_weight > max - sum) {
        sum = max;
      } else {
        sum += server.second->d_config.d_weight;
      }

      poss.at(usableServers) = std::pair(sum, server.first);
      usableServers++;
    }
  }

  // Catch the case where usableServers or sum are equal to 0 to avoid a SIGFPE
  if (usableServers == 0 || sum == 0) {
    return std::nullopt;
  }

  int randomVal = static_cast<int>(val % sum);
  auto selected = std::upper_bound(poss.begin(), poss.begin() + usableServers, randomVal, [](int randomVal_, const typename T::value_type& serverPair) { return  randomVal_ < serverPair.first;});
  if (selected == poss.begin() + usableServers) {
    return std::nullopt;
  }

  return selected->second;
}

static std::optional<ServerPolicy::SelectedServerPosition> valrandom(const unsigned int val, const ServerPolicy::NumberedServerVector& servers)
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

std::optional<ServerPolicy::SelectedServerPosition> wrandom(const ServerPolicy::NumberedServerVector& servers, [[maybe_unused]] const DNSQuestion* dnsQuestion)
{
  return valrandom(dns_random_uint32(), servers);
}

std::optional<ServerPolicy::SelectedServerPosition> whashedFromHash(const ServerPolicy::NumberedServerVector& servers, size_t hash)
{
  return valrandom(hash, servers);
}

std::optional<ServerPolicy::SelectedServerPosition> whashed(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion)
{
  const auto hashPerturbation = dnsdist::configuration::getImmutableConfiguration().d_hashPerturbation;
  return whashedFromHash(servers, dnsQuestion->ids.qname.hash(hashPerturbation));
}

std::optional<ServerPolicy::SelectedServerPosition> chashedFromHash(const ServerPolicy::NumberedServerVector& servers, size_t qhash)
{
  unsigned int sel = std::numeric_limits<unsigned int>::max();
  unsigned int min = std::numeric_limits<unsigned int>::max();
  std::optional<ServerPolicy::SelectedServerPosition> ret;
  std::optional<ServerPolicy::SelectedServerPosition> first;

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

  for (const auto& serverPair: servers) {
    if (serverPair.second->isUp() && (consistentHashBalancingFactor == 0 || static_cast<double>(serverPair.second->outstanding.load()) <= (targetLoad * serverPair.second->d_config.d_weight))) {
      // make sure hashes have been computed
      if (!serverPair.second->hashesComputed) {
        serverPair.second->hash();
      }
      {
        const auto position = serverPair.first;
        const auto& server = serverPair.second;
        auto hashes = server->hashes.read_lock();
        // we want to keep track of the last hash
        if (min > *(hashes->begin())) {
          min = *(hashes->begin());
          first = position;
        }

        auto hash_it = std::lower_bound(hashes->begin(), hashes->end(), qhash);
        if (hash_it != hashes->end()) {
          if (*hash_it < sel) {
            sel = *hash_it;
            ret = position;
          }
        }
      }
    }
  }
  if (ret) {
    return ret;
  }
  if (first) {
    return first;
  }
  return std::nullopt;
}

std::optional<ServerPolicy::SelectedServerPosition> chashed(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion)
{
  const auto hashPerturbation = dnsdist::configuration::getImmutableConfiguration().d_hashPerturbation;
  return chashedFromHash(servers, dnsQuestion->ids.qname.hash(hashPerturbation));
}

std::optional<ServerPolicy::SelectedServerPosition> roundrobin(const ServerPolicy::NumberedServerVector& servers, [[maybe_unused]] const DNSQuestion* dnsQuestion)
{
  if (servers.empty()) {
    return std::nullopt;
  }

  static std::atomic<unsigned int> counter{0};

  size_t serverIdx = (counter++) % servers.size();
  auto currentServer = servers.at(serverIdx);
  if (currentServer.second->isUp()) {
    return currentServer.first;
  }

  vector<size_t> candidates;
  candidates.reserve(servers.size());

  for (const auto& server : servers) {
    if (server.second->isUp()) {
      candidates.push_back(server.first);
    }
  }

  if (candidates.empty()) {
    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_roundrobinFailOnNoServer) {
      return std::nullopt;
    }
    for (const auto& server : servers) {
      candidates.push_back(server.first);
    }
  }

  return candidates.at(counter % candidates.size());
}

std::optional<ServerPolicy::SelectedServerPosition> orderedWrandUntag(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion)
{
  if (servers.empty()) {
    return std::nullopt;
  }

  ServerPolicy::NumberedServerVector candidates;
  candidates.reserve(servers.size());
  std::vector<ServerPolicy::SelectedServerPosition> positionsMap;
  positionsMap.reserve(servers.size());

  int curOrder = std::numeric_limits<int>::max();
  unsigned int curNumber = 1;

  for (const auto& svr : servers) {
    if (svr.second->isUp() && (!dnsQuestion->ids.qTag || dnsQuestion->ids.qTag->count(svr.second->getNameWithAddr()) == 0)) {
      // the servers in a pool are already sorted in ascending order by its 'order', see ``ServerPool::addServer()``
      if (svr.second->d_config.order > curOrder) {
        break;
      }
      curOrder = svr.second->d_config.order;
      candidates.emplace_back(curNumber++, svr.second);
      positionsMap.push_back(svr.first);
    }
  }

  if (candidates.empty()) {
    return std::nullopt;
  }

  auto selected = wrandom(candidates, dnsQuestion);
  if (selected) {
    return positionsMap.at(*selected - 1);
  }
  return selected;
}

const ServerPolicy::NumberedServerVector& getDownstreamCandidates(const std::string& poolName)
{
  return getPool(poolName).getServers();
}

const ServerPool& createPoolIfNotExists(const string& poolName)
{
  {
    const auto& pools = dnsdist::configuration::getCurrentRuntimeConfiguration().d_pools;
    const auto poolIt = pools.find(poolName);
    if (poolIt != pools.end()) {
      return poolIt->second;
    }
  }

  if (!poolName.empty()) {
    VERBOSESLOG(infolog("Creating pool %s", poolName),
               dnsdist::logging::getTopLogger()->info(Logr::Info, "Creating a new pool of backends", "name", Logging::Loggable(poolName)));
  }

  dnsdist::configuration::updateRuntimeConfiguration([&poolName](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_pools.emplace(poolName, ServerPool());
  });

  {
    const auto& pools = dnsdist::configuration::getCurrentRuntimeConfiguration().d_pools;
    const auto poolIt = pools.find(poolName);
    return poolIt->second;
  }
}

void setPoolPolicy(const string& poolName, std::shared_ptr<ServerPolicy> policy)
{
  if (!poolName.empty()) {
    VERBOSESLOG(infolog("Setting pool %s server selection policy to %s", poolName, policy->getName()),
                dnsdist::logging::getTopLogger()->info(Logr::Info, "Setting pool server selection policy", "pool", Logging::Loggable(poolName), "policy", Logging::Loggable(policy->getName())));
  } else {
    VERBOSESLOG(infolog("Setting default pool server selection policy to %s", policy->getName()),
                dnsdist::logging::getTopLogger()->info(Logr::Info, "Setting pool server selection policy", "pool", Logging::Loggable(poolName), "policy", Logging::Loggable(policy->getName())));

  }

  dnsdist::configuration::updateRuntimeConfiguration([&poolName, &policy](dnsdist::configuration::RuntimeConfiguration& config) {
    auto [poolIt, _] = config.d_pools.emplace(poolName, ServerPool());
    poolIt->second.policy = std::move(policy);
  });
}

void addServerToPool(const string& poolName, std::shared_ptr<DownstreamState> server)
{
  if (!poolName.empty()) {
    VERBOSESLOG(infolog("Adding server to pool %s", poolName),
                dnsdist::logging::getTopLogger()->info(Logr::Info, "Adding server to pool", "pool", Logging::Loggable(poolName)));
  } else {
    VERBOSESLOG(infolog("Adding server to default pool"),
                dnsdist::logging::getTopLogger()->info(Logr::Info, "Adding server to pool", "pool", Logging::Loggable(poolName)));
  }

  dnsdist::configuration::updateRuntimeConfiguration([&poolName, &server](dnsdist::configuration::RuntimeConfiguration& config) {
    auto [poolIt, _] = config.d_pools.emplace(poolName, ServerPool());
    poolIt->second.addServer(server);
  });
}

void removeServerFromPool(const string& poolName, std::shared_ptr<DownstreamState> server)
{
  if (!poolName.empty()) {
    VERBOSESLOG(infolog("Removing server from pool %s", poolName),
                dnsdist::logging::getTopLogger()->info(Logr::Info, "Removing server from pool", "pool", Logging::Loggable(poolName)));
  }
  else {
    VERBOSESLOG(infolog("Removing server from default pool"),
                dnsdist::logging::getTopLogger()->info(Logr::Info, "Removing server from pool", "pool", Logging::Loggable(poolName)));
  }

  dnsdist::configuration::updateRuntimeConfiguration([&poolName, &server](dnsdist::configuration::RuntimeConfiguration& config) {
    auto [poolIt, _] = config.d_pools.emplace(poolName, ServerPool());
    poolIt->second.removeServer(server);
  });
}

const ServerPool& getPool(const std::string& poolName)
{
  const auto& pools = dnsdist::configuration::getCurrentRuntimeConfiguration().d_pools;
  auto poolIt = pools.find(poolName);
  if (poolIt == pools.end()) {
    throw std::out_of_range(std::string("No pool named ") + poolName);
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

ServerPolicy::SelectedBackend ServerPolicy::getSelectedBackend(const ServerPolicy::NumberedServerVector& servers, DNSQuestion& dnsQuestion) const
{
  ServerPolicy::SelectedBackend result{servers};

  if (d_isLua) {
    if (!d_isFFI) {
      std::optional<SelectedServerPosition> position;
      {
        auto lock = g_lua.lock();
        position = d_policy(servers, &dnsQuestion);
      }
      if (position && *position > 0 && *position <= servers.size()) {
        result.setSelected(*position - 1);
      }
      return result;
    }

    dnsdist_ffi_dnsquestion_t dnsq(&dnsQuestion);
    dnsdist_ffi_servers_list_t serversList(servers);
    ServerPolicy::SelectedServerPosition selected = 0;

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
      return result;
    }

    result.setSelected(selected);
    return result;
  }

  auto position = d_policy(servers, &dnsQuestion);
  if (position && *position > 0 && *position <= servers.size()) {
    result.setSelected(*position - 1);
  }

  return result;
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
