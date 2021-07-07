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

// get server with least outstanding queries, and within those, with the lowest order, and within those: the fastest
shared_ptr<DownstreamState> leastOutstanding(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq)
{
  if (servers.size() == 1 && servers[0].second->isUp()) {
    return servers[0].second;
  }

  vector<pair<tuple<int,int,double>, size_t>> poss;
  /* so you might wonder, why do we go through this trouble? The data on which we sort could change during the sort,
     which would suck royally and could even lead to crashes. So first we snapshot on what we sort, and then we sort */
  poss.reserve(servers.size());
  size_t position = 0;
  for(const auto& d : servers) {
    if(d.second->isUp()) {
      poss.emplace_back(make_tuple(d.second->outstanding.load(), d.second->order, d.second->latencyUsec), position);
    }
    ++position;
  }

  if (poss.empty()) {
    return shared_ptr<DownstreamState>();
  }

  nth_element(poss.begin(), poss.begin(), poss.end(), [](const decltype(poss)::value_type& a, const decltype(poss)::value_type& b) { return a.first < b.first; });
  return servers.at(poss.begin()->second).second;
}

shared_ptr<DownstreamState> firstAvailable(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq)
{
  for(auto& d : servers) {
    if (d.second->isUp() && d.second->qps.checkOnly()) {
      return d.second;
    }
  }
  return leastOutstanding(servers, dq);
}

double g_weightedBalancingFactor = 0;

static shared_ptr<DownstreamState> valrandom(unsigned int val, const ServerPolicy::NumberedServerVector& servers)
{
  vector<pair<int, size_t>> poss;
  poss.reserve(servers.size());
  int sum = 0;
  int max = std::numeric_limits<int>::max();
  double targetLoad = std::numeric_limits<double>::max();

  if (g_weightedBalancingFactor > 0) {
    /* we start with one, representing the query we are currently handling */
    double currentLoad = 1;
    size_t totalWeight = 0;
    for (const auto& pair : servers) {
      if (pair.second->isUp()) {
        currentLoad += pair.second->outstanding;
        totalWeight += pair.second->weight;
      }
    }

    if (totalWeight > 0) {
      targetLoad = (currentLoad / totalWeight) * g_weightedBalancingFactor;
    }
  }

  for (const auto& d : servers) {      // w=1, w=10 -> 1, 11
    if (d.second->isUp() && (g_weightedBalancingFactor == 0 || (d.second->outstanding <= (targetLoad * d.second->weight)))) {
      // Don't overflow sum when adding high weights
      if (d.second->weight > max - sum) {
        sum = max;
      } else {
        sum += d.second->weight;
      }

      poss.emplace_back(sum, d.first);
    }
  }

  // Catch poss & sum are empty to avoid SIGFPE
  if (poss.empty() || sum == 0) {
    return shared_ptr<DownstreamState>();
  }

  int r = val % sum;
  auto p = upper_bound(poss.begin(), poss.end(),r, [](int r_, const decltype(poss)::value_type& a) { return  r_ < a.first;});
  if (p == poss.end()) {
    return shared_ptr<DownstreamState>();
  }

  return servers.at(p->second - 1).second;
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
  return whashedFromHash(servers, dq->qname->hash(g_hashperturb));
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
        totalWeight += pair.second->weight;
      }
    }

    if (totalWeight > 0) {
      targetLoad = (currentLoad / totalWeight) * g_consistentHashBalancingFactor;
    }
  }

  for (const auto& d: servers) {
    if (d.second->isUp() && (g_consistentHashBalancingFactor == 0 || d.second->outstanding <= (targetLoad * d.second->weight))) {
      // make sure hashes have been computed
      if (d.second->hashes.empty()) {
        d.second->hash();
      }
      {
        ReadLock rl(&(d.second->d_lock));
        const auto& server = d.second;
        // we want to keep track of the last hash
        if (min > *(server->hashes.begin())) {
          min = *(server->hashes.begin());
          first = server;
        }

        auto hash_it = std::lower_bound(server->hashes.begin(), server->hashes.end(), qhash);
        if (hash_it != server->hashes.end()) {
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
  return chashedFromHash(servers, dq->qname->hash(g_hashperturb));
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

const std::shared_ptr<ServerPolicy::NumberedServerVector> getDownstreamCandidates(const pools_t& pools, const std::string& poolName)
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
    pools.insert(std::pair<std::string,std::shared_ptr<ServerPool> >(poolName, pool));
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
