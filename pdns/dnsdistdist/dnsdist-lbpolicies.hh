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

struct dnsdist_ffi_servers_list_t;
struct dnsdist_ffi_server_t;
struct dnsdist_ffi_dnsquestion_t;

struct DNSQuestion;
struct DownstreamState;

struct PerThreadPoliciesState;

class ServerPolicy
{
public:
  template <class T>
  using Numbered = std::pair<unsigned int, T>;
  using NumberedServer = Numbered<shared_ptr<DownstreamState>>;
  template <class T>
  using NumberedVector = std::vector<std::pair<unsigned int, T>>;
  using NumberedServerVector = NumberedVector<shared_ptr<DownstreamState>>;
  using policyfunc_t = std::function<std::shared_ptr<DownstreamState>(const NumberedServerVector& servers, const DNSQuestion*)>;
  using ffipolicyfunc_t = std::function<unsigned int(dnsdist_ffi_servers_list_t* servers, dnsdist_ffi_dnsquestion_t* dq)>;

  ServerPolicy(const std::string& name_, policyfunc_t policy_, bool isLua_) :
    d_name(name_), d_policy(std::move(policy_)), d_isLua(isLua_)
  {
  }

  ServerPolicy(const std::string& name_, ffipolicyfunc_t policy_) :
    d_name(name_), d_ffipolicy(std::move(policy_)), d_isLua(true), d_isFFI(true)
  {
  }

  /* create a per-thread FFI policy */
  ServerPolicy(const std::string& name_, const std::string& code);

  ServerPolicy()
  {
  }

  std::shared_ptr<DownstreamState> getSelectedBackend(const ServerPolicy::NumberedServerVector& servers, DNSQuestion& dq) const;

  const std::string& getName() const
  {
    return d_name;
  }

  std::string toString() const
  {
    return string("ServerPolicy") + (d_isLua ? " (Lua)" : "") + " \"" + d_name + "\"";
  }

private:
  struct PerThreadState;

  const ffipolicyfunc_t& getPerThreadPolicy() const;
  static thread_local std::unique_ptr<PerThreadState> t_perThreadState;

public:
  std::string d_name;
  std::string d_perThreadPolicyCode;

  policyfunc_t d_policy;
  ffipolicyfunc_t d_ffipolicy;

  bool d_isLua{false};
  bool d_isFFI{false};
  bool d_isPerThread{false};
};

struct ServerPool;

using pools_t = std::map<std::string, std::shared_ptr<ServerPool>>;
std::shared_ptr<ServerPool> getPool(const std::string& poolName);
std::shared_ptr<ServerPool> createPoolIfNotExists(const string& poolName);
void setPoolPolicy(const string& poolName, std::shared_ptr<ServerPolicy> policy);
void addServerToPool(const string& poolName, std::shared_ptr<DownstreamState> server);
void removeServerFromPool(const string& poolName, std::shared_ptr<DownstreamState> server);

std::shared_ptr<const ServerPolicy::NumberedServerVector> getDownstreamCandidates(const std::string& poolName);

std::shared_ptr<DownstreamState> firstAvailable(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq);

std::shared_ptr<DownstreamState> leastOutstanding(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> wrandom(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> whashed(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> whashedFromHash(const ServerPolicy::NumberedServerVector& servers, size_t hash);
std::shared_ptr<DownstreamState> chashed(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> chashedFromHash(const ServerPolicy::NumberedServerVector& servers, size_t hash);
std::shared_ptr<DownstreamState> roundrobin(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> orderedWrandUntag(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dq);

#include <unordered_map>

namespace dnsdist::lbpolicies
{
const std::vector<std::shared_ptr<ServerPolicy>>& getBuiltInPolicies();
}
