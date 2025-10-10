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

#include <memory>
#include <optional>

struct dnsdist_ffi_servers_list_t;
struct dnsdist_ffi_server_t;
struct dnsdist_ffi_dnsquestion_t;

struct DNSQuestion;
struct DownstreamState;

struct PerThreadPoliciesState;

class ServerPolicy
{
public:
  using SelectedServerPosition = unsigned int;
  template <class T>
  using Numbered = std::pair<unsigned int, T>;
  using NumberedServer = Numbered<std::shared_ptr<DownstreamState>>;
  template <class T>
  using NumberedVector = std::vector<std::pair<unsigned int, T>>;
  using NumberedServerVector = NumberedVector<std::shared_ptr<DownstreamState>>;
  using policyfunc_t = std::function<std::optional<SelectedServerPosition>(const NumberedServerVector& servers, const DNSQuestion*)>;
  using ffipolicyfunc_t = std::function<SelectedServerPosition(dnsdist_ffi_servers_list_t* servers, dnsdist_ffi_dnsquestion_t* dq)>;

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

  class SelectedBackend
  {
  public:
    SelectedBackend(const NumberedServerVector& backends) :
      d_backends(&backends)
    {
    }

    void setSelected(SelectedServerPosition selected)
    {
      if (selected >= d_backends->size()) {
        throw std::runtime_error("Setting an invalid backend position (" + std::to_string(selected) + " out of " + std::to_string(d_backends->size()) + ") from the server policy");
      }
      d_selected = selected;
    }

    operator bool() const noexcept
    {
      return d_selected.has_value();
    }

    DownstreamState* operator->() const
    {
      return (*d_backends)[*d_selected].second.get();
    }

    const std::shared_ptr<DownstreamState>& get() const
    {
      return (*d_backends)[*d_selected].second;
    }

  private:
    const NumberedServerVector* d_backends{nullptr};
    std::optional<SelectedServerPosition> d_selected{std::nullopt};
  };

  SelectedBackend getSelectedBackend(const ServerPolicy::NumberedServerVector& servers, DNSQuestion& dnsQuestion) const;

  const std::string& getName() const
  {
    return d_name;
  }

  std::string toString() const
  {
    return std::string("ServerPolicy") + (d_isLua ? " (Lua)" : "") + " \"" + d_name + "\"";
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
const ServerPool& getPool(const std::string& poolName);
const ServerPool& createPoolIfNotExists(const std::string& poolName);
void setPoolPolicy(const std::string& poolName, std::shared_ptr<ServerPolicy> policy);
void addServerToPool(const std::string& poolName, std::shared_ptr<DownstreamState> server);
void removeServerFromPool(const std::string& poolName, std::shared_ptr<DownstreamState> server);

const ServerPolicy::NumberedServerVector& getDownstreamCandidates(const std::string& poolName);

std::optional<ServerPolicy::SelectedServerPosition> firstAvailable(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion);
std::optional<ServerPolicy::SelectedServerPosition> leastOutstanding(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion);
std::optional<ServerPolicy::SelectedServerPosition> wrandom(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion);
std::optional<ServerPolicy::SelectedServerPosition> whashed(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion);
std::optional<ServerPolicy::SelectedServerPosition> whashedFromHash(const ServerPolicy::NumberedServerVector& servers, size_t hash);
std::optional<ServerPolicy::SelectedServerPosition> chashed(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion);
std::optional<ServerPolicy::SelectedServerPosition> chashedFromHash(const ServerPolicy::NumberedServerVector& servers, size_t hash);
std::optional<ServerPolicy::SelectedServerPosition> roundrobin(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion);
std::optional<ServerPolicy::SelectedServerPosition> orderedWrandUntag(const ServerPolicy::NumberedServerVector& servers, const DNSQuestion* dnsQuestion);

#include <unordered_map>

namespace dnsdist::lbpolicies
{
const std::vector<std::shared_ptr<ServerPolicy>>& getBuiltInPolicies();
}
