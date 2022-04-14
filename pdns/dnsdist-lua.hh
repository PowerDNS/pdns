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

#include "dnsparser.hh"
#include <random>

struct ResponseConfig
{
  boost::optional<bool> setAA{boost::none};
  boost::optional<bool> setAD{boost::none};
  boost::optional<bool> setRA{boost::none};
  uint32_t ttl{60};
};
void setResponseHeadersFromConfig(dnsheader& dh, const ResponseConfig& config);

class SpoofAction : public DNSAction
{
public:
  SpoofAction(const vector<ComboAddress>& addrs): d_addrs(addrs)
  {
    for (const auto& addr : d_addrs) {
      if (addr.isIPv4()) {
        d_types.insert(QType::A);
      }
      else if (addr.isIPv6()) {
        d_types.insert(QType::AAAA);
      }
    }

    if (!d_addrs.empty()) {
      d_types.insert(QType::ANY);
    }
  }

  SpoofAction(const DNSName& cname): d_cname(cname)
  {
  }

  SpoofAction(const char* rawresponse, size_t len): d_raw(rawresponse, rawresponse + len)
  {
  }

  SpoofAction(const vector<std::string>& raws): d_rawResponses(raws)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override;

  string toString() const override
  {
    string ret = "spoof in ";
    if (!d_cname.empty()) {
      ret += d_cname.toString() + " ";
    }
    if (d_rawResponses.size() > 0) {
      ret += "raw bytes ";
    }
    else {
      for(const auto& a : d_addrs)
        ret += a.toString()+" ";
    }
    return ret;
  }


  ResponseConfig d_responseConfig;
private:
  static thread_local std::default_random_engine t_randomEngine;
  std::vector<ComboAddress> d_addrs;
  std::set<uint16_t> d_types;
  std::vector<std::string> d_rawResponses;
  PacketBuffer d_raw;
  DNSName d_cname;
};

class LimitTTLResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  LimitTTLResponseAction() {}

  LimitTTLResponseAction(uint32_t min, uint32_t max = std::numeric_limits<uint32_t>::max()) : d_min(min), d_max(max)
  {
  }

  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
    auto visitor = [&](uint8_t section, uint16_t qclass, uint16_t qtype, uint32_t ttl) {
      if (d_min > 0) {
        if (ttl < d_min) {
          ttl = d_min;
        }
      }
      if (ttl > d_max) {
        ttl = d_max;
      }
      return ttl;
    };
    editDNSPacketTTL(reinterpret_cast<char *>(dr->getMutableData().data()), dr->getData().size(), visitor);
    return DNSResponseAction::Action::None;
  }

  std::string toString() const override
  {
    return "limit ttl (" + std::to_string(d_min) + " <= ttl <= " + std::to_string(d_max) + ")";
  }

private:
  uint32_t d_min{0};
  uint32_t d_max{std::numeric_limits<uint32_t>::max()};
};

template <class T> using LuaArray = std::vector<std::pair<int, T>>;
template <class T> using LuaAssociativeTable = std::unordered_map<std::string, T>;
template <class T> using LuaTypeOrArrayOf = boost::variant<T, LuaArray<T>>;

using luadnsrule_t = boost::variant<string, LuaArray<std::string>, std::shared_ptr<DNSRule>, DNSName, LuaArray<DNSName>>;
using luaruleparams_t = LuaAssociativeTable<std::string>;
using nmts_t = NetmaskTree<DynBlock, AddressAndPortRange>;

std::shared_ptr<DNSRule> makeRule(const luadnsrule_t& var);
void parseRuleParams(boost::optional<luaruleparams_t> params, boost::uuids::uuid& uuid, std::string& name, uint64_t& creationOrder);
void checkParameterBound(const std::string& parameter, uint64_t value, size_t max = std::numeric_limits<uint16_t>::max());

vector<std::function<void(void)>> setupLua(LuaContext& luaCtx, bool client, bool configCheck, const std::string& config);
void setupLuaActions(LuaContext& luaCtx);
void setupLuaBindings(LuaContext& luaCtx, bool client);
void setupLuaBindingsDNSCrypt(LuaContext& luaCtx, bool client);
void setupLuaBindingsDNSQuestion(LuaContext& luaCtx);
void setupLuaBindingsKVS(LuaContext& luaCtx, bool client);
void setupLuaBindingsNetwork(LuaContext& luaCtx, bool client);
void setupLuaBindingsPacketCache(LuaContext& luaCtx, bool client);
void setupLuaBindingsProtoBuf(LuaContext& luaCtx, bool client, bool configCheck);
void setupLuaRules(LuaContext& luaCtx);
void setupLuaInspection(LuaContext& luaCtx);
void setupLuaVars(LuaContext& luaCtx);
void setupLuaWeb(LuaContext& luaCtx);
void setupLuaLoadBalancingContext(LuaContext& luaCtx);
