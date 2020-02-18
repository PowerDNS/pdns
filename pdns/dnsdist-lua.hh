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

  SpoofAction(const std::string& raw): d_rawResponse(raw)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override;

  string toString() const override
  {
    string ret = "spoof in ";
    if (!d_cname.empty()) {
      ret += d_cname.toString() + " ";
    }
    else if (!d_rawResponse.empty()) {
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
  std::vector<ComboAddress> d_addrs;
  std::set<uint16_t> d_types;
  std::string d_rawResponse;
  DNSName d_cname;
};

typedef boost::variant<string, vector<pair<int, string>>, std::shared_ptr<DNSRule>, DNSName, vector<pair<int, DNSName> > > luadnsrule_t;
std::shared_ptr<DNSRule> makeRule(const luadnsrule_t& var);
typedef std::unordered_map<std::string, boost::variant<std::string> > luaruleparams_t;
void parseRuleParams(boost::optional<luaruleparams_t> params, boost::uuids::uuid& uuid, uint64_t& creationOrder);

typedef NetmaskTree<DynBlock> nmts_t;

vector<std::function<void(void)>> setupLua(bool client, bool configCheck, const std::string& config);
void setupLuaActions();
void setupLuaBindings(bool client);
void setupLuaBindingsDNSCrypt();
void setupLuaBindingsDNSQuestion();
void setupLuaBindingsKVS(bool client);
void setupLuaBindingsPacketCache();
void setupLuaBindingsProtoBuf(bool client, bool configCheck);
void setupLuaRules();
void setupLuaInspection();
void setupLuaVars();
