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

class LuaAction : public DNSAction
{
public:
  typedef std::function<std::tuple<int, boost::optional<string> >(DNSQuestion* dq)> func_t;
  LuaAction(const LuaAction::func_t& func) : d_func(func)
  {}
  Action operator()(DNSQuestion* dq, string* ruleresult) const override;
  string toString() const override
  {
    return "Lua script";
  }
private:
  func_t d_func;
};

class LuaResponseAction : public DNSResponseAction
{
public:
  typedef std::function<std::tuple<int, boost::optional<string> >(DNSResponse* dr)> func_t;
  LuaResponseAction(const LuaResponseAction::func_t& func) : d_func(func)
  {}
  Action operator()(DNSResponse* dr, string* ruleresult) const override;
  string toString() const override
  {
    return "Lua response script";
  }
private:
  func_t d_func;
};

class SpoofAction : public DNSAction
{
public:
  SpoofAction(const vector<ComboAddress>& addrs): d_addrs(addrs)
  {
  }
  SpoofAction(const string& cname): d_cname(cname)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override;
  string toString() const override
  {
    string ret = "spoof in ";
    if(!d_cname.empty()) {
      ret+=d_cname.toString()+ " ";
    } else {
      for(const auto& a : d_addrs)
        ret += a.toString()+" ";
    }
    return ret;
  }
private:
  std::vector<ComboAddress> d_addrs;
  DNSName d_cname;
};

typedef boost::variant<string, vector<pair<int, string>>, std::shared_ptr<DNSRule>, DNSName, vector<pair<int, DNSName> > > luadnsrule_t;
std::shared_ptr<DNSRule> makeRule(const luadnsrule_t& var);
typedef std::unordered_map<std::string, boost::variant<std::string> > luaruleparams_t;
void parseRuleParams(boost::optional<luaruleparams_t> params, boost::uuids::uuid& uuid, uint64_t& creationOrder);

typedef NetmaskTree<DynBlock> nmts_t;

void setupLuaActions();
void setupLuaBindings(bool client);
void setupLuaBindingsDNSCrypt();
void setupLuaBindingsDNSQuestion();
void setupLuaBindingsKVS(bool client);
void setupLuaBindingsPacketCache();
void setupLuaBindingsProtoBuf(bool client);
void setupLuaRules();
void setupLuaInspection();
void setupLuaVars();
