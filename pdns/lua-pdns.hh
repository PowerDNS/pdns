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
#ifndef PDNS_LUA_PDNS_HH
#define PDNS_LUA_PDNS_HH

#include "dns.hh"
#include "iputils.hh"
struct lua_State;

class PowerDNSLua
{
public:
  explicit PowerDNSLua(const std::string& fname);
  ~PowerDNSLua();
  void reload();
  ComboAddress getLocal()
  {
    return d_local;
  }

  void setVariable()
  {
    d_variable=true;
  }

protected: // FIXME?
  lua_State* d_lua;
  bool passthrough(const string& func, const ComboAddress& remote,const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable);
  bool getFromTable(const std::string& key, std::string& value);
  bool getFromTable(const std::string& key, uint32_t& value);
 
  ComboAddress d_local;
  bool d_failed;
  bool d_variable;  
};

void pushResourceRecordsTable(lua_State* lua, const vector<DNSRecord>& records);
void popResourceRecordsTable(lua_State *lua, const DNSName &query, vector<DNSRecord>& ret);
void pushSyslogSecurityLevelTable(lua_State *lua);
int getLuaTableLength(lua_State* lua, int depth);
std::vector<std::pair<std::string, std::string>> getLuaTable(lua_State* lua, int index=0);
void pushLuaTable(lua_State* lua, const vector<pair<string,string>>& table);
void luaStackDump (lua_State *lua);
extern "C" int luaopen_iputils(lua_State*);
#endif
