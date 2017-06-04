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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "lua-pdns.hh"
// #include "syncres.hh"


#if !defined(HAVE_LUA)

// stub implementation

PowerDNSLua::PowerDNSLua(const std::string& fname)
{
  throw runtime_error("Lua support disabled");
}


PowerDNSLua::~PowerDNSLua()
{

}

#else

extern "C" {
#undef L
/* Include the Lua API header files. */
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <stdexcept>
#include "logger.hh"
#include "namespaces.hh"
#include "dnsparser.hh"
#undef L

bool netmaskMatchTable(lua_State* lua, const std::string& ip)
{
  lua_pushnil(lua);  /* first key */
  while (lua_next(lua, 2) != 0) {
    string netmask=lua_tostring(lua, -1);
    Netmask nm(netmask);
    ComboAddress ca(ip);
    lua_pop(lua, 1);

    if(nm.match(ip))
      return true;
  }
  return false;
}

static bool getFromTable(lua_State *lua, const std::string &key, std::string& value)
{
  lua_pushstring(lua, key.c_str()); // 4 is now '1'
  lua_gettable(lua, -2);  // replace by the first entry of our table we hope

  bool ret=false;
  if(!lua_isnil(lua, -1)) {
    value = lua_tostring(lua, -1);
    ret=true;
  }
  lua_pop(lua, 1);
  return ret;
}

static bool getFromTable(lua_State *lua, const std::string &key, uint32_t& value)
{
  lua_pushstring(lua, key.c_str()); // 4 is now '1'
  lua_gettable(lua, -2);  // replace by the first entry of our table we hope

  bool ret=false;

  if(!lua_isnil(lua, -1)) {
    value = (uint32_t)lua_tonumber(lua, -1);
    ret=true;
  }
  lua_pop(lua, 1);
  return ret;
}


void pushLuaTable(lua_State* lua, const vector<pair<string,string>>& table)
{
  lua_newtable(lua);
  for(const auto& e : table) {
    lua_pushstring(lua, e.second.c_str());
    lua_setfield(lua, -2, e.first.c_str());
  }
}

vector<pair<string,string>> getLuaTable(lua_State* lua, int index)
{
  vector<pair<string,string>> ret;
  // Push another reference to the table on top of the stack (so we know
  // where it is, and this function can work for negative, positive and
  // pseudo indices
  lua_pushvalue(lua, index);
  // stack now contains: -1 => table
  lua_pushnil(lua);
  // stack now contains: -1 => nil; -2 => table
  while (lua_next(lua, -2)) {
    // stack now contains: -1 => value; -2 => key; -3 => table
    // copy the key so that lua_tostring does not modify the original
    lua_pushvalue(lua, -2);
    // stack now contains: -1 => key; -2 => value; -3 => key; -4 => table
    const char *key = lua_tostring(lua, -1);
    const char *value = lua_tostring(lua, -2);
    ret.push_back({key,value});
    // pop value + copy of key, leaving original key
    lua_pop(lua, 2);
    // stack now contains: -1 => key; -2 => table
  }
  // stack now contains: -1 => table (when lua_next returns 0 it pops the key
  // but does not push anything.)
  // Pop table
  lua_pop(lua, 1);
  // Stack is now the same as it was on entry to this function
  return ret;
}


void pushResourceRecordsTable(lua_State* lua, const vector<DNSRecord>& records)
{
  // make a table of tables
  lua_newtable(lua);

  int pos=0;
  for(const auto& rr: records)
  {
    // row number, used by 'lua_settable' below
    lua_pushnumber(lua, ++pos);
    // "row" table
    lua_newtable(lua);

    lua_pushstring(lua, rr.d_name.toString().c_str());
    lua_setfield(lua, -2, "qname");  // pushes value at the top of the stack to the table immediately below that (-1 = top, -2 is below)

    lua_pushstring(lua, rr.d_content->getZoneRepresentation().c_str());
    lua_setfield(lua, -2, "content");

    lua_pushnumber(lua, rr.d_type);
    lua_setfield(lua, -2, "qtype");

    lua_pushnumber(lua, rr.d_ttl);
    lua_setfield(lua, -2, "ttl");

    lua_pushnumber(lua, rr.d_place);
    lua_setfield(lua, -2, "place");

    lua_pushnumber(lua, rr.d_class);
    lua_setfield(lua, -2, "qclass");

    lua_settable(lua, -3); // pushes the table we just built into the master table at position pushed above
  }
}
// override the __index metatable under loglevels to return Logger::Error to account for nil accesses to the loglevels table
int loglevels_index(lua_State* lua)
{
  lua_pushnumber(lua, Logger::Error);
  return 1;
}
// push the loglevel subtable onto the stack that will eventually be the pdns table
void pushSyslogSecurityLevelTable(lua_State* lua)
{
  lua_newtable(lua);
// this function takes the global lua_state from the PowerDNSLua constructor and populates it with the syslog enums values
  lua_pushnumber(lua, Logger::All);
  lua_setfield(lua, -2, "All");
  lua_pushnumber(lua, Logger::Alert);
  lua_setfield(lua, -2, "Alert");
  lua_pushnumber(lua, Logger::Critical);
  lua_setfield(lua, -2, "Critical");
  lua_pushnumber(lua, Logger::Error);
  lua_setfield(lua, -2, "Error");
  lua_pushnumber(lua, Logger::Warning);
  lua_setfield(lua, -2, "Warning");
  lua_pushnumber(lua, Logger::Notice);
  lua_setfield(lua, -2, "Notice");
  lua_pushnumber(lua, Logger::Info);
  lua_setfield(lua, -2, "Info");
  lua_pushnumber(lua, Logger::Debug);
  lua_setfield(lua, -2, "Debug");
  lua_pushnumber(lua, Logger::None);
  lua_setfield(lua, -2, "None");
  lua_createtable(lua, 0, 1);
  lua_pushcfunction(lua, loglevels_index);
  lua_setfield(lua, -2, "__index");
  lua_setmetatable(lua, -2);
}
int getLuaTableLength(lua_State* lua, int depth)
{
#ifndef LUA_VERSION_NUM
  return luaL_getn(lua, 2);
#elif LUA_VERSION_NUM < 502
  return lua_objlen(lua, 2);
#else
  return lua_rawlen(lua, 2);
#endif
}

// expects a table at offset 2, and, importantly DOES NOT POP IT from the stack - only the contents
void popResourceRecordsTable(lua_State *lua, const DNSName &query, vector<DNSRecord>& ret)
{
  /* get the result */
  DNSRecord rr;
  rr.d_name = query;
  rr.d_place = DNSResourceRecord::ANSWER;
  rr.d_ttl = 3600;

  int tableLen = getLuaTableLength(lua, 2);

  for(int n=1; n < tableLen + 1; ++n) {
    lua_pushnumber(lua, n);
    lua_gettable(lua, 2);

    uint32_t tmpnum=0;
    if(!getFromTable(lua, "qtype", tmpnum))
      rr.d_type=QType::A;
    else
      rr.d_type=tmpnum;

    if(!getFromTable(lua, "qclass", tmpnum))
      rr.d_class = QClass::IN;
    else {
      rr.d_class = tmpnum;
    }


    string content;
    getFromTable(lua, "content", content);
    rr.d_content=DNSRecordContent::mastermake(rr.d_type, rr.d_class, content);

    if(!getFromTable(lua, "ttl", rr.d_ttl))
      rr.d_ttl=3600;

    string qname;
    if(getFromTable(lua, "qname", qname))
      rr.d_name = DNSName(qname);
    else
      rr.d_name = query;

    if(!getFromTable(lua, "place", tmpnum))
      rr.d_place = DNSResourceRecord::ANSWER;
    else {
      rr.d_place = static_cast<DNSResourceRecord::Place>(tmpnum);
      if(rr.d_place > DNSResourceRecord::ADDITIONAL)
        rr.d_place = DNSResourceRecord::ADDITIONAL;
    }


    /* removes 'value'; keeps 'key' for next iteration */
    lua_pop(lua, 1); // table

    //    cerr<<"Adding content '"<<rr.content<<"' with place "<<(int)rr.d_place<<" \n";
    ret.push_back(rr);
  }
}

extern "C" {

int netmaskMatchLua(lua_State *lua)
{
  bool result=false;
  if(lua_gettop(lua) >= 2) {
    string ip=lua_tostring(lua, 1);
    if(lua_istable(lua, 2)) {
      result = netmaskMatchTable(lua, ip);
    }
    else {
      for(int n=2 ; n <= lua_gettop(lua); ++n) {
        string netmask=lua_tostring(lua, n);
        Netmask nm(netmask);
        ComboAddress ca(ip);

        result = nm.match(ip);
        if(result)
          break;
      }
    }
  }

  lua_pushboolean(lua, result);
  return 1;
}

int getLocalAddressLua(lua_State* lua)
{
  lua_getfield(lua, LUA_REGISTRYINDEX, "__PowerDNSLua");
  PowerDNSLua* pl = (PowerDNSLua*)lua_touserdata(lua, -1);

  lua_pushstring(lua, pl->getLocal().toString().c_str());
  return 1;
}

// called by lua to indicate that this answer is 'variable' and should not be cached
int setVariableLua(lua_State* lua)
{
  lua_getfield(lua, LUA_REGISTRYINDEX, "__PowerDNSLua");
  PowerDNSLua* pl = (PowerDNSLua*)lua_touserdata(lua, -1);
  pl->setVariable();
  return 0;
}

int logLua(lua_State *lua)
{
  // get # of arguments from the pdnslog() lua stack
  // if it is 1, then the old pdnslog(msg) is used, which we keep for posterity and to prevent lua scripts from breaking
  // if it is >= 2, then we process it as pdnslog(msg, urgencylevel) for more granular logging
  int argc = lua_gettop(lua);
  if(argc == 1) {
    string message=lua_tostring(lua, 1);
    theL()<<Logger::Error<<"From Lua script: "<<message<<endl;
  } else if(argc >= 2) {
    string message=lua_tostring(lua, 1);
    int urgencylevel = lua_tonumber(lua, 2);
    theL()<<urgencylevel<<" "<<message<<endl;
  }
  return 0;
}
}

PowerDNSLua::PowerDNSLua(const std::string& fname)
{
  d_lua = luaL_newstate();

  // create module iputils & load it
#if LUA_VERSION_NUM < 502
  luaopen_iputils(d_lua);
#else
  luaL_requiref(d_lua, "iputils", luaopen_iputils, 1);
#endif

  lua_pushcfunction(d_lua, netmaskMatchLua);
  lua_setglobal(d_lua, "matchnetmask");

  lua_pushcfunction(d_lua, logLua);
  lua_setglobal(d_lua, "pdnslog");

  lua_newtable(d_lua);

  for(vector<QType::namenum>::const_iterator iter = QType::names.begin(); iter != QType::names.end(); ++iter) {
    lua_pushnumber(d_lua, iter->second);
    lua_setfield(d_lua, -2, iter->first.c_str());
  }
  lua_pushnumber(d_lua, 0);
  lua_setfield(d_lua, -2, "NOERROR");
  lua_pushnumber(d_lua, 1);
  lua_setfield(d_lua, -2, "FORMERR");
  lua_pushnumber(d_lua, 2);
  lua_setfield(d_lua, -2, "SERVFAIL");
  lua_pushnumber(d_lua, 3);
  lua_setfield(d_lua, -2, "NXDOMAIN");
  lua_pushnumber(d_lua, 4);
  lua_setfield(d_lua, -2, "NOTIMP");
  lua_pushnumber(d_lua, 5);
  lua_setfield(d_lua, -2, "REFUSED");
  // set syslog codes used by Logger/enum Urgency
  pushSyslogSecurityLevelTable(d_lua);
  lua_setfield(d_lua, -2, "loglevels");
  lua_pushnumber(d_lua, PolicyDecision::PASS);
  lua_setfield(d_lua, -2, "PASS");
  lua_pushnumber(d_lua, PolicyDecision::DROP);
  lua_setfield(d_lua, -2, "DROP");
  lua_pushnumber(d_lua, PolicyDecision::TRUNCATE);
  lua_setfield(d_lua, -2, "TRUNCATE");

  lua_setglobal(d_lua, "pdns");

#ifndef LUA_VERSION_NUM
  luaopen_base(d_lua);
  luaopen_string(d_lua);

  if(lua_dofile(d_lua,  fname.c_str()))
#else
  luaL_openlibs(d_lua);
  if(luaL_dofile(d_lua,  fname.c_str()))
#endif
    throw runtime_error(string("Error loading Lua file '")+fname+"': "+ string(lua_isstring(d_lua, -1) ? lua_tostring(d_lua, -1) : "unknown error"));

  lua_settop(d_lua, 0);

  lua_pushcfunction(d_lua, setVariableLua);
  lua_setglobal(d_lua, "setvariable");

  lua_pushcfunction(d_lua, getLocalAddressLua);
  lua_setglobal(d_lua, "getlocaladdress");

  lua_pushlightuserdata(d_lua, (void*)this);
  lua_setfield(d_lua, LUA_REGISTRYINDEX, "__PowerDNSLua");
}

bool PowerDNSLua::getFromTable(const std::string& key, std::string& value)
{
  return ::getFromTable(d_lua, key, value);
}

bool PowerDNSLua::getFromTable(const std::string& key, uint32_t& value)
{
  return ::getFromTable(d_lua, key, value);
}

PowerDNSLua::~PowerDNSLua()
{
  lua_close(d_lua);
}

#if 0
void luaStackDump (lua_State *Lua) {
  int i;
  int top = lua_gettop(Lua);
  for (i = 1; i <= top; i++) {  /* repeat for each level */
    int t = lua_type(Lua, i);
    switch (t) {

    case LUA_TSTRING:  /* strings */
      printf("`%s'", lua_tostring(Lua, i));
      break;

    case LUA_TBOOLEAN:  /* booleans */
      printf(lua_toboolean(Lua, i) ? "true" : "false");
      break;

    case LUA_TNUMBER:  /* numbers */
      printf("%g", lua_tonumber(Lua, i));
      break;

    default:  /* other values */
      printf("%s", lua_typename(Lua, t));
      break;

    }
    printf("  ");  /* put a separator */
  }
  printf("\n");  /* end the listing */
}
#endif

#endif
