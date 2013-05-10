#include "lua-pdns.hh"
// #include "syncres.hh"
#include <boost/foreach.hpp>
#include "config.h"

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

void pushResourceRecordsTable(lua_State* lua, const vector<DNSResourceRecord>& records)
{
  // make a table of tables
  lua_newtable(lua);

  int pos=0;
  BOOST_FOREACH(const DNSResourceRecord& rr, records)
  {
    // row number, used by 'lua_settable' below
    lua_pushnumber(lua, ++pos);
    // "row" table
    lua_newtable(lua);

    lua_pushstring(lua, rr.qname.c_str());
    lua_setfield(lua, -2, "qname");  // pushes value at the top of the stack to the table immediately below that (-1 = top, -2 is below)

    lua_pushstring(lua, rr.content.c_str());
    lua_setfield(lua, -2, "content");

    lua_pushnumber(lua, rr.qtype.getCode());
    lua_setfield(lua, -2, "qtype");

    lua_pushnumber(lua, rr.ttl);
    lua_setfield(lua, -2, "ttl");

    lua_pushnumber(lua, rr.d_place);
    lua_setfield(lua, -2, "place");

    lua_settable(lua, -3); // pushes the table we just built into the master table at position pushed above
  }
}

void popResourceRecordsTable(lua_State *lua, const string &query, vector<DNSResourceRecord>& ret)
{
  /* get the result */
  DNSResourceRecord rr;
  rr.qname = query;
  rr.d_place = DNSResourceRecord::ANSWER;
  rr.ttl = 3600;

//  cerr<<"Lua stacksize "<<lua_gettop(lua)<<endl;
#ifndef LUA_VERSION_NUM
  int tableLen = luaL_getn(lua, 2);
#else
  int tableLen = lua_objlen(lua, 2);
#endif
//  cerr<<"Got back "<<tableLen<< " answers from Lua"<<endl;

  for(int n=1; n < tableLen + 1; ++n) {
    lua_pushnumber(lua, n);
    lua_gettable(lua, 2);

    uint32_t tmpnum=0;
    if(!getFromTable(lua, "qtype", tmpnum))
      rr.qtype=QType::A;
    else
      rr.qtype=tmpnum;

    getFromTable(lua, "content", rr.content);
    if(!getFromTable(lua, "ttl", rr.ttl))
      rr.ttl=3600;

    if(!getFromTable(lua, "qname", rr.qname))
      rr.qname = query;

    if(!getFromTable(lua, "place", tmpnum))
      rr.d_place = DNSResourceRecord::ANSWER;
    else {
      rr.d_place = (DNSResourceRecord::Place) tmpnum;
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
  if(lua_gettop(lua) >= 1) {
    string message=lua_tostring(lua, 1);
    theL()<<Logger::Error<<"From Lua script: "<<message<<endl;
  }
  return 0;
}
}

PowerDNSLua::PowerDNSLua(const std::string& fname)
{
  d_lua = lua_open();

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

  lua_pushcfunction(d_lua, netmaskMatchLua);
  lua_setglobal(d_lua, "matchnetmask");

  lua_pushcfunction(d_lua, logLua);
  lua_setglobal(d_lua, "pdnslog");

  lua_pushcfunction(d_lua, setVariableLua);
  lua_setglobal(d_lua, "setvariable");

  lua_pushcfunction(d_lua, getLocalAddressLua);
  lua_setglobal(d_lua, "getlocaladdress");

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
  lua_setglobal(d_lua, "pdns");

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
#endif
