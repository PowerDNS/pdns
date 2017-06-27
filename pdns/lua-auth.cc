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
#include "lua-auth.hh"

#if !defined(HAVE_LUA)

AuthLua::AuthLua(const std::string &fname)
  : PowerDNSLua(fname)
{
  // empty
}

DNSPacket* AuthLua::prequery(DNSPacket *p)
{
  return 0;
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

AuthLua::AuthLua(const std::string &fname)
  : PowerDNSLua(fname)
{
  registerLuaDNSPacket();
  pthread_mutex_init(&d_lock,0);
}

struct LuaDNSPacket
{
  DNSPacket *d_p;
};

static DNSPacket* ldp_checkDNSPacket(lua_State *L) {
  void *ud = luaL_checkudata(L, 1, "LuaDNSPacket");
  luaL_argcheck(L, ud != NULL, 1, "`LuaDNSPacket' expected");
  return ((LuaDNSPacket *)ud)->d_p;
}

static int ldp_setRcode(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
#if LUA_VERSION_NUM < 503
  int rcode = luaL_checkint(L, 2);
#else
  int rcode = (int)luaL_checkinteger(L, 2);
#endif
  p->setRcode(rcode);
  return 0;
}

static int ldp_getQuestion(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  lua_pushstring(L, p->qdomain.toString().c_str());
  lua_pushnumber(L, p->qtype.getCode());
  return 2;
}

static int ldp_getWild(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  if(p->qdomainwild.empty())
    lua_pushnil(L);
  else
    lua_pushstring(L, p->qdomainwild.toString().c_str());
  return 1;
}

static int ldp_getZone(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  if(p->qdomainzone.empty())
    lua_pushnil(L);
  else
    lua_pushstring(L, p->qdomainzone.toString().c_str());
  return 1;
}

static int ldp_addRecords(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  vector<DNSRecord> rrs;
  popResourceRecordsTable(L, DNSName("BOGUS"), rrs);
  for(const DNSRecord& dr :  rrs) {
    DNSZoneRecord dzr;
    dzr.dr=dr;
    dzr.auth=true; // LET'S HOPE THIS IS TRUE XXX
    p->addRecord(dzr);
  }
  return 0;
}

static int ldp_getRemote(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  lua_pushstring(L, p->getRemote().toString().c_str());
  return 1;
}

static int ldp_getRemoteRaw(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  const ComboAddress& ca=p->getRemote();
  if(ca.sin4.sin_family == AF_INET) {
    lua_pushlstring(L, (const char*)&ca.sin4.sin_addr.s_addr, 4);
  }
  else {
    lua_pushlstring(L, (const char*)&ca.sin6.sin6_addr.s6_addr, 16);
  }
  return 1;
}

static int ldp_getRcode(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  lua_pushnumber(L, p->d.rcode);
  return 1;
}

static int ldp_getSize(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  lua_pushnumber(L, p->getString().size());
  return 1;
}

static int ldp_getRRCounts(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  lua_pushnumber(L, ntohs(p->d.ancount));
  lua_pushnumber(L, ntohs(p->d.nscount));
  lua_pushnumber(L, ntohs(p->d.arcount));
  return 3;
}

// these functions are used for PowerDNS recursor regression testing against auth,
// and for the Lua Policy Engine. The Lua 5.2 implementation is untested.
static const struct luaL_Reg ldp_methods [] = {
      {"setRcode", ldp_setRcode},
      {"getQuestion", ldp_getQuestion},
      {"getWild", ldp_getWild},
      {"getZone", ldp_getZone},
      {"addRecords", ldp_addRecords},
      {"getRemote", ldp_getRemote},
      {"getRemoteRaw", ldp_getRemoteRaw},
      {"getSize", ldp_getSize},
      {"getRRCounts", ldp_getRRCounts},
      {"getRcode", ldp_getRcode},
      {NULL, NULL}
    };

#if LUA_VERSION_NUM < 502
void AuthLua::registerLuaDNSPacket(void) {

  luaL_newmetatable(d_lua, "LuaDNSPacket");

  lua_pushstring(d_lua, "__index");
  lua_pushvalue(d_lua, -2);  /* pushes the metatable */
  lua_settable(d_lua, -3);  /* metatable.__index = metatable */

  luaL_openlib(d_lua, NULL, ldp_methods, 0);

  lua_pop(d_lua, 1);
}
#else

void AuthLua::registerLuaDNSPacket(void) {

  luaL_newmetatable(d_lua, "LuaDNSPacket");

  lua_pushstring(d_lua, "__index");
  lua_pushvalue(d_lua, -2);  /* pushes the metatable */
  lua_settable(d_lua, -3);  /* metatable.__index = metatable */

  luaL_setfuncs(d_lua, ldp_methods, 0);

  lua_pop(d_lua, 1);
}
#endif

DNSPacket* AuthLua::prequery(DNSPacket *p)
{
  lua_getglobal(d_lua,"prequery");
  if(!lua_isfunction(d_lua, -1)) {
    // cerr<<"No such function 'prequery'\n";
    lua_pop(d_lua, 1);
    return 0;
  }
  
  DNSPacket *r=0;
  // allocate a fresh packet and prefill the question
  r=p->replyPacket();

  // wrap it
  LuaDNSPacket* lua_dp = (LuaDNSPacket *)lua_newuserdata(d_lua, sizeof(LuaDNSPacket));
  lua_dp->d_p=r;
  
  // make it of the right type
  luaL_getmetatable(d_lua, "LuaDNSPacket");
  lua_setmetatable(d_lua, -2);

  if(lua_pcall(d_lua,  1, 1, 0)) { // error 
    string error=string("lua error in prequery: ")+lua_tostring(d_lua, -1);
    theL()<<Logger::Error<<error<<endl;

    lua_pop(d_lua, 1);
    throw runtime_error(error);
  }
  bool res=lua_toboolean(d_lua, 1);
  lua_pop(d_lua, 1);
  if(res) {
    // prequery created our response, use it
    theL()<<Logger::Info<<"overriding query from lua prequery result"<<endl;
    return r;
  }
  else
  {
    // prequery wanted nothing to do with this question
    delete r;
    return 0;
  }
}

#endif
