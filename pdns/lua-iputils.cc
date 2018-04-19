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
#ifdef HAVE_LUA
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}
#include <iostream>
#include "iputils.hh"
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include "namespaces.hh"       

#if !defined LUA_VERSION_NUM || LUA_VERSION_NUM==501
/*
** Adapted from Lua 5.2.0
*/
static void pdns_luaL_setfuncs (lua_State *g_log, const luaL_Reg *l, int nup) {
  luaL_checkstack(g_log, nup+1, "too many upvalues");
  for (; l->name != NULL; l++) {  /* fill the table with given functions */
    int i;
    lua_pushstring(g_log, l->name);
    for (i = 0; i < nup; i++)  /* copy upvalues to the top */
      lua_pushvalue(g_log, -(nup+1));
    lua_pushcclosure(g_log, l->func, nup);  /* closure with those upvalues */
    lua_settable(g_log, -(nup + 3));
  }
  lua_pop(g_log, nup);  /* remove upvalues */
}
#else
static void pdns_luaL_setfuncs (lua_State *g_log, const luaL_Reg *l, int nup) {
  luaL_setfuncs(g_log, l, nup);
}
#endif


/////////////////////////////////

static int l_new_ca(lua_State* g_log)
{
  ComboAddress* ca=(ComboAddress*)lua_newuserdata(g_log, sizeof(ComboAddress)); 
  memset(ca, 0, sizeof(ComboAddress));
  *ca=ComboAddress(luaL_checkstring(g_log, 1));
  luaL_getmetatable(g_log, "iputils.ca");
  lua_setmetatable(g_log, -2);
  return 1;
}

static int l_ca_tostring(lua_State* g_log)
{
  ComboAddress* ca = (ComboAddress*)luaL_checkudata(g_log, 1, "iputils.ca");
  
  string ret=ca->toString();
  lua_pushstring(g_log, ret.c_str());
  return 1;
}

static int l_ca_tostringWithPort(lua_State* g_log)
{
  ComboAddress* ca = (ComboAddress*)luaL_checkudata(g_log, 1, "iputils.ca");
  
  string ret=ca->toStringWithPort();
  lua_pushstring(g_log, ret.c_str());
  return 1;
}

static int l_ca_equal(lua_State* g_log)
{
  ComboAddress* ca1 = (ComboAddress*)luaL_checkudata(g_log, 1, "iputils.ca");
  ComboAddress* ca2 = (ComboAddress*)luaL_checkudata(g_log, 2, "iputils.ca");
  lua_pushboolean(g_log, *ca1==*ca2);
  return 1;
}

static const struct luaL_Reg iputils_ca_methods[]={
    {"tostring", l_ca_tostring},
    {"__tostring", l_ca_tostring},
    {"__eq", l_ca_equal},
    {"tostringwithport", l_ca_tostringWithPort},
    {NULL, NULL}
};


/////////////////////////////

typedef set<ComboAddress, ComboAddress::addressOnlyLessThan> ourset_t;

static int l_ipset_index(lua_State* g_log)
{
  ourset_t *ourset = (ourset_t*)luaL_checkudata(g_log, 1, "iputils.ipset");
  ComboAddress* ca1 = (ComboAddress*)luaL_checkudata(g_log, 2, "iputils.ca");
  if(ourset->count(*ca1)) {
    lua_pushboolean(g_log, 1);
    return 1;
  }
  
  return 0;
}

static int l_ipset_newindex(lua_State* g_log)
{
  ourset_t*ourset = (ourset_t*)luaL_checkudata(g_log, 1, "iputils.ipset");
  ComboAddress* ca1 = (ComboAddress*)luaL_checkudata(g_log, 2, "iputils.ca");
  ourset->insert(*ca1);
  return 0;
}

static int l_newipset(lua_State* g_log)
{
  new(lua_newuserdata(g_log, sizeof(ourset_t))) ourset_t();
  luaL_getmetatable(g_log, "iputils.ipset");
  lua_setmetatable(g_log, -2);
  return 1;
}

static int l_ipset_gc(lua_State* g_log)
{
  ourset_t*ourset = (ourset_t*)luaL_checkudata(g_log, 1, "iputils.ipset");
  ourset->~ourset_t();
  return 0;
}

static const struct luaL_Reg ipset_methods[]={
    {"__index", l_ipset_index},
    {"__newindex", l_ipset_newindex},
    {"__gc", l_ipset_gc},
    {NULL, NULL}
};

////////////////////////////////////////////////////


static int l_netmask_tostring(lua_State* g_log)
{
  Netmask* nm = (Netmask*)luaL_checkudata(g_log, 1, "iputils.netmask");
  string ret=nm->toString();
  lua_pushstring(g_log, ret.c_str());
  return 1;
}

static int l_new_netmask(lua_State* g_log)
{
  /*Netmask* nm=*/ new(lua_newuserdata(g_log, sizeof(Netmask))) Netmask(luaL_checkstring(g_log, 1));
  luaL_getmetatable(g_log, "iputils.netmask");
  lua_setmetatable(g_log, -2);
  return 1;
}

static int l_netmask_match(lua_State* g_log)
{
  Netmask* nm=(Netmask*)luaL_checkudata(g_log, 1, "iputils.netmask");
  ComboAddress* ca1 = (ComboAddress*)luaL_checkudata(g_log, 2, "iputils.ca");
  lua_pushboolean(g_log, nm->match(*ca1));
  return 1;
}

static int l_netmask_gc(lua_State* g_log)
{
  Netmask* nm = (Netmask*)luaL_checkudata(g_log, 1, "iputils.netmask");
  nm->~Netmask();
  return 0;
}

static const struct luaL_Reg iputils_netmask_methods[]={
    {"__tostring", l_netmask_tostring},
    {"tostring", l_netmask_tostring},
    {"match", l_netmask_match},
    {"__gc", l_netmask_gc},
    {NULL, NULL}
};


//////////////////////

static int l_nmgroup_tostring(lua_State* g_log)
{
  NetmaskGroup* nmg = (NetmaskGroup*)luaL_checkudata(g_log, 1, "iputils.nmgroup");
  
  string ret=nmg->toString();
  lua_pushstring(g_log, ret.c_str());
  return 1;
}

static int l_new_nmgroup(lua_State* g_log)
{
  /*NetmaskGroup*nmg= */ new(lua_newuserdata(g_log, sizeof(NetmaskGroup))) NetmaskGroup();
  luaL_getmetatable(g_log, "iputils.nmgroup");
  lua_setmetatable(g_log, -2);
  return 1;
}

static int l_nmgroup_match(lua_State* g_log)
{
  NetmaskGroup* nm=(NetmaskGroup*)luaL_checkudata(g_log, 1, "iputils.nmgroup");
  ComboAddress* ca1 = (ComboAddress*)luaL_checkudata(g_log, 2, "iputils.ca");
  lua_pushboolean(g_log, nm->match(*ca1));
  return 1;
}

static int l_nmgroup_add(lua_State* g_log)
{
  NetmaskGroup* nm=(NetmaskGroup*)luaL_checkudata(g_log, 1, "iputils.nmgroup");
  nm->addMask(luaL_checkstring(g_log, 2));
  return 0;
}


static int l_nmgroup_gc(lua_State* g_log)
{
  NetmaskGroup* nm = (NetmaskGroup*)luaL_checkudata(g_log, 1, "iputils.nmgroup");
  nm->~NetmaskGroup();
  return 0;
}

static const struct luaL_Reg iputils_nmgroup_methods[]={
    {"__tostring", l_nmgroup_tostring},
    {"tostring", l_nmgroup_tostring},
    {"match", l_nmgroup_match},
    {"add", l_nmgroup_add},
    {"__gc", l_nmgroup_gc},
    {NULL, NULL}
};

////////////

static const struct luaL_Reg iputils[]={
    {"newca", l_new_ca},
    {"newipset", l_newipset},
    {"newnm", l_new_netmask},
    {"newnmgroup", l_new_nmgroup},
    {NULL, NULL}
};


extern "C" int luaopen_iputils(lua_State* g_log)
{
  luaL_newmetatable(g_log, "iputils.ca");
  lua_pushvalue(g_log, -1);
  lua_setfield(g_log, -2, "__index");
  pdns_luaL_setfuncs(g_log, iputils_ca_methods, 0);

  luaL_newmetatable(g_log, "iputils.ipset");
  lua_pushvalue(g_log, -1);
  lua_setfield(g_log, -2, "__index");
  pdns_luaL_setfuncs(g_log, ipset_methods, 0);

  luaL_newmetatable(g_log, "iputils.netmask");
  lua_pushvalue(g_log, -1);
  lua_setfield(g_log, -2, "__index");
  pdns_luaL_setfuncs(g_log, iputils_netmask_methods, 0);

  luaL_newmetatable(g_log, "iputils.nmgroup");
  lua_pushvalue(g_log, -1);
  lua_setfield(g_log, -2, "__index");
  pdns_luaL_setfuncs(g_log, iputils_nmgroup_methods, 0);

#if LUA_VERSION_NUM < 502
  luaL_register(g_log, "iputils", iputils);
#else
  luaL_newlib(g_log, iputils);
#endif
  return 1;
}

#endif
