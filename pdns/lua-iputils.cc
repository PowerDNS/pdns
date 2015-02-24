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
#undef L

#if !defined LUA_VERSION_NUM || LUA_VERSION_NUM==501
/*
** Adapted from Lua 5.2.0
*/
static void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup) {
  luaL_checkstack(L, nup+1, "too many upvalues");
  for (; l->name != NULL; l++) {  /* fill the table with given functions */
    int i;
    lua_pushstring(L, l->name);
    for (i = 0; i < nup; i++)  /* copy upvalues to the top */
      lua_pushvalue(L, -(nup+1));
    lua_pushcclosure(L, l->func, nup);  /* closure with those upvalues */
    lua_settable(L, -(nup + 3));
  }
  lua_pop(L, nup);  /* remove upvalues */
}
#endif


/////////////////////////////////

static int l_new_ca(lua_State* L)
{
  ComboAddress* ca=(ComboAddress*)lua_newuserdata(L, sizeof(ComboAddress)); 
  memset(ca, 0, sizeof(ComboAddress));
  *ca=ComboAddress(luaL_checkstring(L, 1));
  luaL_getmetatable(L, "iputils.ca");
  lua_setmetatable(L, -2);
  return 1;
}

static int l_ca_tostring(lua_State* L)
{
  ComboAddress* ca = (ComboAddress*)luaL_checkudata(L, 1, "iputils.ca");
  
  string ret=ca->toString();
  lua_pushstring(L, ret.c_str());
  return 1;
}

static int l_ca_tostringWithPort(lua_State* L)
{
  ComboAddress* ca = (ComboAddress*)luaL_checkudata(L, 1, "iputils.ca");
  
  string ret=ca->toStringWithPort();
  lua_pushstring(L, ret.c_str());
  return 1;
}

static int l_ca_equal(lua_State* L)
{
  ComboAddress* ca1 = (ComboAddress*)luaL_checkudata(L, 1, "iputils.ca");
  ComboAddress* ca2 = (ComboAddress*)luaL_checkudata(L, 2, "iputils.ca");
  lua_pushboolean(L, *ca1==*ca2);
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

static int l_ipset_index(lua_State* L)
{
  ourset_t *ourset = (ourset_t*)luaL_checkudata(L, 1, "iputils.ipset");
  ComboAddress* ca1 = (ComboAddress*)luaL_checkudata(L, 2, "iputils.ca");
  if(ourset->count(*ca1)) {
    lua_pushboolean(L, 1);
    return 1;
  }
  
  return 0;
}

static int l_ipset_newindex(lua_State* L)
{
  ourset_t*ourset = (ourset_t*)luaL_checkudata(L, 1, "iputils.ipset");
  ComboAddress* ca1 = (ComboAddress*)luaL_checkudata(L, 2, "iputils.ca");
  ourset->insert(*ca1);
  return 0;
}

static int l_newipset(lua_State* L)
{
  new(lua_newuserdata(L, sizeof(ourset_t))) ourset_t();
  luaL_getmetatable(L, "iputils.ipset");
  lua_setmetatable(L, -2);
  return 1;
}

static int l_ipset_gc(lua_State* L)
{
  ourset_t*ourset = (ourset_t*)luaL_checkudata(L, 1, "iputils.ipset");
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


static int l_netmask_tostring(lua_State* L)
{
  Netmask* nm = (Netmask*)luaL_checkudata(L, 1, "iputils.netmask");
  string ret=nm->toString();
  lua_pushstring(L, ret.c_str());
  return 1;
}

static int l_new_netmask(lua_State* L)
{
  /*Netmask* nm=*/ new(lua_newuserdata(L, sizeof(Netmask))) Netmask(luaL_checkstring(L, 1));
  luaL_getmetatable(L, "iputils.netmask");
  lua_setmetatable(L, -2);
  return 1;
}

static int l_netmask_match(lua_State* L)
{
  Netmask* nm=(Netmask*)luaL_checkudata(L, 1, "iputils.netmask");
  ComboAddress* ca1 = (ComboAddress*)luaL_checkudata(L, 2, "iputils.ca");
  lua_pushboolean(L, nm->match(*ca1));
  return 1;
}

static int l_netmask_gc(lua_State* L)
{
  Netmask* nm = (Netmask*)luaL_checkudata(L, 1, "iputils.netmask");
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

static int l_nmgroup_tostring(lua_State* L)
{
  NetmaskGroup* nmg = (NetmaskGroup*)luaL_checkudata(L, 1, "iputils.nmgroup");
  
  string ret=nmg->toString();
  lua_pushstring(L, ret.c_str());
  return 1;
}

static int l_new_nmgroup(lua_State* L)
{
  /*NetmaskGroup*nmg= */ new(lua_newuserdata(L, sizeof(NetmaskGroup))) NetmaskGroup();
  luaL_getmetatable(L, "iputils.nmgroup");
  lua_setmetatable(L, -2);
  return 1;
}

static int l_nmgroup_match(lua_State* L)
{
  NetmaskGroup* nm=(NetmaskGroup*)luaL_checkudata(L, 1, "iputils.nmgroup");
  ComboAddress* ca1 = (ComboAddress*)luaL_checkudata(L, 2, "iputils.ca");
  lua_pushboolean(L, nm->match(*ca1));
  return 1;
}

static int l_nmgroup_add(lua_State* L)
{
  NetmaskGroup* nm=(NetmaskGroup*)luaL_checkudata(L, 1, "iputils.nmgroup");
  nm->addMask(luaL_checkstring(L, 2));
  return 0;
}


static int l_nmgroup_gc(lua_State* L)
{
  NetmaskGroup* nm = (NetmaskGroup*)luaL_checkudata(L, 1, "iputils.nmgroup");
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


extern "C" int luaopen_iputils(lua_State* L)
{
  luaL_newmetatable(L, "iputils.ca");
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  luaL_setfuncs(L, iputils_ca_methods, 0);

  luaL_newmetatable(L, "iputils.ipset");
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  luaL_setfuncs(L, ipset_methods, 0);

  luaL_newmetatable(L, "iputils.netmask");
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  luaL_setfuncs(L, iputils_netmask_methods, 0);

  luaL_newmetatable(L, "iputils.nmgroup");
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  luaL_setfuncs(L, iputils_nmgroup_methods, 0);

#if LUA_VERSION_NUM < 502
  luaL_register(L, "iputils", iputils);
#else
  luaL_newlib(L, iputils);
#endif
  return 1;
}

#if 0
int makeIPv6sockaddr(const std::string& addr, struct sockaddr_in6* ret)
{
  if(addr.empty())
    return -1;
  string ourAddr(addr);
  int port = -1;
  if(addr[0]=='[') { // [::]:53 style address
    string::size_type pos = addr.find(']');
    if(pos == string::npos || pos + 2 > addr.size() || addr[pos+1]!=':')
      return -1;
    ourAddr.assign(addr.c_str() + 1, pos-1);
    port = atoi(addr.c_str()+pos+2);  
  }
  ret->sin6_scope_id=0;
  ret->sin6_family=AF_INET6;
  if(inet_pton(AF_INET6, ourAddr.c_str(), (void*)&ret->sin6_addr) != 1) {
    struct addrinfo* res;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_NUMERICHOST;
    
    int error;
    if((error=getaddrinfo(ourAddr.c_str(), 0, &hints, &res))) { // this is correct
      return -1;
    }
  
    memcpy(ret, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
  }

  if(port >= 0)
    ret->sin6_port = htons(port);

  return 0;
}

int makeIPv4sockaddr(const std::string& str, struct sockaddr_in* ret)
{
  if(str.empty()) {
    return -1;
  }
  struct in_addr inp;
  
  string::size_type pos = str.find(':');
  if(pos == string::npos) { // no port specified, not touching the port
    if(inet_aton(str.c_str(), &inp)) {
      ret->sin_addr.s_addr=inp.s_addr;
      return 0;
    }
    return -1;
  }
  if(!*(str.c_str() + pos + 1)) // trailing :
    return -1; 
    
  char *eptr = (char*)str.c_str() + str.size();
  int port = strtol(str.c_str() + pos + 1, &eptr, 10);
  if(*eptr)
    return -1;
  
  ret->sin_port = htons(port);
  if(inet_aton(str.substr(0, pos).c_str(), &inp)) {
    ret->sin_addr.s_addr=inp.s_addr;
    return 0;
  }
  return -1;
}


pair<string, string> splitField(const string& inp, char sepa)
{
  pair<string, string> ret;
  string::size_type cpos=inp.find(sepa);
  if(cpos==string::npos)
    ret.first=inp;
  else {
    ret.first=inp.substr(0, cpos);
    ret.second=inp.substr(cpos+1);
  }
  return ret;
}

#endif
#endif
