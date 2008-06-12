#include "lua-pdns-recursor.hh"
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

using namespace std;

extern "C" int netmaskMatchLua(lua_State *lua)
{
  bool result=false;
  if(lua_gettop(lua) == 2) {
    string ip=lua_tostring(lua, 1);
    string netmask=lua_tostring(lua, 2);

    Netmask nm(netmask);
    ComboAddress ca(ip);
    
    result = nm.match(ip);
  }
  lua_pushboolean(lua, result);
  return 1;
}

PowerDNSLua::PowerDNSLua()
{
  d_lua = lua_open();
  luaopen_base(d_lua);
  lua_settop(d_lua, 0);
  if(luaL_dofile(d_lua,  "./script.lua")) {
    cerr<<"Error loading LUA file: ";
    if (lua_isstring(d_lua, -1)) 
      cerr<<lua_tostring(d_lua, -1);
    cerr<<endl;

    d_failed=true;
  }
  lua_pushcfunction(d_lua, netmaskMatchLua);
  lua_setglobal(d_lua, "matchnetmask");
  d_failed=false;
}

bool PowerDNSLua::nxdomain(const ComboAddress& remote, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res)
{
  return passthrough("nxdomain", remote, query, qtype, ret, res);
}

bool PowerDNSLua::prequery(const ComboAddress& remote, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res)
{
  return passthrough("prequery", remote, query, qtype, ret, res);
}

bool PowerDNSLua::passthrough(const string& func, const ComboAddress& remote, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res)
{
  if(d_failed)
    return false;

  /* the function name */
  lua_getglobal(d_lua,  func.c_str());
  if(!lua_isfunction(d_lua, -1)) {
    cerr<<"No such function '"<<func<<"'\n";
    lua_pop(d_lua, 1);
    return false;
  }
  /* the first argument */
  lua_pushstring(d_lua,  remote.toString().c_str() );
  lua_pushstring(d_lua,  query.c_str() );
  lua_pushnumber(d_lua,  qtype.getCode() );

  lua_call(d_lua,  3, 2);
  if(!lua_toboolean(d_lua, 1)) {
    //    cerr << "handler did not handle"<<endl;
    lua_pop(d_lua, 2);
    return false;
  }

  /* get the result */
  DNSResourceRecord rr;
  rr.qname = query;
  rr.d_place = DNSResourceRecord::ANSWER;
  rr.ttl = 3600;

  ret.clear();

  //  cerr<<"Think there are "<<lua_objlen(d_lua, 2)<<" records\n";

  /*           1       2   */
  /* stack:  boolean table */

  for(unsigned int n = 0 ; n <= lua_objlen(d_lua, 2); ++n) {
    lua_pushnumber(d_lua, n); // becomes 3
    lua_gettable(d_lua, 2);  // 3 gone, replaced by table[0] - which is again a table

    lua_pushnumber(d_lua, 1); // 4 is now '1'
    lua_gettable(d_lua, 3);  // replace by the first entry of our table we hope
    
    rr.qtype = QType((int)(lua_tonumber(d_lua, -1)));
    lua_pop(d_lua, 1);
    
    lua_pushnumber(d_lua, 2); // 4 is now '1'
    lua_gettable(d_lua, 3);  // replace by the second entry of our table we hope
    
    rr.content= lua_tostring(d_lua,  -1);
    lua_pop(d_lua, 2); // content + table

    //    cerr<<"Adding content '"<<rr.content<<"'\n";
    ret.push_back(rr);
  }

  lua_pop(d_lua, 2);

  //  printf("\nBack to C again: %s, type %d\n\n", rr.content.c_str(), rr.qtype.getCode());

  res=0;


  return true;
}

PowerDNSLua::~PowerDNSLua()
{
  cerr<<"Destructor called"<<endl;
  /* Remember to destroy the Lua State */
  lua_close(d_lua);
  cerr<<"Done destroying"<<endl;
}

/*
int main()
{
  PowerDNSLua pdl;
  pdl.nxdomain(ComboAddress("127.0.0.1"), "ds9a.nl", QType(QType::A));
}
*/
