#include "lua-auth.hh"

#if !defined(PDNS_ENABLE_LUA)

AuthLua::AuthLua(const std::string &fname)
  : PowerDNSLua(fname)
{
  // empty
}

bool AuthLua::prequery(DNSPacket *p)
{
  return false;
}

bool AuthLua::axfrfilter(const ComboAddress& remote, const string& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out)
{
  return false;
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
#include <boost/foreach.hpp>
#include "logger.hh"
#include "namespaces.hh"

AuthLua::AuthLua(const std::string &fname)
  : PowerDNSLua(fname)
{
  registerLuaDNSPacket();
}

bool AuthLua::axfrfilter(const ComboAddress& remote, const string& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out)
{
  lua_getglobal(d_lua,  "axfrfilter");
  if(!lua_isfunction(d_lua, -1)) {
    cerr<<"No such function 'axfrfilter'\n";
    lua_pop(d_lua, 1);
    return false;
  }
  
  lua_pushstring(d_lua,  remote.toString().c_str() );
  lua_pushstring(d_lua,  zone.c_str() );
  lua_pushstring(d_lua,  in.qname.c_str() );
  lua_pushnumber(d_lua,  in.qtype.getCode() );
  lua_pushnumber(d_lua,  in.ttl );
  lua_pushnumber(d_lua,  in.priority );
  lua_pushstring(d_lua,  in.content.c_str() );

  if(lua_pcall(d_lua,  7, 2, 0)) { // error 
    string error=string("lua error in axfrfilter: ")+lua_tostring(d_lua, -1);
    lua_pop(d_lua, 1);
    throw runtime_error(error);
    return false;
  }
  
  int newres = (int)lua_tonumber(d_lua, 1); // did we handle it?
  if(newres < 0) {
    //cerr << "handler did not handle"<<endl;
    lua_pop(d_lua, 2);
    return false;
  }

  /* get the result */
  DNSResourceRecord rr;
  rr.d_place = DNSResourceRecord::ANSWER;
  rr.ttl = 3600;
  rr.domain_id = in.domain_id;

  out.clear();

  /*           1       2   3   4   */
  /* stack:  boolean table key row */

#ifndef LUA_VERSION_NUM
  int tableLen = luaL_getn(d_lua, 2);
#else
  int tableLen = lua_objlen(d_lua, 2);
#endif
  cerr<<"Returned "<<tableLen<<" rows"<<endl;
  for(int n=1; n < tableLen + 1; ++n) {
    lua_pushnumber(d_lua, n);
    lua_gettable(d_lua, 2);

    uint32_t tmpnum=0;
    if(!getFromTable("qtype", tmpnum)) 
      rr.qtype=QType::A;
    else
      rr.qtype=tmpnum;

    getFromTable("content", rr.content);
    if(!getFromTable("ttl", rr.ttl))
      rr.ttl=3600;

    if(!getFromTable("qname", rr.qname))
      rr.qname = zone;

    if(!getFromTable("place", tmpnum))
      rr.d_place = DNSResourceRecord::ANSWER;
    else
      rr.d_place = (DNSResourceRecord::Place) tmpnum;

    /* removes 'value'; keeps 'key' for next iteration */
    lua_pop(d_lua, 1); // table

    //    cerr<<"Adding content '"<<rr.content<<"' with place "<<(int)rr.d_place<<" \n";
    out.push_back(rr);
  }
  lua_pop(d_lua, 2); // c
  return true;
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
  int rcode = luaL_checkint(L, 2);
  p->setRcode(rcode);
  return 0;
}

static int ldp_getQuestion(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  lua_pushstring(L, p->qdomain.c_str());
  lua_pushnumber(L, p->qtype.getCode());
  return 2;
}

static int ldp_addRecords(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  vector<DNSResourceRecord> rrs;
  popResourceRecordsTable(L, "BOGUS", rrs);
  BOOST_FOREACH(DNSResourceRecord rr, rrs) {
    p->addRecord(rr);
  }
  return 0;
}

static int ldp_getRemote(lua_State *L) {
  DNSPacket *p=ldp_checkDNSPacket(L);
  lua_pushstring(L, p->getRemote().c_str());
  return 1;
}

static const struct luaL_reg ldp_methods [] = {
      {"setRcode", ldp_setRcode},
      {"getQuestion", ldp_getQuestion},
      {"addRecords", ldp_addRecords},
      {"getRemote", ldp_getRemote},
      {NULL, NULL}
    };

void AuthLua::registerLuaDNSPacket(void) {

  luaL_newmetatable(d_lua, "LuaDNSPacket");

  lua_pushstring(d_lua, "__index");
  lua_pushvalue(d_lua, -2);  /* pushes the metatable */
  lua_settable(d_lua, -3);  /* metatable.__index = metatable */

  luaL_openlib(d_lua, NULL, ldp_methods, 0);

  lua_pop(d_lua, 1);
}

DNSPacket* AuthLua::prequery(DNSPacket *p)
{
  lua_getglobal(d_lua,"prequery");
  if(!lua_isfunction(d_lua, -1)) {
    cerr<<"No such function 'prequery'\n";
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
    return 0;
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