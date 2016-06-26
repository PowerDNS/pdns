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

int AuthLua::police(DNSPacket *req, DNSPacket *resp, bool isTcp)
{
  return PolicyDecision::PASS;
}

string AuthLua::policycmd(const vector<string>&parts) {
  return "no policy script loaded";
}

bool AuthLua::axfrfilter(const ComboAddress& remote, const DNSName& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out)
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

#include "logger.hh"
#include "namespaces.hh"

AuthLua::AuthLua(const std::string &fname)
  : PowerDNSLua(fname)
{
  registerLuaDNSPacket();
  pthread_mutex_init(&d_lock,0);
}

bool AuthLua::axfrfilter(const ComboAddress& remote, const DNSName& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out)
{
  lua_getglobal(d_lua,  "axfrfilter");
  if(!lua_isfunction(d_lua, -1)) {
    // cerr<<"No such function 'axfrfilter'\n";
    lua_pop(d_lua, 1);
    return false;
  }
  
  lua_pushstring(d_lua,  remote.toString().c_str() );
  lua_pushstring(d_lua,  zone.toString().c_str() ); // FIXME400 expose DNSName to Lua?
  lua_pushstring(d_lua,  in.qname.toString().c_str() );
  lua_pushnumber(d_lua,  in.qtype.getCode() );
  lua_pushnumber(d_lua,  in.ttl );
  lua_pushstring(d_lua,  in.content.c_str() );

  if(lua_pcall(d_lua,  6, 2, 0)) { // error
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

  int tableLen = getLuaTableLength(d_lua, 2);
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

    string qname;
    if(!getFromTable("qname", qname))
      rr.qname = zone;
    else
      rr.qname=DNSName(qname);

    if(!getFromTable("place", tmpnum))
      rr.d_place = DNSResourceRecord::ANSWER;
    else
      rr.d_place = static_cast<DNSResourceRecord::Place>(tmpnum);

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
    p->addRecord(DNSResourceRecord(dr));
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

int AuthLua::police(DNSPacket *req, DNSPacket *resp, bool isTcp)
{
  Lock l(&d_lock);

  lua_getglobal(d_lua,  "police");
  if(!lua_isfunction(d_lua, -1)) {
    // cerr<<"No such function 'police'\n"; FIXME: raise Exception? check this beforehand so we can log it once?
    lua_pop(d_lua, 1);
    return PolicyDecision::PASS;
  }

  /* wrap request */
  LuaDNSPacket* lreq = (LuaDNSPacket *)lua_newuserdata(d_lua, sizeof(LuaDNSPacket));
  lreq->d_p=req;
  luaL_getmetatable(d_lua, "LuaDNSPacket");
  lua_setmetatable(d_lua, -2);

  /* wrap response */
  if(resp) {
    LuaDNSPacket* lresp = (LuaDNSPacket *)lua_newuserdata(d_lua, sizeof(LuaDNSPacket));
    lresp->d_p=resp;
    luaL_getmetatable(d_lua, "LuaDNSPacket");
    lua_setmetatable(d_lua, -2);
  }
  else
  {
    lua_pushnil(d_lua);
  }

  lua_pushboolean(d_lua, isTcp);

  if(lua_pcall(d_lua, 3, 1, 0)) {
    string error=string("lua error in police: ")+lua_tostring(d_lua, -1);
    lua_pop(d_lua, 1);
    theL()<<Logger::Error<<"police error: "<<error<<endl;

    throw runtime_error(error);
  }

  int res = (int) lua_tonumber(d_lua, 1);
  lua_pop(d_lua, 1);

  return res;
}

string AuthLua::policycmd(const vector<string>&parts) {
  Lock l(&d_lock);

  lua_getglobal(d_lua, "policycmd");
  if(!lua_isfunction(d_lua, -1)) {
    // cerr<<"No such function 'police'\n"; FIXME: raise Exception? check this beforehand so we can log it once?
    lua_pop(d_lua, 1);
    return "no policycmd function in policy script";
  }

  for(vector<string>::size_type i=1; i<parts.size(); i++)
    lua_pushstring(d_lua, parts[i].c_str());

  if(lua_pcall(d_lua, parts.size()-1, 1, 0)) {
    string error = string("lua error in policycmd: ")+lua_tostring(d_lua, -1);
    lua_pop(d_lua, 1);
    return error;
  }

  const char *ret = lua_tostring(d_lua, 1);
  string rets;
  if(ret)
    rets = ret;

  lua_pop(d_lua, 1);

  return rets;
}

#endif
