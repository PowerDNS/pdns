#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "lua-recursor.hh"
// to avoid including all of syncres.hh
int directResolve(const std::string& qname, const QType& qtype, int qclass, vector<DNSResourceRecord>& ret);

#if !defined(HAVE_LUA)

RecursorLua::RecursorLua(const std::string &fname)
  : PowerDNSLua(fname)
{
  // empty
}

bool RecursorLua::nxdomain(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return false;
}

bool RecursorLua::nodata(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return false;
}

bool RecursorLua::postresolve(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return false;
}


bool RecursorLua::preresolve(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return false;
}

bool RecursorLua::preoutquery(const ComboAddress& remote, const ComboAddress& local,const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res)
{
  return false;
}

bool RecursorLua::ipfilter(const ComboAddress& remote, const ComboAddress& local)
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
#include "rec_channel.hh"

static int getRegisteredNameLua(lua_State *L) {
  const char *name = luaL_checkstring(L, 1);
  string regname=getRegisteredName(name).toString();
  lua_pushstring(L, regname.c_str());
  return 1;
}

RecursorLua::RecursorLua(const std::string &fname)
  : PowerDNSLua(fname)
{
  lua_pushcfunction(d_lua, getRegisteredNameLua);
  lua_setglobal(d_lua, "getregisteredname");
}

int followCNAMERecords(vector<DNSResourceRecord>& ret, const QType& qtype)
{
  vector<DNSResourceRecord> resolved;
  string target;
  BOOST_FOREACH(DNSResourceRecord& rr, ret) {
    if(rr.qtype.getCode() == QType::CNAME) {
      target=rr.content;
      break;
    }
  }
  if(target.empty())
    return 0;

  if(target[target.size()-1]!='.')
    target.append(1, '.');

  int rcode=directResolve(target, qtype, 1, resolved); // 1 == class

  BOOST_FOREACH(const DNSResourceRecord& rr, resolved)
  {
    ret.push_back(rr);
  }
  return rcode;

}

int getFakeAAAARecords(const std::string& qname, const std::string& prefix, vector<DNSResourceRecord>& ret)
{
  int rcode=directResolve(qname, QType(QType::A), 1, ret);

  ComboAddress prefixAddress(prefix);

  BOOST_FOREACH(DNSResourceRecord& rr, ret)
  {
    if(rr.qtype.getCode() == QType::A && rr.d_place==DNSResourceRecord::ANSWER) {
      ComboAddress ipv4(rr.content);
      uint32_t tmp;
      memcpy((void*)&tmp, &ipv4.sin4.sin_addr.s_addr, 4);
      // tmp=htonl(tmp);
      memcpy(((char*)&prefixAddress.sin6.sin6_addr.s6_addr)+12, &tmp, 4);
      rr.content = prefixAddress.toString();
      rr.qtype = QType(QType::AAAA);
    }
  }
  return rcode;
}

int getFakePTRRecords(const std::string& qname, const std::string& prefix, vector<DNSResourceRecord>& ret)
{
  /* qname has a reverse ordered IPv6 address, need to extract the underlying IPv4 address from it
     and turn it into an IPv4 in-addr.arpa query */
  ret.clear();
  vector<string> parts;
  stringtok(parts, qname, ".");
  if(parts.size() < 8)
    return -1;

  string newquery;
  for(int n = 0; n < 4; ++n) {
    newquery +=
      lexical_cast<string>(strtol(parts[n*2].c_str(), 0, 16) + 16*strtol(parts[n*2+1].c_str(), 0, 16));
    newquery.append(1,'.');
  }
  newquery += "in-addr.arpa.";


  int rcode = directResolve(newquery, QType(QType::PTR), 1, ret);
  BOOST_FOREACH(DNSResourceRecord& rr, ret)
  {
    if(rr.qtype.getCode() == QType::PTR && rr.d_place==DNSResourceRecord::ANSWER) {
      rr.qname = qname;
    }
  }
  return rcode;

}

bool RecursorLua::nxdomain(const ComboAddress& remote, const ComboAddress& local,const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  if(d_nofuncs.nxdomain)
    return false;

  return passthrough("nxdomain", remote, local, query, qtype, ret, res, variable);
}

bool RecursorLua::preresolve(const ComboAddress& remote, const ComboAddress& local,const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  if(d_nofuncs.preresolve)
    return false;
  return passthrough("preresolve", remote, local, query, qtype, ret, res, variable);
}

bool RecursorLua::nodata(const ComboAddress& remote, const ComboAddress& local,const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  if(d_nofuncs.nodata)
    return false;

  return passthrough("nodata", remote, local, query, qtype, ret, res, variable);
}

bool RecursorLua::postresolve(const ComboAddress& remote, const ComboAddress& local,const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  if(d_nofuncs.postresolve)
    return false;
  return passthrough("postresolve", remote, local, query, qtype, ret, res, variable);
}

bool RecursorLua::preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res)
{
  if(d_nofuncs.preoutquery)
    return false;

  return passthrough("preoutquery", ns, requestor, query, qtype, ret, res, 0);
}

// returns true to block
bool RecursorLua::ipfilter(const ComboAddress& remote, const ComboAddress& local)
{
  if(d_nofuncs.ipfilter)
    return false;

  lua_getglobal(d_lua,  "ipfilter");
  if(!lua_isfunction(d_lua, -1)) {
    d_nofuncs.regist("ipfilter");
    lua_pop(d_lua, 1);
    return false;
  }
  d_local = local;

  ComboAddress* ca=(ComboAddress*)lua_newuserdata(d_lua, sizeof(ComboAddress));
  *ca=remote;
  luaL_getmetatable(d_lua, "iputils.ca");
  lua_setmetatable(d_lua, -2);

  if(lua_pcall(d_lua,  1, 1, 0)) {
    string error=string("lua error in 'ipfilter' while processing: ")+lua_tostring(d_lua, -1);
    lua_pop(d_lua, 1);
    throw runtime_error(error);
    return false;
  }

  int newres = (int)lua_tonumber(d_lua, 1);
  lua_pop(d_lua, 1);
  return newres != -1;
}


bool RecursorLua::passthrough(const string& func, const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret,
  int& res, bool* variable)
{
  d_variable = false;
  lua_getglobal(d_lua,  func.c_str());
  if(!lua_isfunction(d_lua, -1)) {
    // we hit this rarely, so we can be slow
    //    cerr<<"Registering negative for '"<<func<<"'"<<endl;
    d_nofuncs.regist(func);

    lua_pop(d_lua, 1);
    return false;
  }

  d_local = local;
  /* the first argument */
  if(strcmp(func.c_str(),"preoutquery"))
    lua_pushstring(d_lua,  remote.toString().c_str() );
  else {
    ComboAddress* ca=(ComboAddress*)lua_newuserdata(d_lua, sizeof(ComboAddress));
    *ca=remote;
    luaL_getmetatable(d_lua, "iputils.ca");
    lua_setmetatable(d_lua, -2);
  }

  lua_pushstring(d_lua,  query.toString().c_str() );
  lua_pushnumber(d_lua,  qtype.getCode() );

  int extraParameter = 0;
  if(!strcmp(func.c_str(),"nodata")) {
    pushResourceRecordsTable(d_lua, ret);
    extraParameter++;
  }
  else if(!strcmp(func.c_str(),"postresolve")) {
    pushResourceRecordsTable(d_lua, ret);
    lua_pushnumber(d_lua, res);
    extraParameter+=2;
  }

  if(lua_pcall(d_lua,  3 + extraParameter, 3, 0)) {   // NOTE! Means we always get 3 stack entries back, no matter what our lua hook returned!
    string error=string("lua error in '"+func+"' while processing query for '"+query.toString()+"|"+qtype.getName()+": ")+lua_tostring(d_lua, -1);
    lua_pop(d_lua, 1);
    throw runtime_error(error);
    return false;
  }

  if(variable)
    *variable |= d_variable;

  if(!lua_isnumber(d_lua, 1)) {
    string tocall = lua_tostring(d_lua,1);
    lua_remove(d_lua, 1); // the name
    ret.clear();
    if(tocall == "getFakeAAAARecords") {
      string luaprefix = lua_tostring(d_lua, 2);
      string luaqname = lua_tostring(d_lua,1);
      lua_pop(d_lua, 2);
      res = getFakeAAAARecords(luaqname, luaprefix, ret);
    }
    else if(tocall == "getFakePTRRecords") {
      string luaprefix = lua_tostring(d_lua, 2);
      string luaqname = lua_tostring(d_lua,1);
      lua_pop(d_lua, 2);
      res = getFakePTRRecords(luaqname, luaprefix, ret);
    }
    else if(tocall == "followCNAMERecords") {
      popResourceRecordsTable(d_lua, query, ret);
      lua_pop(d_lua, 2);
      res = followCNAMERecords(ret, qtype);
    }

    return true;
    // returned a followup
  }

  int newres = (int)lua_tonumber(d_lua, 1); // new rcode
  if(newres == -1) {
    //    cerr << "handler did not handle"<<endl;
    lua_pop(d_lua, 3);
    return false;
  }
  res=newres;

  ret.clear();

  /*           1       2   3   4   */
  /* stack:  boolean table key row */

  popResourceRecordsTable(d_lua, query, ret); // doesn't actually pop the table itself!
  lua_pop(d_lua, 3);
  return true;
}

#endif
