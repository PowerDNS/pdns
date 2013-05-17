#include "lua-recursor.hh"
#include "config.h"
// to avoid including all of syncres.hh
int directResolve(const std::string& qname, const QType& qtype, int qclass, vector<DNSResourceRecord>& ret);

#if !defined(HAVE_LUA)

RecursorLua::RecursorLua(const std::string &fname)
  : PowerDNSLua(fname)
{
  // empty
}

bool RecursorLua::nxdomain(const ComboAddress& remote,const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return false;
}

bool RecursorLua::nodata(const ComboAddress& remote,const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return false;
}

bool RecursorLua::postresolve(const ComboAddress& remote,const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return false;
}


bool RecursorLua::preresolve(const ComboAddress& remote, const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
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

RecursorLua::RecursorLua(const std::string &fname)
  : PowerDNSLua(fname)
{
  // empty
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

bool RecursorLua::nxdomain(const ComboAddress& remote, const ComboAddress& local,const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return passthrough("nxdomain", remote, local, query, qtype, ret, res, variable);
}

bool RecursorLua::preresolve(const ComboAddress& remote, const ComboAddress& local,const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return passthrough("preresolve", remote, local, query, qtype, ret, res, variable);
}

bool RecursorLua::nodata(const ComboAddress& remote, const ComboAddress& local,const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return passthrough("nodata", remote, local, query, qtype, ret, res, variable);
}

bool RecursorLua::postresolve(const ComboAddress& remote, const ComboAddress& local,const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable)
{
  return passthrough("postresolve", remote, local, query, qtype, ret, res, variable);
}


bool RecursorLua::passthrough(const string& func, const ComboAddress& remote, const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, 
  int& res, bool* variable)
{
  d_variable = false;
  lua_getglobal(d_lua,  func.c_str());
  if(!lua_isfunction(d_lua, -1)) {
    //  cerr<<"No such function '"<<func<<"'\n";
    lua_pop(d_lua, 1);
    return false;
  }
  
  d_local = local; 
  /* the first argument */
  lua_pushstring(d_lua,  remote.toString().c_str() );
  lua_pushstring(d_lua,  query.c_str() );
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

  if(lua_pcall(d_lua,  3 + extraParameter, 3, 0)) { 
    string error=string("lua error in '"+func+"' while processing query for '"+query+"|"+qtype.getName()+": ")+lua_tostring(d_lua, -1);
    lua_pop(d_lua, 1);
    throw runtime_error(error);
    return false;
  }
  
  *variable |= d_variable;
    
  if(!lua_isnumber(d_lua, 1)) {
    string tocall = lua_tostring(d_lua,1);
    string luaqname = lua_tostring(d_lua,2);
    string luaprefix = lua_tostring(d_lua, 3);
    lua_pop(d_lua, 3);
    // cerr<<"should call '"<<tocall<<"' to finish off"<<endl;
    ret.clear();
    if(tocall == "getFakeAAAARecords")
      res = getFakeAAAARecords(luaqname, luaprefix, ret);
    else if(tocall == "getFakePTRRecords")
      res = getFakePTRRecords(luaqname, luaprefix, ret);
    return true;
    // returned a followup 
  }
  
  int newres = (int)lua_tonumber(d_lua, 1); // new rcode
  if(newres < 0) {
    //    cerr << "handler did not handle"<<endl;
    lua_pop(d_lua, 3);
    return false;
  }
  res=newres;

  ret.clear();

  /*           1       2   3   4   */
  /* stack:  boolean table key row */

  popResourceRecordsTable(d_lua, query, ret);

  lua_pop(d_lua, 3);

  return true;
}

#endif
