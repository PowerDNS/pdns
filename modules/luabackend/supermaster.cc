/*
    Copyright (C) 2011 Fredrik Danerklint

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/


#include "luabackend.hh"

#include "pdns/logger.hh"
#include "pdns/arguments.hh"

/*
 //! determine if ip is a supermaster or a domain
  virtual bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db)

  //! called by PowerDNS to create a slave record for a superMaster
  virtual bool createSlaveDomain(const string &ip, const string &domain, const string &account)

*/

bool LUABackend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db) {

    if (f_lua_supermasterbackend == 0)
        return false;

    if (logging)
        L << Logger::Info << backend_name << "(superMasterBackend) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_supermasterbackend);

    lua_pushstring(lua, ip.c_str());
    lua_pushstring(lua, domain.c_str());


    lua_newtable(lua);
    int c = 0;
    for(vector<DNSResourceRecord>::const_iterator i=nsset.begin();i!=nsset.end();++i) {
        c++;
        lua_pushnumber(lua, c);

        DNSResourceRecord rr;

        rr.qtype = i->qtype;
        rr.qclass = i->qclass;
        rr.priority = i->priority;
        rr.ttl = i->ttl;
        rr.auth = i->auth;
        rr.content = i->content;

        dnsrr_to_table(lua, &rr);
        lua_settable(lua, -3);
    }

    if(lua_pcall(lua, 3, 2, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return false;
    }

    size_t returnedwhat = lua_type(lua, -1);
    bool ok = false;

    if (returnedwhat == LUA_TBOOLEAN)
        ok = lua_toboolean(lua, -1);

    lua_pop(lua, 1);

    string a = "";
    returnedwhat = lua_type(lua, -1);
    if (returnedwhat == LUA_TSTRING)
        a = lua_tostring(lua, -1);
    lua_pop(lua, 1);

    if (ok) {
        *account = a;
        *db = this;
    }

    if (logging)
        L << Logger::Info << backend_name << "(superMasterBackend) END" << endl;

    return ok;
}

bool LUABackend::createSlaveDomain(const string &ip, const string &domain, const string &account) {

    if (f_lua_createslavedomain == 0)
        return false;

    if (logging)
        L << Logger::Info << backend_name << "(createSlaveDomain) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_createslavedomain);

    lua_pushstring(lua, ip.c_str());
    lua_pushstring(lua, domain.c_str());
    lua_pushstring(lua, account.c_str());

    if(lua_pcall(lua, 3, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return false;
    }

    size_t returnedwhat = lua_type(lua, -1);
    bool ok = false;

    if (returnedwhat == LUA_TBOOLEAN)
        ok = lua_toboolean(lua, -1);

    lua_pop(lua, 1);

    if (logging)
        L << Logger::Info << backend_name << "(createSlaveDomain) END" << endl;

    return ok;
}
