/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 * originally authored by Fredrik Danerklint
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
#include "luabackend.hh"

#include "pdns/logger.hh"
#include "pdns/arguments.hh"


bool LUABackend::startTransaction(const DNSName& qname, int id) {

    if (f_lua_starttransaction == 0)
        return false;

    if (logging)
        g_log << Logger::Info << backend_name << "(startTransaction) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_starttransaction);

    lua_pushstring(lua, qname.toString().c_str());
    lua_pushinteger(lua, id);

    if(lua_pcall(lua, 2, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
    }

    size_t returnedwhat = lua_type(lua, -1);
    bool ok = false;
    
    if (returnedwhat == LUA_TBOOLEAN)
        ok = lua_toboolean(lua, -1);
    
    lua_pop(lua, 1);
    
    if (logging)
	g_log << Logger::Info << backend_name << "(startTransaction) END" << endl;
	
    return ok;
}

bool LUABackend::commitTransaction() {

    if (f_lua_committransaction == 0)
        return false;
        
    if (logging)
	g_log << Logger::Info << backend_name << "(commitTransaction) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_committransaction);

    if(lua_pcall(lua, 0, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
    }

    size_t returnedwhat = lua_type(lua, -1);
    bool ok = false;
    
    if (returnedwhat == LUA_TBOOLEAN)
        ok = lua_toboolean(lua, -1);
    
    lua_pop(lua, 1);
    
    if (logging)
	g_log << Logger::Info << backend_name << "(commitTransaction) END" << endl;
	
    return ok;
}

bool LUABackend::abortTransaction() {

    if (f_lua_aborttransaction == 0)
        return false;

    if (logging)
	g_log << Logger::Info << backend_name << "(abortTransaction) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_aborttransaction);

    if(lua_pcall(lua, 0, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
    }

    size_t returnedwhat = lua_type(lua, -1);
    bool ok = false;
    
    if (returnedwhat == LUA_TBOOLEAN)
        ok = lua_toboolean(lua, -1);
    
    lua_pop(lua, 1);

    if (logging)
	g_log << Logger::Info << backend_name << "(abortTransaction) END" << endl;
    return ok;
}

bool LUABackend::feedRecord(const DNSResourceRecord &rr, const DNSName &ordername, bool ordernameIsNSEC3) {

    if (f_lua_feedrecord == 0)
        return false;

    if (logging)
	g_log << Logger::Info << backend_name << "(feedRecord) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_feedrecord);
    dnsrr_to_table(lua, &rr);

    if(lua_pcall(lua, 1, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
    }

    size_t returnedwhat = lua_type(lua, -1);
    bool ok = false;
    
    if (returnedwhat == LUA_TBOOLEAN)
        ok = lua_toboolean(lua, -1);
    
    lua_pop(lua, 1);

    if (logging)
	g_log << Logger::Info << backend_name << "(feedRecord) END" << endl;
	
    return ok;
}

void LUABackend::setFresh(uint32_t id) {
    
    if (f_lua_setfresh == 0)
        return;

    if (logging)
	g_log << Logger::Info << backend_name << "(setFresh) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_setfresh);

    lua_pushinteger(lua, id);

    if(lua_pcall(lua, 1, 0, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return;
    }

    if (logging)
	g_log << Logger::Info << backend_name << "(setFresh) END" << endl;

}

void LUABackend::getUnfreshSlaveInfos(vector<DomainInfo>* domains) {
    
    if (f_lua_getunfreshslaveinfos == 0)
        return;

    if (logging)
	g_log << Logger::Info << backend_name << "(getUnfreshSlaveInfos) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_getunfreshslaveinfos);

    if(lua_pcall(lua, 0, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return;
    }

    size_t returnedwhat = lua_type(lua, -1);
    if (returnedwhat != LUA_TTABLE) {
        lua_pop(lua, 1 );
        return;
    }
    
    domains_from_table(domains, "getUnfreshSlaveInfos");
    
    if (logging)
	g_log << Logger::Info << backend_name << "(getUnfreshSlaveInfos) END" << endl;

}

bool LUABackend::getDomainInfo(const DNSName&domain, DomainInfo &di, bool getSerial) {
    if (f_lua_getdomaininfo == 0)
        return false;

    if (logging)
	g_log << Logger::Info << backend_name << "(getDomainInfo) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_getdomaininfo);

    lua_pushstring(lua, domain.toString().c_str());
    
    if(lua_pcall(lua, 1, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
    }

    size_t returnedwhat = lua_type(lua, -1);
    if (returnedwhat != LUA_TTABLE) {
        lua_pop(lua, 1 );
        return false;
    }

    if (logging)
	g_log << Logger::Info << backend_name << "(getDomainInfo) END" << endl;
	
    return domaininfo_from_table(&di);
}
