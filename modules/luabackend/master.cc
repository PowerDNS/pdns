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

void LUABackend::getUpdatedMasters(vector<DomainInfo>* domains) {
	
    if (f_lua_getupdatedmasters == 0)
	return;

    if (logging)
	g_log << Logger::Info << backend_name << "(getUpdatedMasters) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_getupdatedmasters);

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
    
    domains_from_table(domains, "getUpdatedMasters");
    
    if (logging)
	g_log << Logger::Info << backend_name << "(getUpdatedMasters) END" << endl;
}

void LUABackend::setNotified(uint32_t id, uint32_t serial) {
	
    if (f_lua_setnotified == 0)
	return;

    if (logging)
	g_log << Logger::Info << backend_name << "(setNotified) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_setnotified);

    lua_pushinteger(lua, id);
    lua_pushinteger(lua, serial);

    if(lua_pcall(lua, 2, 0, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return;
    }

    if (logging)
	g_log << Logger::Info << backend_name << "(setNotified) END" << endl;
}

