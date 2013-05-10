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
    virtual void getUpdatedMasters(vector<DomainInfo>* domains);
    virtual void setNotifed(int id, u_int32_t serial);
*/

void LUABackend::getUpdatedMasters(vector<DomainInfo>* domains) {

    if (f_lua_getupdatedmasters == 0)
        return;

    if (logging)
        L << Logger::Info << backend_name << "(getUpdatedMasters) BEGIN" << endl;

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
        L << Logger::Info << backend_name << "(getUpdatedMasters) END" << endl;
}

void LUABackend::setNotifed(int id, u_int32_t serial) {

    if (f_lua_setnotifed == 0)
        return;

    if (logging)
        L << Logger::Info << backend_name << "(setNotifed) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_setnotifed);

    lua_pushnumber(lua, id);
    lua_pushnumber(lua, serial);

    if(lua_pcall(lua, 2, 0, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return;
    }

    if (logging)
        L << Logger::Info << backend_name << "(setNotifed) END" << endl;
}

