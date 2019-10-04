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

#include <iostream>
#include <sstream>
using namespace std;

#include "lua_functions.hh"

void LUABackend::get_lua_function(lua_State *lua_state, const char *name, int *function) {
    *function = 0;
    
    string f = "f_";
    f.append(name);
    
    string arg = "";
    if (!::arg().isEmpty(string(LUABACKEND_PREFIX)+"-"+f))
        arg = getArg(f);

    lua_getglobal(lua_state, arg == "" ? name : arg.c_str());
    if (!lua_isnil(lua_state, -1)) {
	lua_pushvalue(lua_state, -1);     
        *function = luaL_ref(lua_state, LUA_REGISTRYINDEX);
    }
}


void LUABackend::reload() {
    
    backend_name.clear();

    backend_name = "[LUABackend: " + uitoa((uintptr_t)backend_pid) + " (" + uitoa(backend_count) +")] ";
    
    if (lua)
	lua_close(lua);
	
    logging = ::arg().mustDo("query-logging") || mustDo("query-logging");

#if LUA_VERSION_NUM >= 502
    lua = luaL_newstate();
#else
    lua = lua_open();
#endif

    if (lua != NULL) {
	lua_atpanic(lua, my_lua_panic);
	
	string filename = getArg("filename"); //"powerdns-luabackend.lua";
	
	if (luaL_loadfile (lua, filename.c_str()) != 0) {
	    stringstream e;
	    e << backend_name << "Error loading the file '" << filename << "' : " << lua_tostring(lua,-1) << endl;

    	    lua_pop(lua, 1);
	    throw LUAException (e.str());
	} else {
	
	    lua_pushlightuserdata(lua, (void*)this); 
	    lua_setfield(lua, LUA_REGISTRYINDEX, "__LUABACKEND");
	    
	    register_lua_functions(lua);
	    
	    if(lua_pcall(lua,  0, 0, 0)) { 
		stringstream e;
		e << backend_name << "Error running the file '" << filename << "' : " << lua_tostring(lua,-1) << endl;

    		lua_pop(lua, 1);
		throw LUAException (e.str());

	    } else {
		get_lua_function(lua, "exec_error", &f_lua_exec_error);
		
		//minimal functions....
        	get_lua_function(lua, "list", &f_lua_list);
    		get_lua_function(lua, "lookup", &f_lua_lookup);
		get_lua_function(lua, "get", &f_lua_get);
    		get_lua_function(lua, "getsoa", &f_lua_getsoa);
    		
    		if (f_lua_list == 0 || f_lua_lookup == 0 || f_lua_get == 0 || f_lua_getsoa == 0) {
			throw LUAException (backend_name + "MINIMAL BACKEND: Missing required function(s)!");
    		}
    		
    		//master functions....
        	get_lua_function(lua, "getupdatedmasters", &f_lua_getupdatedmasters);
		get_lua_function(lua, "setnotified", &f_lua_setnotified);
    		
    		//slave functions....
		get_lua_function(lua, "getdomaininfo", &f_lua_getdomaininfo);
		get_lua_function(lua, "ismaster", &f_lua_ismaster);
		get_lua_function(lua, "getunfreshslaveinfos", &f_lua_getunfreshslaveinfos);
		get_lua_function(lua, "setfresh", &f_lua_setfresh);
    		get_lua_function(lua, "starttransaction", &f_lua_starttransaction);
		get_lua_function(lua, "committransaction", &f_lua_committransaction);
		get_lua_function(lua, "aborttransaction", &f_lua_aborttransaction);
		get_lua_function(lua, "feedrecord", &f_lua_feedrecord);

		//supermaster functions....
		get_lua_function(lua, "supermasterbackend", &f_lua_supermasterbackend);
		get_lua_function(lua, "createslavedomain", &f_lua_createslavedomain);
    		
    		//rediscover
		get_lua_function(lua, "rediscover", &f_lua_rediscover);
		
		 //dnssec
		get_lua_function(lua, "alsonotifies", &f_lua_alsonotifies);
		get_lua_function(lua, "getdomainmetadata", &f_lua_getdomainmetadata);
		get_lua_function(lua, "setdomainmetadata", &f_lua_setdomainmetadata);

		get_lua_function(lua, "getdomainkeys", &f_lua_getdomainkeys);
		get_lua_function(lua, "removedomainkey", &f_lua_removedomainkey);
		get_lua_function(lua, "activatedomainkey", &f_lua_activatedomainkey);
		get_lua_function(lua, "deactivatedomainkey", &f_lua_deactivatedomainkey);
		get_lua_function(lua, "updatedomainkey", &f_lua_updatedomainkey);
		get_lua_function(lua, "adddomainkey", &f_lua_adddomainkey);

		get_lua_function(lua, "gettsigkey", &f_lua_gettsigkey);
 
		get_lua_function(lua, "getbeforeandafternamesabsolute", &f_lua_getbeforeandafternamesabsolute);
		get_lua_function(lua, "updatednssecorderandauthabsolute", &f_lua_updatednssecorderandauthabsolute);
		get_lua_function(lua, "updatednssecorderandauth", &f_lua_updatednssecorderandauth); // not needed...

	    }
	}
    } else {
	//a big kaboom here!
	throw LUAException (backend_name + "LUA OPEN FAILED!");
    }
}

void LUABackend::rediscover(string* status) {
    
    if (f_lua_rediscover == 0)
        return;

    if (logging)
	g_log << Logger::Info << backend_name << "(rediscover) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_rediscover);

    if(lua_pcall(lua, 0, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
    }

    size_t returnedwhat = lua_type(lua, -1);
    if (returnedwhat != LUA_TSTRING) {
        lua_pop(lua, 1 );
        return;
    }

    string s = lua_tostring(lua, -1);
    lua_pop(lua, 1 );
    *status = s;
    
    if (logging)
	g_log << Logger::Info << backend_name << "(rediscover) END" << endl;
	
    return;
}

