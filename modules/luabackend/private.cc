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

string LUABackend::my_getArg(string a) {
    return getArg(a);
}

bool LUABackend::my_mustDo(string a) {
    return mustDo(a);
}

bool LUABackend::domaininfo_from_table(DomainInfo *di) {

    di->backend = NULL;
    
    if (!getValueFromTable(lua, "id", di->id))
	return false;
	
    if (!getValueFromTable(lua, "zone", di->zone))
	return false;
	
    if (!getValueFromTable(lua, "serial", di->serial))
	return false;
	
    getValueFromTable(lua, "notified_serial", di->notified_serial);
    getValueFromTable(lua, "last_check", di->last_check);
    
    di->kind = DomainInfo::Native;
    
    string kind;
    if (getValueFromTable(lua, "kind", kind)) {
    
	if (kind == "MASTER")
	    di->kind = DomainInfo::Master;
	else if (kind == "SLAVE")
	    di->kind = DomainInfo::Slave;
    }

    lua_pushstring(lua, "masters"); 
    lua_gettable(lua, -2);  

    if(!lua_isnil(lua, -1)) {
	lua_pushnil(lua);  
	const char *key, *value;
	while (lua_next(lua, -2)) {
    	    value = lua_tostring(lua, -1);
    	    lua_pop(lua,1);
    	    key = lua_tostring(lua, -1); 

    	    di->masters.push_back(value);
	}    
    }
  
    lua_pop(lua, 1);
    
    di->backend = this;

    return true;
}

void LUABackend::domains_from_table(vector<DomainInfo>* domains, const char *f_name) {
    lua_pushnil(lua);  

    int k;
    size_t returnedwhat;
    
    while (lua_next(lua, -2)) {
        returnedwhat = lua_type(lua, -1);
        if (returnedwhat == LUA_TTABLE) {
            DomainInfo di;

            if (domaininfo_from_table(&di)) 
                domains->push_back(di);
        }

        lua_pop(lua,1);
        k = lua_tonumber(lua, -1);
    }
}


void LUABackend::dnsrr_to_table(lua_State *lua, const DNSResourceRecord *rr) {

    lua_newtable(lua);
    
    lua_pushliteral(lua, "qtype");
    lua_pushstring(lua, rr->qtype.getName().c_str());
    lua_settable(lua, -3);
    
    lua_pushliteral(lua, "qclass");
    lua_pushnumber(lua, rr->qclass);
    lua_settable(lua, -3);
    
    lua_pushliteral(lua, "priority");
    lua_pushnumber(lua, rr->priority);
    lua_settable(lua, -3);

    lua_pushliteral(lua, "ttl");
    lua_pushnumber(lua, rr->ttl);
    lua_settable(lua, -3);

    lua_pushliteral(lua, "auth");
    lua_pushboolean(lua, rr->auth);
    lua_settable(lua, -3);
    
    lua_pushliteral(lua, "content");
    lua_pushstring(lua, rr->content.c_str());
    lua_settable(lua, -3);
    
}