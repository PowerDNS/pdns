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

string LUABackend::my_getArg(string a) {
    return getArg(a);
}

bool LUABackend::my_mustDo(string a) {
    return mustDo(a);
}

bool LUABackend::my_isEmpty(string a) {
    return ::arg().isEmpty(string(LUABACKEND_PREFIX)+"-"+a);
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
	const char *value;
	while (lua_next(lua, -2)) {
    	    value = lua_tostring(lua, -1);
    	    lua_pop(lua,1);
    	    di->masters.push_back(ComboAddress(value, 53));
	}    
    }
  
    lua_pop(lua, 1);
    
    di->backend = this;

    return true;
}

void LUABackend::domains_from_table(vector<DomainInfo>* domains, const char *f_name) {
    lua_pushnil(lua);  

    size_t returnedwhat;
    
    while (lua_next(lua, -2)) {
        returnedwhat = lua_type(lua, -1);
        if (returnedwhat == LUA_TTABLE) {
            DomainInfo di;

            if (domaininfo_from_table(&di)) 
                domains->push_back(di);
        }

        lua_pop(lua,1);
    }
}


void LUABackend::dnsrr_to_table(lua_State *lua, const DNSResourceRecord *rr) {

    lua_newtable(lua);
    
    lua_pushliteral(lua, "qtype");
    lua_pushstring(lua, rr->qtype.getName().c_str());
    lua_settable(lua, -3);
    
    lua_pushliteral(lua, "qclass");
    lua_pushinteger(lua, rr->qclass);
    lua_settable(lua, -3);

    lua_pushliteral(lua, "ttl");
    lua_pushinteger(lua, rr->ttl);
    lua_settable(lua, -3);

    lua_pushliteral(lua, "auth");
    lua_pushboolean(lua, rr->auth);
    lua_settable(lua, -3);
    
    lua_pushliteral(lua, "content");
    lua_pushstring(lua, rr->content.c_str());
    lua_settable(lua, -3);
    
}

bool LUABackend::dnsrr_from_table(lua_State *lua, DNSResourceRecord &rr) {

    bool got_content = false;
    string qt_name;
    uint16_t qt_code;

    // look for qname key first
    // try name key if qname wasn't set
    if (!getValueFromTable(lua, "qname", rr.qname))
        getValueFromTable(lua, "name", rr.qname);

    // qtype is either a table, string or number
    // when it's a table prefer the code key
    lua_pushliteral(lua, "qtype");
    lua_gettable(lua, -2);
    size_t returnedwhat = lua_type(lua, -1);
    if (LUA_TTABLE == returnedwhat) {
        if (getValueFromTable(lua, "code", qt_code))
            rr.qtype = qt_code;
        else
            if (getValueFromTable(lua, "name", qt_name))
                rr.qtype = qt_name;
        lua_pop(lua, 1);
    } else if (LUA_TNUMBER == returnedwhat) {
        lua_pop(lua, 1);
        if (getValueFromTable(lua, "qtype", qt_code))
            rr.qtype = qt_code;
    } else {
        lua_pop(lua, 1);
        if (getValueFromTable(lua, "qtype", qt_name))
            rr.qtype = qt_name;
        else // fallback to old key for tests to pass
            if (getValueFromTable(lua, "type", qt_name))
                rr.qtype = qt_name;
    }

    getValueFromTable(lua, "qclass", rr.qclass);
    getValueFromTable(lua, "domain_id", rr.domain_id);
    getValueFromTable(lua, "auth", rr.auth);
    getValueFromTable(lua, "last_modified", rr.last_modified);

    getValueFromTable(lua, "ttl", rr.ttl);
    got_content = getValueFromTable(lua, "content", rr.content);
    getValueFromTable(lua, "scopeMask", rr.scopeMask);

    return got_content;

}
