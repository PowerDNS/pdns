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


bool LUABackend::updateDNSSECOrderAndAuth(uint32_t domain_id, const DNSName& zonename, const DNSName& qname, bool auth) {

    if(f_lua_updatednssecorderandauth == 0) {

	if(logging)
	    g_log << Logger::Info << backend_name << "(updateDNSSECOrderAndAuth) domain_id: '" << domain_id << "' zonename: '" << zonename << "' qname: '" << qname << "' auth: '" << auth << "'" << endl;
	    
	string ins=qname.makeRelative(zonename).makeLowerCase().labelReverse().toString(" ", false);
	return this->updateDNSSECOrderAndAuthAbsolute(domain_id, qname, ins, auth);
    } 

    if(logging)
        g_log << Logger::Info << backend_name << "(updateDNSSECOrderAndAuth) BEGIN domain_id: '" << domain_id << "' zonename: '" << zonename << "' qname: '" << qname << "' auth: '" << auth << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_updatednssecorderandauth);

    lua_pushinteger(lua, domain_id);
    lua_pushstring(lua, zonename.toString().c_str());
    lua_pushstring(lua, qname.toString().c_str());
    lua_pushboolean(lua, auth);

    if(lua_pcall(lua, 4, 1, f_lua_exec_error) != 0) {
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

    if(logging)
        g_log << Logger::Info << backend_name << "(updateDNSSECOrderAndAuth) END" << endl;
    
    return ok;
}

bool LUABackend::updateDNSSECOrderNameAndAuth(unsigned int, DNSName const&, DNSName const&, bool, unsigned short)
{
  return false;
}

bool LUABackend::updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const DNSName& qname, const std::string& ordername, bool auth) {

    if(f_lua_updatednssecorderandauthabsolute == 0)
	return false;
	
    if(logging)
        g_log << Logger::Info << backend_name << "(updateDNSSECOrderAndAuthAbsolute) BEGIN domain_id: '" << domain_id << "' qname: '" << qname << "' ordername: '" << ordername << "' auth: '" << auth << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_updatednssecorderandauthabsolute);

    lua_pushinteger(lua, domain_id);
    lua_pushstring(lua, qname.toString().c_str());
    lua_pushstring(lua, ordername.c_str());
    lua_pushboolean(lua, auth);

    if(lua_pcall(lua, 4, 1, f_lua_exec_error) != 0) {
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

    if(logging)
        g_log << Logger::Info << backend_name << "(updateDNSSECOrderAndAuthAbsolute) END" << endl;

    return ok;
}

bool LUABackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) {

    if(f_lua_getbeforeandafternamesabsolute == 0)
	return false;

    unhashed.clear(); 
    before.clear(); 
    after.clear();

    if(logging)
	g_log << Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) BEGIN id: '" << id << "' qname: '" << qname << "'" << endl;
	
    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_updatednssecorderandauthabsolute);

    lua_pushinteger(lua, id);
    lua_pushstring(lua, qname.toString().c_str());

    if(lua_pcall(lua, 2, 3, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return false;
    }
    
    size_t returnedwhat = lua_type(lua, -1);
    bool ok = returnedwhat == LUA_TSTRING;
    
    if (!ok) {
	if(logging)
	    g_log << Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) ERROR!" << endl;
	    
	return false;
    }
    
    //will this be correct since we are poping one at the time?
    unhashed = DNSName(lua_tostring(lua, -1));
    lua_pop(lua, 1);

    returnedwhat = lua_type(lua, -1);
    ok = (returnedwhat == LUA_TSTRING) && ok;
    
    before = DNSName(lua_tostring(lua, -1));
    lua_pop(lua, 1);

    returnedwhat = lua_type(lua, -1);
    ok = (returnedwhat == LUA_TSTRING) && ok;
    
    after = DNSName(lua_tostring(lua, -1));
    lua_pop(lua, 1);

    if(logging)
        g_log << Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) END unhashed: '" << unhashed << "' before: '" << before << "' after: '" << after << "' " << endl;
    
    return ok;
}

bool LUABackend::updateDomainKey(const DNSName& name, unsigned int &id, bool toowhat ) {

    if(f_lua_updatedomainkey == 0) 
	return false;

    if(logging)
	g_log << Logger::Info << backend_name << "(updateDomainKey) BEGIN name: '" << name << "' id: '" << id << "' toowhat: '" << toowhat << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_updatedomainkey);

    lua_pushstring(lua, name.toString().c_str());
    lua_pushinteger(lua, id);
    lua_pushboolean(lua, toowhat);

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

    if(logging)
	g_log << Logger::Info << backend_name << "(updateDomainKey) END" << endl;
	
    return ok;
}

bool LUABackend::activateDomainKey(const DNSName& name, unsigned int id) {

    if(f_lua_activatedomainkey == 0) 
	return updateDomainKey(name, id, true);

    if(logging)
	g_log << Logger::Info << backend_name << "(activateDomainKey) BEGIN name: '" << name << "' id: '" << id << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_activatedomainkey);

    lua_pushstring(lua, name.toString().c_str());
    lua_pushinteger(lua, id);

    if(lua_pcall(lua, 2, 1, f_lua_exec_error) != 0) {
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

    if(logging)
	g_log << Logger::Info << backend_name << "(activateDomainKey) END" << endl;
	
    return ok;
}

bool LUABackend::deactivateDomainKey(const DNSName& name, unsigned int id) {

    if(f_lua_deactivatedomainkey == 0) 
	return updateDomainKey(name, id, false);

    if(logging)
	g_log << Logger::Info << backend_name << "(deactivateDomainKey) BEGIN name: '" << name << "' id: '" << id << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_deactivatedomainkey);

    lua_pushstring(lua, name.toString().c_str());
    lua_pushinteger(lua, id);

    if(lua_pcall(lua, 2, 1, f_lua_exec_error) != 0) {
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

    if(logging)
	g_log << Logger::Info << backend_name << "(deactivateDomainKey) END" << endl;
	
    return ok;
}

bool LUABackend::removeDomainKey(const DNSName& name, unsigned int id) {

    if(f_lua_removedomainkey == 0) 
	return false;

    if(logging)
	g_log << Logger::Info << backend_name << "(removeDomainKey) BEGIN name: '" << name << "' id: '" << id << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_removedomainkey);

    lua_pushstring(lua, name.toString().c_str());
    lua_pushinteger(lua, id);

    if(lua_pcall(lua, 2, 1, f_lua_exec_error) != 0) {
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

    if(logging)
	g_log << Logger::Info << backend_name << "(removeDomainKey) END" << endl;
	
    return ok;
}

// TODO: tcely: Find out about the logging situation and remove cerr if possible.
bool LUABackend::addDomainKey(const DNSName& name, const KeyData& key, int64_t& id) {
// there is no logging function in pdnsutil when running this routine?

//key = id, flags, active, content

    if(f_lua_adddomainkey == 0) 
	return false;

    if(logging)
	//g_log << Logger::Info << backend_name << "(addDomainKey) BEGIN name: '" << name << "' id: '" << id << endl;
	cerr << backend_name << "(addDomainKey) BEGIN name: '" << name << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_adddomainkey);

    lua_pushstring(lua, name.toString().c_str());

    lua_newtable(lua);
    
    lua_pushliteral(lua, "flags");
    lua_pushinteger(lua, key.flags);
    lua_settable(lua, -3);

    lua_pushliteral(lua, "active");
    lua_pushboolean(lua, key.active);
    lua_settable(lua, -3);
    
    lua_pushliteral(lua, "content");
    lua_pushstring(lua, key.content.c_str());
    lua_settable(lua, -3);

    if(lua_pcall(lua, 2, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
    }

    size_t returnedwhat = lua_type(lua, -1);
    int ok = -1;
    
    if (returnedwhat == LUA_TNUMBER)
        ok = lua_tonumber(lua, -1);
    
    lua_pop(lua, 1);

    if(logging)
        cerr << backend_name << "(addDomainKey) END" << endl;

    return ok >= 0;
}

bool LUABackend::getDomainKeys(const DNSName& name, std::vector<KeyData>& keys) {
    if(f_lua_getdomainkeys == 0) 
	return false;

    if(logging)
	g_log << Logger::Info << backend_name << "(getDomainKeys) BEGIN name: '" << name << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_getdomainkeys);

    lua_pushstring(lua, name.toString().c_str());

    if(lua_pcall(lua, 1, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);

        throw runtime_error(e);
        return false;
    }

    size_t returnedwhat = lua_type(lua, -1);

    if (returnedwhat != LUA_TTABLE) {
	lua_pop(lua, 1);
	if(logging)
	    g_log << Logger::Info << backend_name << "(getDomainKeys) ERROR!" << endl;
	    
	return false;
    }

    lua_pushnil(lua);  

    int j = 0;
    
    while (lua_next(lua, -2)) {
        returnedwhat = lua_type(lua, -1);
        if (returnedwhat == LUA_TTABLE) {
    	    KeyData kd;
    	    bool i,f,a,c = false;
    	    
    	    i = getValueFromTable(lua, "id", kd.id);
    	    f = getValueFromTable(lua, "flags", kd.flags);
    	    a = getValueFromTable(lua, "active", kd.active);
    	    c = getValueFromTable(lua, "content", kd.content);
    	    
    	    if (i && f && a && c) {
    		j++;
    		keys.push_back(kd);
    	    }
        }

        lua_pop(lua,1);
    }

    if(logging)
	g_log << Logger::Info << backend_name << "(getDomainKeys) END" << endl;
	
    return j > 0;
}

bool LUABackend::getTSIGKey(const DNSName& name, DNSName* algorithm, string* content) { 

    if(f_lua_gettsigkey == 0) 
	return false;

    if(logging)
	g_log << Logger::Info << backend_name << "(getTSIGKey) BEGIN name: '" << name << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_gettsigkey);

    lua_pushstring(lua, name.toString().c_str());

    if(lua_pcall(lua, 1, 2, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return false;
    }

    if ( (lua_type(lua, -1) != LUA_TSTRING) && (lua_type(lua, -2) != LUA_TSTRING) ) {
	lua_pop(lua, 2);
	if(logging)
	    g_log << Logger::Info << backend_name << "(getTSIGKey) ERROR" << endl;
	return false;
    }
    
    string a,c = "";
    
    a = lua_tostring(lua, -1);
    lua_pop(lua, 1);

    c  = lua_tostring(lua, -1);
    lua_pop(lua, 1);
    
    *algorithm = DNSName(a);
    *content = c;
    
    if(logging)
	g_log << Logger::Info << backend_name << "(getTSIGKey) END" << endl;
	
    return true;
}

bool LUABackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta) {

    if(f_lua_setdomainmetadata == 0) 
	return false;

    if(logging)
	g_log << Logger::Info << backend_name << "(setDomainMetadata) BEGIN name: '" << name << "' kind: '" << kind << "'" << endl;
	
    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_setdomainmetadata);

    lua_pushstring(lua, name.toString().c_str());
    lua_pushstring(lua, kind.c_str());

    lua_newtable(lua);

    std::vector<std::string>::const_iterator i;

    int c = 0;
    
    for(i = meta.begin(); i<meta.end(); i++ ) {
	c++;
	lua_pushinteger(lua, c);
        lua_pushstring(lua, i->c_str());
        lua_settable(lua, -3);
    }

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

    if(logging)
	g_log << Logger::Info << backend_name << "(setDomainMetadata) END" << endl;
	
    return ok;

}

bool LUABackend::getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta) {
    if(f_lua_getdomainmetadata == 0) 
	return false;

    if(logging)
	g_log << Logger::Info << backend_name << "(getDomainMetadata) BEGIN name: '" << name << "' kind: '" << kind << "'" << endl;
	
    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_getdomainmetadata);

    lua_pushstring(lua, name.toString().c_str());
    lua_pushstring(lua, kind.c_str());

    if(lua_pcall(lua, 2, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return false;
    }

    if (lua_type(lua, -1) != LUA_TTABLE)
        return false;

    lua_pushnil(lua);  

    int j = 0;
    size_t returnedwhat;
    
    while (lua_next(lua, -2)) {
        returnedwhat = lua_type(lua, -1);
        if (returnedwhat == LUA_TSTRING) {
    	    j++;
    	    meta.push_back(lua_tostring(lua, -1));
        }

        lua_pop(lua,1);
    }

    if(logging)
	g_log << Logger::Info << backend_name << "(getDomainMetadata) END" << endl;
	
    return j > 0;

}

void LUABackend::alsoNotifies(const DNSName& domain, set<string> *ips) {

    if(f_lua_alsonotifies == 0) 
	return;

    if(logging)
	g_log << Logger::Info << backend_name << "(alsonotifies) BEGIN domain: '" << domain << "'" << endl;
	
    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_alsonotifies);

    lua_pushstring(lua, domain.toString().c_str());

    if(lua_pcall(lua, 1, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return;
    }

    if (lua_type(lua, -1) != LUA_TTABLE)
        return;

    lua_pushnil(lua);  

    size_t returnedwhat;
    
    while (lua_next(lua, -2)) {
        returnedwhat = lua_type(lua, -1);
        if (returnedwhat == LUA_TSTRING) {
    	    ips->insert(lua_tostring(lua, -1));
        }

        lua_pop(lua,1);
    }

    if(logging)
	g_log << Logger::Info << backend_name << "(alsoNotifies) END" << endl;
	
    return;

}
