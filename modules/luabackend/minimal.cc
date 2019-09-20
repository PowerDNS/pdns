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

/* FIRST PART */

LUABackend::LUABackend(const string &suffix) {

    setArgPrefix(LUABACKEND_PREFIX+suffix);

    try {

	if (pthread_equal(backend_pid, pthread_self())) {
    	    backend_count++;
	} else {
    	    backend_count = 1;
    	    backend_pid = pthread_self();
	}

	lua = NULL;
	dnspacket = NULL;
	dnssec = false;

	reload();
    }

    catch(LUAException &e) {
        g_log<<Logger::Error<<backend_name<<"Error: "<<e.what<<endl;
        throw PDNSException(e.what);
    }

}

LUABackend::~LUABackend() {
    try {
        g_log<<Logger::Info<<backend_name<<"Closing..." << endl;
    }
    catch (...) {
    }

    lua_close(lua);
}

bool LUABackend::list(const DNSName &target, int domain_id, bool include_disabled) {
    if (logging)
	g_log << Logger::Info << backend_name << "(list) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_list);

    lua_pushstring(lua, target.toString().c_str());
    lua_pushinteger(lua, domain_id);

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
	g_log << Logger::Info << backend_name << "(list) END" << endl;

    return ok;
}

void LUABackend::lookup(const QType &qtype, const DNSName &qname, int domain_id, DNSPacket *p) {
    if (logging)
	g_log << Logger::Info << backend_name << "(lookup) BEGIN" << endl;

    dnspacket = p;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_lookup);

    lua_newtable(lua);
    lua_pushliteral(lua, "name");
    lua_pushstring(lua, qtype.getName().c_str());
    lua_settable(lua, -3);
    lua_pushliteral(lua, "code");
    lua_pushinteger(lua, qtype.getCode());
    lua_settable(lua, -3);
    lua_newtable(lua);
    if(0 == luaL_loadstring(lua, "return function (t) return t.name end")) {
	lua_call(lua, 0, 1);
	lua_setfield(lua, -2, "__tostring");
    }
    lua_setmetatable(lua, -2);

    lua_pushstring(lua, qname.toString().c_str());
    lua_pushinteger(lua, domain_id);

    if(lua_pcall(lua, 3, 0, f_lua_exec_error) != 0) {
	string e = backend_name + lua_tostring(lua, -1);
	lua_pop(lua, 1);

	dnspacket = NULL;

	throw runtime_error(e);
	return;
    }

    dnspacket = NULL;

    if (logging)
	g_log << Logger::Info << backend_name << "(lookup) END" << endl;
}

bool LUABackend::get(DNSResourceRecord &rr) {
    if (logging)
	g_log << Logger::Info << backend_name << "(get) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_get);

    if(lua_pcall(lua, 0, 1, f_lua_exec_error) != 0) {
	string e = backend_name + lua_tostring(lua, -1);
	lua_pop(lua, 1);

	throw runtime_error(e);
	return false;
    }

    size_t returnedwhat = lua_type(lua, -1);
    if (returnedwhat != LUA_TTABLE) {
	lua_pop(lua, 1 );
	return false;
    }

    rr.content.clear();
    bool got_content = false;
    got_content = dnsrr_from_table(lua, rr);

    if (rr.ttl == 0)
        rr.ttl = ::arg().asNum( "default-ttl" );

    if (logging)
	g_log << Logger::Info << backend_name << "(get) END " << got_content << endl;

    return got_content;
}

bool LUABackend::getSOA(const DNSName &name, SOAData &soadata) {
    if (logging)
	g_log << Logger::Info << backend_name << "(getsoa) BEGIN" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_getsoa);

    lua_pushstring(lua, name.toString().c_str());

    if(lua_pcall(lua, 1, 1, f_lua_exec_error) != 0) {
	string e = backend_name + lua_tostring(lua, -1);
	lua_pop(lua, 1);

	throw runtime_error(e);
	return false;
    }

    size_t returnedwhat = lua_type(lua, -1);
    if (returnedwhat != LUA_TTABLE) {
	lua_pop(lua, 1 );
	return false;
    }

    soadata.db = this;
    soadata.qname = name;
    soadata.serial = 0;
    soadata.qname = name;
    getValueFromTable(lua, "serial", soadata.serial);
    if (soadata.serial == 0) {
	lua_pop(lua, 1 );
	return false;
    }

    getValueFromTable(lua, "refresh", soadata.refresh);
    getValueFromTable(lua, "retry", soadata.retry);
    getValueFromTable(lua, "expire", soadata.expire);
    getValueFromTable(lua, "default_ttl", soadata.default_ttl);
    getValueFromTable(lua, "domain_id", soadata.domain_id);

    getValueFromTable(lua, "ttl", soadata.ttl);
    if (soadata.ttl == 0 && soadata.default_ttl > 0)
	soadata.ttl = soadata.default_ttl;

    if (soadata.ttl == 0) {
	lua_pop(lua, 1 );
	return false;
    }

    if (!getValueFromTable(lua, "nameserver", soadata.nameserver)) {
        soadata.nameserver = DNSName(::arg()["default-soa-name"]);
        if (soadata.nameserver.empty()) {
    	    g_log<<Logger::Error << backend_name << "(getSOA)" << " Error: SOA Record is missing nameserver for the domain '" << name << "'" << endl;
	    lua_pop(lua, 1 );
            return false;
        }
    }

    if (!getValueFromTable(lua, "hostmaster", soadata.hostmaster))
      soadata.hostmaster = DNSName("hostmaster")+DNSName(name);

    lua_pop(lua, 1 );

    if (logging)
	g_log << Logger::Info << backend_name << "(getsoa) END" << endl;

    return true;
}
