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
    virtual bool updateDNSSECOrderAndAuth(uint32_t domain_id, const std::string& zonename, const std::string& qname, bool auth)
    virtual bool updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const std::string& qname, const std::string& ordername, bool auth)
    virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after)

    virtual bool getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys)
    virtual bool removeDomainKey(const string& name, unsigned int id)
    virtual int addDomainKey(const string& name, const KeyData& key)
    virtual bool activateDomainKey(const string& name, unsigned int id)
    virtual bool deactivateDomainKey(const string& name, unsigned int id)

    virtual bool getTSIGKey(const string& name, string* algorithm, string* content) { return false; }

    virtual bool setDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
    virtual bool getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
    virtual void alsoNotifies(const string &domain, set<string> *ips)

*/

bool LUABackend::updateDNSSECOrderAndAuth(uint32_t domain_id, const std::string& zonename, const std::string& qname, bool auth) {

    if(f_lua_updatednssecorderandauth == 0) {

        if(logging)
            L << Logger::Info << backend_name << "(updateDNSSECOrderAndAuth) domain_id: '" << domain_id << "' zonename: '" << zonename << "' qname: '" << qname << "' auth: '" << auth << "'" << endl;

        string ins=toLower(labelReverse(makeRelative(qname, zonename)));
        return this->updateDNSSECOrderAndAuthAbsolute(domain_id, qname, ins, auth);

    }

    if(logging)
        L << Logger::Info << backend_name << "(updateDNSSECOrderAndAuth) BEGIN domain_id: '" << domain_id << "' zonename: '" << zonename << "' qname: '" << qname << "' auth: '" << auth << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_updatednssecorderandauth);

    lua_pushnumber(lua, domain_id);
    lua_pushstring(lua, zonename.c_str());
    lua_pushstring(lua, qname.c_str());
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
        L << Logger::Info << backend_name << "(updateDNSSECOrderAndAuth) END" << endl;

    return ok;
}

bool LUABackend::updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const std::string& qname, const std::string& ordername, bool auth) {

    if(f_lua_updatednssecorderandauthabsolute == 0)
        return false;

    if(logging)
        L << Logger::Info << backend_name << "(updateDNSSECOrderAndAuthAbsolute) BEGIN domain_id: '" << domain_id << "' qname: '" << qname << "' ordername: '" << ordername << "' auth: '" << auth << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_updatednssecorderandauthabsolute);

    lua_pushnumber(lua, domain_id);
    lua_pushstring(lua, qname.c_str());
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
        L << Logger::Info << backend_name << "(updateDNSSECOrderAndAuthAbsolute) END" << endl;

    return ok;
}

bool LUABackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after) {

    if(f_lua_getbeforeandafternamesabsolute == 0)
        return false;

    unhashed.clear();
    before.clear();
    after.clear();

    if(logging)
        L << Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) BEGIN id: '" << id << "' qname: '" << qname << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_updatednssecorderandauthabsolute);

    lua_pushnumber(lua, id);
    lua_pushstring(lua, qname.c_str());

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
            L << Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) ERROR!" << endl;

        return false;
    }

    //will this be correct since we are poping one at the time?
    unhashed = lua_tostring(lua, -1);
    lua_pop(lua, 1);

    returnedwhat = lua_type(lua, -1);
    ok = (returnedwhat == LUA_TSTRING) && ok;

    before = lua_tostring(lua, -1);
    lua_pop(lua, 1);

    returnedwhat = lua_type(lua, -1);
    ok = (returnedwhat == LUA_TSTRING) && ok;

    after = lua_tostring(lua, -1);
    lua_pop(lua, 1);

    if(logging)
        L << Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) END unhashed: '" << unhashed << "' before: '" << before << "' after: '" << after << "' " << endl;

    return ok;
}

bool LUABackend::updateDomainKey(const string& name, unsigned int &id, bool toowhat ) {

    if(f_lua_updatedomainkey == 0)
        return false;

    if(logging)
        L << Logger::Info << backend_name << "(updateDomainKey) BEGIN name: '" << name << "' id: '" << id << "' toowhat: '" << toowhat << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_updatedomainkey);

    lua_pushstring(lua, name.c_str());
    lua_pushnumber(lua, id);
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
        L << Logger::Info << backend_name << "(updateDomainKey) END" << endl;

    return ok;
}

bool LUABackend::activateDomainKey(const string& name, unsigned int id) {

    if(f_lua_activatedomainkey == 0)
        return updateDomainKey(name, id, true);

    if(logging)
        L << Logger::Info << backend_name << "(activateDomainKey) BEGIN name: '" << name << "' id: '" << id << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_activatedomainkey);

    lua_pushstring(lua, name.c_str());
    lua_pushnumber(lua, id);

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
        L << Logger::Info << backend_name << "(activateDomainKey) END" << endl;

    return ok;
}

bool LUABackend::deactivateDomainKey(const string& name, unsigned int id) {

    if(f_lua_deactivatedomainkey == 0)
        return updateDomainKey(name, id, false);

    if(logging)
        L << Logger::Info << backend_name << "(deactivateDomainKey) BEGIN name: '" << name << "' id: '" << id << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_deactivatedomainkey);

    lua_pushstring(lua, name.c_str());
    lua_pushnumber(lua, id);

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
        L << Logger::Info << backend_name << "(deactivateDomainKey) END" << endl;

    return ok;
}

bool LUABackend::removeDomainKey(const string& name, unsigned int id) {

    if(f_lua_removedomainkey == 0)
        return false;

    if(logging)
        L << Logger::Info << backend_name << "(removeDomainKey) BEGIN name: '" << name << "' id: '" << id << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_removedomainkey);

    lua_pushstring(lua, name.c_str());
    lua_pushnumber(lua, id);

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
        L << Logger::Info << backend_name << "(removeDomainKey) END" << endl;

    return ok;
}

int LUABackend::addDomainKey(const string& name, const KeyData& key) {
// there is no logging function in pdnssec when running this routine?

//key = id, flags, active, content

    if(f_lua_adddomainkey == 0)
        return -1;

    if(logging)
        //L << Logger::Info << backend_name << "(addDomainKey) BEGIN name: '" << name << "' id: '" << id << endl;
        cerr << backend_name << "(addDomainKey) BEGIN name: '" << name << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_adddomainkey);

    lua_pushstring(lua, name.c_str());

    lua_newtable(lua);

    lua_pushliteral(lua, "flags");
    lua_pushnumber(lua, key.flags);
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
        return -1;
    }

    size_t returnedwhat = lua_type(lua, -1);
    int ok = -1;

    if (returnedwhat == LUA_TNUMBER)
        ok = lua_tonumber(lua, -1);

    lua_pop(lua, 1);

    if(logging)
        cerr << backend_name << "(addDomainKey) END" << endl;

    return ok;
}

bool LUABackend::getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys) {
    //what is kind used for?

    if(f_lua_getdomainkeys == 0)
        return false;

    if(logging)
        L << Logger::Info << backend_name << "(getDomainKeys) BEGIN name: '" << name << "' kind: '" << kind << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_getdomainkeys);

    lua_pushstring(lua, name.c_str());
    lua_pushnumber(lua, kind);

    if(lua_pcall(lua, 2, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return false;
    }

    size_t returnedwhat = lua_type(lua, -1);

    if (returnedwhat != LUA_TTABLE) {
        lua_pop(lua, 1);
        if(logging)
            L << Logger::Info << backend_name << "(getDomainKeys) ERROR!" << endl;

        return false;
    }

    lua_pushnil(lua);

    int key;
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
        key = lua_tonumber(lua, -1);
    }

    if(logging)
        L << Logger::Info << backend_name << "(getDomainKeys) END" << endl;

    return j > 0;
}

bool LUABackend::getTSIGKey(const string& name, string* algorithm, string* content) {

    if(f_lua_gettsigkey == 0)
        return false;

    if(logging)
        L << Logger::Info << backend_name << "(getTSIGKey) BEGIN name: '" << name << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_gettsigkey);

    lua_pushstring(lua, name.c_str());

    if(lua_pcall(lua, 1, 2, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return false;
    }

    if ( (lua_type(lua, -1) != LUA_TSTRING) && (lua_type(lua, -2) != LUA_TSTRING) ) {
        lua_pop(lua, 2);
        if(logging)
            L << Logger::Info << backend_name << "(getTSIGKey) ERROR" << endl;
        return false;
    }

    string a,c = "";

    a = lua_tostring(lua, -1);
    lua_pop(lua, 1);

    c  = lua_tostring(lua, -1);
    lua_pop(lua, 1);

    *algorithm = a;
    *content = c;

    if(logging)
        L << Logger::Info << backend_name << "(getTSIGKey) END" << endl;

    return true;
}

bool LUABackend::setDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta) {

    if(f_lua_setdomainmetadata == 0)
        return false;

    if(logging)
        L << Logger::Info << backend_name << "(setDomainMetadata) BEGIN name: '" << name << "' kind: '" << kind << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_setdomainmetadata);

    lua_pushstring(lua, name.c_str());
    lua_pushstring(lua, kind.c_str());

    lua_newtable(lua);
    std::vector<std::string>::iterator i;

    int c = 0;

    for(i = meta.begin(); i<meta.end(); i++ ) {
        c++;
        lua_pushnumber(lua, c);
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
        L << Logger::Info << backend_name << "(setDomainMetadata) END" << endl;

    return ok;

}

bool LUABackend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta) {
    if(f_lua_getdomainmetadata == 0)
        return false;

    if(logging)
        L << Logger::Info << backend_name << "(getDomainMetadata) BEGIN name: '" << name << "' kind: '" << kind << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_getdomainmetadata);

    lua_pushstring(lua, name.c_str());
    lua_pushstring(lua, kind.c_str());

    if(lua_pcall(lua, 2, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return false;
    }

    lua_pushnil(lua);

    int key;
    int j = 0;
    size_t returnedwhat;

    while (lua_next(lua, -2)) {
        returnedwhat = lua_type(lua, -1);
        if (returnedwhat == LUA_TSTRING) {
                j++;
                meta.push_back(lua_tostring(lua, -1));
        }

        lua_pop(lua,1);
        key = lua_tonumber(lua, -1);
    }

    if(logging)
        L << Logger::Info << backend_name << "(getDomainMetadata) END" << endl;

    return j > 0;

}

void LUABackend::alsoNotifies(const string &domain, set<string> *ips) {

    if(f_lua_alsonotifies == 0)
        return;

    if(logging)
        L << Logger::Info << backend_name << "(alsonotifies) BEGIN domain: '" << domain << "'" << endl;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, f_lua_alsonotifies);

    lua_pushstring(lua, domain.c_str());

    if(lua_pcall(lua, 1, 1, f_lua_exec_error) != 0) {
        string e = backend_name + lua_tostring(lua, -1);
        lua_pop(lua, 1);

        throw runtime_error(e);
        return;
    }

    lua_pushnil(lua);

    int key;
    size_t returnedwhat;

    while (lua_next(lua, -2)) {
        returnedwhat = lua_type(lua, -1);
        if (returnedwhat == LUA_TSTRING) {
                ips->insert(lua_tostring(lua, -1));
        }

        lua_pop(lua,1);
        key = lua_tonumber(lua, -1);
    }

    if(logging)
        L << Logger::Info << backend_name << "(alsoNotifies) END" << endl;

    return;

}
