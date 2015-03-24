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

#define LUABACKEND_EXTERN_F_HH

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "luabackend.hh"

#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "pdns/dnspacket.hh"

#include <iostream>
#include <sstream>
using namespace std;

const luaL_Reg lualibs[] = {
    {"", luaopen_base},
    {LUA_LOADLIBNAME, luaopen_package},
    {LUA_TABLIBNAME, luaopen_table},
    {LUA_IOLIBNAME, luaopen_io},
    {LUA_OSLIBNAME, luaopen_os},
    {LUA_STRLIBNAME, luaopen_string},
    {LUA_MATHLIBNAME, luaopen_math},
    {LUA_DBLIBNAME, luaopen_debug},
//    {LUA_COLIBNAME, luaopen_coroutine},
#ifdef USE_LUAJIT    
    {"bit",     luaopen_bit},
    {"jit",     luaopen_jit},
#endif
    {NULL, NULL}
};

int my_lua_panic (lua_State *lua) {
    lua_getfield(lua, LUA_REGISTRYINDEX, "__LUABACKEND"); 
    LUABackend* lb = (LUABackend*)lua_touserdata(lua, -1);
    
    assert(lua == lb->lua);
    
    stringstream e;
    
    e << lb->backend_name << "LUA PANIC! '" << lua_tostring(lua,-1) << "'" << endl;
    
    throw LUAException (e.str());
    
    return 0;
}

int l_arg_get (lua_State *lua) {
    int i = lua_gettop(lua);
    if (i < 1)
	return 0;
	
    lua_getfield(lua, LUA_REGISTRYINDEX, "__LUABACKEND"); 
    LUABackend* lb = (LUABackend*)lua_touserdata(lua, -1);

    string a = lua_tostring(lua, 1);

    if (::arg().isEmpty(a))
	lua_pushnil(lua);
    else 
        lua_pushstring(lua, lb->my_getArg(a).c_str());

    return 1;
}

int l_arg_mustdo (lua_State *lua) {
    int i = lua_gettop(lua);
    if (i < 1)
	return 0;
	
    lua_getfield(lua, LUA_REGISTRYINDEX, "__LUABACKEND"); 
    LUABackend* lb = (LUABackend*)lua_touserdata(lua, -1);
    
    string a = lua_tostring(lua, 1);

    if (::arg().isEmpty(a))
	lua_pushnil(lua);
    else 
        lua_pushboolean(lua, lb->my_mustDo(a));

    return 1;
}

int l_dnspacket (lua_State *lua) {
    lua_getfield(lua, LUA_REGISTRYINDEX, "__LUABACKEND"); 
    LUABackend* lb = (LUABackend*)lua_touserdata(lua, -1);

    if (lb->dnspacket == NULL) {
	lua_pushnil(lua);
	
	return 1;
    }

    lua_pushstring(lua, lb->dnspacket->getRemote().c_str());
    lua_pushnumber(lua, lb->dnspacket->getRemotePort());
    lua_pushstring(lua, lb->dnspacket->getLocal().c_str());
    
    return 3;
}

int l_logger (lua_State *lua) {
//    assert(lua == lb->lua);
    
    lua_getfield(lua, LUA_REGISTRYINDEX, "__LUABACKEND"); 
    LUABackend* lb = (LUABackend*)lua_touserdata(lua, -1);
    
    int i = lua_gettop(lua);
    if (i < 1)
	return 0;

    int log_level = 0;
    stringstream s;
    int j;
    const char *ss;

    log_level = lua_tointeger(lua, 1);
    
    string space = "";
    
    for(j=2; j<=i; j++) {
	ss = lua_tostring(lua, j);
	s << space << ss;
	space = " ";
    }
    
    L.log(lb->backend_name + s.str(), (Logger::Urgency) log_level);
    
    return 0;
}

void register_lua_functions(lua_State *lua) {
    lua_gc(lua, LUA_GCSTOP, 0);  // stop collector during initialization 

    const luaL_Reg *lib = lualibs;
    for (; lib->func; lib++) {
        lua_pushcfunction(lua, lib->func);
        lua_pushstring(lua, lib->name);
        lua_call(lua, 1, 0);
    }

    lua_gc(lua, LUA_GCRESTART, 0);

    lua_pushinteger(lua, Logger::All);
    lua_setglobal(lua, "log_all");

    lua_pushinteger(lua, Logger::NTLog);
    lua_setglobal(lua, "log_ntlog");

    lua_pushinteger(lua, Logger::Alert);
    lua_setglobal(lua, "log_alert");

    lua_pushinteger(lua, Logger::Critical);
    lua_setglobal(lua, "log_critical");

    lua_pushinteger(lua, Logger::Error);
    lua_setglobal(lua, "log_error");

    lua_pushinteger(lua, Logger::Warning);
    lua_setglobal(lua, "log_warning");

    lua_pushinteger(lua, Logger::Notice);
    lua_setglobal(lua, "log_notice");

    lua_pushinteger(lua, Logger::Info);
    lua_setglobal(lua, "log_info");
    
    lua_pushinteger(lua, Logger::Debug);
    lua_setglobal(lua, "log_debug");

    lua_pushinteger(lua, Logger::None);
    lua_setglobal(lua, "log_none");
    
    lua_pushcfunction(lua, l_dnspacket);
    lua_setglobal(lua, "dnspacket");
    
    lua_pushcfunction(lua, l_logger);
    lua_setglobal(lua, "logger");

    lua_pushcfunction(lua, l_arg_get);
    lua_setglobal(lua, "getarg");

    lua_pushcfunction(lua, l_arg_mustdo);
    lua_setglobal(lua, "mustdo");
    
    lua_newtable(lua);
    for(vector<QType::namenum>::const_iterator iter = QType::names.begin(); iter != QType::names.end(); ++iter) {
	lua_pushnumber(lua, iter->second);
	lua_setfield(lua, -2, iter->first.c_str());
    }
    lua_pushnumber(lua, 3);
    lua_setfield(lua, -2, "NXDOMAIN");
    lua_setglobal(lua, "QTypes");
}

bool LUABackend::getValueFromTable(lua_State *lua, const std::string& key, string& value) {
  lua_pushstring(lua, key.c_str()); 
  lua_gettable(lua, -2);  

  bool ret = false;
  
  if(!lua_isnil(lua, -1)) {
    value = lua_tostring(lua, -1);
    ret = true;
  }
  
  lua_pop(lua, 1);
  
  return ret;
}

bool LUABackend::getValueFromTable(lua_State *lua, uint32_t key, string& value) {
  lua_pushnumber(lua, key); 
  lua_gettable(lua, -2);  

  bool ret = false;
  
  if(!lua_isnil(lua, -1)) {
    value = lua_tostring(lua, -1);
    ret = true;
  }
  
  lua_pop(lua, 1);
  
  return ret;
}

bool LUABackend::getValueFromTable(lua_State *lua, const std::string& key, time_t& value) {
  lua_pushstring(lua, key.c_str()); 
  lua_gettable(lua, -2);  

  bool ret = false;
  
  if(!lua_isnil(lua, -1)) {
    value = (time_t)lua_tonumber(lua, -1);
    ret = true;
  }
  
  lua_pop(lua, 1);
  
  return ret;
}

bool LUABackend::getValueFromTable(lua_State *lua, const std::string& key, uint32_t& value) {
  lua_pushstring(lua, key.c_str()); 
  lua_gettable(lua, -2);  

  bool ret = false;
  
  if(!lua_isnil(lua, -1)) {
    value = (uint32_t)lua_tonumber(lua, -1);
    ret = true;
  }
  
  lua_pop(lua, 1);
  
  return ret;
}

bool LUABackend::getValueFromTable(lua_State *lua, const std::string& key, uint16_t& value) {
  lua_pushstring(lua, key.c_str()); 
  lua_gettable(lua, -2);  

  bool ret = false;
  
  if(!lua_isnil(lua, -1)) {
    value = (uint16_t)lua_tonumber(lua, -1);
    ret = true;
  }
  
  lua_pop(lua, 1);
  
  return ret;
}

bool LUABackend::getValueFromTable(lua_State *lua, const std::string& key, int& value) {
  lua_pushstring(lua, key.c_str()); 
  lua_gettable(lua, -2);  

  bool ret = false;
  
  if(!lua_isnil(lua, -1)) {
    value = (int)lua_tonumber(lua, -1);
    ret = true;
  }
  
  lua_pop(lua, 1);
  
  return ret;
}

bool LUABackend::getValueFromTable(lua_State *lua, const std::string& key, bool& value) {
  lua_pushstring(lua, key.c_str()); 
  lua_gettable(lua, -2);  

  bool ret = false;
  
  if(!lua_isnil(lua, -1)) {
    value = lua_toboolean(lua, -1);
    ret = true;
  }
  
  lua_pop(lua, 1);
  
  return ret;
}

