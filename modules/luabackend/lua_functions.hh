#ifndef LUABACKEND_EXTERN_F_HH
#define LUABACKEND_EXTERN_F_HH

//extern LUABackend* lb;
extern int my_lua_panic(lua_State* lua);
extern void register_lua_functions(lua_State* lua);

#endif
