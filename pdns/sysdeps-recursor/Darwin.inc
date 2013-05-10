CXXFLAGS+=-D_XOPEN_SOURCE -DHAVE_STRCASESTR

LUA_CPPFLAGS_CONFIG ?= -I/usr/include/lua5.1
LUA_LIBS_CONFIG ?= -llua5.1 -rdynamic

# Lua 5.0 settings
#LUA_CPPFLAGS_CONFIG=-I/usr/include/lua50
#LUA_LIBS_CONFIG=-llua50 -llualib50

