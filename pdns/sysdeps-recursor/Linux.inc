OPTIONALS:=optional/epollmplexer.o
OS_SPECIFIC_INSTALL=mkdir -p $(DESTDIR)/etc/init.d ; cp pdns-recursor.init.d $(DESTDIR)/etc/init.d/pdns-recursor

ifeq ($(CC),cc)
	CC:=gcc
endif

CXXFLAGS := $(CXXFLAGS) -D_GNU_SOURCE -DHAVE_STRCASESTR -std=gnu++11
CFLAGS := $(CFLAGS) -D_GNU_SOURCE

LUA_CPPFLAGS_CONFIG ?= -I/usr/include/lua5.2
LUA_LIBS_CONFIG ?= -llua5.2 -rdynamic

# Lua 5.0 settings
#LUA_CPPFLAGS_CONFIG=-I/usr/include/lua50 
#LUA_LIBS_CONFIG=-llua50 -llualib50


optional/epollmplexer.o: epollmplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

