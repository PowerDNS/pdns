AM_CPPFLAGS=-I/usr/include/lua5.1 @THREADFLAGS@
#AM_CPPFLAGS=-I/usr/local/include/luajit-2.0 -DUSE_LUAJIT @THREADFLAGS@
EXTRA_DIST=OBJECTFILES OBJECTLIBS


lib_LTLIBRARIES = libluabackend.la

libluabackend_la_SOURCES=luabackend.cc luabackend.hh minimal.cc reload.cc lua_functions.cc master.cc private.cc slave.cc supermaster.cc dnssec.cc \
	lua_functions.hh

libluabackend_la_LDFLAGS=-module -avoid-version -llua5.1
#-lluajit-5.1
