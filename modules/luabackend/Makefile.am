AM_CPPFLAGS=@THREADFLAGS@
EXTRA_DIST=OBJECTFILES OBJECTLIBS 

INCLUDES=-I/usr/include/lua5.1
#INCLUDES=-I/usr/local/include/luajit-2.0 -DUSE_LUAJIT

lib_LTLIBRARIES = libluabackend.la

libluabackend_la_SOURCES=luabackend.cc luabackend.hh minimal.cc reload.cc lua_functions.cc master.cc private.cc slave.cc supermaster.cc dnssec.cc 
libluabackend_la_LDFLAGS=-module -avoid-version -llua5.1
#-lluajit-5.1
