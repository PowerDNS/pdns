AM_CPPFLAGS += $(LUA_CFLAGS)

EXTRA_DIST = OBJECTFILES OBJECTLIBS

pkglib_LTLIBRARIES = libluabackend.la

libluabackend_la_SOURCES = \
	dnssec.cc \
	lua_functions.cc lua_functions.hh \
	luabackend.cc luabackend.hh \
	master.cc \
	minimal.cc \
	private.cc \
	reload.cc \
	slave.cc \
	supermaster.cc

libluabackend_la_LDFLAGS = -module -avoid-version
libluabackend_la_LIBADD = $(LUA_LIBS)
