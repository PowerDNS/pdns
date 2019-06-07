AM_CPPFLAGS += $(LUA_CFLAGS) \
	-I$(top_srcdir)/ext/luawrapper/include

EXTRA_DIST = OBJECTFILES OBJECTLIBS

pkglib_LTLIBRARIES = liblua2backend.la

liblua2backend_la_SOURCES = \
	lua2backend.cc lua2backend.hh \
	lua2api2.hh lua2api2.cc

if !HAVE_LUA_HPP
BUILT_SOURCES = lua.hpp
nodist_liblua2backend_la_SOURCES = lua.hpp
CLEANFILES = lua.hpp
endif

liblua2backend_la_LDFLAGS = -module -avoid-version
liblua2backend_la_LIBADD = $(LUA_LIBS)

if !HAVE_LUA_HPP
include ../../pdns/lua_hpp.mk
endif
