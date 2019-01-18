AM_CPPFLAGS += $(LUA_CFLAGS) \
	-I$(top_srcdir)/ext/luawrapper/include

EXTRA_DIST = OBJECTFILES OBJECTLIBS

pkglib_LTLIBRARIES = liblua2backend.la

liblua2backend_la_SOURCES = \
	lua2backend.cc lua2backend.hh \
	lua2api2.hh lua2api2.cc

liblua2backend_la_LDFLAGS = -module -avoid-version
liblua2backend_la_LIBADD = $(LUA_LIBS)
