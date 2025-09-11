AM_CPPFLAGS += $(LUA_CFLAGS) \
	-I$(top_srcdir)/ext/luawrapper/include \
	$(LIBCRYPTO_INCLUDES)

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	meson.build

pkglib_LTLIBRARIES = liblua2backend.la

liblua2backend_la_SOURCES = \
	lua2api2.hh lua2api2.cc \
	lua2backend.cc lua2backend.hh

if LUA2BACKEND_DYNMODULE
liblua2backend_la_LDFLAGS = -module -avoid-version
else
liblua2backend_la_LDFLAGS = -static -avoid-version
endif
liblua2backend_la_LIBADD = $(LUA_LIBS)
