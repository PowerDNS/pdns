AM_CPPFLAGS += $(YAML_CFLAGS) $(GEOIP_CFLAGS) $(MMDB_CFLAGS) $(LIBCRYPTO_INCLUDES)

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	meson.build

pkglib_LTLIBRARIES = libgeoipbackend.la

libgeoipbackend_la_SOURCES = \
	geoipbackend.cc geoipbackend.hh \
	geoipinterface-dat.cc \
	geoipinterface-mmdb.cc \
	geoipinterface.cc geoipinterface.hh

if GEOIPBACKEND_DYNMODULE
libgeoipbackend_la_LDFLAGS = -module -avoid-version
else
libgeoipbackend_la_LDFLAGS = -static -avoid-version
endif
libgeoipbackend_la_LIBADD = $(YAML_LIBS) $(GEOIP_LIBS) $(MMDB_LIBS) $(CXXFS_LIBS)
