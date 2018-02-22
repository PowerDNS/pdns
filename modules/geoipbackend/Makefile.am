AM_CPPFLAGS += $(YAML_CFLAGS) $(GEOIP_CFLAGS) $(MMDB_CFLAGS)

EXTRA_DIST = OBJECTFILES OBJECTLIBS

pkglib_LTLIBRARIES = libgeoipbackend.la

libgeoipbackend_la_SOURCES = geoipbackend.cc geoipbackend.hh \
	geoipinterface.cc geoipinterface.hh \
	geoipinterface-dat.cc \
	geoipinterface-mmdb.cc
libgeoipbackend_la_LDFLAGS = -module -avoid-version
libgeoipbackend_la_LIBADD = $(YAML_LIBS) $(GEOIP_LIBS) $(MMDB_LIBS)
