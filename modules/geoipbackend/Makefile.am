AM_CPPFLAGS=$(THREADFLAGS) $(BOOST_CPPFLAGS) $(YAML_CFLAGS) $(GEOIP_CFLAGS)
EXTRA_DIST=OBJECTFILES OBJECTLIBS
pkglib_LTLIBRARIES = libgeoipbackend.la
libgeoipbackend_la_SOURCES=geoipbackend.cc geoipbackend.hh
libgeoipbackend_la_LDFLAGS=-module -avoid-version $(YAML_LIBS) $(GEOIP_LIBS)
