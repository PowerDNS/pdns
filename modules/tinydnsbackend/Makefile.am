AM_CPPFLAGS += $(CDB_CFLAGS) $(LIBCRYPTO_INCLUDES)

pkglib_LTLIBRARIES = libtinydnsbackend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	meson.build

libtinydnsbackend_la_SOURCES = \
	../../pdns/cdb.cc ../../pdns/cdb.hh \
	tinydnsbackend.cc tinydnsbackend.hh

if TINYDNSBACKEND_DYNMODULE
libtinydnsbackend_la_LDFLAGS = -module -avoid-version $(LIBCRYPTO_LDFLAGS) $(LIBSSL_LDFLAGS)
else
libtinydnsbackend_la_LDFLAGS = -static -avoid-version $(LIBCRYPTO_LDFLAGS) $(LIBSSL_LDFLAGS)
endif
libtinydnsbackend_la_LIBADD = $(CDB_LIBS)
