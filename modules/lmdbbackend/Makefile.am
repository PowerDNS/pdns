AM_CPPFLAGS += $(LMDB_CFLAGS) $(LIBCRYPTO_INCLUDES)

pkglib_LTLIBRARIES = liblmdbbackend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	meson.build

liblmdbbackend_la_SOURCES = \
	../../ext/lmdb-safe/lmdb-safe.hh ../../ext/lmdb-safe/lmdb-safe.cc \
	../../ext/lmdb-safe/lmdb-typed.hh ../../ext/lmdb-safe/lmdb-typed.cc \
	lmdbbackend.cc lmdbbackend.hh
if LMDBBACKEND_DYNMODULE
liblmdbbackend_la_LDFLAGS = -module -avoid-version $(BOOST_SERIALIZATION_LDFLAGS)
else
liblmdbbackend_la_LDFLAGS = -static -avoid-version $(BOOST_SERIALIZATION_LDFLAGS)
endif
liblmdbbackend_la_LIBADD = $(LMDB_LIBS) $(BOOST_SERIALIZATION_LIBS) $(SYSTEMD_LIBS)
