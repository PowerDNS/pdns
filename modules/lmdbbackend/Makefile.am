AM_CPPFLAGS += $(LMDB_CFLAGS)

pkglib_LTLIBRARIES = liblmdbbackend.la

EXTRA_DIST = OBJECTFILES OBJECTLIBS

liblmdbbackend_la_SOURCES = \
	../../ext/lmdb-safe/lmdb-safe.hh ../../ext/lmdb-safe/lmdb-safe.cc \
	../../ext/lmdb-safe/lmdb-typed.hh ../../ext/lmdb-safe/lmdb-typed.cc \
	lmdbbackend.cc lmdbbackend.hh
liblmdbbackend_la_LDFLAGS = -module -avoid-version
liblmdbbackend_la_LIBADD = $(LMDB_LIBS) $(BOOST_SERIALIZATION_LIBS)
