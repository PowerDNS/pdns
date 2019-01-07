AM_CPPFLAGS += $(LMDB_CFLAGS)

pkglib_LTLIBRARIES = liblmdbbackend.la

EXTRA_DIST = OBJECTFILES OBJECTLIBS

liblmdbbackend_la_SOURCES = lmdbbackend.cc lmdbbackend.hh lmdb-safe.cc lmdb-typed.hh lmdb-typed.cc
liblmdbbackend_la_LDFLAGS = -module -avoid-version
liblmdbbackend_la_LIBADD = $(LMDB_LIBS) $(BOOST_SERIALIZATION_LIBS)