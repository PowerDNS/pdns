AM_CPPFLAGS += $(ORACLE_CFLAGS)

pkglib_LTLIBRARIES = liboraclebackend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	drop-schema.oracle.sql \
	schema.oracle.sql

dist_doc_DATA = \
	schema.oracle.sql \
	drop-schema.oracle.sql

liboraclebackend_la_SOURCES = oraclebackend.cc oraclebackend.hh
liboraclebackend_la_LDFLAGS = -module -avoid-version
liboraclebackend_la_LIBADD = $(ORACLE_LIBS) -lclntsh
