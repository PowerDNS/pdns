AM_CPPFLAGS += $(UNIXODBC_CFLAGS) $(LIBCRYPTO_INCLUDES)
pkglib_LTLIBRARIES = libgodbcbackend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS

dist_doc_DATA = \
	schema.mssql.sql \
	4.0.0_to_4.2.0_schema.mssql.sql \
	4.2.0_to_4.3.0_schema.mssql.sql \
	4.3.0_to_4.7.0_schema.mssql.sql

libgodbcbackend_la_SOURCES = \
	godbcbackend.cc godbcbackend.hh \
	sodbc.cc sodbc.hh

if GODBCBACKEND_DYNMODULE
libgodbcbackend_la_LDFLAGS = -module -avoid-version
else
libgodbcbackend_la_LDFLAGS = -static -avoid-version
endif
libgodbcbackend_la_LIBADD = $(UNIXODBC_LIBS)
