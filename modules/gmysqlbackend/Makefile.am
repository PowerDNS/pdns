AM_CPPFLAGS += $(MYSQL_CFLAGS) $(LIBCRYPTO_INCLUDES)

pkglib_LTLIBRARIES = libgmysqlbackend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS

dist_doc_DATA = \
	dnssec-3.x_to_3.4.0_schema.mysql.sql \
	enable-foreign-keys.mysql.sql \
	nodnssec-3.x_to_3.4.0_schema.mysql.sql \
	3.4.0_to_4.1.0_schema.mysql.sql \
	4.1.0_to_4.2.0_schema.mysql.sql \
	4.2.0_to_4.3.0_schema.mysql.sql \
	4.3.0_to_4.7.0_schema.mysql.sql \
	schema.mysql.sql

libgmysqlbackend_la_SOURCES = \
	gmysqlbackend.cc gmysqlbackend.hh \
	smysql.cc smysql.hh

if GMYSQLBACKEND_DYNMODULE
libgmysqlbackend_la_LDFLAGS = -module -avoid-version $(LIBCRYPTO_LDFLAGS) $(LIBSSL_LDFLAGS)
else
libgmysqlbackend_la_LDFLAGS = -static -avoid-version $(LIBCRYPTO_LDFLAGS) $(LIBSSL_LDFLAGS)
endif
libgmysqlbackend_la_LIBADD = $(MYSQL_LIBS)
