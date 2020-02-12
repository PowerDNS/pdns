AM_CPPFLAGS += $(MYSQL_CFLAGS)

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
	schema.mysql.sql

libgmysqlbackend_la_SOURCES = \
	gmysqlbackend.cc gmysqlbackend.hh \
	smysql.cc smysql.hh

libgmysqlbackend_la_LDFLAGS = -module -avoid-version
libgmysqlbackend_la_LIBADD = $(MYSQL_LIBS)
