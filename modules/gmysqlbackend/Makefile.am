AM_CPPFLAGS += $(MYSQL_CFLAGS)

pkglib_LTLIBRARIES = libgmysqlbackend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	dnssec-3.x_to_3.4.0_schema.mysql.sql \
	nodnssec-3.x_to_3.4.0_schema.mysql.sql \
	schema.mysql.sql

dist_doc_DATA = \
	dnssec-3.x_to_3.4.0_schema.mysql.sql \
	nodnssec-3.x_to_3.4.0_schema.mysql.sql \
	3.4.0_to_4.1.0_schema.mysql.sql \
	4.1.0_to_5.0.0_schema.mysql.sql \
	schema.mysql.sql

libgmysqlbackend_la_SOURCES = \
	gmysqlbackend.cc gmysqlbackend.hh \
	smysql.cc smysql.hh

libgmysqlbackend_la_LDFLAGS = -module -avoid-version
libgmysqlbackend_la_LIBADD = $(MYSQL_LIBS)
