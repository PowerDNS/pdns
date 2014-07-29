AM_CPPFLAGS=$(MYSQL_inc) $(THREADFLAGS) $(BOOST_CPPFLAGS)
pkglib_LTLIBRARIES = libgmysqlbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS \
	schema.mysql.sql nodnssec-3.x_to_3.4.0_schema.mysql.sql dnssec-3.x_to_3.4.0_schema.mysql.sql

dist_doc_DATA = schema.mysql.sql nodnssec-3.x_to_3.4.0_schema.mysql.sql dnssec-3.x_to_3.4.0_schema.mysql.sql

libgmysqlbackend_la_SOURCES=gmysqlbackend.cc gmysqlbackend.hh \
	smysql.hh smysql.cc

libgmysqlbackend_la_LDFLAGS=-module -avoid-version $(MYSQL_lib)
