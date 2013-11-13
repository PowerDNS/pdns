AM_CPPFLAGS=@MYSQL_inc@ @THREADFLAGS@ $(BOOST_CPPFLAGS)
lib_LTLIBRARIES = libgmysqlbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS \
	dnssec.schema.mysql.sql no-dnssec.schema.mysql.sql

libgmysqlbackend_la_SOURCES=gmysqlbackend.cc gmysqlbackend.hh \
	smysql.hh smysql.cc

libgmysqlbackend_la_LDFLAGS=-module -avoid-version $(MYSQL_lib)
