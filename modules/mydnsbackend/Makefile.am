AM_CPPFLAGS=$(MYSQL_inc) $(THREADFLAGS) $(BOOST_CPPFLAGS)
pkglib_LTLIBRARIES = libmydnsbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS \
	schema.mydns.sql

dist_doc_DATA=schema.mydns.sql

libmydnsbackend_la_SOURCES=mydnsbackend.cc mydnsbackend.hh

libmydnsbackend_la_LDFLAGS=-module -avoid-version $(MYSQL_lib)
libmydnsbackend_la_LIBADD=../gmysqlbackend/smysql.lo
