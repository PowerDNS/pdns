AM_CPPFLAGS=@THREADFLAGS@
INCLUDES=@MYSQL_inc@
lib_LTLIBRARIES = libmydnsbackend.la 
EXTRA_DIST=OBJECTFILES OBJECTLIBS
libmydnsbackend_la_SOURCES=mydnsbackend.cc mydnsbackend.hh 
libmydnsbackend_la_LDFLAGS=-module -avoid-version @MYSQL_lib@ -lmysqlclient

