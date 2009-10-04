AM_CPPFLAGS=@THREADFLAGS@
INCLUDES=-I@MYSQL_incdir@ 
lib_LTLIBRARIES = libmydnsbackend.la 
EXTRA_DIST=OBJECTFILES OBJECTLIBS
libmydnsbackend_la_SOURCES=mydnsbackend.cc mydnsbackend.hh 
libmydnsbackend_la_LDFLAGS=-module -avoid-version @MYSQL_lib@ -lmysqlclient

