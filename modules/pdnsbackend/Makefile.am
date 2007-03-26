AM_CPPFLAGS=@THREADFLAGS@
INCLUDES=-I@MYSQL_incdir@
lib_LTLIBRARIES = libpdnsbackend.la 
EXTRA_DIST=OBJECTFILES OBJECTLIBS

libpdnsbackend_la_SOURCES=pdnsbackend.cc pdnsbackend.hh 
libpdnsbackend_la_LDFLAGS=-lmysqlclient

