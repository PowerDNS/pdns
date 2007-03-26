AM_CPPFLAGS=@THREADFLAGS@
INCLUDES=-I@MYSQL_incdir@ 
lib_LTLIBRARIES = libmysqlbackend.la 
EXTRA_DIST=OBJECTFILES OBJECTLIBS
libmysqlbackend_la_SOURCES=mysqlcbackend.cc mysqlcbackend.hh 
libmysqlbackend_la_LDFLAGS=@MYSQL_lib@ -lmysqlclient

