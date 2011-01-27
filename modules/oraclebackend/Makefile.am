AM_CPPFLAGS=@THREADFLAGS@

lib_LTLIBRARIES = liboraclebackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS schema.sql dropschema.sql

INCLUDES= -I$(ORACLE_HOME)/rdbms/public

liboraclebackend_la_SOURCES=oraclebackend.cc oraclebackend.hh
liboraclebackend_la_LDFLAGS=-module -avoid-version -L$(ORACLE_HOME)/lib
liboraclebackend_la_LIBADD=-lclntsh
