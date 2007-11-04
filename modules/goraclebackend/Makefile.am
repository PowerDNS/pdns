AM_CPPFLAGS=@THREADFLAGS@
lib_LTLIBRARIES = libgoraclebackend.la
#bin_PROGRAMS = soracle

#soracle_SOURCES=soracle.cc soracle.hh 

EXTRA_DIST=OBJECTFILES OBJECTLIBS

ORACLE_HOME	?= /opt/oracle

INCLUDES= -I$(ORACLE_HOME)/rdbms/demo \
		  -I$(ORACLE_HOME)/rdbms/public 

libgoraclebackend_la_SOURCES=goraclebackend.cc goraclebackend.hh \
		soracle.hh soracle.cc


libgoraclebackend_la_LDFLAGS=-module -avoid-version -L$(ORACLE_HOME)/lib -lclient9  -lclntst9
#soracle_LDFLAGS=-module  -L$(ORACLE_HOME)/lib -lclient9  -lclntst9 -ldl -pthread

#	-Wl,-Bstatic -lpq++ -lpq -Wl,-Bdynamic -lssl -lcrypt -lcrypto


	
