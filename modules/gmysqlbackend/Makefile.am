AM_CPPFLAGS=@THREADFLAGS@ $(BOOST_CPPFLAGS)
lib_LTLIBRARIES = libgmysqlbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS

INCLUDES=@MYSQL_inc@

libgmysqlbackend_la_SOURCES=gmysqlbackend.cc gmysqlbackend.hh \
		smysql.hh smysql.cc


libgmysqlbackend_la_LDFLAGS=-module -avoid-version $(MYSQL_lib)

#	-Wl,-Bstatic -lpq++ -lpq -Wl,-Bdynamic -lssl -lcrypt -lcrypto


	
