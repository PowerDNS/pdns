lib_LTLIBRARIES = libgmysqlbackend.la

INCLUDES=-I@MYSQL_incdir@

libgmysqlbackend_la_SOURCES=gmysqlbackend.cc gmysqlbackend.hh \
		smysql.hh smysql.cc


libgmysqlbackend_la_LDFLAGS=-module -lmysqlclient 

#	-Wl,-Bstatic -lpq++ -lpq -Wl,-Bdynamic -lssl -lcrypt -lcrypto


	
