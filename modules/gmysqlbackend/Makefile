PDNS_HOME		= ../../pdns
PDNS_LIBDIR		= /usr/lib/powerdns

MYSQL_INCLUDES	     = /usr/include/mysql
MYSQL_LIBDIR         = ./
MYSQL_LIBS           = -lmysqlclient 

POSTGRES_INCLUDES	= /opt/postgresql/include
POSTGRES_LIBDIR         = /opt/postgresql-with-3.2/lib
POSTGRES_LIBS           = -Wl,-Bstatic  -lpq++ -lpq -Wl,-Bdynamic -lssl -lcrypt -lcrypto
VERSION			= 2.9

all: libgmysqlbackend.so smysql.o

CPPFLAGS=-I$(PDNS_HOME) -I$(MYSQL_INCLUDES) -I$(POSTGRES_INCLUDES)

LIBS= -L$(POSTGRES_LIBDIR) -L$(MYSQL_LIBDIR)  $(MYSQL_LIBS)  $(POSTGRES_LIBS)
DIRNAME=pdns-gmypgsqlbackend-$(VERSION)

dist:
	mkdir $(DIRNAME)
	cp COPYING smysql.cc spgsql.cc gmysqlbackend.cc gmysqlbackend.hh smysql.hh ssql.hh spgsql.hh Makefile INSTALL $(DIRNAME)
	tar cvzf $(DIRNAME).tar.gz $(DIRNAME)
	rm -rf $(DIRNAME)
	
deps:
	g++ -M -g -c $(CXXFLAGS) $(CPPFLAGS) *.cc > deps

-include deps


libgmysqlbackend.so: gmysqlbackend.o smysql.o spgsql.o 
	g++ gmysqlbackend.o -Wl,-rpath -Wl,$(POSTGRES_LIBDIR) smysql.o spgsql.o $(LIBS) -Wl,-soname -Wl,libgmysqlbackend.so.0 -shared  -o libgmysqlbackend.so 

.cc.o:
	g++ -MD -g -c $(CXXFLAGS) $(CPPFLAGS) $<

clean:
	rm -f *.o *.so *~ *.d deps

install: libgmysqlbackend.so
	mv $< $(PDNS_LIBDIR)