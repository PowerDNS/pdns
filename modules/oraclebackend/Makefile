##
## File    : Makefile
## Author  : Stefan Arentz
## Project : PowerDNS
## Version : $Id: Makefile,v 1.1 2002/11/27 15:35:52 ahu Exp $
##

ORACLE_HOME	= /opt/oracle
PDNS_HOME	= ../ahudns

INCLUDE		= -I$(ORACLE_HOME)/rdbms/demo \
		  -I$(ORACLE_HOME)/rdbms/public \
		  -I$(PDNS_HOME)
VERSION=2.1

all: liboraclebackend.so


DIRNAME=pdns-oraclebackend-$(VERSION)

dist:
	mkdir $(DIRNAME)
	cp oraclebackend.cc oraclebackend.hh Makefile README LICENSE $(DIRNAME) 

	tar cvzf $(DIRNAME).tar.gz $(DIRNAME)
	rm -rf $(DIRNAME)


liboraclebackend.so: oraclebackend.o
	g++ -shared -o liboraclebackend.so oraclebackend.o -L$(ORACLE_HOME)/lib -lclntsh -lwtc8

liboraclebackend.o: oraclebackend.cc oraclebackend.hh

install: liboraclebackend.so
	cp liboraclebackend.so /usr/lib/powerdns/

.SUFFIXES:
.SUFFIXES: .cc .o

.cc.o:
	g++ -g -c $(LCFLAGS) $(INCLUDE) $<

clean:
	rm -f *.o *.so

