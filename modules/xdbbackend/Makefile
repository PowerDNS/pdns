
PDNS_HOME		= ../../
XDB_LIBS           = -Wl,-Bstatic -lgdbm -ltdb -Wl,-Bdynamic
VERSION			= 2.6

all: libxdbbackend.so

CPPFLAGS=-I$(PDNS_HOME)  -O3 -pthread

LIBS= $(XDB_LIBS)
DIRNAME=pdns-xdbbackend-$(VERSION)

dist:
	mkdir $(DIRNAME)
	cp pgsqlbackend.cc pgsqlbackend.hh Makefile $(DIRNAME)
	tar cvzf $(DIRNAME).tar.gz $(DIRNAME)
	rm -rf $(DIRNAME)

xdb-fill: xdb-fill.o xgdbm.o xtdb.o
	g++ xdb-fill.o xgdbm.o xtdb.o $(XDB_LIBS) -o xdb-fill

libxdbbackend.so: xdbbackend.o  xtdb.o
	g++ xdbbackend.o $(XDB_LIBS) -shared  -o libxdbbackend.so 

.cc.o:
	g++ -MD -g -c $(CXXFLAGS) $(CPPFLAGS) $<

clean:
	rm -f *.o *.so *~ *.d

