# Generated automatically from Makefile.in by configure.
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

PACKAGE = pdns
VERSION = 2.9
DISTFILES=*.cc *.hh Makefile.in OBJECTFILES OBJECTLIBS

top_distdir = ../..
distdir = $(top_distdir)/$(PACKAGE)-$(VERSION)

distdir: $(DISTFILES)
	@for file in $(DISTFILES); do \
	  if test -f $$file; then d=.; else d=$(srcdir); fi; \
	  dir=`echo "$$file" | sed -e 's,/[^/]*$$,,'`; \
	  if test "$$dir" != "$$file" && test "$$dir" != "."; then \
	    $(mkinstalldirs) "$(distdir)/$$dir"; \
	  fi; \
	  if test -d $$d/$$file; then \
	    cp -pR $$d/$$file $(distdir) \
	    || exit 1; \
	  else \
	    test -f $(distdir)/$$file \
	    || cp -p $$d/$$file $(distdir)/$$file \
	    || exit 1; \
	  fi; \
	done
	
deps:
	g++ -M -g -c $(CXXFLAGS) $(CPPFLAGS) *.cc > deps

-include deps


libgmysqlbackend.so: gmysqlbackend.o smysql.o spgsql.o 
	g++ gmysqlbackend.o -Wl,-rpath -Wl,$(POSTGRES_LIBDIR) smysql.o spgsql.o $(LIBS) -Wl,-soname -Wl,libgmysqlbackend.so.0 -shared  -o libgmysqlbackend.so 

.cc.o:
	g++ -MD -g -c $(CXXFLAGS) $(CPPFLAGS) $<

distclean: clean

clean:
	rm -f *.o *.so *~ *.d deps

install: libgmysqlbackend.so
	mv $< $(PDNS_LIBDIR)