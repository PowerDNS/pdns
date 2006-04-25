ifeq ($(CC),cc)
	CC:=gcc
endif

LDFLAGS+=-lresolv -lsocket -lnsl
OS_SPECIFIC_INSTALL=mkdir -p $(DESTDIR)/etc/init.d ; cp pdns-recursor.init.d $(DESTDIR)/etc/init.d/pdns-recursor

OPTIONALS:=optional/portsmplexer.o
	
optional/portsmplexer.o: portsmplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@  ; true

