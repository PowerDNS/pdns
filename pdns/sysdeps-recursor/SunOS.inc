ifeq ($(CC),cc)
	CC:=gcc
endif

LDFLAGS+=-lresolv -lsocket -lnsl -ldl
OS_SPECIFIC_INSTALL=mkdir -p $(DESTDIR)/etc/init.d ; cp pdns-recursor.init.d $(DESTDIR)/etc/init.d/pdns-recursor

LUA_LIBS_CONFIG ?= -llua

CXXFLAGS+= -D__MAKECONTEXT_V2_SOURCE

ifeq ($(shell uname -r),5.11)
	CXXFLAGS+= -DHAVE_STRCASESTR
endif

OPTIONALS:=optional/portsmplexer.o optional/devpollmplexer.o

optional/portsmplexer.o: portsmplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@  ; true


optional/devpollmplexer.o: devpollmplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@  ; true

