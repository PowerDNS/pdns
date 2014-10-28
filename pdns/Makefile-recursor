# user editable stuff:
SBINDIR=/usr/sbin/
BINDIR=/usr/bin/
SYSCONFDIR=/etc/powerdns/
LOCALSTATEDIR=/var/run/
OPTFLAGS?=-O3
CXXFLAGS:= $(CXXFLAGS) -Iext/rapidjson/include -I$(CURDIR)/ext/polarssl-1.3.2/include -Wall $(OPTFLAGS) $(PROFILEFLAGS) $(ARCHFLAGS) -pthread -Iext/yahttp
CFLAGS:=$(CFLAGS) -Wall $(OPTFLAGS) $(PROFILEFLAGS) $(ARCHFLAGS) -I$(CURDIR)/ext/polarssl-1.3.2/include -pthread
LDFLAGS:=$(LDFLAGS) $(ARCHFLAGS) -pthread
STRIP_BINARIES?=1

LINKCC=$(CXX)
CC?=gcc

# Lua 5.1 settings

# static dependencies

PDNS_RECURSOR_OBJECTS=syncres.o  misc.o unix_utility.o qtype.o logger.o  \
arguments.o lwres.o pdns_recursor.o recursor_cache.o dnsparser.o \
dnswriter.o dnsrecords.o rcpgenerator.o base64.o zoneparser-tng.o \
rec_channel.o rec_channel_rec.o selectmplexer.o sillyrecords.o \
dns_random.o ext/polarssl-1.3.2/library/aes.o ext/polarssl-1.3.2/library/padlock.o dnslabeltext.o \
lua-pdns.o lua-recursor.o randomhelper.o recpacketcache.o dns.o \
reczones.o base32.o nsecrecords.o json.o ws-recursor.o ws-api.o \
version.o responsestats.o webserver.o ext/yahttp/yahttp/reqresp.o ext/yahttp/yahttp/router.o \
rec-carbon.o

REC_CONTROL_OBJECTS=rec_channel.o rec_control.o arguments.o misc.o \
	unix_utility.o logger.o qtype.o

# what we need 
all: message version_generated.h build

# OS specific instructions
-include sysdeps/$(shell uname).inc
ifeq ($(shell uname),GNU/kFreeBSD)
	-include sysdeps/FreeBSD.inc
endif
ifeq ($(shell uname),GNU/Hurd)
	-include sysdeps/Linux.inc
endif

ifeq ($(LUA), 1)
	LUALIBS=$(LUA_LIBS_CONFIG)
	CXXFLAGS+=$(LUA_CPPFLAGS_CONFIG) -DPDNS_ENABLE_LUA -DHAVE_LUA
endif


ifeq ($(STATIC),semi)
	STATICFLAGS=-Wl,-Bstatic -lstdc++ $(LUALIBS) -lgcc -Wl,-Bdynamic -static-libgcc -lm -lc
	LINKCC=$(CC)
	LDFLAGS += -ldl -lm
else 
   ifeq ($(STATIC),full)
	STATICFLAGS=-lstdc++ $(LUALIBS) -ldl -lm -static 
	LINKCC=$(CC)
   else
	LDFLAGS +=  $(LUALIBS)
   endif
endif


LDFLAGS += $(PROFILEFLAGS) $(STATICFLAGS)

CXXFLAGS += -DSYSCONFDIR='"$(SYSCONFDIR)"' -DLOCALSTATEDIR='"$(LOCALSTATEDIR)"'
CFLAGS += -DSYSCONFDIR='"$(SYSCONFDIR)"' -DLOCALSTATEDIR='"$(LOCALSTATEDIR)"'

%.cc: %.rl
	ragel $< -o $@

# Version
build_date=$(shell LC_TIME=C date '+%Y%m%d%H%M%S')
build_host=$(shell id -u -n)@$(shell hostname -f)

.PHONY: version_generated.h
version_generated.h:
	echo '#ifndef VERSION_GENERATED_H' > $@
	echo '#define VERSION_GENERATED_H' >> $@
	echo '#include "config.h"' >> $@
	echo '#define PDNS_VERSION VERSION' >> $@
	echo '#define BUILD_DATE "$(build_date)"' >> $@
	echo '#define BUILD_HOST "$(build_host)"' >> $@
	echo '#endif //!VERSION_GENERATED_H' >> $@

message: 
	@echo
	@echo PLEASE READ: If you get an error mentioning \#include '<boost/something.hpp>', please read README
	@echo PLEASE READ: for an easy fix!
	@echo 

basic_checks: 
	@-rm -f pdns_hw
	-$(CXX) $(CXXFLAGS)  pdns_hw.cc -o pdns_hw 
	@echo
	@if test -x ./pdns_hw ; \
		 then if ./pdns_hw; then echo Everything ok, now run $(MAKE) using same settings \(if any\) you passed ./configure; else echo Could compile binary, but not run it, read README please ; fi; \
	 else 	\
	 	echo; echo Could not compile simple binary, read README please; \
		rm -f dep ; \
	 fi

install: build-stamp
	-mkdir -p $(DESTDIR)/$(SBINDIR)
	mv pdns_recursor $(DESTDIR)/$(SBINDIR)
ifeq ($(STRIP_BINARIES), 1)
	strip $(DESTDIR)/$(SBINDIR)/pdns_recursor
endif
	mkdir -p $(DESTDIR)/$(BINDIR)
	mv rec_control $(DESTDIR)/$(BINDIR)
ifeq ($(STRIP_BINARIES), 1)
	strip $(DESTDIR)/$(BINDIR)/rec_control
endif
	-mkdir -p $(DESTDIR)/$(SYSCONFDIR)
	$(DESTDIR)/$(SBINDIR)/pdns_recursor --config > $(DESTDIR)/$(SYSCONFDIR)/recursor.conf-dist
	-mkdir -p $(DESTDIR)/usr/share/man/man1
	cp pdns_recursor.1 rec_control.1 $(DESTDIR)/usr/share/man/man1
	$(OS_SPECIFIC_INSTALL)	

clean: binclean
	-rm -f dep *~ *.gcda *.gcno optional/*.gcda optional/*.gcno

binclean:
	-rm -f *.o pdns_hw pdns_recursor rec_control optional/*.o build-stamp ext/polarssl-1.3.2/library/*.o ext/yahttp/yahttp/*.o version_generated.h

dep:
	$(CXX) $(CXXFLAGS) -MM -MG *.cc *.hh > $@

-include dep

optional:
	mkdir optional

pdns_recursor: optional $(OPTIONALS) $(PDNS_RECURSOR_OBJECTS) 
	$(LINKCC) $(PDNS_RECURSOR_OBJECTS) $(wildcard optional/*.o) $(LDFLAGS) -o $@

rec_control: $(REC_CONTROL_OBJECTS)
	$(LINKCC) $(REC_CONTROL_OBJECTS) $(LDFLAGS) -o $@

build-stamp:
	$(MAKE) build

build: pdns_recursor rec_control
	touch build-stamp

