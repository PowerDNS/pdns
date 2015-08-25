AM_CPPFLAGS = -I pdns $(LUA_CFLAGS) $(YAHTTP_CFLAGS) $(BOOST_CPPFLAGS) -I$(CURDIR)/ext/mbedtls/include -O3 -Wall -pthread -DSYSCONFDIR=\"${sysconfdir}\"

ACLOCAL_AMFLAGS = -I m4

SUBDIRS=ext/yahttp

dnslabeltext.cc: dnslabeltext.rl
	ragel $< -o dnslabeltext.cc

BUILT_SOURCES=htmlfiles.h

htmlfiles.h: html/*
	./incfiles > $@

man_MANS=dnsdist.1

EXTRA_DIST=dnslabeltext.rl \
	   dnsdistconf.lua \
	   README.md \
	   delaypipe.cc delaypipe.hh \
	   html \
	   dnsdist.1 \
	   .version \
	   contrib

bin_PROGRAMS = dnsdist
dnsdist_SOURCES = \
	base64.hh \
	dns.hh \
	dnsdist.cc dnsdist.hh \
	dnsdist-carbon.cc \
	dnsdist-lua.cc \
	dnsdist-tcp.cc \
	dnsdist-web.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.hh \
	dnsrulactions.hh \
	dnswriter.cc dnswriter.hh \
	dolog.hh \
	iputils.cc iputils.hh \
	mbedtlscompat.hh \
	misc.cc misc.hh \
	htmlfiles.h \
	namespaces.hh \
	pdnsexception.hh \
	qtype.cc qtype.hh \
	sholder.hh \
	sodcrypto.cc sodcrypto.hh \
	sstuff.hh \
	ext/luawrapper/include/LuaContext.hpp \
	ext/json11/json11.cpp \
	ext/json11/json11.hpp \
	ext/incbin/incbin.h \
	ext/mbedtls/include/mbedtls/config.h \
	ext/mbedtls/include/mbedtls/check_config.h \
	ext/mbedtls/include/mbedtls/base64.h \
	ext/mbedtls/include/mbedtls/platform.h \
	ext/mbedtls/library/base64.c

dnsdist_LDFLAGS = \
	$(AM_LDFLAGS) \
	-pthread 

dnsdist_LDADD = \
	$(LUA_LIBS) \
	$(READLINE_LIBS) \
	$(RT_LIBS) \
	$(YAHTTP_LIBS) \
	$(LIBSODIUM_LIBS)

