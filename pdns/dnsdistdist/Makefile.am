AM_CPPFLAGS = -I pdns $(LUA_CFLAGS) $(YAHTTP_CFLAGS) $(BOOST_CPPFLAGS) -O3 -Wall -pthread -DSYSCONFDIR=\"${sysconfdir}\"

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
	   html \
	   dnsdist.1 \
	   .version \
	   contrib

bin_PROGRAMS = dnsdist
dnsdist_SOURCES = \
	base64.hh \
	dns.hh \
	dnsdist.cc dnsdist.hh \
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
	ext/incbin/incbin.h

dnsdist_LDFLAGS = \
	$(AM_LDFLAGS) \
	-pthread 

dnsdist_LDADD = \
	-lreadline -lrt \
	$(LUA_LIBS) $(YAHTTP_LIBS) ${LIBSODIUM_LIBS}

