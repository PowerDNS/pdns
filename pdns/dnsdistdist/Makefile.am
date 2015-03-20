AM_CPPFLAGS = -I pdns $(LUA_CFLAGS) -O3 -Wall -pthread

dnslabeltext.cc: dnslabeltext.rl
	ragel $< -o dnslabeltext.cc


EXTRA_DIST=dnslabeltext.rl dnsdistconf.lua README.md

bin_PROGRAMS = dnsdist
dnsdist_SOURCES = \
	base64.hh \
	dns.hh \
	dnsdist.cc dnsdist.hh \
	dnsdist-lua.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.hh \
	dnsrulactions.hh \
	dnswriter.cc dnswriter.hh \
	dolog.hh \
	iputils.cc iputils.hh \
	misc.cc misc.hh \
	namespaces.hh \
	pdnsexception.hh \
	qtype.cc qtype.hh \
	sholder.hh \
	sodcrypto.cc sodcrypto.hh \
	sstuff.hh pdns/ext/luawrapper/include/LuaContext.hpp

dnsdist_LDFLAGS = \
	$(AM_LDFLAGS) \
	-pthread

dnsdist_LDADD = \
	-lreadline -lrt -ltermcap \
	$(LUA_LIBS) ${libsodium_LIBS}

