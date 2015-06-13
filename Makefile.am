SUBDIRS = ext modules codedocs docs

if WITH_PDNS_SERVER
  SUBDIRS += pdns
endif

EXTRA_DIST = \
	INSTALL \
	NOTICE \
	README \
	build-scripts/redhat/pdns-server-test.spec \
	build-scripts/semistaticg++ \
	codedocs/doxygen.conf \
	contrib/powerdns.solaris.init.d \
	contrib/systemd-pdns-recursor.service \
	contrib/systemd-pdns.service \
	contrib/systemd-pdns@.service \
	debian \
	pdns.spec \
	pdns/named.conf.parsertest \
	regression-tests/zones/unit.test

ACLOCAL_AMFLAGS = -I m4

dvi: # do nothing to build dvi
