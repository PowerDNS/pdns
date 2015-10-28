SUBDIRS = ext modules codedocs docs

if WITH_PDNS_SERVER
  SUBDIRS += pdns
endif

EXTRA_DIST = \
	INSTALL \
	NOTICE \
	README \
	.version \
	build-aux/gen-version \
	build-scripts/semistaticg++ \
	codedocs/doxygen.conf \
	contrib/powerdns.solaris.init.d \
	contrib/systemd-pdns-recursor.service \
	contrib/systemd-pdns.service \
	pdns/named.conf.parsertest \
	regression-tests/zones/unit.test

ACLOCAL_AMFLAGS = -I m4

dvi: # do nothing to build dvi
