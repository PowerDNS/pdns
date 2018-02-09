SUBDIRS = ext modules codedocs docs

SUBDIRS += pdns

EXTRA_DIST = \
	INSTALL \
	NOTICE \
	README \
	.version \
	build-aux/gen-version \
	codedocs/doxygen.conf \
	contrib/powerdns.solaris.init.d \
	pdns/named.conf.parsertest \
	regression-tests/zones/unit.test

ACLOCAL_AMFLAGS = -I m4

if HAVE_STATIC_ANALYSIS
analyze:
	$(MAKE) -C pdns analyze

.PHONY: analyze
endif


dvi: # do nothing to build dvi
