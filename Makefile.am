SUBDIRS = ext modules pdns codedocs docs

EXTRA_DIST = \
	INSTALL \
	NOTICE \
	README \
	COPYING \
	codedocs/doxygen.conf \
	contrib/powerdns.solaris.init.d \
	pdns/named.conf.parsertest \
	regression-tests/zones/unit.test \
	regression-tests/zones/unit2.test \
	regression-tests/zonemd-allunsup.zone \
	regression-tests/zonemd-duplicate.zone \
	regression-tests/zonemd-invalid.zone \
	regression-tests/zonemd-nozonemd.zone \
	regression-tests/zonemd-serialmismatch.zone \
	regression-tests/zonemd-sha512.zone \
	regression-tests/zonemd-syntax.zone \
	regression-tests/zonemd1.zone \
	regression-tests/zonemd2.zone \
	regression-tests/zonemd3.zone \
	regression-tests/zonemd4.zone \
	regression-tests/zonemd5.zone \
	builder-support/gen-version

ACLOCAL_AMFLAGS = -I m4

dvi: # do nothing to build dvi

format-code:
	./build-scripts/format-code `find . -type f -name '*.[ch][ch]' | LANG=C sort | LANG=C comm -23 - .not-formatted`

