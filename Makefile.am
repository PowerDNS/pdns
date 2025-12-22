SUBDIRS = ext modules pdns codedocs docs

EXTRA_DIST = \
	INSTALL \
	NOTICE \
	README \
	COPYING \
	codedocs/doxygen.conf \
	contrib/powerdns.solaris.init.d \
	meson \
	meson.build \
	meson_options.txt \
	pdns/named.conf.parsertest \
	regression-tests/zones/unit.test \
	regression-tests/zones/unit2.test \
	regression-tests/zones/zonemd-allunsup.zone \
	regression-tests/zones/zonemd-duplicate.zone \
	regression-tests/zones/zonemd-invalid.zone \
	regression-tests/zones/zonemd-nozonemd.zone \
	regression-tests/zones/zonemd-serialmismatch.zone \
	regression-tests/zones/zonemd-sha512.zone \
	regression-tests/zones/zonemd-syntax.zone \
	regression-tests/zones/zonemd1.zone \
	regression-tests/zones/zonemd2.zone \
	regression-tests/zones/zonemd3.zone \
	regression-tests/zones/zonemd4.zone \
	regression-tests/zones/zonemd5.zone \
	builder-support/gen-version

ACLOCAL_AMFLAGS = -I m4

dvi: # do nothing to build dvi

format-code:
	./build-scripts/format-code `find . -type f -name '*.[ch][ch]' | LANG=C sort | LANG=C comm -23 - .not-formatted`
