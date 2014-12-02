SUBDIRS = modules codedocs pdns/docs

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
	debian \
	pdns.spec \
	pdns/named.conf.parsertest \
	regression-tests/zones/unit.test

ACLOCAL_AMFLAGS = -I m4

install-exec-local: 
	-@chmod +x pdns/pdns.init
	@echo "***********************************************************"
	@echo
	@echo An init.d startup script has been made for you in pdns/pdns.init.
	@echo You may want to copy this to /etc/init.d or equivalent.
	@echo
	@echo "***********************************************************"

dvi: # do nothing to build dvi
