SUBDIRS=modules codedocs @programdescend@
DIST_SUBDIRS=modules codedocs pdns
EXTRA_DIST=README INSTALL NOTICE debian-pdns pdns.spec  \
codedocs/doxygen.conf contrib/powerdns.solaris.init.d \
contrib/systemd-pdns.service contrib/systemd-pdns-recursor.service \
bootstrap build-scripts/semistaticg++ pdns/docs/dnstcpbench.1 \
build-scripts/redhat/pdns-server-test.spec \
pdns/named.conf.parsertest regression-tests/zones/unit.test

ACLOCAL_AMFLAGS = -I m4

man1_MANS=pdns/docs/pdns_control.1 pdns/docs/pdnssec.1 pdns/docs/pdns_server.1 \
  pdns/docs/zone2ldap.1 pdns/docs/zone2sql.1

if TOOLS
  man1_MANS += pdns/docs/dnsreplay.1 pdns/docs/dnsscope.1 pdns/docs/dnswasher.1
  man1_MANS += pdns/docs/dnstcpbench.1
endif

pdns/docs/dnstcpbench.1:
	cd pdns/docs && $(MAKE) dnstcpbench.1

pdns/docs/dnsdist.1:
	cd pdns/docs && $(MAKE) dnsdist.1

install-exec-local: 
	-@chmod +x pdns/pdns
	@echo "***********************************************************"
	@echo
	@echo An init.d startup script has been made for you in pdns/pdns.
	@echo You may want to copy this to /etc/init.d or equivalent.
	@echo
	@echo "***********************************************************"

