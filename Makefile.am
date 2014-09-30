SUBDIRS=modules codedocs @programdescend@
DIST_SUBDIRS=modules codedocs pdns
EXTRA_DIST=README INSTALL NOTICE debian-pdns pdns.spec  \
codedocs/doxygen.conf contrib/powerdns.solaris.init.d \
contrib/systemd-pdns.service contrib/systemd-pdns-recursor.service \
bootstrap build-scripts/semistaticg++ pdns/docs/dnstcpbench.1 \
pdns/docs/dnsdist.1 \
build-scripts/redhat/pdns-server-test.spec \
pdns/named.conf.parsertest regression-tests/zones/unit.test

ACLOCAL_AMFLAGS = -I m4

man8_MANS=pdns/docs/pdns_control.8 pdns/docs/pdnssec.8 pdns/docs/pdns_server.8 \
  pdns/docs/zone2ldap.8 pdns/docs/zone2sql.8

if TOOLS
  man8_MANS += pdns/docs/dnsreplay.8 pdns/docs/dnsscope.8 pdns/docs/dnswasher.8
  man1_MANS = pdns/docs/dnstcpbench.1 pdns/docs/dnsdist.1
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

