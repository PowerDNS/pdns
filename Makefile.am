SUBDIRS=modules codedocs @programdescend@
DIST_SUBDIRS=modules codedocs pdns pdns/ext/rapidjson
EXTRA_DIST=TODO README HACKING INSTALL ChangeLog debian-pdns/* pdns.spec  \
codedocs/Makefile codedocs/doxygen.conf contrib/powerdns.solaris.init.d \
contrib/systemd-pdns.service contrib/systemd-pdns-recursor.service \
bootstrap build-scripts/semistaticg++

ACLOCAL_AMFLAGS = -I m4

man8_MANS=pdns/docs/dnsreplay.8 pdns/docs/dnsscope.8 pdns/docs/dnswasher.8 pdns/docs/pdns_control.8 pdns/docs/pdnssec.8 pdns/docs/pdns_server.8 pdns/docs/zone2ldap.8 pdns/docs/zone2sql.8 

install-exec-local: 
	-@chmod +x pdns/pdns
	-@chmod +x pdns/precursor
	@echo "***********************************************************"
	@echo
	@echo init.d startup scripts have been made for you in pdns/pdns
	@echo and in pdns/precursor
	@echo You may want to copy these to /etc/init.d or equivalent
	@echo
	@echo "***********************************************************"


