SUBDIRS=modules codedocs @programdescend@
EXTRA_DIST=TODO README HACKING INSTALL ChangeLog debian-pdns pdns.spec  \
codedocs/Makefile codedocs/doxygen.conf contrib/powerdns.solaris.init.d \
bootstrap

ACLOCAL_AMFLAGS = -I.

man8_MANS=pdns/docs/pdns_control.8 pdns/docs/pdns_server.8 pdns/docs/zone2sql.8 

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


