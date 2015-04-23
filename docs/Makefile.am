MANPAGES_TARGET = dnsbulktest.1 \
	dnsdist.1 \
	dnsgram.1 \
	dnsreplay.1 \
	dnsscan.1 \
	dnsscope.1 \
	dnstcpbench.1 \
	dnswasher.1 \
	nsec3dig.1 \
	pdns_control.1 \
	pdns_recursor.1 \
	pdnssec.1 \
	pdns_server.1 \
	rec_control.1 \
	saxfr.1 \
	zone2ldap.1 \
	zone2sql.1

if HAVE_PANDOC
man_MANS = $(MANPAGES_TARGET)
else
if HAVE_MANPAGES
dist_man_MANS = $(MANPAGES_TARGET)
endif
endif

EXTRA_DIST = manpages \
	markdown \
	$(MANPAGES_TARGET) 
#	html

.PHONY: html manpages
html: html/index.html

html/index.html: process-md.sh mkdocs.yml markdown/** markdown/*/** manpages/*
	mkdir -p doc-build
	rsync -a --delete markdown/. doc-build/.
	cp -r manpages/ doc-build/
	./process-md.sh pre
	mkdocs build --clean
	./process-md.sh post

html.tar.bz2: html
	tar cjf html.tar.bz2 html/

manpages: $(MANPAGES_TARGET)

if HAVE_PANDOC
$(MANPAGES_TARGET): %: manpages/%.md
	$(PANDOC) -s -t man $< -o $@
else
$(MANPAGES_TARGET):
	echo "You need pandoc to generate the manpages"
	exit 1
endif

if HAVE_LINKCHECKER
check-links: html
	./checklinks.sh

endif

clean:
	rm -rf html html.tar.bz2 *.8 *.1

publish: html html.tar.bz2
	rsync -crv --exclude '*~' ./html/ pdnsdocs@xs.powerdns.com:md/
	rsync -crv --exclude '*~' ./html.tar.bz2 pdnsdocs@xs.powerdns.com:html.tar.bz2
