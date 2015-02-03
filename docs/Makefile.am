MANPAGES_TARGET = dnsdist.1 \
	dnsreplay.1 \
	dnsscope.1 \
	dnstcpbench.1 \
	dnswasher.1 \
	pdns_control.1 \
	pdnssec.1 \
	pdns_server.1 \
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

html/index.html: process-md.sh mkdocs.yml markdown/** markdown/*/**
	mkdir -p doc-build
	rsync -a --delete markdown/. doc-build/.
	./process-md.sh pre
	mkdocs build --clean
	./process-md.sh post

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
	linkchecker --anchors \
	  --ignore-url=.eot$ \
	  --ignore-url=\.svg \
	  --ignore-url=mailto \
	  --ignore-url=.ttf$ \
	  --ignore-url=woff$ \
	  html/index.html
endif

clean:
	rm -rf html *.8 *.1

publish3:
	rsync -crv --exclude '*~' ./html/ pdnsdocs@xs.powerdns.com:md/
