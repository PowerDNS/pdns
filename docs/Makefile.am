MANPAGES_TARGET = dnsdist.1 \
	dnsreplay.1 \
	dnsscope.1 \
	dnstcpbench.1 \
	dnswasher.1 \
	pdns_control.1 \
	pdns_recursor.1 \
	pdnssec.1 \
	pdns_server.1 \
	rec_control.1 \
	zone2ldap.1 \
	zone2sql.1

man_MANS = $(MANPAGES_TARGET)

EXTRA_DIST = manpages \
	markdown \
	$(MANPAGES_TARGET) \
	html

.PHONY: html
html: html/index.html

html/index.html: process-md.sh mkdocs.yml markdown/** markdown/*/**
	mkdir -p doc-build
	rsync -a --delete markdown/. doc-build/.
	./process-md.sh pre
	mkdocs build --clean
	./process-md.sh post

.PHONY: manpages
manpages: $(MANPAGES_TARGET)

$(MANPAGES_TARGET): %: manpages/%.md
	pandoc -s -t man $< -o $@

clean:
	rm -rf html *.8 *.1

publish3:
	rsync -crv ./html/ pdnsdocs@xs.powerdns.com:md/
