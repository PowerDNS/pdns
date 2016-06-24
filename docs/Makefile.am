MANPAGES_TARGET_AUTH = pdns_server.1 \
	pdns_control.1 \
	pdnsutil.1 \
	zone2json.1 \
	zone2ldap.1 \
	zone2sql.1

MANPAGES_TARGET_TOOLS = calidns.1 \
	dnsgram.1 \
	dnsreplay.1 \
	dnsscan.1 \
	dnsscope.1 \
	dnswasher.1 \
	dumresp.1 \
	ixplore.1 \
	nproxy.1 \
	nsec3dig.1 \
	pdns_notify.1 \
	saxfr.1 \
	sdig.1

if HAVE_BOOST_GE_148
MANPAGES_TARGET_TOOLS += dnsbulktest.1 \
	dnstcpbench.1
endif


if HAVE_PROTOBUF
if HAVE_PROTOC
MANPAGES_TARGET_TOOLS += dnspcap2protobuf.1
endif
endif

MANPAGES_TARGET_DNSDIST = dnsdist.1

MANPAGES_TARGET_RECURSOR = pdns_recursor.1 \
	rec_control.1

MANPAGES_TARGET_ALL=$(MANPAGES_TARGET_AUTH) \
		$(MANPAGES_TARGET_RECURSOR) \
		$(MANPAGES_TARGET_TOOLS) \
		$(MANPAGES_TARGET_DNSDIST)

# The manpages to distribute and install are only those for the
# auth server and tools. For the recursor and dnsdist tarballs,
# the respective dist- scripts will take care of this
if HAVE_PANDOC
dist_man_MANS = $(MANPAGES_TARGET_AUTH) $(MANPAGES_TARGET_TOOLS)
endif
if HAVE_MANPAGES
dist_man_MANS = $(MANPAGES_TARGET_AUTH) $(MANPAGES_TARGET_TOOLS)
endif

EXTRA_DIST = manpages markdown/*.md markdown/appendix markdown/authoritative markdown/common markdown/httpapi markdown/recursor markdown/security markdown/tools


.PHONY: html all-manpages

html: html/index.html

if FROM_GIT
html/index.html: process-md.sh mkdocs.yml markdown/** markdown/*/** manpages/*
	mkdir -p doc-build
	rsync -a --delete markdown/. doc-build/.
	cp -r manpages doc-build/
	./process-md.sh pre
	mkdocs build --clean
	./process-md.sh post

html.tar.bz2: html
	tar cjf html.tar.bz2 html/

check-links: html
	./checklinks.sh

publish: html html.tar.bz2
	rsync -crv --no-p --chmod=g=rwX --exclude '*~' ./html/ web1.powerdns.com:/srv/www/doc.powerdns.com/md
	rsync -crv --no-p --chmod=g=rwX --exclude '*~' ./html.tar.bz2 web1.powerdns.com:/srv/www/doc.powerdns.com/html.tar.bz2
else
html/index.html:
	@echo "Building the documentation HTML is only"
	@echo "supported from a git checkout"
endif

all-manpages: $(MANPAGES_TARGET_ALL)

if HAVE_PANDOC
$(MANPAGES_TARGET_ALL): %: manpages/%.md
	$(PANDOC) -s -t man $< -o $@
else
$(MANPAGES_TARGET_ALL):
	echo "You need pandoc to generate the manpages"
	exit 1
endif

clean:
	rm -rf html html.tar.bz2 *.8 *.1
