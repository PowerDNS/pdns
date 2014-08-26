# $Id$ 

all: pdns.txt pdns.pdf html/index.html html.tar.bz2 pdns-expanded.html manpages

clean:
	rm -rf *.dvi *.pdf *.tex *.toc *.aux *.ps *.bak *.tmp *~ *.log pdns.txt html.tar.bz2 html pdns pdns-expanded.html pdns-expanded.xml pdns_recursor.1 rec_control.1 html-new doc-build

manpages: dnsdist.1 pdns_recursor.1 rec_control.1 dnstcpbench.1

html-new/index.html: process-md.sh mkdocs.yml markdown/** markdown/*/**
	rm -rf html-new/*
	mkdir -p html-new
	mkdir -p doc-build
	rsync -a --delete markdown/. doc-build/.
	./process-md.sh
	mkdocs build

pdns-expanded.html: pdns-expanded.xml
	xmlto xhtml-nochunks -m config.xsl $<

html.tar.bz2: html/index.html
	tar cjf html.tar.bz2 html/

%1.xml: %1.txt
	asciidoc -b docbook -d manpage  $<

%.1: %.1.xml
	xmlto man $<

%.html: %1.txt
	asciidoc -b xhtml11 -d manpage  $<

publish:
	rsync --exclude "*.png" --copy-links --delete -avrz ./html pdns.txt pdns.pdf html.tar.bz2 \
		xs.powerdns.com:/var/www/doc.powerdns.com/

publish3:
	rsync --exclude "*.png" --copy-links --delete -avrz ./html pdns.txt pdns.pdf html.tar.bz2 \
		peter@xs.powerdns.com:doc.powerdns.com/

publish-lieter: html-new/index.html
	rsync -avrz --delete ./html-new/* \
	  lieter@mango.plexis.eu:/srv/www/pdns-docs.plexis.eu/
