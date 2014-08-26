# $Id$ 

all: pdns.txt pdns.pdf html/index.html html.tar.bz2 pdns-expanded.html manpages

clean:
	rm -rf *.dvi *.pdf *.tex *.toc *.aux *.ps *.bak *.tmp *~ *.log pdns.txt html.tar.bz2 html pdns pdns-expanded.html pdns-expanded.xml pdns_recursor.1 rec_control.1

manpages: dnsdist.1 pdns_recursor.1 rec_control.1 dnstcpbench.1

html-new: html-new/index.html

html-new/process: markdown/** markdown/*/** mkdocs.yml
	rm -rf html-new
	mkdir html-new
	rm -rf doc-build
	mkdir doc-build
	rsync -a --delete markdown/. doc-build/.
	./process-md.sh

html-new/index.html: html-new/process
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
