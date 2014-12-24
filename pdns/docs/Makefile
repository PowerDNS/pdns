# $Id$ 

all: html-new/index.html manpages

clean:
	rm -rf *.dvi *.pdf *.tex *.toc *.aux *.ps *.bak *.tmp *~ *.log pdns.txt html.tar.bz2 html pdns pdns-expanded.html pdns-expanded.xml pdns_recursor.1 rec_control.1 html-new/*

manpages: dnsdist.1 pdns_recursor.1 rec_control.1 dnstcpbench.1

html-new/index.html: process-md.sh mkdocs.yml markdown/** markdown/*/**
	rm -rf html-new/*
	mkdir -p html-new
	mkdir -p doc-build
	rsync -a --delete markdown/. doc-build/.
	./process-md.sh pre
	mkdocs build --clean
	./process-md.sh post

%1.xml: %1.txt
	asciidoc -b docbook -d manpage  $<

%.1: %.1.xml
	xmlto man $<

%.html: %1.txt
	asciidoc -b xhtml11 -d manpage  $<

publish3:
	rsync -crv ./html-new/ pdnsdocs@xs.powerdns.com:md/
