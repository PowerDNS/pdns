# $Id: Makefile,v 1.1 2002/11/27 15:18:34 ahu Exp $ 

all: pdns.txt pdns.pdf html/index.html html.tar.gz


clean:
	rm -rf *.dvi *.pdf *.tex *.toc *.aux *.txt *.ps *.bak *.tmp *~ *.log html

html/index.html: pdns.sgml
	db2html -o html $<

html.tar.gz: html/index.html
	tar czf html.tar.gz html/

%.txt: %.sgml
	docbook2txt $<

%.pdf: %.sgml
	docbook2pdf $<

publish:
	rsync --copy-links --delete -avrze ssh ./html pdns.txt pdns.pdf \
	spoon.powerdns.com:/opt/websites/downloads.powerdns.com/www/documentation/