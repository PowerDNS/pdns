# $Id$ 

all: pdns.txt pdns.pdf html/index.html html.tar.gz

pdns-expanded.sgml: pdns.sgml
	./expand < $< > $@
	
clean:
	rm -rf *.dvi *.pdf *.tex *.toc *.aux *.txt *.ps *.bak *.tmp *~ *.log html.tar.gz html pdns

html/index.html: pdns-expanded.sgml
	db2html -V %use-id-as-filename% -o html $<

html.tar.gz: html/index.html
	tar czf html.tar.gz html/

%.txt: %-expanded.sgml
	docbook2txt $<
	mv pdns-expanded.txt pdns.txt

%.pdf: %-expanded.sgml
	docbook2pdf $<
	mv pdns-expanded.pdf pdns.pdf

publish:
	rsync --copy-links --delete -avrze ssh ./html pdns.txt pdns.pdf \
	exit.powerdns.com:/opt/websites/downloads.powerdns.com/www/documentation/
	ssh exit.powerdns.com ln -s /opt/websites/downloads.powerdns.com/www/documentation/images \
	/opt/websites/downloads.powerdns.com/www/documentation/html/
