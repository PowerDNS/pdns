# $Id$ 

all: pdns.txt pdns.pdf html/index.html html.tar.gz

pdns-expanded.sgml: pdns.sgml
	./expand < $< > $@
	
clean:
	rm -rf *.xml *.dvi *.pdf *.tex *.toc *.aux *.ps *.bak *.tmp *~ *.log html.tar.gz html pdns

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

%.xml: %.txt
	asciidoc -b docbook -d manpage  $<
        
%: %.xml
	xmlto man $<
                
%.html: %.txt
	asciidoc -b xhtml11 -d manpage  $<
                        
publish:
	rsync --copy-links --delete -avrze ssh ./html pdns.txt pdns.pdf \
	exit.powerdns.com:/opt/websites/downloads.powerdns.com/www/documentation/
	ssh exit.powerdns.com ln -s /opt/websites/downloads.powerdns.com/www/documentation/images \
	/opt/websites/downloads.powerdns.com/www/documentation/html/

publish2:
	rsync --copy-links --delete -avrze ssh ./html pdns.txt pdns.pdf \
	ds9a.nl:/var/www/ds9a.nl/tmp/pdns-docs/
