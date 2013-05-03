# $Id$ 

all: pdns.txt pdns.pdf html/index.html html.tar.gz pdns-expanded.html

pdns-expanded.xml: pdns.xml
	./expand < $< > $@
	
clean:
	rm -rf *.dvi *.pdf *.tex *.toc *.aux *.ps *.bak *.tmp *~ *.log pdns.txt html.tar.gz html pdns pdns-expanded.html pdns-expanded.xml pdns_recursor.1 rec_control.1

html/index.html: pdns-expanded.xml
	rm -rf html
	xmlto xhtml -m config.xsl -o html $<
	cp docbook.css html

pdns-expanded.html: pdns-expanded.xml
	xmlto xhtml-nochunks -m config.xsl $<
	
html.tar.gz: html/index.html
	tar czf html.tar.gz html/

%.txt: %-expanded.xml
	xmlto txt -m config.xsl  $<
	mv pdns-expanded.txt pdns.txt

%.pdf: %-expanded.xml
	xmlto --with-dblatex pdf $<
	mv pdns-expanded.pdf pdns.pdf

%1.xml: %1.txt
	asciidoc -b docbook -d manpage  $<
        
%.1: %.1.xml
	xmlto man $<
                
%.html: %1.txt
	asciidoc -b xhtml11 -d manpage  $<
                        
publish:
	rsync --exclude "*.png" --copy-links --delete -avrz ./html pdns.txt pdns.pdf html.tar.gz \
		xs.powerdns.com:/var/www/doc.powerdns.com/

publish3:
	rsync --exclude "*.png" --copy-links --delete -avrz ./html pdns.txt pdns.pdf html.tar.gz \
		peter@xs.powerdns.com:doc.powerdns.com/
