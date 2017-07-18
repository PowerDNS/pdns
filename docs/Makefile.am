# HTML documentation
html: html/index.html

html/index.html: process-md.sh mkdocs.yml markdown/** markdown/*/** manpages/*
	mkdir -p doc-build
	rsync -a --delete markdown/. doc-build/.
	cp -r manpages doc-build/
	./process-md.sh pre
	mkdocs build --clean
	./process-md.sh post

check-links: html
	./checklinks.sh

publish: html
	rsync -crv --no-p --chmod=g=rwX --exclude '*~' ./html/ web1.powerdns.com:/srv/www/doc.powerdns.com/md

.PHONY: html all-manpages
