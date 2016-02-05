all: html/index.html

html/index.html: markdown/*
	mkdocs build --clean

upload: html/index.html
	rsync -vr --delete html/* web1.powerdns.com:/srv/www/dnsdist.org/
