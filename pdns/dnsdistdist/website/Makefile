all: html/index.html

html/index.html: markdown/*
	mkdocs build --clean

upload: html/index.html
	rsync -cvr --no-p --chmod=g=rwX --exclude '*~' --delete html/* web1.powerdns.com:/srv/www/dnsdist.org/
