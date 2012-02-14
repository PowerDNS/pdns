
DESTDIR=/usr/local
PREFIX=polarssl_

.SILENT:

all:
	cd library  && $(MAKE) all && cd ..

install:

distclean: clean

clean:
	cd library  && $(MAKE) clean && cd ..

check:

distdir:
	mkdir -p $(distdir)
	cp ChangeLog LICENSE  Makefile  README  $(distdir)
	mkdir $(distdir)/library
	mkdir -p $(distdir)/include/polarssl
	cp library/Makefile library/*.c $(distdir)/library
	cp include/polarssl/*.h $(distdir)/include/polarssl
