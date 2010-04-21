
DESTDIR=/usr/local
PREFIX=polarssl_

.SILENT:

all:
	cd library  && make all && cd ..

install:
	mkdir -p $(DESTDIR)/include/polarssl
	cp -r include/polarssl $(DESTDIR)/include
	
	mkdir -p $(DESTDIR)/lib
	cp library/libpolarssl.* $(DESTDIR)/lib
	
	mkdir -p $(DESTDIR)/bin
	for p in programs/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        cp $$p $(DESTDIR)/bin/$$f ;     \
	    fi                                  \
	done

clean:
	cd library  && make clean && cd ..

check:
	( cd tests && make check )

distdir:
	mkdir -p $(distdir)
	cp ChangeLog LICENSE  Makefile  README  $(distdir)
	mkdir $(distdir)/library
	mkdir -p $(distdir)/include/polarssl
	cp library/Makefile library/*.c $(distdir)/library
	cp include/polarssl/*.h $(distdir)/include/polarssl

	
