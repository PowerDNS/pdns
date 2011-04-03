all:
	cd library  && $(MAKE) all && cd ..

clean:
	cd library  && $(MAKE) clean && cd ..

distclean: clean

install:
	

distdir:
	mkdir -p $(distdir)
	cp ChangeLog LICENSE  Makefile  README  $(distdir)
	mkdir $(distdir)/library
	mkdir -p $(distdir)/include/polarssl
	cp library/Makefile library/*.c $(distdir)/library
	cp include/polarssl/*.h $(distdir)/include/polarssl

	
