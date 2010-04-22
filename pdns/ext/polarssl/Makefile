all:
	cd library  && make all && cd ..

clean:
	cd library  && make clean && cd ..

distdir:
	mkdir -p $(distdir)
	cp ChangeLog LICENSE  Makefile  README  $(distdir)
	mkdir $(distdir)/library
	mkdir -p $(distdir)/include/polarssl
	cp library/Makefile library/*.c $(distdir)/library
	cp include/polarssl/*.h $(distdir)/include/polarssl

	
