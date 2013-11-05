.SILENT:

all:
	$(MAKE) -C yahttp all

install:

uninstall:

distclean: clean

clean:
	$(MAKE) -C yahttp clean

check:

distdir:
	mkdir -p $(distdir)
	cp LICENSE Makefile $(distdir)
	mkdir $(distdir)/yahttp
	cp yahttp/Makefile yahttp/*.cpp yahttp/*.hpp $(distdir)/yahttp

