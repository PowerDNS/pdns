OPTIONALS:=optional/epollmplexer.o
OS_SPECIFIC_INSTALL=mkdir -p $(DESTDIR)/etc/init.d ; cp pdns-recursor.init.d $(DESTDIR)/etc/init.d/pdns-recursor

ifeq ($(CC),cc)
	CC:=gcc
endif
	
optional/epollmplexer.o: epollmplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@ ; true

