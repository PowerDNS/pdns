OPTIONALS:=optional/epollmplexer.o
OS_SPECIFIC_INSTALL=mkdirhier $(DESTDIR)/etc/init.d ; cp pdns-recursor.init.d $(DESTDIR)/etc/init.d/pdns-recursor
	
optional/epollmplexer.o: epollmplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@ ; true

