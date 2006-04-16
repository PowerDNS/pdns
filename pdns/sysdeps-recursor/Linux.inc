OPTIONALS:=optional/epollmplexer.o
	
optional/epollmplexer.o: epollmplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@ 2> /dev/null ; true

