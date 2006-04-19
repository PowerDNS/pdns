OPTIONALS:=optional/epollmplexer.o
	
optional/epollmplexer.o: epollmplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@ ; true

