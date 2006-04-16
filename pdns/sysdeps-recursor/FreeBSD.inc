OPTIONALS:=optional/kqueuemplexer.o

optional/kqueuemplexer.o: kqueuemplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@ 2> /dev/null; true

