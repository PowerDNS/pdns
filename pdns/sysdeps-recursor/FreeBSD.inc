CXXFLAGS+=-I/usr/local/include/
OPTIONALS:=optional/kqueuemplexer.o

optional/kqueuemplexer.o: kqueuemplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@ ; true

