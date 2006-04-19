LDFLAGS+=-lresolv -lsocket -lnsl

OPTIONALS:=optional/portsmplexer.o
	
optional/portsmplexer.o: portsmplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@  ; true

