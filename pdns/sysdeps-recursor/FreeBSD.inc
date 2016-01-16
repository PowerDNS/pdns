CXXFLAGS+=-I/usr/local/include/ -DHAVE_STRCASESTR -std=gnu++11
OPTIONALS:=optional/kqueuemplexer.o

optional/kqueuemplexer.o: kqueuemplexer.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

LUA_CPPFLAGS_CONFIG ?= -I/usr/local/include/lua51
LUA_LIBS_CONFIG ?= -L/usr/local/lib/ -llua-5.1 -rdynamic

