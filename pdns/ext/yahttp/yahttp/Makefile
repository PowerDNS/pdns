
all: libyahttp.a


clean:
	-rm -f *.o *.a


reqresp.o: *.cpp *.hpp


libyahttp.a: reqresp.o
	echo AR $@
	$(AR) rcs $@ $<
