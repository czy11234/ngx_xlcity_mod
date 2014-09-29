
BASELIB=/root/BaseLib
CFLAGS += -g -I$(BASELIB) -DCITYTEST
LDFLAGS += $(BASELIB)/baselib.a

testcity: ip_city.cpp ip_city.h
	g++ $(CFLAGS) $^ $(LDFLAGS) -o $@ 

clean: 
	rm -f testcity
	