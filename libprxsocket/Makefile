CXX = g++
CXXFLAGS = -c -pthread -I ~/boost -std=c++14
AR = ar
ARFLAGS = -cr
RANLIB = ranlib

ifeq ($(RELEASE), 1)
	CXXFLAGS += -g3 -O2 -DNDEBUG
else
	CXXFLAGS += -g3 -O0 -D_DEBUG
endif

objects = address.o http_header.o socket_base.o socket_raw.o socks5_base.o socket_socks5.o socket_websock.o
baseheaders = stdafx.h address.h endpoint.h buffer.h socket_base.h

all : libprxsocket.a

libprxsocket.a : $(objects)
	$(AR) $(ARFLAGS) $@ $(objects)
	$(RANLIB) $@
address.o : stdafx.h address.h address.cpp
	$(CXX) address.cpp $(CXXFLAGS) -o address.o
http_header.o : stdafx.h http_header.h http_header.cpp
	$(CXX) http_header.cpp $(CXXFLAGS) -o http_header.o
socket_base.o : $(baseheaders) socket_base.cpp
	$(CXX) socket_base.cpp $(CXXFLAGS) -o socket_base.o
socket_http.o : $(baseheaders) socket_http.h http_header.h socket_http.cpp
	$(CXX) socket_http.cpp $(CXXFLAGS) -o socket_http.o
socket_raw.o : $(baseheaders) socket_raw.h socket_raw.cpp
	$(CXX) socket_raw.cpp $(CXXFLAGS) -o socket_raw.o
socks5_base.o : $(baseheaders) socks5_base.h socks5_base.cpp
	$(CXX) socks5_base.cpp $(CXXFLAGS) -o socks5_base.o
socket_socks5.o : $(baseheaders) socks5_base.h socket_socks5.h socket_socks5.cpp
	$(CXX) socket_socks5.cpp $(CXXFLAGS) -o socket_socks5.o
socket_websock.o : $(baseheaders) socket_websock.h http_header.h socket_websock.cpp
	$(CXX) socket_websock.cpp $(CXXFLAGS) -o socket_websock.o

clean :
	rm -rf *.o *.a
