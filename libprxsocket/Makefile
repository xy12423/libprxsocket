CXX = g++
CXXFLAGS = -c -pthread -I ~/boost -std=c++14 -Wall
AR = ar
ARFLAGS = -cr
RANLIB = ranlib

ifeq ($(RELEASE), 1)
	CXXFLAGS += -g3 -O2 -DNDEBUG
else
	CXXFLAGS += -g3 -O0 -D_DEBUG
endif

objects = address.o endpoint.o socket_base.o http_header.o socket_http.o socket_raw.o socks5_base.o socket_socks5.o socket_ss.o socket_ss_crypto.o socket_ssr_auth.o socket_ssr_obfs.o socket_vmess.o socket_obfs_websock.o
baseheaders = stdafx.h address.h endpoint.h buffer.h socket_base.h

all : libprxsocket.a

libprxsocket.a : $(objects)
	$(AR) $(ARFLAGS) $@ $(objects)
	$(RANLIB) $@
address.o : stdafx.h address.h address.cpp
	$(CXX) address.cpp $(CXXFLAGS) -o address.o
endpoint.o : stdafx.h address.h endpoint.h endpoint.cpp
	$(CXX) endpoint.cpp $(CXXFLAGS) -o endpoint.o
socket_base.o : $(baseheaders) socket_base.cpp
	$(CXX) socket_base.cpp $(CXXFLAGS) -o socket_base.o
http_header.o : stdafx.h http_header.h http_header.cpp
	$(CXX) http_header.cpp $(CXXFLAGS) -o http_header.o
socket_http.o : $(baseheaders) socket_http.h http_header.h socket_http.cpp
	$(CXX) socket_http.cpp $(CXXFLAGS) -o socket_http.o
socket_raw.o : $(baseheaders) socket_raw.h socket_raw.cpp
	$(CXX) socket_raw.cpp $(CXXFLAGS) -o socket_raw.o
socks5_base.o : $(baseheaders) socks5_base.h socks5_base.cpp
	$(CXX) socks5_base.cpp $(CXXFLAGS) -o socks5_base.o
socket_socks5.o : $(baseheaders) socks5_base.h socket_socks5.h socket_socks5.cpp
	$(CXX) socket_socks5.cpp $(CXXFLAGS) -o socket_socks5.o
socket_ss.o : $(baseheaders) socket_ss.h socket_ss.cpp
	$(CXX) socket_ss.cpp $(CXXFLAGS) -o socket_ss.o
socket_ss_crypto.o : $(baseheaders) socket_transparent.h crypto_base.h socket_ss_crypto.h socket_ss_crypto.cpp
	$(CXX) socket_ss_crypto.cpp $(CXXFLAGS) -o socket_ss_crypto.o
socket_ssr_auth.o : $(baseheaders) socket_transparent.h random_generator.h crypto_base.h socket_ss_crypto.h socket_ssr_auth.h socket_ssr_auth.cpp
	$(CXX) socket_ssr_auth.cpp $(CXXFLAGS) -o socket_ssr_auth.o
socket_ssr_obfs.o : $(baseheaders) socket_transparent.h socket_ssr_obfs.h socket_ssr_obfs.cpp
	$(CXX) socket_ssr_obfs.cpp $(CXXFLAGS) -o socket_ssr_obfs.o
socket_vmess.o : $(baseheaders) random_generator.h socket_vmess.h socket_vmess.cpp
	$(CXX) socket_vmess.cpp $(CXXFLAGS) -o socket_vmess.o
socket_obfs_websock.o : $(baseheaders) random_generator.h socket_obfs_websock.h http_header.h socket_obfs_websock.cpp
	$(CXX) socket_obfs_websock.cpp $(CXXFLAGS) -o socket_obfs_websock.o

clean :
	rm -rf *.o *.a
