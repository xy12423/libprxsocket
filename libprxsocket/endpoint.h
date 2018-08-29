#ifndef _H_ENDPOINT
#define _H_ENDPOINT

#include "address.h"
typedef uint16_t port_type;

class endpoint
{
public:
	endpoint() :port(0) {}
	template <typename T>
	endpoint(T&& _addr, port_type _port) : addr(std::forward<T>(_addr)), port(_port)
	{}

	const address& get_addr() const { return addr; }
	port_type get_port() const { return port; }
	template <typename T> void set_addr(T&& _addr) { addr = std::forward<T>(_addr); }
	void set_port(port_type _port) { port = _port; }

	bool operator==(const endpoint& b) const { return port == b.port && addr == b.addr; }
	bool operator!=(const endpoint& b) const { return port != b.port || addr != b.addr; }
private:
	address addr;
	port_type port;
};

#endif
