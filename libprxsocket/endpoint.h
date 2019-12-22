#ifndef _H_ENDPOINT
#define _H_ENDPOINT

#include "address.h"

typedef uint16_t port_type;

class endpoint
{
public:
	endpoint() :m_port(0) {}
	template <typename T>
	endpoint(T &&addr, port_type port) : m_addr(std::forward<T>(addr)), m_port(port)
	{}

	const address &addr() const { return m_addr; }
	port_type port() const { return m_port; }
	template <typename T> void set_addr(T &&addr) { m_addr = std::forward<T>(addr); }
	void set_port(port_type port) { m_port = port; }

	bool operator==(const endpoint &b) const { return m_port == b.m_port && m_addr == b.m_addr; }
	bool operator!=(const endpoint &b) const { return m_port != b.m_port || m_addr != b.m_addr; }
private:
	address m_addr;
	port_type m_port;
};

#endif
