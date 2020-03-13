#ifndef LIBPRXSOCKET_H_ENDPOINT
#define LIBPRXSOCKET_H_ENDPOINT

#include "address.h"

namespace prxsocket
{

	using port_type = uint16_t;

	class endpoint
	{
	public:
		endpoint() :port_(0) {}
		template <typename T> endpoint(T &&addr, port_type port) : addr_(std::forward<T>(addr)), port_(port) {}

		const address &addr() const { return addr_; }
		port_type port() const { return port_; }
		template <typename T> void set_addr(T &&addr) { addr_ = std::forward<T>(addr); }
		void set_port(port_type port) { port_ = port; }

		size_t from_socks5(const char *data);
		void to_socks5(std::string &ret) const;
		std::string to_string() const;

		bool operator==(const endpoint &b) const { return port_ == b.port_ && addr_ == b.addr_; }
		bool operator!=(const endpoint &b) const { return port_ != b.port_ || addr_ != b.addr_; }
	private:
		address addr_;
		port_type port_;
	};

}

#endif
