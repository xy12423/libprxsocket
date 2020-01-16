#include "stdafx.h"
#include "endpoint.h"

size_t endpoint::from_socks5(const char * data)
{
	size_t size = addr_.from_socks5(data);
	if (size == 0)
		return 0;
	port_ = ((uint8_t)(data[size]) << 8) | (uint8_t)(data[size + 1]);
	return size + 2;
}

void endpoint::to_socks5(std::string & ret) const
{
	addr_.to_socks5(ret);
	ret.push_back(port_ >> 8);
	ret.push_back(port_ & 0xFF);
}

std::string endpoint::to_string() const
{
	if (addr_.type() == address::UNDEFINED)
		return std::string();
	return addr_.to_string() + ':' + std::to_string(port_);
}
