/*
Copyright (c) 2020 xy12423

This file is part of libprxsocket.

libprxsocket is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

libprxsocket is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libprxsocket. If not, see <https://www.gnu.org/licenses/>.
*/

#include "stdafx.h"
#include "endpoint.h"

using namespace prxsocket;

size_t endpoint::from_socks5(const char *data)
{
	size_t size = addr_.from_socks5(data);
	if (size == 0)
		return 0;
	port_ = ((uint8_t)(data[size]) << 8) | (uint8_t)(data[size + 1]);
	return size + 2;
}

void endpoint::to_socks5(std::string &ret) const
{
	addr_.to_socks5(ret);
	uint16_t port_be = boost::endian::native_to_big((uint16_t)port_);
	ret.append((char *)&port_be, sizeof(port_be));
}

std::string endpoint::to_string() const
{
	if (addr_.type() == address::UNDEFINED)
		return std::string();
	return addr_.to_string() + ':' + std::to_string(port_);
}

std::string endpoint::to_uri_string() const
{
	if (addr_.type() == address::UNDEFINED)
		return std::string();
	return addr_.to_uri_string() + ':' + std::to_string(port_);
}
