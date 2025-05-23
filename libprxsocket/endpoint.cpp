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
