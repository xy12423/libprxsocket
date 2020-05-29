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
#include "socket_base.h"

using namespace prxsocket;

void prx_tcp_socket::read(const mutable_buffer &buffer, error_code &ec)
{
	char *data = buffer.data();
	size_t size = buffer.size();
	while (size > 0)
	{
		size_t size_recv;
		recv(mutable_buffer(data, size), size_recv, ec);
		if (ec)
			return;
		if (size_recv >= size)
			return;
		data += size_recv;
		size -= size_recv;
	}
}

static void do_async_read(prx_tcp_socket &socket, const mutable_buffer &buffer, const std::shared_ptr<null_callback> &callback)
{
	socket.async_recv(buffer, [&socket, buffer, callback](error_code err, size_t transferred) {
		if (err)
		{
			(*callback)(err);
			return;
		}
		if (transferred >= buffer.size())
		{
			(*callback)(0);
			return;
		}
		do_async_read(socket, mutable_buffer(buffer.data() + transferred, buffer.size() - transferred), callback);
	});
}

void prx_tcp_socket::async_read(const mutable_buffer &buffer, null_callback &&complete_handler)
{
	do_async_read(*this, buffer, std::make_shared<null_callback>(std::move(complete_handler)));
}

void prx_tcp_socket::write(const const_buffer &buffer, error_code &ec)
{
	const char *data = buffer.data();
	size_t size = buffer.size();
	while (size > 0)
	{
		size_t size_sent;
		send(const_buffer(data, size), size_sent, ec);
		if (ec)
			return;
		if (size_sent >= size)
			return;
		data += size_sent;
		size -= size_sent;
	}
	return;
}

static void do_async_write(prx_tcp_socket &socket, const const_buffer &buffer, const std::shared_ptr<null_callback> &callback)
{
	socket.async_send(buffer, [&socket, buffer, callback](error_code err, size_t transferred) {
		if (err)
		{
			(*callback)(err);
			return;
		}
		if (buffer.size() <= transferred)
		{
			(*callback)(0);
			return;
		}
		do_async_write(socket, const_buffer(buffer.data() + transferred, buffer.size() - transferred), callback);
	});
}

void prx_tcp_socket::async_write(const const_buffer &buffer, null_callback &&complete_handler)
{
	do_async_write(*this, buffer, std::make_shared<null_callback>(std::move(complete_handler)));
}

#ifndef _LIBPRXSOCKET_STRICT
static inline void check_ec(const error_code &ec)
{
	if (ec)
		throw(socket_exception(ec));
}

void prx_tcp_socket::local_endpoint(endpoint &ep)
{
	error_code ec;
	local_endpoint(ep, ec);
	check_ec(ec);
}

void prx_tcp_socket::remote_endpoint(endpoint &ep)
{
	error_code ec;
	remote_endpoint(ep, ec);
	check_ec(ec);
}

void prx_tcp_socket::open()
{
	error_code ec;
	open(ec);
	check_ec(ec);
}

void prx_tcp_socket::bind(const endpoint &ep)
{
	error_code ec;
	bind(ep, ec);
	check_ec(ec);
}

void prx_tcp_socket::connect(const endpoint &ep)
{
	error_code ec;
	connect(ep, ec);
	check_ec(ec);
}

void prx_tcp_socket::send(const const_buffer &buffer, size_t &transferred)
{
	error_code ec;
	send(buffer, transferred, ec);
	check_ec(ec);
}

void prx_tcp_socket::recv(const mutable_buffer &buffer, size_t &transferred)
{
	error_code ec;
	recv(buffer, transferred, ec);
	check_ec(ec);
}

void prx_tcp_socket::read(const mutable_buffer &buffer)
{
	error_code ec;
	read(buffer, ec);
	check_ec(ec);
}

void prx_tcp_socket::write(const const_buffer &buffer)
{
	error_code ec;
	write(buffer, ec);
	check_ec(ec);
}

void prx_tcp_socket::read(mutable_buffer_sequence &&buffer)
{
	error_code ec;
	read(std::move(buffer), ec);
	check_ec(ec);
}

void prx_tcp_socket::write(const_buffer_sequence &&buffer)
{
	error_code ec;
	write(std::move(buffer), ec);
	check_ec(ec);
}

void prx_tcp_socket::close()
{
	error_code ec;
	close(ec);
	check_ec(ec);
}

void prx_udp_socket::local_endpoint(endpoint &ep)
{
	error_code ec;
	local_endpoint(ep, ec);
	check_ec(ec);
}

void prx_udp_socket::open()
{
	error_code ec;
	open(ec);
	check_ec(ec);
}

void prx_udp_socket::bind(const endpoint &ep)
{
	error_code ec;
	bind(ep, ec);
	check_ec(ec);
}

void prx_udp_socket::send_to(const endpoint &ep, const const_buffer &buffer)
{
	error_code ec;
	send_to(ep, buffer, ec);
	check_ec(ec);
}

void prx_udp_socket::send_to(const endpoint &ep, const_buffer_sequence &&buffer)
{
	error_code ec;
	send_to(ep, std::move(buffer), ec);
	check_ec(ec);
}

void prx_udp_socket::recv_from(endpoint &ep, const mutable_buffer &buffer, size_t &transferred)
{
	error_code ec;
	recv_from(ep, buffer, transferred, ec);
	check_ec(ec);
}

void prx_udp_socket::recv_from(endpoint &ep, mutable_buffer_sequence &&buffer, size_t &transferred)
{
	error_code ec;
	recv_from(ep, std::move(buffer), transferred, ec);
	check_ec(ec);
}

void prx_udp_socket::close()
{
	error_code ec;
	close(ec);
	check_ec(ec);
}

void prx_listener::local_endpoint(endpoint &ep)
{
	error_code ec;
	local_endpoint(ep, ec);
	check_ec(ec);
}

void prx_listener::open()
{
	error_code ec;
	open(ec);
	check_ec(ec);
}

void prx_listener::bind(const endpoint &ep)
{
	error_code ec;
	bind(ep, ec);
	check_ec(ec);
}

void prx_listener::listen()
{
	error_code ec;
	listen(ec);
	check_ec(ec);
}

void prx_listener::accept(std::unique_ptr<prx_tcp_socket> &socket)
{
	error_code ec;
	accept(socket, ec);
	check_ec(ec);
}

void prx_listener::close()
{
	error_code ec;
	close(ec);
	check_ec(ec);
}
#endif
