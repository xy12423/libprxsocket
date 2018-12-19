#include "stdafx.h"
#include "socket_base.h"

#ifndef _LIBPRXSOCKET_STRICT
inline void check_ec(const error_code &ec)
{
	if (ec)
		throw(socket_exception(ec));
}

void prx_tcp_socket_base::local_endpoint(endpoint &ep)
{
	error_code ec;
	local_endpoint(ep, ec);
	check_ec(ec);
}

void prx_tcp_socket_base::remote_endpoint(endpoint &ep)
{
	error_code ec;
	remote_endpoint(ep, ec);
	check_ec(ec);
}

void prx_tcp_socket_base::open()
{
	error_code ec;
	open(ec);
	check_ec(ec);
}

void prx_tcp_socket_base::bind(const endpoint &ep)
{
	error_code ec;
	bind(ep, ec);
	check_ec(ec);
}

void prx_tcp_socket_base::connect(const endpoint &ep)
{
	error_code ec;
	connect(ep, ec);
	check_ec(ec);
}

void prx_tcp_socket_base::send(const const_buffer &buffer, size_t &transferred)
{
	error_code ec;
	send(buffer, transferred, ec);
	check_ec(ec);
}

void prx_tcp_socket_base::recv(const mutable_buffer &buffer, size_t &transferred)
{
	error_code ec;
	recv(buffer, transferred, ec);
	check_ec(ec);
}

void prx_tcp_socket_base::close()
{
	error_code ec;
	close(ec);
	check_ec(ec);
}

void read(prx_tcp_socket_base &socket, const mutable_buffer &buffer, error_code &ec)
{
	char *data = buffer.access_data();
	size_t size = buffer.get_size();
	while (size > 0)
	{
		size_t size_recv;
		socket.recv(mutable_buffer(data, size), size_recv, ec);
		if (ec)
			return;
		if (size_recv >= size)
			return;
		data += size_recv;
		size -= size_recv;
	}
}

void read(prx_tcp_socket_base &socket, const mutable_buffer &buffer)
{
	error_code ec;
	read(socket, buffer, ec);
	check_ec(ec);
}

void do_async_read(prx_tcp_socket_base &socket, const mutable_buffer &buffer, const std::shared_ptr<null_callback> &callback)
{
	socket.async_recv(buffer, [&socket, buffer, callback](error_code err, size_t transferred) {
		if (err)
		{
			(*callback)(err);
			return;
		}
		if (transferred >= buffer.get_size())
		{
			(*callback)(0);
			return;
		}
		do_async_read(socket, mutable_buffer(buffer.access_data() + transferred, buffer.get_size() - transferred), callback);
	});
}

void async_read(prx_tcp_socket_base &socket, const mutable_buffer &buffer, null_callback &&complete_handler)
{
	do_async_read(socket, buffer, std::make_shared<null_callback>(std::move(complete_handler)));
}

void write(prx_tcp_socket_base &socket, const const_buffer &buffer, error_code &ec)
{
	const char *data = buffer.get_data();
	size_t size = buffer.get_size();
	while (size > 0)
	{
		size_t size_sent;
		socket.send(const_buffer(data, size), size_sent, ec);
		if (ec)
			return;
		if (size_sent >= size)
			return;
		data += size_sent;
		size -= size_sent;
	}
	return;
}

void write(prx_tcp_socket_base &socket, const const_buffer &buffer)
{
	error_code ec;
	write(socket, buffer, ec);
	check_ec(ec);
}

void do_async_write(prx_tcp_socket_base &socket, const const_buffer &buffer, const std::shared_ptr<null_callback> &callback)
{
	socket.async_send(buffer, [&socket, buffer, callback](error_code err, size_t transferred) {
		if (err)
		{
			(*callback)(err);
			return;
		}
		if (buffer.get_size() <= transferred)
		{
			(*callback)(0);
			return;
		}
		do_async_write(socket, const_buffer(buffer.get_data() + transferred, buffer.get_size() - transferred), callback);
	});
}

void async_write(prx_tcp_socket_base &socket, const const_buffer &buffer, null_callback &&complete_handler)
{
	do_async_write(socket, buffer, std::make_shared<null_callback>(std::move(complete_handler)));
}

void prx_udp_socket_base::local_endpoint(endpoint &ep)
{
	error_code ec;
	local_endpoint(ep, ec);
	check_ec(ec);
}

void prx_udp_socket_base::open()
{
	error_code ec;
	open(ec);
	check_ec(ec);
}

void prx_udp_socket_base::bind(const endpoint &ep)
{
	error_code ec;
	bind(ep, ec);
	check_ec(ec);
}

void prx_udp_socket_base::send_to(const endpoint &ep, const const_buffer &buffer)
{
	error_code ec;
	send_to(ep, buffer, ec);
	check_ec(ec);
}

void prx_udp_socket_base::recv_from(endpoint &ep, const mutable_buffer &buffer, size_t &transferred)
{
	error_code ec;
	recv_from(ep, buffer, transferred, ec);
	check_ec(ec);
}

void prx_udp_socket_base::close()
{
	error_code ec;
	close(ec);
	check_ec(ec);
}

void prx_listener_base::local_endpoint(endpoint &ep)
{
	error_code ec;
	local_endpoint(ep, ec);
	check_ec(ec);
}

void prx_listener_base::open()
{
	error_code ec;
	open(ec);
	check_ec(ec);
}

void prx_listener_base::bind(const endpoint &ep)
{
	error_code ec;
	bind(ep, ec);
	check_ec(ec);
}

void prx_listener_base::listen()
{
	error_code ec;
	listen(ec);
	check_ec(ec);
}

void prx_listener_base::accept(prx_tcp_socket_base *&socket)
{
	error_code ec;
	accept(socket, ec);
	check_ec(ec);
}

void prx_listener_base::close()
{
	error_code ec;
	close(ec);
	check_ec(ec);
}
#endif
