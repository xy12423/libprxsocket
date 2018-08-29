#include "stdafx.h"
#include "socket_base.h"

err_type read(prx_tcp_socket_base& socket, const mutable_buffer& buffer)
{
	char *data = buffer.access_data();
	size_t size = buffer.get_size();
	while (size > 0)
	{
		size_t size_recv;
		err_type err = socket.recv(mutable_buffer(data, size), size_recv);
		if (err)
			return err;
		if (size_recv >= size)
			return 0;
		data += size_recv;
		size -= size_recv;
	}
	return 0;
}

void do_async_read(prx_tcp_socket_base& socket, const mutable_buffer& buffer, const std::shared_ptr<null_callback>& callback)
{
	socket.async_recv(buffer, [&socket, buffer, callback](err_type err, size_t transferred) {
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

void async_read(prx_tcp_socket_base& socket, const mutable_buffer& buffer, null_callback&& complete_handler)
{
	do_async_read(socket, buffer, std::make_shared<null_callback>(std::move(complete_handler)));
}

err_type write(prx_tcp_socket_base& socket, const const_buffer& buffer)
{
	const char *data = buffer.get_data();
	size_t size = buffer.get_size();
	while (size > 0)
	{
		size_t size_sent;
		err_type err = socket.send(const_buffer(data, size), size_sent);
		if (err)
			return err;
		if (size_sent >= size)
			return 0;
		data += size_sent;
		size -= size_sent;
	}
	return 0;
}

void do_async_write(prx_tcp_socket_base& socket, const const_buffer& buffer, const std::shared_ptr<null_callback>& callback)
{
	socket.async_send(buffer, [&socket, buffer, callback](err_type err, size_t transferred) {
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

void async_write(prx_tcp_socket_base& socket, const const_buffer& buffer, null_callback&& complete_handler)
{
	do_async_write(socket, buffer, std::make_shared<null_callback>(std::move(complete_handler)));
}
