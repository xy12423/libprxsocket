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

namespace
{
	using data_handler_callback = std::function<error_code_or_op_result(const_buffer &)>;
	using data_complete_callback = std::function<void(error_code_or_op_result, buffer_with_data_store &&)>;

	struct do_async_recv_until_handlers
	{
		do_async_recv_until_handlers(data_handler_callback &&data, data_complete_callback &&complete) :data_handler(std::move(data)), complete_handler(std::move(complete)) {}

		data_handler_callback data_handler;
		data_complete_callback complete_handler;
	};
}

void prxsocket::prx_tcp_socket::recv_until(buffer_with_data_store &leftover, data_handler_callback &&data_handler, error_code_or_op_result &ec_or_result)
{
	buffer_with_data_store buffer;
	if (leftover.buffer.size() > 0)
	{
		buffer.buffer = leftover.buffer;
		leftover.buffer = const_buffer();
		buffer.holder.swap(leftover.holder);
	}

	error_code_or_op_result ec{ OPRESULT_CONTINUE };
	if (buffer.buffer.size() > 0)
	{
		ec = data_handler(buffer.buffer);
		assert(ec.code != OPRESULT_CONTINUE || buffer.buffer.size() == 0);
	}
	while (ec.code == OPRESULT_CONTINUE)
	{
		error_code ec2;
		recv(buffer.buffer, buffer.holder, ec2);
		if (ec2)
		{
			ec_or_result = error_code_or_op_result{ ec2 };
			leftover = std::move(buffer);
			return;
		}
		ec = data_handler(buffer.buffer);
		assert(ec.code != OPRESULT_CONTINUE || buffer.buffer.size() == 0);
	}
	ec_or_result = ec;
	leftover = buffer.buffer.size() > 0 ? std::move(buffer) : buffer_with_data_store{};
}

static void do_async_recv_until(prx_tcp_socket *socket,
	const_buffer buffer_recv, buffer_data_store_holder &&buffer_holder,
	const std::shared_ptr<do_async_recv_until_handlers> &callbacks)
{
	buffer_data_store_holder buffer_recv_holder(std::move(buffer_holder));

	error_code_or_op_result ec = callbacks->data_handler(buffer_recv);
	assert(ec.code != OPRESULT_CONTINUE || buffer_recv.size() == 0);

	if (ec.code == OPRESULT_CONTINUE)
	{
		socket->async_recv([socket, callbacks](error_code ec, const_buffer buffer, buffer_data_store_holder &&buffer_holder)
		{
			if (ec)
			{
				callbacks->complete_handler(error_code_or_op_result{ ec }, buffer_with_data_store{ buffer, std::move(buffer_holder) });
				return;
			}
			do_async_recv_until(socket, buffer, std::move(buffer_holder), callbacks);
		});
		return;
	}

	callbacks->complete_handler(ec, buffer_recv.size() > 0 ? buffer_with_data_store{ buffer_recv, std::move(buffer_recv_holder) } : buffer_with_data_store{});
}

void prxsocket::prx_tcp_socket::async_recv_until(buffer_with_data_store &&leftover, data_handler_callback &&data_handler, data_complete_callback &&complete_handler)
{
	std::shared_ptr<do_async_recv_until_handlers> callbacks = std::make_shared<do_async_recv_until_handlers>(std::move(data_handler), std::move(complete_handler));
	if (leftover.buffer.size() > 0)
	{
		do_async_recv_until(this, leftover.buffer, std::move(leftover.holder), callbacks);
	}
	else
	{
		async_recv([this, callbacks](error_code ec, const_buffer buffer, buffer_data_store_holder &&buffer_holder)
		{
			if (ec)
			{
				callbacks->complete_handler(error_code_or_op_result{ ec }, buffer_with_data_store{ buffer, std::move(buffer_holder) });
				return;
			}
			do_async_recv_until(this, buffer, std::move(buffer_holder), callbacks);
		});
	}
}
