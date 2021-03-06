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
#include "socket_ss.h"

using namespace prxsocket;
using namespace prxsocket::ss;

void ss_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	socket_->connect(server_ep_, err);
	if (err)
		return;

	remote_ep_ = ep;
	std::string header;
	remote_ep_.to_socks5(header);
	socket_->write(const_buffer(header), err);
	if (err)
	{
		reset();
		return;
	}
	remote_ep_sent_ = true;
}

void ss_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket_->async_connect(server_ep_,
		[this, ep, callback](error_code err)
	{
		if (err)
		{
			(*callback)(err);
			return;
		}

		remote_ep_ = ep;
		std::shared_ptr<std::string> header = std::make_shared<std::string>();
		remote_ep_.to_socks5(*header);
		socket_->async_write(const_buffer(*header),
			[this, header, callback](error_code err)
		{
			if (err)
			{
				reset();
				(*callback)(err);
				return;
			}
			remote_ep_sent_ = true;
			(*callback)(0);
		});
	});
}

void ss_tcp_socket::close(error_code &ec)
{
	reset();
	socket_->close(ec);
}

void ss_tcp_socket::async_close(null_callback &&complete_handler)
{
	reset();
	socket_->async_close(std::move(complete_handler));
}

void ss_udp_socket::send_to(const endpoint &ep, const_buffer buffer, error_code &err)
{
	return send_to(ep, const_buffer_sequence(buffer), err);
}

void ss_udp_socket::async_send_to(const endpoint &ep, const_buffer buffer, null_callback &&complete_handler)
{
	return async_send_to(ep, const_buffer_sequence(buffer), std::move(complete_handler));
}

void ss_udp_socket::recv_from(endpoint &ep, mutable_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t udp_recv_size;
	udp_socket_->recv_from(udp_recv_ep_, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE), udp_recv_size, err);
	if (err)
	{
		if (!udp_socket_->is_open())
			reset();
		return;
	}

	try
	{
		size_t ep_size = ep.from_socks5(udp_recv_buf_.get());
		if (ep_size == 0 || ep_size > udp_recv_size)
		{
			err = ERR_OPERATION_FAILURE;
			return;
		}

		char *payload = udp_recv_buf_.get() + ep_size;
		size_t payload_size = udp_recv_size - ep_size;
		transferred = std::min(buffer.size(), payload_size);
		memcpy(buffer.data(), payload, transferred);
	}
	catch (const std::exception &)
	{
		transferred = 0;
		err = ERR_OPERATION_FAILURE;
		return;
	}
}

void ss_udp_socket::async_recv_from(endpoint &ep, mutable_buffer buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	udp_socket_->async_recv_from(udp_recv_ep_, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE),
		[this, &ep, buffer, callback](error_code err, size_t udp_recv_size)
	{
		if (err)
		{
			if (!udp_socket_->is_open())
				reset();
			(*callback)(err, 0);
			return;
		}

		try
		{
			size_t ep_size = ep.from_socks5(udp_recv_buf_.get());
			if (ep_size == 0 || ep_size > udp_recv_size)
			{
				(*callback)(ERR_OPERATION_FAILURE, 0);
				return;
			}

			char *payload = udp_recv_buf_.get() + ep_size;
			size_t payload_size = udp_recv_size - ep_size;
			size_t transferred = std::min(buffer.size(), payload_size);
			memcpy(buffer.data(), payload, transferred);
			(*callback)(err, transferred);
		}
		catch (const std::exception &)
		{
			(*callback)(ERR_OPERATION_FAILURE, 0);
			return;
		}
	});
}

void ss_udp_socket::send_to(const endpoint &ep, const_buffer_sequence &&buffers, error_code &err)
{
	err = 0;

	std::string header;
	try
	{
		ep.to_socks5(header);
		buffers.push_front(const_buffer(header));
	}
	catch (const std::exception &)
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}

	udp_socket_->send_to(udp_server_ep_, std::move(buffers), err);
	if (!udp_socket_->is_open())
		reset();
}

void ss_udp_socket::async_send_to(const endpoint &ep, const_buffer_sequence &&buffers, null_callback &&complete_handler)
{
	std::shared_ptr<std::string> header = std::make_shared<std::string>();
	try
	{
		ep.to_socks5(*header);
		buffers.push_front(const_buffer(*header));
	}
	catch (const std::exception &)
	{
		complete_handler(ERR_OPERATION_FAILURE);
		return;
	}

	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	udp_socket_->async_send_to(udp_server_ep_, std::move(buffers),
		[this, header, callback](error_code err)
	{
		if (!udp_socket_->is_open())
			reset();
		(*callback)(err);
	});
}

void ss_udp_socket::recv_from(endpoint &ep, mutable_buffer_sequence &&buffers, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t udp_recv_size;
	udp_socket_->recv_from(udp_recv_ep_, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE), udp_recv_size, err);
	if (err)
	{
		if (!udp_socket_->is_open())
			reset();
		return;
	}

	try
	{
		size_t ep_size = ep.from_socks5(udp_recv_buf_.get());
		if (ep_size == 0 || ep_size > udp_recv_size)
		{
			err = ERR_OPERATION_FAILURE;
			return;
		}

		char *payload = udp_recv_buf_.get() + ep_size;
		size_t payload_size = udp_recv_size - ep_size;

		transferred = buffers.scatter(payload, payload_size);
	}
	catch (const std::exception &)
	{
		transferred = 0;
		err = ERR_OPERATION_FAILURE;
		return;
	}
}

void ss_udp_socket::async_recv_from(endpoint &ep, mutable_buffer_sequence &&buffers, transfer_callback &&complete_handler)
{
	std::shared_ptr<mutable_buffer_sequence> buffer = std::make_shared<mutable_buffer_sequence>(std::move(buffers));
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	udp_socket_->async_recv_from(udp_recv_ep_, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE),
		[this, &ep, buffer, callback](error_code err, size_t udp_recv_size)
	{
		if (err)
		{
			if (!udp_socket_->is_open())
				reset();
			(*callback)(err, 0);
			return;
		}

		try
		{
			size_t ep_size = ep.from_socks5(udp_recv_buf_.get());
			if (ep_size == 0 || ep_size > udp_recv_size)
			{
				(*callback)(ERR_OPERATION_FAILURE, 0);
				return;
			}

			char *payload = udp_recv_buf_.get() + ep_size;
			size_t payload_size = udp_recv_size - ep_size;
			
			size_t transferred = buffer->scatter(payload, payload_size);

			(*callback)(err, transferred);
		}
		catch (const std::exception &)
		{
			(*callback)(ERR_OPERATION_FAILURE, 0);
			return;
		}
	});
}
