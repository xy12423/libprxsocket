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
#include "socket_socks5.h"

using namespace prxsocket;

static const endpoint udp_local_ep_zero(address(static_cast<uint32_t>(0)), 0);

void prxsocket::socks5_tcp_socket::open(error_code &err)
{
	state_ = STATE_INIT;
	err = open_and_auth(server_ep_);
	if (err)
		reset();
	else
		state_ = STATE_OPEN;
}

void prxsocket::socks5_tcp_socket::async_open(null_callback &&complete_handler)
{
	state_ = STATE_INIT;
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	async_open_and_auth(server_ep_,
		[this, callback](error_code err)
	{
		if (err)
			reset();
		else
			state_ = STATE_OPEN;
		(*callback)(err);
	});
}

void prxsocket::socks5_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	err = 0;

	remote_ep_ = ep;
	PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, req, req_holder);
	make_s5_header(req, CONNECT, ep);
	socket_->send(const_buffer(req), std::move(req_holder), err);
	if (err)
	{
		reset();
		return;
	}
	uint8_t rep;
	err = recv_s5(rep, local_ep_);
	if (err)
	{
		reset();
		return;
	}
	if (rep != 0)
	{
		reset();
		err = rep;
		return;
	}

	state_ = STATE_CONNECTED;
}

void prxsocket::socks5_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	remote_ep_ = ep;
	PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, req, req_holder);
	make_s5_header(req, CONNECT, ep);
	socket_->async_send(const_buffer(req), std::move(req_holder),
		[this, callback](error_code err)
	{
		if (err)
		{
			reset();
			(*callback)(err);
			return;
		}
		async_recv_s5([this, callback](error_code err, uint8_t rep, const endpoint &ep)
		{
			if (err)
			{
				reset();
				(*callback)(err);
				return;
			}
			if (rep != 0)
			{
				reset();
				(*callback)(rep);
				return;
			}
			state_ = STATE_CONNECTED;
			local_ep_ = ep;
			(*callback)(0);
		});
	});
}

size_t prxsocket::socks5_tcp_socket::send_size_max()
{
	return socket_->send_size_max();
}

void prxsocket::socks5_tcp_socket::send(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, error_code &ec)
{
	return socket_->send(buffer, std::move(buffer_data_holder), ec);
}

void prxsocket::socks5_tcp_socket::async_send(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, null_callback &&complete_handler)
{
	return socket_->async_send(buffer, std::move(buffer_data_holder), std::move(complete_handler));
}

void prxsocket::socks5_tcp_socket::send_partial(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, error_code &ec)
{
	return socket_->send_partial(buffer, std::move(buffer_data_holder), ec);
}

void prxsocket::socks5_tcp_socket::async_send_partial(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, null_callback &&complete_handler)
{
	return socket_->async_send_partial(buffer, std::move(buffer_data_holder), std::move(complete_handler));
}

void prxsocket::socks5_tcp_socket::recv(const_buffer &buffer, buffer_data_store_holder &buffer_data_holder, error_code &ec)
{
	return socket_->recv(buffer, buffer_data_holder, ec);
}

void prxsocket::socks5_tcp_socket::async_recv(transfer_data_callback &&complete_handler)
{
	return socket_->async_recv(std::move(complete_handler));
}

void prxsocket::socks5_tcp_socket::shutdown(shutdown_type type, error_code &ec)
{
	return socket_->shutdown(type, ec);
}

void prxsocket::socks5_tcp_socket::async_shutdown(shutdown_type type, null_callback &&complete_handler)
{
	return socket_->async_shutdown(type, std::move(complete_handler));
}

void prxsocket::socks5_tcp_socket::close(error_code &ec)
{
	reset();
	socket_->close(ec);
}

void prxsocket::socks5_tcp_socket::async_close(null_callback &&complete_handler)
{
	reset();
	socket_->async_close(std::move(complete_handler));
}

void prxsocket::socks5_udp_socket::local_endpoint(endpoint &ep, error_code &err)
{
	err = ERR_UNSUPPORTED;
	return;
}

void prxsocket::socks5_udp_socket::open(error_code &err)
{
	open(udp_local_ep_zero, err);
}

void prxsocket::socks5_udp_socket::async_open(null_callback &&complete_handler)
{
	async_open(udp_local_ep_zero, std::move(complete_handler));
}

void prxsocket::socks5_udp_socket::bind(const endpoint &ep, error_code &err)
{
	err = ERR_UNSUPPORTED;
	return;
}

void prxsocket::socks5_udp_socket::async_bind(const endpoint &ep, null_callback &&complete_handler)
{
	complete_handler(ERR_UNSUPPORTED);
	return;
}

void prxsocket::socks5_udp_socket::open(const endpoint &ep, error_code &err)
{
	close(err);

	err = 0;
	if (udp_socket_)
	{
		udp_socket_->open(err);
		if (!udp_socket_->is_open())
		{
			reset();
			if (!err)
				err = ERR_OPERATION_FAILURE;
			return;
		}
	}

	err = open_and_auth(server_ep_);
	if (err)
	{
		reset();
		return;
	}
	if (!ep.addr().is_any())
	{
		reset();
		err = ERR_OPERATION_FAILURE;
		return;
	}

	PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, req, req_holder);
	make_s5_header(req, UDP_ASSOCIATE, ep);
	socket_->send(const_buffer(req), std::move(req_holder), err);
	if (err)
	{
		reset();
		return;
	}

	uint8_t rep;
	err = recv_s5(rep, udp_server_ep_);
	if (err)
	{
		reset();
		return;
	}
	if (rep != 0)
	{
		reset();
		err = rep;
		return;
	}

	state_ = STATE_ASSOCIATED;
}

void prxsocket::socks5_udp_socket::async_open(const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	async_close([this, ep, callback](error_code)
	{
		if (udp_socket_)
		{
			udp_socket_->async_open([this, ep, callback](error_code err)
			{
				if (!udp_socket_->is_open())
				{
					reset();
					(*callback)(err ? err : ERR_OPERATION_FAILURE);
					return;
				}
				async_open_continue(ep, callback);
			});
			return;
		}

		async_open_continue(ep, callback);
	});
}

void prxsocket::socks5_udp_socket::async_open_continue(const endpoint &ep, const std::shared_ptr<null_callback> &callback)
{
	async_open_and_auth(server_ep_,
		[this, ep, callback](error_code err)
	{
		if (err)
		{
			reset();
			(*callback)(err);
			return;
		}
		if (!ep.addr().is_any())
		{
			reset();
			(*callback)(ERR_OPERATION_FAILURE);
			return;
		}
		PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, req, req_holder);
		make_s5_header(req, UDP_ASSOCIATE, ep);
		socket_->async_send(const_buffer(req), std::move(req_holder), 
			[this, callback](error_code err)
		{
			if (err)
			{
				reset();
				(*callback)(err);
				return;
			}
			async_recv_s5([this, callback](error_code err, uint8_t rep, const endpoint &ep)
			{
				if (err)
				{
					reset();
					(*callback)(err);
					return;
				}
				if (rep != 0)
				{
					reset();
					(*callback)(rep);
					return;
				}
				udp_server_ep_ = ep;

				state_ = STATE_ASSOCIATED;
				(*callback)(0);
			});
		});
	});
}

void prxsocket::socks5_udp_socket::send_to(const endpoint &ep, const_buffer buffer, error_code &err)
{
	return send_to(ep, const_buffer_sequence(buffer), err);
}

void prxsocket::socks5_udp_socket::async_send_to(const endpoint &ep, const_buffer buffer, null_callback &&complete_handler)
{
	return async_send_to(ep, const_buffer_sequence(buffer), std::move(complete_handler));
}

void prxsocket::socks5_udp_socket::recv_from(endpoint &ep, mutable_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t udp_recv_size;
	if (!socket_->is_connected())
	{
		reset();
		err = ERR_OPERATION_FAILURE;
		return;
	}
	udp_socket_->recv_from(udp_recv_ep_, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE), udp_recv_size, err);
	if (err)
	{
		if (!udp_socket_->is_open())
			reset();
		return;
	}
	
	err = parse_udp(udp_recv_size, ep, buffer, transferred);
}

void prxsocket::socks5_udp_socket::async_recv_from(endpoint &ep, mutable_buffer buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	if (!socket_->is_connected())
	{
		reset();
		(*callback)(ERR_OPERATION_FAILURE, 0);
		return;
	}
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
		size_t transferred;
		err = parse_udp(udp_recv_size, ep, buffer, transferred);
		(*callback)(err, transferred);
	});
}

void prxsocket::socks5_udp_socket::send_to(const endpoint &ep, const_buffer_sequence &&buffers, error_code &err)
{
	err = 0;

	std::vector<byte> header;
	try
	{
		make_s5_header(header, 0, ep);
		header[0] = header[1] = header[2] = byte{ 0 }; //RSV && FRAG
		buffers.push_front(const_buffer(header));
	}
	catch (const std::exception &)
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}

	if (!socket_->is_connected())
	{
		reset();
		err = ERR_OPERATION_FAILURE;
		return;
	}
	udp_socket_->send_to(udp_server_ep_, std::move(buffers), err);
	if (err && !udp_socket_->is_open())
	{
		reset();
		return;
	}
}

void prxsocket::socks5_udp_socket::async_send_to(const endpoint &ep, const_buffer_sequence &&buffers, null_callback &&complete_handler)
{
	std::shared_ptr<std::vector<byte>> header_holder = std::make_shared<std::vector<byte>>();
	std::vector<byte> &header = *header_holder;
	try
	{
		make_s5_header(header, 0, ep);
		header[0] = header[1] = header[2] = byte{ 0 }; //RSV && FRAG
		buffers.push_front(const_buffer(header));
	}
	catch (const std::exception &)
	{
		complete_handler(ERR_OPERATION_FAILURE);
		return;
	}

	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	if (!socket_->is_connected())
	{
		reset();
		(*callback)(ERR_OPERATION_FAILURE);
		return;
	}
	udp_socket_->async_send_to(server_ep_, std::move(buffers),
		[this, header, callback](error_code err)
	{
		if (err && !udp_socket_->is_open())
			reset();
		(*callback)(err);
	});
}

void prxsocket::socks5_udp_socket::recv_from(endpoint &ep, mutable_buffer_sequence &&buffers, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t udp_recv_size;
	if (!socket_->is_connected())
	{
		reset();
		err = ERR_OPERATION_FAILURE;
		return;
	}
	udp_socket_->recv_from(udp_recv_ep_, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE), udp_recv_size, err);
	if (err)
	{
		if (!udp_socket_->is_open())
			reset();
		return;
	}

	err = parse_udp(udp_recv_size, ep, std::move(buffers), transferred);
}

void prxsocket::socks5_udp_socket::async_recv_from(endpoint &ep, mutable_buffer_sequence &&buffers, transfer_callback &&complete_handler)
{
	std::shared_ptr<mutable_buffer_sequence> buffer = std::make_shared<mutable_buffer_sequence>(std::move(buffers));
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	if (!socket_->is_connected())
	{
		reset();
		(*callback)(ERR_OPERATION_FAILURE, 0);
		return;
	}
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
		size_t transferred;
		err = parse_udp(udp_recv_size, ep, std::move(*buffer), transferred);
		(*callback)(err, transferred);
	});
}

void prxsocket::socks5_udp_socket::close(error_code &ec)
{
	reset();
	if (udp_socket_)
	{
		error_code err;
		udp_socket_->close(err);
	}
	return socket_->close(ec);
}

void prxsocket::socks5_udp_socket::async_close(null_callback &&complete_handler)
{
	reset();
	if (udp_socket_)
	{
		std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
		udp_socket_->async_close([this, callback](error_code){ socket_->async_close(std::move(*callback)); });
		return;
	}
	socket_->async_close(std::move(complete_handler));
}

void prxsocket::socks5_udp_socket::async_skip(size_t size, const std::shared_ptr<transfer_callback> &callback)
{
	if (size == 0)
	{
		(*callback)(ERR_OPERATION_FAILURE, 0);
		return;
	}
	size_t size_read = std::min(size, UDP_BUF_SIZE);
	size_t size_last = size - size_read;
	async_read(mutable_buffer(udp_recv_buf_.get(), size_read),
		[this, callback, size_last](error_code err)
	{
		if (err)
		{
			reset();
			(*callback)(err, 0);
			return;
		}
		async_skip(size_last, callback);
	});
}

error_code prxsocket::socks5_udp_socket::parse_udp(size_t udp_recv_size, endpoint &ep, mutable_buffer buffer, size_t &transferred)
{
	const byte *buf;
	error_code err = socks5_base::parse_udp(udp_recv_buf_.get(), udp_recv_size, ep, buf, transferred);
	if (err)
		return err;
	transferred = std::min(buffer.size(), transferred);
	memcpy(buffer.data(), buf, transferred);
	return 0;
}

error_code prxsocket::socks5_udp_socket::parse_udp(size_t udp_recv_size, endpoint &ep, mutable_buffer_sequence &&buffers, size_t &transferred)
{
	transferred = 0;

	const byte *buf;
	size_t buf_size;
	error_code err = socks5_base::parse_udp(udp_recv_buf_.get(), udp_recv_size, ep, buf, buf_size);
	if (err)
		return err;

	transferred = buffers.scatter(buf, buf_size);
	return 0;
}

void prxsocket::socks5_listener::open(error_code &err)
{
	if (!cur_socket_)
		cur_socket_ = std::make_unique<socks5_tcp_socket>(gen_socket_(), server_ep_, methods_);
	cur_socket_->open(err);
	if (!err)
		listening_ = false;
}

void prxsocket::socks5_listener::async_open(null_callback &&complete_handler)
{
	if (!cur_socket_)
		cur_socket_ = std::make_unique<socks5_tcp_socket>(gen_socket_(), server_ep_, methods_);
	auto callback = std::make_shared<null_callback>(std::move(complete_handler));
	cur_socket_->async_open([this, callback](error_code err)
	{
		if (!err)
			listening_ = false;
		(*callback)(err);
	});
}

void prxsocket::socks5_listener::bind(const endpoint &ep, error_code &err)
{
	err = 0;
	if (!is_open() || cur_socket_->get_auth_method() != 0x80)
	{
		err = ERR_UNSUPPORTED;
		return;
	}
	local_ep_ = ep;
}

void prxsocket::socks5_listener::async_bind(const endpoint &ep, null_callback &&complete_handler)
{
	if (!is_open() || cur_socket_->get_auth_method() != 0x80)
	{
		complete_handler(ERR_UNSUPPORTED);
		return;
	}
	local_ep_ = ep;
	complete_handler(0);
}

void prxsocket::socks5_listener::listen(error_code &err)
{
	err = 0;

	PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, req, req_holder);
	socks5::socks5_base::make_s5_header(req, cur_socket_->BIND, local_ep_);
	cur_socket_->send(const_buffer(req), std::move(req_holder), err);
	if (err)
	{
		reset();
		return;
	}
	uint8_t rep;
	err = cur_socket_->recv_s5(rep, cur_socket_->local_ep_);
	if (err)
	{
		reset();
		return;
	}
	if (rep != 0)
	{
		reset();
		err = rep;
		return;
	}

	listening_ = true;
}

void prxsocket::socks5_listener::async_listen(null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, req, req_holder);
	socks5::socks5_base::make_s5_header(req, cur_socket_->BIND, local_ep_);
	cur_socket_->async_send(const_buffer(req), std::move(req_holder),
		[this, callback](error_code err)
	{
		if (err)
		{
			reset();
			(*callback)(err);
			return;
		}
		cur_socket_->async_recv_s5([this, callback](error_code err, uint8_t rep, const endpoint &ep)
		{
			if (err)
			{
				reset();
				(*callback)(err);
				return;
			}
			if (rep != 0)
			{
				reset();
				(*callback)(rep);
				return;
			}
			cur_socket_->local_ep_ = ep;

			listening_ = true;
			(*callback)(0);
		});
	});
}

void prxsocket::socks5_listener::accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &err)
{
	socket = nullptr;
	err = ERR_OPERATION_FAILURE;

	if (!listening_)
		return;
	listening_ = false;

	uint8_t rep;
	err = cur_socket_->recv_s5(rep, cur_socket_->remote_ep_);
	if (err)
	{
		reset();
		return;
	}
	if (rep != 0)
	{
		reset();
		err = rep;
		return;
	}
	cur_socket_->state_ = cur_socket_->STATE_CONNECTED;

	std::unique_ptr<socks5_tcp_socket> ret;
	ret.swap(cur_socket_);

	error_code ec;
	open(ec);
	if (is_open())
		listen(ec);

	socket = std::move(ret);
	err = 0;
}

void prxsocket::socks5_listener::async_accept(accept_callback &&complete_handler)
{
	//TODO: support queue
	if (!listening_)
	{
		complete_handler(ERR_OPERATION_FAILURE, nullptr);
		return;
	}
	listening_ = false;
	std::shared_ptr<accept_callback> callback = std::make_shared<accept_callback>(std::move(complete_handler));

	cur_socket_->async_recv_s5([this, callback](error_code err, uint8_t rep, const endpoint &ep)
	{
		if (err)
		{
			reset();
			(*callback)(err, nullptr);
			return;
		}
		if (rep != 0)
		{
			reset();
			(*callback)(rep, nullptr);
			return;
		}
		cur_socket_->remote_ep_ = ep;
		cur_socket_->state_ = cur_socket_->STATE_CONNECTED;

		std::shared_ptr<std::unique_ptr<socks5_tcp_socket>> ret = std::make_shared<std::unique_ptr<socks5_tcp_socket>>();
		ret->swap(cur_socket_);
		async_open([this, ret, callback](error_code err)
		{
			if (!is_open())
			{
				(*callback)(0, std::move(*ret));
				return;
			}
			async_listen([ret, callback](error_code)
			{
				(*callback)(0, std::move(*ret));
			});
		});
	});
}

void prxsocket::socks5_listener::close(error_code &err)
{
	err = 0;
	if (cur_socket_)
		cur_socket_->close(err);
}

void prxsocket::socks5_listener::async_close(null_callback &&complete_handler)
{
	if (cur_socket_)
	{
		cur_socket_->async_close(std::move(complete_handler));
		return;
	}
	complete_handler(0);
}
