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

void socks5_tcp_socket::open(error_code &err)
{
	state_ = STATE_INIT;
	err = open_and_auth(server_ep_);
	if (!err)
		state_ = STATE_OPEN;
}

void socks5_tcp_socket::async_open(null_callback &&complete_handler)
{
	state_ = STATE_INIT;
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	async_open_and_auth(server_ep_,
		[this, callback](error_code err)
	{
		if (!err)
			state_ = STATE_OPEN;
		(*callback)(err);
	});
}

void socks5_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	err = 0;
	error_code ec;

	remote_ep_ = ep;
	err = send_s5(CONNECT, ep);
	if (err)
	{
		close(ec);
		return;
	}
	uint8_t rep;
	err = recv_s5(rep, local_ep_);
	if (err)
	{
		close(ec);
		return;
	}
	if (rep != 0)
	{
		err = rep;
		close(ec);
		return;
	}

	state_ = STATE_CONNECTED;
}

void socks5_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	remote_ep_ = ep;
	async_send_s5(CONNECT, ep,
		[this, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}
		async_recv_s5([this, callback](error_code err, uint8_t rep, const endpoint &ep)
		{
			if (err)
			{
				async_close([callback, err](error_code) { (*callback)(err); });
				return;
			}
			if (rep != 0)
			{
				async_close([callback, rep](error_code) { (*callback)(rep); });
				return;
			}
			state_ = STATE_CONNECTED;
			local_ep_ = ep;
			(*callback)(0);
		});
	});
}

void socks5_tcp_socket::send(const const_buffer &buffer, size_t &transferred, error_code &err)
{
	socks5_base::send(buffer, transferred, err);
	if (err)
	{
		error_code ec;
		close(ec);
	}
}

void socks5_tcp_socket::async_send(const const_buffer &buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socks5_base::async_send(buffer,
		[this, callback](error_code err, size_t transferred)
	{
		if (err)
			async_close([callback, err, transferred](error_code) { (*callback)(err, transferred); });
		else
			(*callback)(0, transferred);
	});
}

void socks5_tcp_socket::recv(const mutable_buffer &buffer, size_t &transferred, error_code &err)
{
	socks5_base::recv(buffer, transferred, err);
	if (err)
	{
		error_code ec;
		close(ec);
	}
}

void socks5_tcp_socket::async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socks5_base::async_recv(buffer,
		[this, callback](error_code err, size_t transferred)
	{
		if (err)
			async_close([callback, err, transferred](error_code) { (*callback)(err, transferred); });
		else
			(*callback)(0, transferred);
	});
}

void socks5_tcp_socket::read(mutable_buffer_sequence &&buffer, error_code &err)
{
	socks5_base::read(std::move(buffer), err);
	if (err)
	{
		error_code ec;
		close(ec);
	}
}

void socks5_tcp_socket::async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socks5_base::async_read(std::move(buffer),
		[this, callback](error_code err)
	{
		if (err)
			async_close([callback, err](error_code) { (*callback)(err); });
		else
			(*callback)(0);
	});
}

void socks5_tcp_socket::write(const_buffer_sequence &&buffer, error_code &err)
{
	socks5_base::write(std::move(buffer), err);
	if (err)
	{
		error_code ec;
		close(ec);
	}
}

void socks5_tcp_socket::async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socks5_base::async_write(std::move(buffer),
		[this, callback](error_code err)
	{
		if (err)
			async_close([callback, err](error_code) { (*callback)(err); });
		else
			(*callback)(0);
	});
}

void socks5_udp_socket::local_endpoint(endpoint &ep, error_code &err)
{
	err = 0;
	if (!is_open())
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}
	if (get_auth_method() != 0x80)
	{
		err = ERR_UNSUPPORTED;
		return;
	}
	ep = udp_local_ep_;
}

void socks5_udp_socket::open(error_code &err)
{
	open(udp_local_ep_zero, err);
}

void socks5_udp_socket::async_open(null_callback &&complete_handler)
{
	async_open(udp_local_ep_zero, std::move(complete_handler));
}

void socks5_udp_socket::bind(const endpoint &ep, error_code &err)
{
	if (get_auth_method() != 0x80 && get_auth_method() != 0xFF)
	{
		err = ERR_UNSUPPORTED;
		return;
	}
	open(ep, err);
}

void socks5_udp_socket::async_bind(const endpoint &ep, null_callback &&complete_handler)
{
	if (get_auth_method() != 0x80 && get_auth_method() != 0xFF)
	{
		complete_handler(ERR_UNSUPPORTED);
		return;
	}
	async_open(ep, std::move(complete_handler));
}

void socks5_udp_socket::open(const endpoint &ep, error_code &err)
{
	close();

	err = 0;
	if (udp_socket_)
	{
		udp_socket_->open(err);
		if (!udp_socket_->is_open())
		{
			if (!err)
				err = ERR_OPERATION_FAILURE;
			return;
		}
	}

	err = open_and_auth(server_ep_);
	if (err)
		return;
	if (!ep.addr().is_any() && get_auth_method() != 0x80)
	{
		close();
		err = ERR_OPERATION_FAILURE;
		return;
	}

	err = send_s5(udp_socket_ ? UDP_ASSOCIATE : UDP_ASSOCIATE_OVER_TCP, ep);
	if (err)
		return;

	uint8_t rep;
	err = recv_s5(rep, udp_server_ep_);
	if (err)
		return;
	if (rep != 0)
	{
		err = rep;
		return;
	}

	if (get_auth_method() == 0x80)
	{
		err = recv_s5(rep, udp_local_ep_);
		if (err)
			return;
		if (rep != 0)
		{
			err = rep;
			return;
		}
	}

	state_ = STATE_ASSOCIATED;
}

void socks5_udp_socket::async_open(const endpoint &ep, null_callback &&complete_handler)
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

void socks5_udp_socket::async_open_continue(const endpoint &ep, const std::shared_ptr<null_callback> &callback)
{
	async_open_and_auth(server_ep_,
		[this, ep, callback](error_code err)
	{
		if (err)
		{
			(*callback)(err);
			return;
		}
		if (get_auth_method() != 0x80 && !ep.addr().is_any())
		{
			async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}
		async_send_s5(udp_socket_ ? UDP_ASSOCIATE : UDP_ASSOCIATE_OVER_TCP, ep,
			[this, callback](error_code err)
		{
			if (err)
			{
				(*callback)(err);
				return;
			}
			async_recv_s5([this, callback](error_code err, uint8_t rep, const endpoint &ep)
			{
				if (err)
				{
					(*callback)(err);
					return;
				}
				if (rep != 0)
				{
					(*callback)(rep);
					return;
				}
				udp_server_ep_ = ep;

				if (get_auth_method() == 0x80)
				{
					async_recv_s5([this, callback](error_code err, uint8_t rep, const endpoint &ep)
					{
						if (err)
						{
							(*callback)(err);
							return;
						}
						if (rep != 0)
						{
							(*callback)(rep);
							return;
						}
						udp_local_ep_ = ep;

						state_ = STATE_ASSOCIATED;
						(*callback)(0);
					});
				}
				else
				{
					state_ = STATE_ASSOCIATED;
					(*callback)(0);
				}
			});
		});
	});
}

void socks5_udp_socket::send_to(const endpoint &ep, const const_buffer &buffer, error_code &err)
{
	return send_to(ep, const_buffer_sequence(buffer), err);
}

void socks5_udp_socket::async_send_to(const endpoint &ep, const const_buffer &buffer, null_callback &&complete_handler)
{
	return async_send_to(ep, const_buffer_sequence(buffer), std::move(complete_handler));
}

void socks5_udp_socket::recv_from(endpoint &ep, const mutable_buffer &buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t udp_recv_size;
	if (udp_socket_)
	{
		if (!socket_->is_connected())
		{
			close();
			err = ERR_OPERATION_FAILURE;
			return;
		}
		udp_socket_->recv_from(udp_recv_ep_, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE), udp_recv_size, err);
		if (err)
		{
			if (!udp_socket_->is_open())
				close();
			return;
		}
	}
	else
	{
		read(mutable_buffer(udp_recv_buf_.get(), 2), err);
		if (err)
		{
			close();
			return;
		}
		uint16_t size = (uint8_t)udp_recv_buf_[0] | ((uint8_t)udp_recv_buf_[1] << 8u);
		if (size > UDP_BUF_SIZE)
		{
			//Skip
			size -= 2;
			while (size > 0)
			{
				size_t size_read = std::min((size_t)size, UDP_BUF_SIZE);
				read(mutable_buffer(udp_recv_buf_.get(), size_read), err);
				if (err)
				{
					close();
					return;
				}
				size -= (uint16_t)size_read;
			}
			err = ERR_OPERATION_FAILURE;
			return;
		}
		read(mutable_buffer(udp_recv_buf_.get() + 2, size - 2), err);
		if (err)
		{
			close();
			return;
		}
		udp_recv_buf_[0] = udp_recv_buf_[1] = 0;
		udp_recv_size = size;
	}
	
	err = parse_udp(udp_recv_size, ep, buffer, transferred);
}

void socks5_udp_socket::async_recv_from(endpoint &ep, const mutable_buffer &buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	if (udp_socket_)
	{
		if (!socket_->is_connected())
		{
			async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE, 0); });
			return;
		}
		udp_socket_->async_recv_from(udp_recv_ep_, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE),
			[this, &ep, buffer, callback](error_code err, size_t udp_recv_size)
		{
			if (err)
			{
				if (!udp_socket_->is_open())
				{
					async_close([err, callback](error_code) { (*callback)(err, 0); });
				}
				else
				{
					(*callback)(err, 0);
				}
				return;
			}
			size_t transferred;
			err = parse_udp(udp_recv_size, ep, buffer, transferred);
			(*callback)(err, transferred);
		});
	}
	else
	{
		async_read(mutable_buffer(udp_recv_buf_.get(), 2),
			[this, &ep, buffer, callback](error_code err)
		{
			if (err)
			{
				async_close([err, callback](error_code) { (*callback)(err, 0); });
				return;
			}
			uint16_t size = (uint8_t)udp_recv_buf_[0] | ((uint8_t)udp_recv_buf_[1] << 8u);
			if (size > UDP_BUF_SIZE)
			{
				async_skip(size - 2, callback);
				return;
			}
			async_read(mutable_buffer(udp_recv_buf_.get() + 2, size - 2),
				[this, size, &ep, buffer, callback](error_code err)
			{
				if (err)
				{
					async_close([err, callback](error_code) { (*callback)(err, 0); });
					return;
				}
				udp_recv_buf_[0] = udp_recv_buf_[1] = 0;
				size_t transferred;
				err = parse_udp(size, ep, buffer, transferred);
				(*callback)(err, transferred);
			});
		});
	}
}

void socks5_udp_socket::send_to(const endpoint &ep, const_buffer_sequence &&buffers, error_code &err)
{
	err = 0;

	std::string header;
	try
	{
		header.append(3, '\0');           //RSV && FRAG
		ep.to_socks5(header);             //ATYP && DST
		buffers.push_front(const_buffer(header));
	}
	catch (const std::exception &)
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}

	if (udp_socket_)
	{
		if (!socket_->is_connected())
		{
			close();
			err = ERR_OPERATION_FAILURE;
			return;
		}
		udp_socket_->send_to(udp_server_ep_, std::move(buffers), err);
		if (err && !udp_socket_->is_open())
			close();
	}
	else
	{
		if (buffers.size_total() > 0xFFFFu)
		{
			err = ERR_OPERATION_FAILURE;
			return;
		}
		size_t buf_size = buffers.size_total();
		header[0] = (uint8_t)(buf_size);
		header[1] = (uint8_t)(buf_size >> 8);

		write(std::move(buffers), err);
		if (err)
			close();
	}
}

void socks5_udp_socket::async_send_to(const endpoint &ep, const_buffer_sequence &&buffers, null_callback &&complete_handler)
{
	std::shared_ptr<std::string> header = std::make_shared<std::string>();
	try
	{
		header->append(3, '\0');    //RSV && FRAG
		ep.to_socks5(*header);      //ATYP && DST
		buffers.push_front(const_buffer(*header));
	}
	catch (const std::exception &)
	{
		complete_handler(ERR_OPERATION_FAILURE);
		return;
	}

	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	if (udp_socket_)
	{
		if (!socket_->is_connected())
		{
			async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}
		udp_socket_->async_send_to(server_ep_, std::move(buffers),
			[this, header, callback](error_code err)
		{
			if (err && !udp_socket_->is_open())
			{
				async_close([err, callback](error_code) { (*callback)(err); });
			}
			else
			{
				(*callback)(err);
			}
		});
	}
	else
	{
		if (buffers.size_total() > 0xFFFFu)
		{
			(*callback)(ERR_OPERATION_FAILURE);
			return;
		}
		size_t buf_size = buffers.size_total();
		(*header)[0] = (uint8_t)(buf_size);
		(*header)[1] = (uint8_t)(buf_size >> 8);
		assert(buffers.front().data() == header->data());

		async_write(std::move(buffers),
			[this, header, callback](error_code err)
		{
			if (err)
			{
				async_close([err, callback](error_code) { (*callback)(err); });
				return;
			}
			(*callback)(0);
		});
	}
}

void socks5_udp_socket::recv_from(endpoint &ep, mutable_buffer_sequence &&buffers, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t udp_recv_size;
	if (udp_socket_)
	{
		if (!socket_->is_connected())
		{
			close();
			err = ERR_OPERATION_FAILURE;
			return;
		}
		udp_socket_->recv_from(udp_recv_ep_, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE), udp_recv_size, err);
		if (err)
		{
			if (!udp_socket_->is_open())
				close();
			return;
		}
	}
	else
	{
		read(mutable_buffer(udp_recv_buf_.get(), 2), err);
		if (err)
		{
			close();
			return;
		}
		uint16_t size = (uint8_t)udp_recv_buf_[0] | ((uint8_t)udp_recv_buf_[1] << 8u);
		if (size > UDP_BUF_SIZE)
		{
			//Skip
			size -= 2;
			while (size > 0)
			{
				size_t size_read = std::min((size_t)size, UDP_BUF_SIZE);
				read(mutable_buffer(udp_recv_buf_.get(), size_read), err);
				if (err)
				{
					close();
					return;
				}
				size -= (uint16_t)size_read;
			}
			err = ERR_OPERATION_FAILURE;
			return;
		}
		read(mutable_buffer(udp_recv_buf_.get() + 2, size - 2), err);
		if (err)
		{
			close();
			return;
		}
		udp_recv_buf_[0] = udp_recv_buf_[1] = 0;
		udp_recv_size = size;
	}

	err = parse_udp(udp_recv_size, ep, std::move(buffers), transferred);
}

void socks5_udp_socket::async_recv_from(endpoint &ep, mutable_buffer_sequence &&buffers, transfer_callback &&complete_handler)
{
	std::shared_ptr<mutable_buffer_sequence> buffer = std::make_shared<mutable_buffer_sequence>(std::move(buffers));
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	if (udp_socket_)
	{
		if (!socket_->is_connected())
		{
			async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE, 0); });
			return;
		}
		udp_socket_->async_recv_from(udp_recv_ep_, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE),
			[this, &ep, buffer, callback](error_code err, size_t udp_recv_size)
		{
			if (err)
			{
				if (!udp_socket_->is_open())
				{
					async_close([err, callback](error_code) { (*callback)(err, 0); });
				}
				else
				{
					(*callback)(err, 0);
				}
				return;
			}
			size_t transferred;
			err = parse_udp(udp_recv_size, ep, std::move(*buffer), transferred);
			(*callback)(err, transferred);
		});
	}
	else
	{
		async_read(mutable_buffer(udp_recv_buf_.get(), 2),
			[this, &ep, buffer, callback](error_code err)
		{
			if (err)
			{
				async_close([err, callback](error_code) { (*callback)(err, 0); });
				return;
			}
			uint16_t size = (uint8_t)udp_recv_buf_[0] | ((uint8_t)udp_recv_buf_[1] << 8u);
			if (size > UDP_BUF_SIZE)
			{
				async_skip(size - 2, callback);
				return;
			}
			async_read(mutable_buffer(udp_recv_buf_.get() + 2, size - 2),
				[this, size, &ep, buffer, callback](error_code err)
			{
				if (err)
				{
					async_close([err, callback](error_code) { (*callback)(err, 0); });
					return;
				}
				udp_recv_buf_[0] = udp_recv_buf_[1] = 0;
				size_t transferred;
				err = parse_udp(size, ep, std::move(*buffer), transferred);
				(*callback)(err, transferred);
			});
		});
	}
}

void socks5_udp_socket::close(error_code &ec)
{
	state_ = STATE_INIT;
	if (udp_socket_)
	{
		error_code err;
		udp_socket_->close(err);
	}
	return socks5_base::close(ec);
}

void socks5_udp_socket::async_close(null_callback &&complete_handler)
{
	state_ = STATE_INIT;
	if (udp_socket_)
	{
		std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
		udp_socket_->async_close([this, callback](error_code){ socks5_base::async_close(std::move(*callback)); });
		return;
	}
	socks5_base::async_close(std::move(complete_handler));
}

void socks5_udp_socket::async_skip(size_t size, const std::shared_ptr<transfer_callback> &callback)
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
			(*callback)(err, 0);
			return;
		}
		async_skip(size_last, callback);
	});
}

error_code socks5_udp_socket::parse_udp(size_t udp_recv_size, endpoint &ep, const mutable_buffer &buffer, size_t &transferred)
{
	const char *buf;
	error_code err = socks5_base::parse_udp(udp_recv_buf_.get(), udp_recv_size, ep, buf, transferred);
	if (err)
		return err;
	transferred = std::min(buffer.size(), transferred);
	memcpy(buffer.data(), buf, transferred);
	return 0;
}

error_code socks5_udp_socket::parse_udp(size_t udp_recv_size, endpoint &ep, mutable_buffer_sequence &&buffers, size_t &transferred)
{
	transferred = 0;

	const char *buf;
	size_t buf_size;
	error_code err = socks5_base::parse_udp(udp_recv_buf_.get(), udp_recv_size, ep, buf, buf_size);
	if (err)
		return err;

	transferred = buffers.scatter(buf, buf_size);
	return 0;
}

void socks5_listener::open(error_code &err)
{
	if (!cur_socket_)
		cur_socket_ = std::make_unique<socks5_tcp_socket>(gen_socket_(), server_ep_, methods_);
	cur_socket_->open(err);
	if (!err)
		listening_ = false;
}

void socks5_listener::async_open(null_callback &&complete_handler)
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

void socks5_listener::bind(const endpoint &ep, error_code &err)
{
	err = 0;
	if (!is_open() || cur_socket_->get_auth_method() != 0x80)
	{
		err = ERR_UNSUPPORTED;
		return;
	}
	local_ep_ = ep;
}

void socks5_listener::async_bind(const endpoint &ep, null_callback &&complete_handler)
{
	if (!is_open() || cur_socket_->get_auth_method() != 0x80)
	{
		complete_handler(ERR_UNSUPPORTED);
		return;
	}
	local_ep_ = ep;
	complete_handler(0);
}

void socks5_listener::listen(error_code &err)
{
	err = 0;

	err = cur_socket_->send_s5(cur_socket_->BIND, local_ep_);
	if (err)
	{
		close();
		return;
	}
	uint8_t rep;
	err = cur_socket_->recv_s5(rep, cur_socket_->local_ep_);
	if (err)
	{
		close();
		return;
	}
	if (rep != 0)
	{
		err = rep;
		close();
		return;
	}

	listening_ = true;
}

void socks5_listener::async_listen(null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	cur_socket_->async_send_s5(cur_socket_->BIND, local_ep_,
		[this, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}
		cur_socket_->async_recv_s5([this, callback](error_code err, uint8_t rep, const endpoint &ep)
		{
			if (err)
			{
				async_close([callback, err](error_code) { (*callback)(err); });
				return;
			}
			if (rep != 0)
			{
				async_close([callback, rep](error_code) { (*callback)(rep); });
				return;
			}
			cur_socket_->local_ep_ = ep;

			listening_ = true;
			(*callback)(0);
		});
	});
}

void socks5_listener::accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &err)
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
		close();
		return;
	}
	if (rep != 0)
	{
		err = rep;
		close();
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

void socks5_listener::async_accept(accept_callback &&complete_handler)
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
			async_close([callback, err](error_code) { (*callback)(err, nullptr); });
			return;
		}
		if (rep != 0)
		{
			async_close([callback, rep](error_code) { (*callback)(rep, nullptr); });
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

void socks5_listener::close(error_code &err)
{
	err = 0;
	if (cur_socket_)
		cur_socket_->close(err);
}

void socks5_listener::async_close(null_callback &&complete_handler)
{
	if (cur_socket_)
	{
		cur_socket_->async_close(std::move(complete_handler));
		return;
	}
	complete_handler(0);
}
