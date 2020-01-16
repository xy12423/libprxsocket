#include "stdafx.h"
#include "socket_socks5.h"

static endpoint udp_local_ep_zero(address(static_cast<uint32_t>(0)), 0);

void socks5_tcp_socket::open(error_code &err)
{
	err = 0;
	if (is_open())
	{
		err = WARN_ALREADY_IN_STATE;
		return;
	}
	err = open_and_auth(server_ep);
	if (!err)
		state = STATE_OPEN;
}

void socks5_tcp_socket::async_open(null_callback &&complete_handler)
{
	if (is_open())
	{
		complete_handler(WARN_ALREADY_IN_STATE);
		return;
	}
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	async_open_and_auth(server_ep,
		[this, callback](error_code err)
	{
		if (!err)
			state = STATE_OPEN;
		(*callback)(err);
	});
}

void socks5_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	err = 0;
	if (!is_open())
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}
	if (is_connected())
	{
		err = ERR_ALREADY_IN_STATE;
		return;
	}

	error_code ec;

	remote_ep = ep;
	err = send_s5(CONNECT, ep);
	if (err)
	{
		close(ec);
		return;
	}
	uint8_t rep;
	err = recv_s5(rep, local_ep);
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

	state = STATE_CONNECTED;
}

void socks5_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	if (!is_open())
	{
		complete_handler(ERR_OPERATION_FAILURE);
		return;
	}
	if (is_connected())
	{
		complete_handler(ERR_ALREADY_IN_STATE);
		return;
	}
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	remote_ep = ep;
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
			state = STATE_CONNECTED;
			local_ep = ep;
			(*callback)(0);
		});
	});
}

void socks5_tcp_socket::send(const const_buffer &buffer, size_t &transferred, error_code &err)
{
	err = 0;
	if (!is_connected())
	{
		transferred = 0;
		err = ERR_OPERATION_FAILURE;
		return;
	}
	socks5_base::send(buffer, transferred, err);
	if (err)
	{
		error_code ec;
		close(ec);
	}
}

void socks5_tcp_socket::async_send(const const_buffer &buffer, transfer_callback &&complete_handler)
{
	if (!is_connected())
	{
		complete_handler(ERR_OPERATION_FAILURE, 0);
		return;
	}
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
	err = 0;
	if (!is_connected())
	{
		transferred = 0;
		err = ERR_OPERATION_FAILURE;
		return;
	}
	socks5_base::recv(buffer, transferred, err);
	if (err)
	{
		error_code ec;
		close(ec);
	}
}

void socks5_tcp_socket::async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler)
{
	if (!is_connected())
	{
		complete_handler(ERR_OPERATION_FAILURE, 0);
		return;
	}
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

void socks5_udp_socket::local_endpoint(endpoint &ep, error_code &err)
{
	err = 0;
	if (get_auth_method() != 0x80)
	{
		err = ERR_UNSUPPORTED;
		return;
	}
	if (!is_open())
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}
	ep = udp_local_ep;
}

void socks5_udp_socket::open(error_code &err)
{
	if (is_open())
	{
		err = WARN_ALREADY_IN_STATE;
		return;
	}
	open(udp_local_ep_zero, err);
}

void socks5_udp_socket::async_open(null_callback &&complete_handler)
{
	if (is_open())
	{
		complete_handler(WARN_ALREADY_IN_STATE);
		return;
	}
	async_open(udp_local_ep_zero, std::move(complete_handler));
}

void socks5_udp_socket::bind(const endpoint &ep, error_code &err)
{
	if (get_auth_method() != 0x80 && get_auth_method() != 0xFF)
	{
		err = ERR_UNSUPPORTED;
		return;
	}
	if (is_open())
	{
		close();
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
	if (is_open())
	{
		close();
	}
	async_open(ep, std::move(complete_handler));
}

void socks5_udp_socket::open(const endpoint &ep, error_code &err)
{
	err = 0;
	if (udp_socket && !udp_socket->is_open())
	{
		udp_socket->open(err);
		if (!udp_socket->is_open())
		{
			if (!err)
				err = ERR_OPERATION_FAILURE;
			return;
		}
	}

	err = open_and_auth(server_ep);
	if (err)
		return;
	if (!ep.addr().is_any() && get_auth_method() != 0x80)
	{
		close();
		err = ERR_OPERATION_FAILURE;
		return;
	}

	err = send_s5(UDP_ASSOCIATE, ep);
	if (err)
		return;

	uint8_t rep;
	err = recv_s5(rep, udp_server_ep);
	if (err)
		return;
	if (rep != 0)
	{
		err = rep;
		return;
	}

	if (get_auth_method() == 0x80)
	{
		err = recv_s5(rep, udp_local_ep);
		if (err)
			return;
		if (rep != 0)
		{
			err = rep;
			return;
		}
	}

	state = STATE_ASSOCIATED;
	if (udp_socket)
		udp_alive();
}

void socks5_udp_socket::async_open(const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	if (udp_socket && !udp_socket->is_open())
	{
		udp_socket->async_open([this, ep, callback](error_code err)
		{
			if (!udp_socket->is_open())
			{
				(*callback)(err ? err : ERR_OPERATION_FAILURE);
				return;
			}
			async_open(ep, std::move(*callback));
		});
		return;
	}

	async_open_and_auth(server_ep,
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
		async_send_s5(UDP_ASSOCIATE, ep,
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
				udp_server_ep = ep;

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
						udp_local_ep = ep;

						state = STATE_ASSOCIATED;
						if (udp_socket)
							udp_alive();
						(*callback)(0);
					});
				}
				else
				{
					state = STATE_ASSOCIATED;
					if (udp_socket)
						udp_alive();
					(*callback)(0);
				}
			});
		});
	});
}

void socks5_udp_socket::udp_alive()
{
	async_recv(mutable_buffer(&udp_alive_buf, 1),
		[this](error_code err, size_t)
	{
		if (err)
			close();
		else
			udp_alive();
	});
}

void socks5_udp_socket::send_to(const endpoint &ep, const const_buffer &buffer, error_code &err)
{
	err = 0;
	if (!is_open())
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}

	std::string buf;
	try
	{
		buf.append(3, '\0');           //RSV && FRAG
		ep.to_socks5(buf);             //ATYP && DST
		buf.append(buffer.data(), buffer.size());	//DATA
	}
	catch (std::exception &)
	{
		err = WARN_OPERATION_FAILURE;
		return;
	}

	if (udp_socket)
	{
		udp_socket->send_to(udp_server_ep, const_buffer(buf), err);
		if (!udp_socket->is_open())
			close();
	}
	else
	{
		if (buf.size() > 0xFFFFu)
		{
			err = WARN_OPERATION_FAILURE;
			return;
		}
		size_t buf_size = buf.size();
		buf[0] = (uint8_t)(buf_size);
		buf[1] = (uint8_t)(buf_size >> 8);

		write(access_socket(), const_buffer(buf), err);
		if (err)
			close();
	}
}

void socks5_udp_socket::async_send_to(const endpoint &ep, const const_buffer &buffer, null_callback &&complete_handler)
{
	if (!is_open())
	{
		complete_handler(ERR_OPERATION_FAILURE);
		return;
	}

	std::shared_ptr<std::string> buf = std::make_shared<std::string>();
	try
	{
		buf->append(3, '\0');    //RSV && FRAG
		ep.to_socks5(*buf);      //ATYP && DST
		buf->append(buffer.data(), buffer.size());
	}
	catch (std::exception &)
	{
		complete_handler(WARN_OPERATION_FAILURE);
		return;
	}

	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	if (udp_socket)
	{
		udp_socket->async_send_to(server_ep, const_buffer(*buf),
			[this, buf, callback](error_code err)
		{
			if (!udp_socket->is_open())
			{
				async_close([err, callback](error_code) { (*callback)(err ? err : ERR_OPERATION_FAILURE); });
			}
			else
			{
				(*callback)(err);
			}
		});
	}
	else
	{
		if (buf->size() > 0xFFFFu)
		{
			(*callback)(WARN_OPERATION_FAILURE);
			return;
		}
		size_t buf_size = buf->size();
		(*buf)[0] = (uint8_t)(buf_size);
		(*buf)[1] = (uint8_t)(buf_size >> 8);

		async_write(access_socket(), const_buffer(*buf),
			[this, buf, callback](error_code err)
		{
			if (err)
				close();
			(*callback)(err);
		});
	}
}

void socks5_udp_socket::recv_from(endpoint &ep, const mutable_buffer &buffer, size_t &transferred, error_code &err)
{
	if (!is_open())
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}

	size_t udp_recv_size;
	err = 0;
	if (udp_socket)
	{
		udp_socket->recv_from(udp_recv_ep, mutable_buffer(udp_recv_buf.get(), udp_buf_size), udp_recv_size, err);
		if (!udp_socket->is_open())
		{
			close();
			if (!err)
				err = ERR_OPERATION_FAILURE;
		}
		if (err)
			return;
	}
	else
	{
		read(access_socket(), mutable_buffer(udp_recv_buf.get(), 2), err);
		if (err)
		{
			close();
			return;
		}
		uint16_t size = (uint8_t)udp_recv_buf[0] | ((uint8_t)udp_recv_buf[1] << 8u);
		if (size > udp_buf_size)
		{
			//Skip
			size -= 2;
			while (size > 0)
			{
				size_t size_read = std::min((size_t)size, udp_buf_size);
				read(access_socket(), mutable_buffer(udp_recv_buf.get(), size_read), err);
				if (err)
				{
					close();
					return;
				}
				size -= (uint16_t)size_read;
			}
			err = WARN_OPERATION_FAILURE;
			return;
		}
		read(access_socket(), mutable_buffer(udp_recv_buf.get() + 2, size - 2), err);
		if (err)
		{
			close();
			return;
		}
		udp_recv_buf[0] = udp_recv_buf[1] = 0;
		udp_recv_size = size;
	}
	
	err = parse_udp(udp_recv_size, ep, buffer, transferred);
}

void socks5_udp_socket::async_recv_from(endpoint &ep, const mutable_buffer &buffer, transfer_callback &&complete_handler)
{
	if (!is_open())
	{
		complete_handler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	if (udp_socket)
	{
		udp_socket->async_recv_from(udp_recv_ep, mutable_buffer(udp_recv_buf.get(), udp_buf_size),
			[this, &ep, buffer, callback](error_code err, size_t udp_recv_size)
		{
			if (err)
			{
				if (!udp_socket->is_open())
				{
					async_close([this, err, callback](error_code) { (*callback)(err ? err : ERR_OPERATION_FAILURE, 0); });
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
		async_read(access_socket(), mutable_buffer(udp_recv_buf.get(), 2),
			[this, &ep, buffer, callback](error_code err)
		{
			if (err)
			{
				async_close([this, err, callback](error_code) { (*callback)(err, 0); });
				return;
			}
			uint16_t size = (uint8_t)udp_recv_buf[0] | ((uint8_t)udp_recv_buf[1] << 8u);
			if (size > udp_buf_size)
			{
				async_skip(size - 2, callback);
				return;
			}
			async_read(access_socket(), mutable_buffer(udp_recv_buf.get() + 2, size - 2),
				[this, size, &ep, buffer, callback](error_code err)
			{
				if (err)
				{
					async_close([this, err, callback](error_code) { (*callback)(err, 0); });
					return;
				}
				udp_recv_buf[0] = udp_recv_buf[1] = 0;
				size_t transferred;
				err = parse_udp(size, ep, buffer, transferred);
				(*callback)(err, transferred);
			});
		});
	}
}

void socks5_udp_socket::async_skip(size_t size, const std::shared_ptr<transfer_callback> &callback)
{
	if (size == 0)
	{
		(*callback)(WARN_OPERATION_FAILURE, 0);
		return;
	}
	size_t size_read = std::min(size, udp_buf_size);
	size_t size_last = size - size_read;
	async_read(access_socket(), mutable_buffer(udp_recv_buf.get(), size_read),
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
	error_code err = socks5_base::parse_udp(udp_recv_buf.get(), udp_recv_size, ep, buf, transferred);
	if (err)
		return err;
	transferred = std::min(buffer.size(), transferred);
	memmove(buffer.access_data(), buf, transferred);
	return 0;
}

void socks5_listener::open(error_code &err)
{
	if (!cur_socket)
		cur_socket = std::make_unique<socks5_tcp_socket>(server_ep, gen_socket(), methods);
	cur_socket->open(err);
	if (!err)
		listening = false;
}

void socks5_listener::async_open(null_callback &&complete_handler)
{
	if (!cur_socket)
		cur_socket = std::make_unique<socks5_tcp_socket>(server_ep, gen_socket(), methods);
	auto callback = std::make_shared<null_callback>(std::move(complete_handler));
	cur_socket->async_open([this, callback](error_code err)
	{
		if (!err)
			listening = false;
		(*callback)(err);
	});
}

void socks5_listener::bind(const endpoint &ep, error_code &err)
{
	err = 0;
	if (!is_open() || cur_socket->get_auth_method() != 0x80)
	{
		err = ERR_UNSUPPORTED;
		return;
	}
	local_ep = ep;
}

void socks5_listener::async_bind(const endpoint &ep, null_callback &&complete_handler)
{
	if (!is_open() || cur_socket->get_auth_method() != 0x80)
	{
		complete_handler(ERR_UNSUPPORTED);
		return;
	}
	local_ep = ep;
	complete_handler(0);
}

void socks5_listener::listen(error_code &err)
{
	err = 0;
	if (!is_open())
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}
	if (listening)
	{
		err = WARN_ALREADY_IN_STATE;
		return;
	}

	err = cur_socket->send_s5(cur_socket->BIND, local_ep);
	if (err)
	{
		close();
		return;
	}
	uint8_t rep;
	err = cur_socket->recv_s5(rep, cur_socket->local_ep);
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

	listening = true;
}

void socks5_listener::async_listen(null_callback &&complete_handler)
{
	if (!cur_socket || !cur_socket->is_open())
	{
		complete_handler(ERR_OPERATION_FAILURE);
		return;
	}
	if (listening)
	{
		complete_handler(0);
		return;
	}
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	cur_socket->async_send_s5(cur_socket->BIND, local_ep,
		[this, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}
		cur_socket->async_recv_s5([this, callback](error_code err, uint8_t rep, const endpoint &ep)
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
			cur_socket->local_ep = ep;

			listening = true;
			(*callback)(0);
		});
	});
}

void socks5_listener::accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &err)
{
	socket = nullptr;
	err = ERR_OPERATION_FAILURE;

	if (!listening)
		return;
	listening = false;

	uint8_t rep;
	err = cur_socket->recv_s5(rep, cur_socket->remote_ep);
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
	cur_socket->state = cur_socket->STATE_CONNECTED;

	std::unique_ptr<socks5_tcp_socket> ret;
	ret.swap(cur_socket);

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
	if (!listening)
	{
		complete_handler(ERR_OPERATION_FAILURE, nullptr);
		return;
	}
	listening = false;
	std::shared_ptr<accept_callback> callback = std::make_shared<accept_callback>(std::move(complete_handler));

	cur_socket->async_recv_s5([this, callback](error_code err, uint8_t rep, const endpoint &ep)
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
		cur_socket->remote_ep = ep;
		cur_socket->state = cur_socket->STATE_CONNECTED;

		std::shared_ptr<std::unique_ptr<socks5_tcp_socket>> ret = std::make_shared<std::unique_ptr<socks5_tcp_socket>>();
		ret->swap(cur_socket);
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
	if (cur_socket)
		cur_socket->close(err);
}

void socks5_listener::async_close(null_callback &&complete_handler)
{
	if (cur_socket)
	{
		cur_socket->async_close(std::move(complete_handler));
		return;
	}
	complete_handler(0);
}
