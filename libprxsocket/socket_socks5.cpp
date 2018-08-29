#include "stdafx.h"
#include "socket_socks5.h"

static endpoint udp_local_ep_zero(address(static_cast<uint32_t>(0)), 0);

err_type socks5_tcp_socket::open()
{
	if (state >= STATE_OPEN)
		return WARN_ALREADY_IN_STATE;
	err_type err = open_and_auth(server_ep);
	if (!err)
		state = STATE_OPEN;
	return err;
}

void socks5_tcp_socket::async_open(null_callback&& complete_handler)
{
	if (state >= STATE_OPEN)
	{
		complete_handler(WARN_ALREADY_IN_STATE);
		return;
	}
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	async_open_and_auth(server_ep, [this, callback](err_type err) {
		if (!err)
			state = STATE_OPEN;
		(*callback)(err);
	});
}

err_type socks5_tcp_socket::connect(const endpoint& ep)
{
	if (state != STATE_OPEN)
		return ERR_OPERATION_FAILURE;

	remote_ep = ep;
	err_type err = send_s5(CONNECT, ep);
	if (err)
	{
		close();
		return err;
	}
	uint8_t rep;
	err = recv_s5(rep, local_ep);
	if (err)
	{
		close();
		return err;
	}
	if (rep != 0)
	{
		close();
		return err;
	}
	state = STATE_CONNECTED;
	return 0;
}

void socks5_tcp_socket::async_connect(const endpoint& ep, null_callback&& complete_handler)
{
	if (state != STATE_OPEN)
	{
		complete_handler(ERR_OPERATION_FAILURE);
		return;
	}
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	remote_ep = ep;
	async_send_s5(CONNECT, ep, [this, callback](err_type err) {
		if (err)
		{
			async_close([callback, err](err_type) { (*callback)(err); });
			return;
		}
		async_recv_s5([this, callback](err_type err, uint8_t rep, const endpoint& ep) {
			if (err)
			{
				async_close([callback, err](err_type) { (*callback)(err); });
				return;
			}
			if (rep != 0)
			{
				async_close([callback, rep](err_type) { (*callback)(rep); });
				return;
			}
			state = STATE_CONNECTED;
			local_ep = ep;
			(*callback)(0);
		});
	});
}

err_type socks5_tcp_socket::send(const const_buffer& buffer, size_t& transferred)
{
	if (state < STATE_CONNECTED)
	{
		transferred = 0;
		return ERR_OPERATION_FAILURE;
	}
	err_type err = socks5_base::send(buffer, transferred);
	if (err)
		close();
	return err;
}

void socks5_tcp_socket::async_send(const const_buffer& buffer, transfer_callback&& complete_handler)
{
	if (state < STATE_CONNECTED)
	{
		complete_handler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socks5_base::async_send(buffer, [this, callback](err_type err, size_t transferred) {
		if (err)
			async_close([callback, err, transferred](err_type) { (*callback)(err, transferred); });
		else
			(*callback)(0, transferred);
	});
}

err_type socks5_tcp_socket::recv(const mutable_buffer& buffer, size_t& transferred)
{
	if (state < STATE_CONNECTED)
	{
		transferred = 0;
		return ERR_OPERATION_FAILURE;
	}
	err_type err = socks5_base::recv(buffer, transferred);
	if (err)
		close();
	return err;
}

void socks5_tcp_socket::async_recv(const mutable_buffer& buffer, transfer_callback&& complete_handler)
{
	if (state < STATE_CONNECTED)
	{
		complete_handler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socks5_base::async_recv(buffer, [this, callback](err_type err, size_t transferred) {
		if (err)
			async_close([callback, err, transferred](err_type) { (*callback)(err, transferred); });
		else
			(*callback)(0, transferred);
	});
}

err_type socks5_udp_socket::local_endpoint(endpoint & ep)
{
	if (get_auth_method() != 0x80)
		return ERR_UNSUPPORTED;
	if (state < STATE_ASSOCIATED)
		return ERR_OPERATION_FAILURE;
	ep = udp_local_ep;
	return 0;
}

err_type socks5_udp_socket::open()
{
	if (state >= STATE_ASSOCIATED)
		return WARN_ALREADY_IN_STATE;
	return open(udp_local_ep_zero);
}

void socks5_udp_socket::async_open(null_callback&& complete_handler)
{
	if (state >= STATE_ASSOCIATED)
	{
		complete_handler(WARN_ALREADY_IN_STATE);
		return;
	}
	async_open(udp_local_ep_zero, std::move(complete_handler));
}

err_type socks5_udp_socket::bind(const endpoint& ep)
{
	if (get_auth_method() != 0x80 && get_auth_method() != 0xFF)
		return ERR_UNSUPPORTED;
	if (state >= STATE_ASSOCIATED)
	{
		socks5_base::close();
		state = STATE_INIT;
	}
	return open(ep);
}

void socks5_udp_socket::async_bind(const endpoint& ep, null_callback&& complete_handler)
{
	if (get_auth_method() != 0x80 && get_auth_method() != 0xFF)
	{
		complete_handler(ERR_UNSUPPORTED);
		return;
	}
	if (state >= STATE_ASSOCIATED)
	{
		socks5_base::close();
		state = STATE_INIT;
	}
	async_open(ep, std::move(complete_handler));
}

err_type socks5_udp_socket::open(const endpoint& ep)
{
	err_type err = 0;
	if (udp_socket && !udp_socket->is_open())
	{
		err = udp_socket->open();
		if (err > 0)
			return err;
	}

	err = open_and_auth(server_ep);
	if (err)
		return err;
	if (get_auth_method() != 0x80 && !ep.get_addr().is_any())
	{
		close();
		return ERR_OPERATION_FAILURE;
	}

	err = send_s5(UDP_ASSOCIATE, ep);
	if (err)
		return err;

	uint8_t rep;
	err = recv_s5(rep, udp_server_ep);
	if (err)
		return err;
	if (rep != 0)
		return rep;

	if (get_auth_method() == 0x80)
	{
		err = recv_s5(rep, udp_local_ep);
		if (err)
			return err;
		if (rep != 0)
			return rep;
	}

	state = STATE_ASSOCIATED;
	if (udp_socket)
		udp_alive();
	return 0;
}

void socks5_udp_socket::async_open(const endpoint& ep, null_callback&& complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	if (udp_socket && !udp_socket->is_open())
	{
		udp_socket->async_open([this, ep, callback](err_type err) {
			if (err > 0)
			{
				(*callback)(err);
				return;
			}
			async_open(ep, std::move(*callback));
		});
		return;
	}

	async_open_and_auth(server_ep, [this, ep, callback](err_type err) {
		if (err)
		{
			(*callback)(err);
			return;
		}
		if (get_auth_method() != 0x80 && !ep.get_addr().is_any())
		{
			async_close([callback](err_type) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}
		async_send_s5(UDP_ASSOCIATE, ep, [this, callback](err_type err) {
			if (err)
			{
				(*callback)(err);
				return;
			}
			async_recv_s5([this, callback](err_type err, uint8_t rep, const endpoint& ep) {
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
					async_recv_s5([this, callback](err_type err, uint8_t rep, const endpoint& ep) {
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
	async_recv(mutable_buffer(&udp_alive_buf, 1), [this](err_type err, size_t) {
		if (err)
			close();
		else
			udp_alive();
	});
}

err_type socks5_udp_socket::send_to(const endpoint& ep, const const_buffer& buffer)
{
	if (state < STATE_ASSOCIATED)
		return ERR_OPERATION_FAILURE;

	std::string buf;
	try
	{
		buf.append(3, '\0');               //RSV && FRAG
		ep.get_addr().to_socks5(buf);      //ATYP && DST.ADDR
		buf.push_back(ep.get_port() >> 8); //DST.PORT
		buf.push_back(ep.get_port() & 0xFF);
		buf.append(buffer.get_data(), buffer.get_size());	//DATA
	}
	catch (std::exception &)
	{
		return WARN_OPERATION_FAILURE;
	}

	err_type err = 0;
	if (udp_socket)
	{
		err = udp_socket->send_to(udp_server_ep, const_buffer(buf));
		if (err > 0 || !udp_socket->is_open())
		{
			close();
			if (err <= 0)
				err = ERR_OPERATION_FAILURE;
		}
	}
	else
	{
		if (buf.size() > 0xFFFFu)
			return WARN_OPERATION_FAILURE;
		size_t buf_size = buf.size();
		buf[0] = (uint8_t)(buf_size);
		buf[1] = (uint8_t)(buf_size >> 8);

		err = write(access_socket(), const_buffer(buf));
		if (err)
			close();
	}

	return err;
}

void socks5_udp_socket::async_send_to(const endpoint& ep, const const_buffer& buffer, null_callback&& complete_handler)
{
	if (state < STATE_ASSOCIATED)
	{
		complete_handler(ERR_OPERATION_FAILURE);
		return;
	}

	std::shared_ptr<std::string> buf = std::make_shared<std::string>();
	try
	{
		buf->append(3, '\0');               //RSV && FRAG
		ep.get_addr().to_socks5(*buf);      //ATYP && DST.ADDR
		buf->push_back(ep.get_port() >> 8); //DST.PORT
		buf->push_back(ep.get_port() & 0xFF);
		buf->append(buffer.get_data(), buffer.get_size());
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
			[this, buf, callback](err_type err)
		{
			if (err > 0 || !udp_socket->is_open())
			{
				async_close([err, callback](err_type) { (*callback)(err <= 0 ? ERR_OPERATION_FAILURE : err); });
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
			[this, buf, callback](err_type err)
		{
			if (err)
				close();
			(*callback)(err);
		});
	}
}

err_type socks5_udp_socket::recv_from(endpoint& ep, const mutable_buffer& buffer, size_t& transferred)
{
	if (state < STATE_ASSOCIATED)
		return ERR_OPERATION_FAILURE;

	size_t udp_recv_size;
	err_type err = 0;
	if (udp_socket)
	{
		err = udp_socket->recv_from(udp_recv_ep, mutable_buffer(udp_recv_buf.get(), udp_buf_size), udp_recv_size);
		if (err > 0 || !udp_socket->is_open())
		{
			close();
			if (err <= 0)
				err = ERR_OPERATION_FAILURE;
		}
		if (err)
			return err;
	}
	else
	{
		err = read(access_socket(), mutable_buffer(udp_recv_buf.get(), 2));
		if (err)
		{
			close();
			return err;
		}
		uint16_t size = (uint8_t)udp_recv_buf[0] | ((uint8_t)udp_recv_buf[1] << 8u);
		if (size > udp_buf_size)
		{
			while (size > 0)
			{
				size_t size_read = std::min((size_t)size, udp_buf_size);
				err = read(access_socket(), mutable_buffer(udp_recv_buf.get(), size_read));
				if (err)
				{
					close();
					return err;
				}
				size -= (uint16_t)size_read;
			}
			return WARN_OPERATION_FAILURE;
		}
		err = read(access_socket(), mutable_buffer(udp_recv_buf.get() + 2, size - 2));
		if (err)
		{
			close();
			return err;
		}
		udp_recv_buf[0] = udp_recv_buf[1] = 0;
		udp_recv_size = size;
	}
	
	return parse_udp(udp_recv_size, ep, buffer, transferred);
}

void socks5_udp_socket::async_recv_from(endpoint& ep, const mutable_buffer& buffer, transfer_callback&& complete_handler)
{
	if (state < STATE_ASSOCIATED)
	{
		complete_handler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	if (udp_socket)
	{
		udp_socket->async_recv_from(udp_recv_ep, mutable_buffer(udp_recv_buf.get(), udp_buf_size),
			[this, &ep, buffer, callback](err_type err, size_t udp_recv_size)
		{
			if (err)
			{
				if (err > 0 || !udp_socket->is_open())
				{
					async_close([this, err, callback](err_type) { (*callback)(err < 0 ? ERR_OPERATION_FAILURE : err, 0); });
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
			[this, &ep, buffer, callback](err_type err)
		{
			if (err)
			{
				close();
				(*callback)(err, 0);
				return;
			}
			uint16_t size = (uint8_t)udp_recv_buf[0] | ((uint8_t)udp_recv_buf[1] << 8u);
			if (size > udp_buf_size)
			{
				async_skip(size, callback);
				return;
			}
			async_read(access_socket(), mutable_buffer(udp_recv_buf.get() + 2, size - 2),
				[this, size, &ep, buffer, callback](err_type err)
			{
				if (err)
				{
					close();
					(*callback)(err, 0);
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

void socks5_udp_socket::async_skip(size_t size, const std::shared_ptr<transfer_callback>& callback)
{
	if (size == 0)
	{
		(*callback)(WARN_OPERATION_FAILURE, 0);
		return;
	}
	size_t size_read = std::min((size_t)size, udp_buf_size);
	size_t size_last = size - size_read;
	async_read(access_socket(), mutable_buffer(udp_recv_buf.get(), size_read),
		[this, callback, size_last](err_type err)
	{
		if (err)
		{
			(*callback)(err, 0);
			return;
		}
		async_skip(size_last, callback);
	});
}

err_type socks5_udp_socket::parse_udp(size_t udp_recv_size, endpoint& ep, const mutable_buffer& buffer, size_t& transferred)
{
	const char *buf;
	err_type err = socks5_base::parse_udp(udp_recv_buf.get(), udp_recv_size, ep, buf, transferred);
	if (err)
		return err;
	transferred = std::min(buffer.get_size(), transferred);
	memmove(buffer.access_data(), buf, transferred);
	return 0;
}

err_type socks5_listener::open()
{
	if (!cur_socket)
		cur_socket = std::make_unique<socks5_tcp_socket>(server_ep, std::unique_ptr<prx_tcp_socket_base>(gen_socket()), methods);
	return cur_socket->open();
}

void socks5_listener::async_open(null_callback&& complete_handler)
{
	if (!cur_socket)
		cur_socket = std::make_unique<socks5_tcp_socket>(server_ep, std::unique_ptr<prx_tcp_socket_base>(gen_socket()), methods);
	cur_socket->async_open(std::move(complete_handler));
}

err_type socks5_listener::bind(const endpoint& ep)
{
	if (!cur_socket || cur_socket->get_auth_method() != 0x80)
		return ERR_UNSUPPORTED;
	local_ep = ep;
	return 0;
}

void socks5_listener::async_bind(const endpoint& ep, null_callback&& complete_handler)
{
	if (!cur_socket || cur_socket->get_auth_method() != 0x80)
	{
		complete_handler(ERR_UNSUPPORTED);
		return;
	}
	local_ep = ep;
	complete_handler(0);
}

prx_tcp_socket_base* socks5_listener::accept()
{
	if (!cur_socket || !cur_socket->is_open())
		return nullptr;

	err_type err = cur_socket->send_s5(cur_socket->BIND, local_ep);
	if (err)
	{
		close();
		return nullptr;
	}
	uint8_t rep;
	err = cur_socket->recv_s5(rep, cur_socket->local_ep);
	if (err)
	{
		close();
		return nullptr;
	}
	if (rep != 0)
	{
		close();
		return nullptr;
	}

	err = cur_socket->recv_s5(rep, cur_socket->remote_ep);
	if (err)
	{
		close();
		return nullptr;
	}
	if (rep != 0)
	{
		close();
		return nullptr;
	}
	cur_socket->state = cur_socket->STATE_CONNECTED;

	std::unique_ptr<socks5_tcp_socket> ret;
	ret.swap(cur_socket);
	open();
	return ret.release();
}

void socks5_listener::async_accept(accept_callback&& complete_handler)
{
	if (!cur_socket || !cur_socket->is_open())
	{
		complete_handler(ERR_OPERATION_FAILURE, nullptr);
		return;
	}
	std::shared_ptr<accept_callback> callback = std::make_shared<accept_callback>(std::move(complete_handler));

	cur_socket->async_send_s5(cur_socket->BIND, local_ep, [this, callback](err_type err) {
		if (err)
		{
			async_close([callback, err](err_type) { (*callback)(err, nullptr); });
			return;
		}
		cur_socket->async_recv_s5([this, callback](err_type err, uint8_t rep, const endpoint& ep) {
			if (err)
			{
				async_close([callback, err](err_type) { (*callback)(err, nullptr); });
				return;
			}
			if (rep != 0)
			{
				async_close([callback, rep](err_type) { (*callback)(rep, nullptr); });
				return;
			}
			cur_socket->local_ep = ep;
			cur_socket->async_recv_s5([this, callback](err_type err, uint8_t rep, const endpoint& ep) {
				if (err)
				{
					async_close([callback, err](err_type) { (*callback)(err, nullptr); });
					return;
				}
				else if (rep != 0)
				{
					async_close([callback, rep](err_type) { (*callback)(rep, nullptr); });
					return;
				}
				cur_socket->remote_ep = ep;
				cur_socket->state = cur_socket->STATE_CONNECTED;

				std::shared_ptr<std::unique_ptr<socks5_tcp_socket>> ret = std::make_shared<std::unique_ptr<socks5_tcp_socket>>();
				ret->swap(cur_socket);
				async_open([ret, callback](err_type) { (*callback)(0, ret->release()); });
			});
		});
	});
}

err_type socks5_listener::close()
{
	if (cur_socket)
		return cur_socket->close();
	return 0;
}

void socks5_listener::async_close(null_callback&& complete_handler)
{
	if (cur_socket)
	{
		cur_socket->async_close(std::move(complete_handler));
		return;
	}
	complete_handler(0);
}
