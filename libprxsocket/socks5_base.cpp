#include "stdafx.h"
#include "socks5_base.h"

static endpoint empty_endpoint;

error_code socks5_base::auth()
{
	auth_method = 0xFF;
	try
	{
		std::string auth_data;
		char method_chosen[2];
		error_code err;
		auth_data.reserve(2 + available_methods.size());
		auth_data.push_back(socks_version);
		auth_data.push_back((uint8_t)available_methods.size());
		auth_data.append(available_methods);
		write(*socket.get(), const_buffer(auth_data), err);
		if (err)
			throw(socks5_error(err));
		read(*socket.get(), mutable_buffer(method_chosen, sizeof(method_chosen)), err);
		if (err)
			throw(socks5_error(err));
		if (method_chosen[0] != socks_version || method_chosen[1] == '\xFF')
			throw(socks5_error(ERR_BAD_ARG_REMOTE));
		auth_method = (unsigned char)method_chosen[1];
	}
	catch (socks5_error &ex)
	{
		close();
		return ex.get_err();
	}
	catch (std::exception &)
	{
		close();
		return ERR_OPERATION_FAILURE;
	}
	return 0;
}

void socks5_base::async_auth(null_callback &&complete_handler)
{
	auth_method = 0xFF;
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	try
	{
		std::shared_ptr<std::string> auth_data = std::make_shared<std::string>();
		auth_data->reserve(2 + available_methods.size());
		auth_data->push_back(socks_version);
		auth_data->push_back((uint8_t)available_methods.size());
		auth_data->append(available_methods);
		async_write(*socket.get(), const_buffer(*auth_data),
			[this, auth_data, callback](error_code err)
		{
			try
			{
				if (err)
					throw(socks5_error(err));
				async_auth_recv(callback);
			}
			catch (socks5_error &ex)
			{
				close();
				(*callback)(ex.get_err());
			}
			catch (std::exception &)
			{
				close();
				(*callback)(ERR_OPERATION_FAILURE);
			}
		});
	}
	catch (std::exception &)
	{
		close();
		(*callback)(ERR_OPERATION_FAILURE);
	}
}

void socks5_base::async_auth_recv(const std::shared_ptr<null_callback> &callback)
{
	std::shared_ptr<std::array<char, 2>> method_chosen = std::make_shared<std::array<char, 2>>();
	async_read(*socket.get(), mutable_buffer(method_chosen->data(), 2),
		[this, method_chosen, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			if ((*method_chosen)[0] != socks_version || (*method_chosen)[1] == '\xFF')
				throw(socks5_error(ERR_BAD_ARG_REMOTE));
			auth_method = (unsigned char)(*method_chosen)[1];
			(*callback)(0);
		}
		catch (socks5_error &ex)
		{
			close();
			(*callback)(ex.get_err());
		}
		catch (std::exception &)
		{
			close();
			(*callback)(ERR_OPERATION_FAILURE);
		}
	});
}

error_code socks5_base::select(sockssel_callback &&selector)
{
	auth_method = 0xFF;
	try
	{
		char method_avail[257];
		error_code err;
		read(*socket.get(), mutable_buffer(method_avail, 2), err);
		if (err)
			throw(socks5_error(err));
		if (method_avail[0] != socks_version)
			throw(socks5_error(ERR_BAD_ARG_REMOTE));
		read(*socket.get(), mutable_buffer(method_avail + 2, (uint8_t)method_avail[1]), err);
		if (err)
			throw(socks5_error(err));
		auth_method = selector((uint8_t)method_avail[1], (uint8_t*)(method_avail + 2));

		char method_selected[2];
		method_selected[0] = socks_version;
		method_selected[1] = auth_method;
		write(*socket.get(), const_buffer(method_selected, sizeof(method_selected)), err);
		if (err)
			throw(socks5_error(err));
	}
	catch (socks5_error &ex)
	{
		close();
		return ex.get_err();
	}
	catch (std::exception &)
	{
		close();
		return ERR_OPERATION_FAILURE;
	}
	return 0;
}

void socks5_base::async_select(sockssel_callback &&_selector, null_callback &&complete_handler)
{
	auth_method = 0xFF;
	std::shared_ptr<sockssel_callback> selector = std::make_shared<sockssel_callback>(std::move(_selector));
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	std::shared_ptr<std::array<char, 257>> method_avail = std::make_shared<std::array<char, 257>>();
	async_read(*socket.get(), mutable_buffer(method_avail->data(), 2),
		[this, selector, callback, method_avail](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			if ((*method_avail)[0] != socks_version)
				throw(socks5_error(ERR_BAD_ARG_REMOTE));
			async_select_recv_body(selector, method_avail, callback);
		}
		catch (socks5_error &ex)
		{
			close();
			(*callback)(ex.get_err());
		}
		catch (std::exception &)
		{
			close();
			(*callback)(ERR_OPERATION_FAILURE);
		}
	});
}

void socks5_base::async_select_recv_body(const std::shared_ptr<sockssel_callback> &selector, const std::shared_ptr<std::array<char, 257>> &method_avail, const std::shared_ptr<null_callback> &callback)
{
	async_read(*socket.get(), mutable_buffer(mutable_buffer(method_avail->data() + 2, (uint8_t)(*method_avail)[1])),
		[this, selector, callback, method_avail](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			auth_method = (*selector)((uint8_t)(*method_avail)[1], (uint8_t*)(method_avail->data() + 2));
			async_select_send(callback);
		}
		catch (socks5_error &ex)
		{
			close();
			(*callback)(ex.get_err());
		}
		catch (std::exception &)
		{
			close();
			(*callback)(ERR_OPERATION_FAILURE);
		}
	});
}

void socks5_base::async_select_send(const std::shared_ptr<null_callback> &callback)
{
	std::shared_ptr<std::array<char, 2>> method_selected = std::make_shared<std::array<char, 2>>();
	(*method_selected)[0] = socks_version;
	(*method_selected)[1] = auth_method;
	async_write(*socket.get(), const_buffer(method_selected->data(), method_selected->size()),
		[this, method_selected, callback](error_code err)
	{
		if (err)
			(*callback)(err);
		else
			(*callback)(0);
	});
}

error_code socks5_base::open_and_auth(const endpoint &server_ep)
{
	error_code err;

	open(err);
	if (!socket->is_open())
		return err ? err : ERR_OPERATION_FAILURE;

	connect(server_ep, err);
	if (err)
		return err;

	err = auth();
	if (err)
		return err;

	return 0;
}

void socks5_base::async_open_and_auth(const endpoint &server_ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	async_open([this, server_ep, callback](error_code err) {
		if (!socket->is_open())
		{
			(*callback)(err ? err : ERR_OPERATION_FAILURE);
			return;
		}
		async_connect(server_ep, [this, callback](error_code err)
		{
			if (err)
			{
				(*callback)(err);
				return;
			}
			async_auth([this, callback](error_code err)
			{
				(*callback)(err);
			});
		});
	});
}

error_code socks5_base::send_s5(uint8_t type, const endpoint &ep)
{
	try
	{
		std::string req;
		req.push_back(socks_version);  //VER
		req.push_back(type);           //CMD / REP
		req.push_back(0);              //RSV
		ep.to_socks5(req);             //ATYP && DST.ADDR
		error_code err;
		write(*socket.get(), const_buffer(req), err);
		if (err)
			throw(socks5_error(err));
	}
	catch (socks5_error &ex)
	{
		close();
		return ex.get_err();
	}
	catch (std::exception &)
	{
		close();
		return 1;
	}
	return 0;
}

void socks5_base::async_send_s5(uint8_t type, const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	try
	{
		std::shared_ptr<std::string> req_data = std::make_shared<std::string>();
		req_data->push_back(socks_version);  //VER
		req_data->push_back(type);           //CMD / REP
		req_data->push_back(0);              //RSV
		ep.to_socks5(*req_data);             //ATYP && DST

		async_write(*socket.get(), const_buffer(*req_data),
			[this, req_data, callback](error_code err)
		{
			try
			{
				if (err)
					throw(socks5_error(err));
				(*callback)(err);
			}
			catch (socks5_error &ex)
			{
				close();
				(*callback)(ex.get_err());
			}
			catch (std::exception &)
			{
				close();
				(*callback)(ERR_OPERATION_FAILURE);
			}
		});
	}
	catch (std::exception &)
	{
		close();
		(*callback)(ERR_OPERATION_FAILURE);
	}
}

error_code socks5_base::recv_s5(uint8_t &resp, endpoint &result)
{
	try
	{
		char resp_head[263];
		error_code err;
		read(*socket.get(), mutable_buffer(resp_head, 5), err);
		if (err)
			throw(socks5_error(err));
		if (resp_head[0] != socks_version || resp_head[2] != 0) //VER && RSV
			throw(socks5_error(ERR_OPERATION_FAILURE));
		resp = resp_head[1];    //CMD / REP
		switch (resp_head[3])   //ATYP
		{
		case 1:
			read(*socket.get(), mutable_buffer(resp_head + 5, address_v4::addr_size + 1));
			result = endpoint(
				address_v4(resp_head + 4),
				((uint8_t)(resp_head[4 + address_v4::addr_size]) << 8) | (uint8_t)(resp_head[4 + address_v4::addr_size + 1])
			);
			break;
		case 3:
			read(*socket.get(), mutable_buffer(resp_head + 5, resp_head[4] + 2));
			result = endpoint(
				address_str(resp_head + 5, (size_t)(uint8_t)(resp_head[4])),
				((uint8_t)(resp_head[5 + resp_head[4]]) << 8) | (uint8_t)(resp_head[5 + resp_head[4] + 1])
			);
			break;
		case 4:
			read(*socket.get(), mutable_buffer(resp_head + 5, address_v6::addr_size + 1));
			result = endpoint(
				address_v6(resp_head + 4),
				((uint8_t)(resp_head[4 + address_v6::addr_size]) << 8) | (uint8_t)(resp_head[4 + address_v6::addr_size + 1])
			);
			break;
		default:
			throw(socks5_error(ERR_UNSUPPORTED));
		}
	}
	catch (socks5_error &ex)
	{
		close();
		return ex.get_err();
	}
	catch (std::exception &)
	{
		close();
		return 1;
	}
	return 0;
}

void socks5_base::async_recv_s5(socksreq_callback &&complete_handler)
{
	std::shared_ptr<socksreq_callback> callback = std::make_shared<socksreq_callback>(complete_handler);

	std::shared_ptr<std::array<char, 263>> resp_data = std::make_shared<std::array<char, 263>>();
	async_read(*socket.get(), mutable_buffer(resp_data->data(), 5),
		[this, resp_data, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			std::array<char, 263> &resp_head = *resp_data;
			if (resp_head[0] != socks_version || resp_head[2] != 0) //VER && RSV
				throw(socks5_error(ERR_BAD_ARG_REMOTE));
			async_recv_s5_body(resp_data, callback);
		}
		catch (socks5_error &ex)
		{
			close();
			(*callback)(ex.get_err(), -1, empty_endpoint);
		}
		catch (std::exception &)
		{
			close();
			(*callback)(ERR_OPERATION_FAILURE, -1, empty_endpoint);
		}
	});
}

void socks5_base::async_recv_s5_body(const std::shared_ptr<std::array<char, 263>> &resp_data, const std::shared_ptr<socksreq_callback> &callback)
{
	std::array<char, 263> &resp_head = *resp_data;
	size_t bytes_last;
	switch (resp_head[3])	//ATYP
	{
		case 1:
			bytes_last = address_v4::addr_size + 1;
			break;
		case 3:
			bytes_last = resp_head[4] + 2;
			break;
		case 4:
			bytes_last = address_v6::addr_size + 1;
			break;
		default:
			throw(socks5_error(ERR_UNSUPPORTED));
	}
	async_read(*socket.get(), mutable_buffer(resp_data->data() + 5, bytes_last),
		[this, bytes_last, resp_data, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));

			std::array<char, 263> &resp_head = *resp_data;
			endpoint bnd;
			bnd.from_socks5(resp_data->data() + 3);
			(*callback)(0, resp_head[1], bnd);
		}
		catch (socks5_error &ex)
		{
			close();
			(*callback)(ex.get_err(), -1, empty_endpoint);
		}
		catch (std::exception &)
		{
			close();
			(*callback)(ERR_OPERATION_FAILURE, -1, empty_endpoint);
		}
	});
}

error_code socks5_base::parse_udp(const char *udp_recv_buf, size_t udp_recv_size, endpoint &ep, const char *&buffer, size_t &transferred)
{
	try
	{
		transferred = 0;

		for (int i = 0; i < 3; i++)
			if (udp_recv_buf[i] != 0)
				return WARN_OPERATION_FAILURE;

		size_t ep_size = ep.from_socks5(udp_recv_buf + 3);
		if (ep_size == 0 || 3 + ep_size >= udp_recv_size)
			return WARN_OPERATION_FAILURE;

		buffer = udp_recv_buf + 3 + ep_size;
		transferred = udp_recv_size - (3 + ep_size);
	}
	catch (std::exception &)
	{
		return WARN_OPERATION_FAILURE;
	}
	return 0;
}
