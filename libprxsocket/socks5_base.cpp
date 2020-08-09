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
#include "socks5_base.h"

using namespace prxsocket;
using namespace prxsocket::socks5_helper;

static const endpoint empty_endpoint;

error_code socks5_base::auth()
{
	auth_method_ = 0xFF;
	try
	{
		std::string auth_data;
		char method_chosen[2];
		error_code err;
		auth_data.reserve(2 + available_methods_.size());
		auth_data.push_back(SOCKS_VERSION);
		auth_data.push_back((uint8_t)available_methods_.size());
		auth_data.append(available_methods_);
		write(const_buffer(auth_data), err);
		if (err)
			throw(socks5_error(err));
		read(mutable_buffer(method_chosen, sizeof(method_chosen)), err);
		if (err)
			throw(socks5_error(err));
		if (method_chosen[0] != SOCKS_VERSION || method_chosen[1] == '\xFF')
			throw(socks5_error(ERR_BAD_ARG_REMOTE));
		auth_method_ = (unsigned char)method_chosen[1];
	}
	catch (const socks5_error &ex)
	{
		close();
		return ex.get_err();
	}
	catch (const std::exception &)
	{
		close();
		return ERR_OPERATION_FAILURE;
	}
	return 0;
}

void socks5_base::async_auth(null_callback &&complete_handler)
{
	auth_method_ = 0xFF;
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	try
	{
		std::shared_ptr<std::string> auth_data = std::make_shared<std::string>();
		auth_data->reserve(2 + available_methods_.size());
		auth_data->push_back(SOCKS_VERSION);
		auth_data->push_back((uint8_t)available_methods_.size());
		auth_data->append(available_methods_);
		async_write(const_buffer(*auth_data),
			[this, auth_data, callback](error_code err)
		{
			try
			{
				if (err)
					throw(socks5_error(err));
				async_auth_recv(callback);
			}
			catch (const socks5_error &ex)
			{
				close();
				(*callback)(ex.get_err());
			}
			catch (const std::exception &)
			{
				close();
				(*callback)(ERR_OPERATION_FAILURE);
			}
		});
	}
	catch (const std::exception &)
	{
		close();
		(*callback)(ERR_OPERATION_FAILURE);
	}
}

void socks5_base::async_auth_recv(const std::shared_ptr<null_callback> &callback)
{
	std::shared_ptr<std::array<char, 2>> method_chosen = std::make_shared<std::array<char, 2>>();
	async_read(mutable_buffer(method_chosen->data(), 2),
		[this, method_chosen, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			if ((*method_chosen)[0] != SOCKS_VERSION || (*method_chosen)[1] == '\xFF')
				throw(socks5_error(ERR_BAD_ARG_REMOTE));
			auth_method_ = (unsigned char)(*method_chosen)[1];
			(*callback)(0);
		}
		catch (const socks5_error &ex)
		{
			close();
			(*callback)(ex.get_err());
		}
		catch (const std::exception &)
		{
			close();
			(*callback)(ERR_OPERATION_FAILURE);
		}
	});
}

error_code socks5_base::select(sockssel_callback &&selector)
{
	auth_method_ = 0xFF;
	try
	{
		char method_avail[257];
		error_code err;
		read(mutable_buffer(method_avail, 2), err);
		if (err)
			throw(socks5_error(err));
		if (method_avail[0] != SOCKS_VERSION)
			throw(socks5_error(ERR_BAD_ARG_REMOTE));
		read(mutable_buffer(method_avail + 2, (uint8_t)method_avail[1]), err);
		if (err)
			throw(socks5_error(err));
		auth_method_ = selector((uint8_t)method_avail[1], (uint8_t*)(method_avail + 2));

		char method_selected[2];
		method_selected[0] = SOCKS_VERSION;
		method_selected[1] = auth_method_;
		write(const_buffer(method_selected, sizeof(method_selected)), err);
		if (err)
			throw(socks5_error(err));
	}
	catch (const socks5_error &ex)
	{
		close();
		return ex.get_err();
	}
	catch (const std::exception &)
	{
		close();
		return ERR_OPERATION_FAILURE;
	}
	return 0;
}

void socks5_base::async_select(sockssel_callback &&_selector, null_callback &&complete_handler)
{
	auth_method_ = 0xFF;
	std::shared_ptr<sockssel_callback> selector = std::make_shared<sockssel_callback>(std::move(_selector));
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	std::shared_ptr<std::array<char, 257>> method_avail = std::make_shared<std::array<char, 257>>();
	async_read(mutable_buffer(method_avail->data(), 2),
		[this, selector, callback, method_avail](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			if ((*method_avail)[0] != SOCKS_VERSION)
				throw(socks5_error(ERR_BAD_ARG_REMOTE));
			async_select_recv_body(selector, method_avail, callback);
		}
		catch (const socks5_error &ex)
		{
			close();
			(*callback)(ex.get_err());
		}
		catch (const std::exception &)
		{
			close();
			(*callback)(ERR_OPERATION_FAILURE);
		}
	});
}

void socks5_base::async_select_recv_body(const std::shared_ptr<sockssel_callback> &selector, const std::shared_ptr<std::array<char, 257>> &method_avail, const std::shared_ptr<null_callback> &callback)
{
	async_read(mutable_buffer(mutable_buffer(method_avail->data() + 2, (uint8_t)(*method_avail)[1])),
		[this, selector, callback, method_avail](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			auth_method_ = (*selector)((uint8_t)(*method_avail)[1], (uint8_t*)(method_avail->data() + 2));
			async_select_send(callback);
		}
		catch (const socks5_error &ex)
		{
			close();
			(*callback)(ex.get_err());
		}
		catch (const std::exception &)
		{
			close();
			(*callback)(ERR_OPERATION_FAILURE);
		}
	});
}

void socks5_base::async_select_send(const std::shared_ptr<null_callback> &callback)
{
	std::shared_ptr<std::array<char, 2>> method_selected = std::make_shared<std::array<char, 2>>();
	(*method_selected)[0] = SOCKS_VERSION;
	(*method_selected)[1] = auth_method_;
	async_write(const_buffer(method_selected->data(), method_selected->size()),
		[method_selected, callback](error_code err)
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
	if (!socket_->is_open())
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
		if (!socket_->is_open())
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
			async_auth([callback](error_code err)
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
		req.push_back(SOCKS_VERSION);  //VER
		req.push_back(type);           //CMD / REP
		req.push_back(0);              //RSV
		ep.to_socks5(req);             //ATYP && DST.ADDR
		error_code err;
		write(const_buffer(req), err);
		if (err)
			throw(socks5_error(err));
	}
	catch (const socks5_error &ex)
	{
		close();
		return ex.get_err();
	}
	catch (const std::exception &)
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
		req_data->push_back(SOCKS_VERSION);  //VER
		req_data->push_back(type);           //CMD / REP
		req_data->push_back(0);              //RSV
		ep.to_socks5(*req_data);             //ATYP && DST

		async_write(const_buffer(*req_data),
			[this, req_data, callback](error_code err)
		{
			try
			{
				if (err)
					throw(socks5_error(err));
				(*callback)(err);
			}
			catch (const socks5_error &ex)
			{
				close();
				(*callback)(ex.get_err());
			}
			catch (const std::exception &)
			{
				close();
				(*callback)(ERR_OPERATION_FAILURE);
			}
		});
	}
	catch (const std::exception &)
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
		read(mutable_buffer(resp_head, 5), err);
		if (err)
			throw(socks5_error(err));
		if (resp_head[0] != SOCKS_VERSION || resp_head[2] != 0) //VER && RSV
			throw(socks5_error(ERR_OPERATION_FAILURE));
		resp = resp_head[1];    //CMD / REP
		switch (resp_head[3])   //ATYP
		{
		case 1:
			read(mutable_buffer(resp_head + 5, address_v4::ADDR_SIZE + 1));
			result = endpoint(
				address_v4(resp_head + 4),
				((uint8_t)(resp_head[4 + address_v4::ADDR_SIZE]) << 8) | (uint8_t)(resp_head[4 + address_v4::ADDR_SIZE + 1])
			);
			break;
		case 3:
			read(mutable_buffer(resp_head + 5, resp_head[4] + 2));
			result = endpoint(
				address_str(resp_head + 5, (size_t)(uint8_t)(resp_head[4])),
				((uint8_t)(resp_head[5 + resp_head[4]]) << 8) | (uint8_t)(resp_head[5 + resp_head[4] + 1])
			);
			break;
		case 4:
			read(mutable_buffer(resp_head + 5, address_v6::ADDR_SIZE + 1));
			result = endpoint(
				address_v6(resp_head + 4),
				((uint8_t)(resp_head[4 + address_v6::ADDR_SIZE]) << 8) | (uint8_t)(resp_head[4 + address_v6::ADDR_SIZE + 1])
			);
			break;
		default:
			throw(socks5_error(ERR_UNSUPPORTED));
		}
	}
	catch (const socks5_error &ex)
	{
		close();
		return ex.get_err();
	}
	catch (const std::exception &)
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
	async_read(mutable_buffer(resp_data->data(), 5),
		[this, resp_data, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			std::array<char, 263> &resp_head = *resp_data;
			if (resp_head[0] != SOCKS_VERSION || resp_head[2] != 0) //VER && RSV
				throw(socks5_error(ERR_BAD_ARG_REMOTE));
			async_recv_s5_body(resp_data, callback);
		}
		catch (const socks5_error &ex)
		{
			close();
			(*callback)(ex.get_err(), -1, empty_endpoint);
		}
		catch (const std::exception &)
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
			bytes_last = address_v4::ADDR_SIZE + 1;
			break;
		case 3:
			bytes_last = resp_head[4] + 2;
			break;
		case 4:
			bytes_last = address_v6::ADDR_SIZE + 1;
			break;
		default:
			throw(socks5_error(ERR_UNSUPPORTED));
	}
	async_read(mutable_buffer(resp_data->data() + 5, bytes_last),
		[this, resp_data, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));

			std::array<char, 263> &resp_head = *resp_data;
			endpoint bnd;
			bnd.from_socks5(resp_head.data() + 3);
			(*callback)(0, resp_head[1], bnd);
		}
		catch (const socks5_error &ex)
		{
			close();
			(*callback)(ex.get_err(), -1, empty_endpoint);
		}
		catch (const std::exception &)
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
				return ERR_OPERATION_FAILURE;

		size_t ep_size = ep.from_socks5(udp_recv_buf + 3);
		if (ep_size == 0 || 3 + ep_size > udp_recv_size)
			return ERR_OPERATION_FAILURE;

		buffer = udp_recv_buf + 3 + ep_size;
		transferred = udp_recv_size - (3 + ep_size);
	}
	catch (const std::exception &)
	{
		return ERR_OPERATION_FAILURE;
	}
	return 0;
}
