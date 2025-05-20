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
using namespace prxsocket::socks5;

static const endpoint empty_endpoint;

error_code socks5_base::auth()
{
	auth_method_ = 0xFF;
	try
	{
		PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, auth_data, auth_data_holder);
		size_t available_method_count = std::min<size_t>(available_methods_.size(), 0xFFu);
		auth_data.reserve(2 + available_method_count);
		auth_data.push_back(byte{ SOCKS_VERSION });
		auth_data.push_back(byte{ static_cast<unsigned char>(available_method_count) });
		auth_data.insert(auth_data.end(), available_methods_.cbegin(), available_methods_.cbegin() + available_method_count);
		error_code err;
		socket_->send(const_buffer(auth_data), std::move(auth_data_holder), err);
		if (err)
			throw(socks5_error(err));

		byte method_chosen[2];
		read(mutable_buffer(method_chosen, sizeof(method_chosen)), err);
		if (err)
			throw(socks5_error(err));
		if (std::to_integer<unsigned int>(method_chosen[0]) != SOCKS_VERSION || std::to_integer<unsigned int>(method_chosen[1]) == 0xFF)
			throw(socks5_error(ERR_BAD_ARG_REMOTE));
		auth_method_ = std::to_integer<unsigned char>(method_chosen[1]);
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
		PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, auth_data, auth_data_holder);
		size_t available_method_count = std::min<size_t>(available_methods_.size(), 0xFFu);
		auth_data.reserve(2 + available_method_count);
		auth_data.push_back(byte{ SOCKS_VERSION });
		auth_data.push_back(byte{ static_cast<unsigned char>(available_method_count) });
		auth_data.insert(auth_data.end(), available_methods_.cbegin(), available_methods_.cbegin() + available_method_count);
		socket_->async_send(const_buffer(auth_data), std::move(auth_data_holder),
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
	std::shared_ptr<std::array<byte, 2>> method_chosen_p = std::make_shared<std::array<byte, 2>>();
	async_read(mutable_buffer(method_chosen_p->data(), 2),
		[this, method_chosen_p, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			std::array<byte, 2> &method_chosen = *method_chosen_p;
			if (std::to_integer<unsigned int>(method_chosen[0]) != SOCKS_VERSION || std::to_integer<unsigned int>(method_chosen[1]) == 0xFF)
				throw(socks5_error(ERR_BAD_ARG_REMOTE));
			auth_method_ = std::to_integer<unsigned char>(method_chosen[1]);
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

error_code socks5_base::open_and_auth(const endpoint &server_ep)
{
	error_code err;

	socket_->open(err);
	if (!socket_->is_open())
		return err ? err : ERR_OPERATION_FAILURE;

	socket_->connect(server_ep, err);
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
	socket_->async_open([this, server_ep, callback](error_code err)
	{
		if (!socket_->is_open())
		{
			(*callback)(err ? err : ERR_OPERATION_FAILURE);
			return;
		}
		socket_->async_connect(server_ep, [this, callback](error_code err)
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

void socks5_base::make_s5_header(std::vector<byte> &req, uint8_t type, const endpoint &ep)
{
	req.push_back(byte{ SOCKS_VERSION });  //VER
	req.push_back(byte{ type });           //CMD / REP
	req.push_back(byte{ 0 });              //RSV
	switch (ep.addr().type())              //ATYP && DST.ADDR
	{
	case address::addr_type::V4:
	{
		req.push_back(byte{ 1 });
		const byte *data = ep.addr().v4().data();
		req.insert(req.end(), data, data + address_v4::ADDR_SIZE);
		break;
	}
	case address::addr_type::STR:
	{
		req.push_back(byte{ 3 });
		const std::string &data = ep.addr().str().data();
		byte data_append_size = byte{ static_cast<unsigned char>(data.size()) };
		req.push_back(data_append_size);
		req.insert(req.end(), (const byte *)data.data(), (const byte *)(data.data() + std::to_integer<ptrdiff_t>(data_append_size)));
		break;
	}
	case address::addr_type::V6:
	{
		req.push_back(byte{ 4 });
		const byte *data = ep.addr().v6().data();
		req.insert(req.end(), data, data + address_v6::ADDR_SIZE);
		break;
	}
	}
	req.insert(req.end(), { byte{ static_cast<unsigned char>(ep.port() >> 8) }, byte{ static_cast<unsigned char>(ep.port() & 0xFF) } });
}

namespace
{
	struct recv_s5_state
	{
		byte resp_head[263];
		size_t resp_size_read = 0;

		uint8_t resp_code;
		endpoint resp_ep;
	};

	bool parse_s5(recv_s5_state &state, const_buffer &recv_buffer)
	{
		constexpr size_t resp_size_min = 7;
		if (state.resp_size_read < resp_size_min)
		{
			state.resp_size_read += const_buffer::consume(state.resp_head + state.resp_size_read, resp_size_min - state.resp_size_read, recv_buffer);
			if (state.resp_size_read < resp_size_min)
				return false;
		}

		size_t size_needed;
		unsigned int atyp = std::to_integer<unsigned int>(state.resp_head[3]);
		switch (atyp)
		{
		case 1:
			size_needed = 10;
			break;
		case 3:
			size_needed = resp_size_min + std::to_integer<unsigned char>(state.resp_head[4]);
			break;
		case 4:
			size_needed = 22;
			break;
		default:
			throw std::invalid_argument("Invalid ATYP");
		}
		if (state.resp_size_read < size_needed)
		{
			state.resp_size_read += const_buffer::consume(state.resp_head + state.resp_size_read, size_needed - state.resp_size_read, recv_buffer);
			if (state.resp_size_read < size_needed)
				return false;
		}

		state.resp_code = std::to_integer<unsigned char>(state.resp_head[1]);
		switch (atyp)
		{
		case 1:
			state.resp_ep = endpoint(address_v4(state.resp_head + 4), static_cast<port_type>((std::to_integer<unsigned int>(state.resp_head[8]) << 8) | std::to_integer<unsigned int>(state.resp_head[9])));
			break;
		case 3:
		{
			uint8_t addr_len = std::to_integer<uint8_t>(state.resp_head[4]);
			size_t port_offset = (resp_size_min - 2) + addr_len;
			state.resp_ep = endpoint(address_str((const char *)(state.resp_head + 5), addr_len), static_cast<port_type>((std::to_integer<unsigned int>(state.resp_head[port_offset]) << 8) | std::to_integer<unsigned int>(state.resp_head[port_offset + 1])));
			break;
		}
		case 4:
			state.resp_ep = endpoint(address_v6(state.resp_head + 4), static_cast<port_type>((std::to_integer<unsigned int>(state.resp_head[20]) << 8) | std::to_integer<unsigned int>(state.resp_head[21])));
			break;
		}
		return true;
	}
}

error_code socks5_base::recv_s5(uint8_t &resp, endpoint &result)
{
	recv_s5_state state;

	error_code_or_op_result ec_or_result{};
	socket_->recv_until(socket_recv_buf_, [this, &state](const_buffer &buffer_recv)
	{
		try
		{
			bool header_parsed = parse_s5(state, buffer_recv);
			return error_code_or_op_result{ header_parsed ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
		}
		catch (const std::exception &)
		{
			return error_code_or_op_result{ OPRESULT_ERROR };
		}
	}, ec_or_result);
	if (ec_or_result.code == OPRESULT_ERROR) [[unlikely]]
	{
		close();
		return ERR_OPERATION_FAILURE;
	}
	if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
	{
		close();
		return ec_or_result.code != 0 ? ec_or_result.code : ERR_OPERATION_FAILURE;
	}
	resp = state.resp_code;
	result = state.resp_ep;
	return 0;
}

void socks5_base::async_recv_s5(socksreq_callback &&complete_handler)
{
	std::shared_ptr<std::pair<recv_s5_state, socksreq_callback>> state_callback = std::make_shared<std::pair<recv_s5_state, socksreq_callback>>(recv_s5_state(), std::move(complete_handler));
	socket_->async_recv_until(std::move(socket_recv_buf_), [this, state_callback](const_buffer &buffer_recv)
	{
		try
		{
			bool header_parsed = parse_s5(state_callback->first, buffer_recv);
			return error_code_or_op_result{ header_parsed ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
		}
		catch (const std::exception &)
		{
			return error_code_or_op_result{ OPRESULT_ERROR };
		}
	}, [this, state_callback](error_code_or_op_result ec_or_result, buffer_with_data_store &&leftover)
	{
		if (ec_or_result.code == OPRESULT_ERROR) [[unlikely]]
		{
			close();
			state_callback->second(ERR_OPERATION_FAILURE, -1, empty_endpoint);
			return;
		}
		if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
		{
			close();
			state_callback->second(ec_or_result.code != 0 ? ec_or_result.code : ERR_OPERATION_FAILURE, -1, empty_endpoint);
			return;
		}
		socket_recv_buf_ = std::move(leftover);
		recv_s5_state &state = state_callback->first;
		state_callback->second(0, state.resp_code, state.resp_ep);
	});
}

error_code socks5_base::parse_udp(const byte *udp_recv_buf, size_t udp_recv_size, endpoint &ep, const byte *&buffer, size_t &transferred)
{
	try
	{
		transferred = 0;

		for (int i = 0; i < 3; i++)
			if (std::to_integer<unsigned char>(udp_recv_buf[i]) != 0)
				return ERR_OPERATION_FAILURE;

		size_t header_size = 0;
		switch (static_cast<unsigned char>(udp_recv_buf[3]))
		{
		case 1:
			if (udp_recv_size < 10)
				return ERR_OPERATION_FAILURE;
			header_size = 10;
			ep = endpoint(address_v4(udp_recv_buf + 4), static_cast<port_type>((std::to_integer<unsigned int>(udp_recv_buf[8]) << 8) | std::to_integer<unsigned int>(udp_recv_buf[9])));
			break;
		case 3:
		{
			if (udp_recv_size < 7)
				return ERR_OPERATION_FAILURE;
			uint8_t addr_len = std::to_integer<uint8_t>(udp_recv_buf[4]);
			if (udp_recv_size < static_cast<size_t>(7) + addr_len)
				return ERR_OPERATION_FAILURE;
			size_t port_offset = static_cast<size_t>(5) + addr_len;
			ep = endpoint(address_str((const char *)(udp_recv_buf + 5), addr_len), static_cast<port_type>((std::to_integer<unsigned int>(udp_recv_buf[port_offset]) << 8) | std::to_integer<unsigned int>(udp_recv_buf[port_offset + 1])));
			header_size = static_cast<size_t>(7) + addr_len;
			break;
		}
		case 4:
			if (udp_recv_size < 22)
				return ERR_OPERATION_FAILURE;
			header_size = 22;
			ep = endpoint(address_v6(udp_recv_buf + 4), static_cast<port_type>((std::to_integer<unsigned int>(udp_recv_buf[20]) << 8) | std::to_integer<unsigned int>(udp_recv_buf[21])));
			break;
		}
		if (header_size == 0)
			return ERR_OPERATION_FAILURE;

		buffer = udp_recv_buf + header_size;
		transferred = udp_recv_size - header_size;
	}
	catch (const std::exception &)
	{
		return ERR_OPERATION_FAILURE;
	}
	return 0;
}

void socks5_base::read(mutable_buffer buffer, error_code &ec)
{
	size_t size_read = 0;
	error_code_or_op_result ec_or_result{};
	socket_->recv_until(socket_recv_buf_, [buffer, &size_read](const_buffer &data)
	{
		size_t size_copy = std::min(buffer.size() - size_read, data.size());
		memcpy(buffer.data() + size_read, data.data(), size_copy);
		data = data.after_consume(size_copy);
		size_read += size_copy;
		return error_code_or_op_result{ size_read >= buffer.size() ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
	}, ec_or_result);
	if (ec_or_result.code == OPRESULT_COMPLETED)
		ec = 0;
	else if (ec_or_result.code != 0)
		ec = ec_or_result.code;
	else
		ec = ERR_OPERATION_FAILURE;
}

void socks5_base::async_read(mutable_buffer buffer, null_callback &&complete_handler)
{
	std::shared_ptr<std::pair<size_t, null_callback>> state = std::make_shared<std::pair<size_t, null_callback>>(0, std::move(complete_handler));
	socket_->async_recv_until(std::move(socket_recv_buf_), [buffer, state](const_buffer &data)
	{
		size_t &size_read = state->first;
		size_t size_copy = std::min(buffer.size() - size_read, data.size());
		memcpy(buffer.data() + size_read, data.data(), size_copy);
		data = data.after_consume(size_copy);
		size_read += size_copy;
		return error_code_or_op_result{ size_read >= buffer.size() ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
	}, [this, state](error_code_or_op_result ec_or_result, buffer_with_data_store &&leftover)
	{
		null_callback &handler = state->second;
		if (ec_or_result.code == OPRESULT_COMPLETED)
			handler(0);
		else if (ec_or_result.code != 0)
			handler(ec_or_result.code);
		else
			handler(ERR_OPERATION_FAILURE);
	});
}
