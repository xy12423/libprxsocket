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
#include "socket_http.h"

using namespace prxsocket;
using namespace prxsocket::http;

void prxsocket::http_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	socket_->connect(server_ep_, err);
	if (err)
		return;

	try
	{
		PRXSOCKET_MAKE_INPLACE_BUFFER(std::string, http_req, http_req_holder);
		std::string host = ep.to_uri_string();
		http_req.append("CONNECT ");
		http_req.append(host);
		http_req.append(" HTTP/1.1\r\nHost: ");
		http_req.append(host);
		http_req.append("\r\n\r\n");

		socket_->send(const_buffer(reinterpret_cast<const byte *>(http_req.data()), http_req.size()), std::move(http_req_holder), err);
		if (err)
		{
			reset();
			return;
		}

		recv_buf_.buffer = const_buffer();
		recv_buf_.holder.reset();
		http_header header;
		error_code_or_op_result ec_or_result;
		socket_->recv_until(recv_buf_, [this, &header](const_buffer &buffer_recv)
		{
			try
			{
				size_t size_parsed;
				bool header_parsed = header.parse(reinterpret_cast<const char *>(buffer_recv.data()), buffer_recv.size(), size_parsed);
				buffer_recv = buffer_recv.after_consume(size_parsed);
				return error_code_or_op_result{ header_parsed ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
			}
			catch (const std::exception &)
			{
				return error_code_or_op_result{ OPRESULT_ERROR };
			}
		}, ec_or_result);
		if (ec_or_result.code == OPRESULT_ERROR) [[unlikely]]
		{
			shutdown(shutdown_both, err);
			err = ERR_OPERATION_FAILURE;
			return;
		}
		if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
		{
			err = ec_or_result.code;
			if (err == 0)
				err = ERR_OPERATION_FAILURE;
			reset();
			return;
		}

		if (header.at(http_header::NAME_STATUS_CODE) != "200")
			throw(std::runtime_error("HTTP request failed"));
	}
	catch (const std::exception &)
	{
		reset();
		err = ERR_OPERATION_FAILURE;
		return;
	}

	remote_ep_ = ep;
	state_ = STATE_OK;
}

void prxsocket::http_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	remote_ep_ = ep;
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket_->async_connect(server_ep_,
		[this, callback](error_code err)
	{
		if (err)
		{
			(*callback)(err);
			return;
		}
		send_http_req(callback);
	});
}

void prxsocket::http_tcp_socket::recv(const_buffer &buffer, buffer_data_store_holder &buffer_data_holder, error_code &ec)
{
	if (recv_buf_.buffer.size() > 0) [[unlikely]]
	{
		buffer = recv_buf_.buffer;
		recv_buf_.buffer = const_buffer();
		buffer_data_holder = std::move(recv_buf_.holder);
		return;
	}
	return socket_->recv(buffer, buffer_data_holder, ec);
}

void prxsocket::http_tcp_socket::async_recv(transfer_data_callback &&complete_handler)
{
	if (recv_buf_.buffer.size() > 0) [[unlikely]]
	{
		const_buffer buffer = recv_buf_.buffer;
		recv_buf_.buffer = const_buffer();
		complete_handler(0, buffer, buffer_data_store_holder(std::move(recv_buf_.holder)));
		return;
	}
	return socket_->async_recv(std::move(complete_handler));
}

void prxsocket::http_tcp_socket::send_http_req(const std::shared_ptr<null_callback> &callback)
{
	PRXSOCKET_MAKE_INPLACE_BUFFER(std::string, http_req, http_req_holder);
	try
	{
		std::string host = remote_ep_.to_uri_string();
		http_req.append("CONNECT ");
		http_req.append(host);
		http_req.append(" HTTP/1.1\r\nHost: ");
		http_req.append(host);
		http_req.append("\r\n\r\n");
	}
	catch (const std::exception &)
	{
		reset();
		(*callback)(ERR_OPERATION_FAILURE);
		return;
	}

	socket_->async_send(const_buffer(reinterpret_cast<const byte *>(http_req.data()), http_req.size()), std::move(http_req_holder),
		[this, http_req, callback](error_code err)
	{
		if (err)
		{
			reset();
			(*callback)(err);
			return;
		}
		recv_buf_.buffer = const_buffer();
		recv_buf_.holder.reset();
		recv_http_resp(callback, std::make_shared<http_header>());
	});
}

void prxsocket::http_tcp_socket::recv_http_resp(const std::shared_ptr<null_callback> &callback, const std::shared_ptr<http_header> &header)
{
	socket_->async_recv_until(std::move(recv_buf_), [this, header](const_buffer &buffer_recv)
	{
		try
		{
			size_t size_parsed;
			bool header_parsed = header->parse(reinterpret_cast<const char *>(buffer_recv.data()), buffer_recv.size(), size_parsed);
			buffer_recv = buffer_recv.after_consume(size_parsed);
			return error_code_or_op_result{ header_parsed ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
		}
		catch (const std::exception &)
		{
			return error_code_or_op_result{ OPRESULT_ERROR };
		}
	}, [this, callback, header](error_code_or_op_result ec_or_result, buffer_with_data_store &&leftover)
	{
		if (ec_or_result.code == OPRESULT_ERROR) [[unlikely]]
		{
			async_shutdown(shutdown_both, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}
		if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
		{
			reset();
			(*callback)(ec_or_result.code != 0 ? ec_or_result.code : ERR_OPERATION_FAILURE);
			return;
		}
		if (header->at(http_header::NAME_STATUS_CODE) != "200")
			throw(std::runtime_error("HTTP request failed"));
		state_ = STATE_OK;
		(*callback)(0);
	});
}

void prxsocket::http_tcp_socket::shutdown(shutdown_type type, error_code &ec)
{
	//if (type & shutdown_send)
	//	reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->shutdown(type, ec);
}

void prxsocket::http_tcp_socket::async_shutdown(shutdown_type type, null_callback &&complete_handler)
{
	//if (type & shutdown_send)
	//	reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->async_shutdown(type, std::move(complete_handler));
}

void prxsocket::http_tcp_socket::close(error_code &ec)
{
	reset();
	return socket_->close(ec);
}

void prxsocket::http_tcp_socket::async_close(null_callback &&complete_handler)
{
	reset();
	socket_->async_close(std::move(complete_handler));
}
