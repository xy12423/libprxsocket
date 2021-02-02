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
using namespace prxsocket::http_helper;

void http_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	socket_->connect(server_ep_, err);
	if (err)
		return;

	try
	{
		std::string host = ep.to_uri_string();
		std::string http_req;
		http_req.append("CONNECT ");
		http_req.append(host);
		http_req.append(" HTTP/1.1\r\nHost: ");
		http_req.append(host);
		http_req.append("\r\n\r\n");

		socket_->write(const_buffer(http_req), err);
		if (err)
		{
			reset();
			return;
		}

		http_header header;
		size_t size_read, size_parsed;
		bool finished;
		recv_buf_ptr_ = recv_buf_ptr_end_ = 0;
		while (finished = header.parse(recv_buf_.get() + recv_buf_ptr_, recv_buf_ptr_end_ - recv_buf_ptr_, size_parsed), recv_buf_ptr_ += size_parsed, !finished)
		{
			if (recv_buf_ptr_end_ >= RECV_BUF_SIZE)
				throw(std::runtime_error("HTTP response too long"));
			socket_->recv(mutable_buffer(recv_buf_.get() + recv_buf_ptr_end_, RECV_BUF_SIZE - recv_buf_ptr_end_), size_read, err);
			if (err)
			{
				reset();
				return;
			}
			recv_buf_ptr_end_ += size_read;
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

void http_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
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

void http_tcp_socket::send_http_req(const std::shared_ptr<null_callback> &callback)
{
	std::shared_ptr<std::string> http_req = std::make_shared<std::string>();
	try
	{
		std::string host = remote_ep_.to_uri_string();

		http_req->append("CONNECT ");
		http_req->append(host);
		http_req->append(" HTTP/1.1\r\nHost: ");
		http_req->append(host);
		http_req->append("\r\n\r\n");
	}
	catch (const std::exception &)
	{
		reset();
		(*callback)(ERR_OPERATION_FAILURE);
		return;
	}

	socket_->async_write(const_buffer(*http_req),
		[this, http_req, callback](error_code err)
	{
		if (err)
		{
			reset();
			(*callback)(err);
			return;
		}
		recv_buf_ptr_ = recv_buf_ptr_end_ = 0;
		recv_http_resp(callback, std::make_shared<http_header>());
	});
}

void http_tcp_socket::recv_http_resp(const std::shared_ptr<null_callback> &callback, const std::shared_ptr<http_header> &header)
{
	socket_->async_recv(mutable_buffer(recv_buf_.get() + recv_buf_ptr_end_, RECV_BUF_SIZE - recv_buf_ptr_end_),
		[this, callback, header](error_code err, size_t transferred)
	{
		if (err)
		{
			reset();
			(*callback)(err);
			return;
		}

		try
		{
			recv_buf_ptr_end_ += transferred;
			size_t size_parsed;
			bool finished = header->parse(recv_buf_.get() + recv_buf_ptr_, recv_buf_ptr_end_ - recv_buf_ptr_, size_parsed);
			recv_buf_ptr_ += size_parsed;
			if (!finished)
			{
				if (recv_buf_ptr_end_ >= RECV_BUF_SIZE)
					throw(std::runtime_error("HTTP response too long"));
				recv_http_resp(callback, header);
				return;
			}

			if (header->at(http_header::NAME_STATUS_CODE) != "200")
				throw(std::runtime_error("HTTP request failed"));
			state_ = STATE_OK;
			(*callback)(0);
		}
		catch (const std::exception &)
		{
			reset();
			(*callback)(ERR_OPERATION_FAILURE);
		}
	});
}

void http_tcp_socket::send(const_buffer buffer, size_t &transferred, error_code &err)
{
	socket_->send(buffer, transferred, err);
	if (err)
		reset_send();
}

void http_tcp_socket::async_send(const_buffer buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socket_->async_send(buffer,
		[this, callback](error_code err, size_t transferred)
	{
		if (err)
		{
			reset_send();
			(*callback)(err, transferred);
			return;
		}
		(*callback)(0, transferred);
	});
}

void http_tcp_socket::recv(mutable_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	if (recv_buf_ptr_ < recv_buf_ptr_end_)
	{
		transferred = std::min(buffer.size(), recv_buf_ptr_end_ - recv_buf_ptr_);
		memcpy(buffer.data(), recv_buf_.get() + recv_buf_ptr_, transferred);
		recv_buf_ptr_ += transferred;
		return;
	}
	socket_->recv(buffer, transferred, err);
	if (err)
		reset_recv();
}

void http_tcp_socket::async_recv(mutable_buffer buffer, transfer_callback &&complete_handler)
{
	if (recv_buf_ptr_ < recv_buf_ptr_end_)
	{
		size_t transferred = std::min(buffer.size(), recv_buf_ptr_end_ - recv_buf_ptr_);
		memcpy(buffer.data(), recv_buf_.get() + recv_buf_ptr_, transferred);
		recv_buf_ptr_ += transferred;
		complete_handler(0, transferred);
		return;
	}
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socket_->async_recv(buffer,
		[this, callback](error_code err, size_t transferred)
	{
		if (err)
		{
			reset_recv();
			(*callback)(err, transferred);
			return;
		}
		(*callback)(0, transferred);
	});
}

void http_tcp_socket::read(mutable_buffer_sequence &&buffer, error_code &err)
{
	err = 0;
	if (buffer.empty())
		return;
	if (recv_buf_ptr_ < recv_buf_ptr_end_)
	{
		size_t transferred = buffer.scatter(recv_buf_.get() + recv_buf_ptr_, recv_buf_ptr_end_ - recv_buf_ptr_);
		recv_buf_ptr_ += transferred;
		if (buffer.empty())
			return;
	}
	socket_->read(std::move(buffer), err);
	if (err)
		reset_recv();
}

void http_tcp_socket::async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	if (buffer.empty())
	{
		complete_handler(0);
		return;
	}
	if (recv_buf_ptr_ < recv_buf_ptr_end_)
	{
		size_t transferred = buffer.scatter(recv_buf_.get() + recv_buf_ptr_, recv_buf_ptr_end_ - recv_buf_ptr_);
		recv_buf_ptr_ += transferred;
		if (buffer.empty())
		{
			complete_handler(0);
			return;
		}
	}
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket_->async_read(std::move(buffer),
		[this, callback](error_code err)
	{
		if (err)
		{
			reset_recv();
			(*callback)(err);
			return;
		}
		(*callback)(0);
	});
}

void http_tcp_socket::write(const_buffer_sequence &&buffer, error_code &err)
{
	socket_->write(std::move(buffer), err);
	if (err)
		reset_send();
}

void http_tcp_socket::async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket_->async_write(std::move(buffer),
		[this, callback](error_code err)
	{
		if (err)
		{
			reset_send();
			(*callback)(err);
			return;
		}
		(*callback)(0);
	});
}

void http_tcp_socket::shutdown(shutdown_type type, error_code &ec)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->shutdown(type, ec);
}

void http_tcp_socket::async_shutdown(shutdown_type type, null_callback &&complete_handler)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->async_shutdown(type, std::move(complete_handler));
}

void http_tcp_socket::close(error_code &ec)
{
	reset();
	return socket_->close(ec);
}

void http_tcp_socket::async_close(null_callback &&complete_handler)
{
	reset();
	socket_->async_close(std::move(complete_handler));
}
