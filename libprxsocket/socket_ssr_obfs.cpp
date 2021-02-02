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
#include "socket_ssr_obfs.h"

using namespace prxsocket;
using namespace prxsocket::ssr;

ssr_http_simple_tcp_socket::ssr_http_simple_tcp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, const std::string &arg)
	:transparent_tcp_socket(std::move(base_socket)), recv_buf_(std::make_unique<char[]>(RECV_BUF_SIZE))
{
	size_t delim_pos = arg.find('#');
	if (delim_pos != std::string::npos)
	{
		custom_body_ = true;
		host_ = arg.substr(0, delim_pos);
		for (size_t i = delim_pos + 1; i < arg.size(); ++i)
		{
			if (arg[i] == '\n')
				body_.append("\r\n");
			else if (arg[i] == '\\' && i + 1 < arg.size() && arg[i + 1] == 'n')
				body_.append("\r\n"), ++i;
			else
				body_.push_back(arg[i]);
		}
	}
	else
	{
		host_ = arg;
	}
}

void ssr_http_simple_tcp_socket::send(const_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	if (!header_sent_)
	{
		std::string header;
		size_t transferring = make_header(header, buffer);
		socket_->write(const_buffer(header), err);
		if (err)
		{
			reset_send();
			transferred = 0;
			return;
		}
		header_sent_ = true;
		transferred = transferring;
		return;
	}
	socket_->send(buffer, transferred, err);
	if (err)
		reset_send();
}

void ssr_http_simple_tcp_socket::async_send(const_buffer buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	if (!header_sent_)
	{
		std::shared_ptr<std::string> header = std::make_shared<std::string>();
		size_t transferring = make_header(*header, buffer);
		socket_->async_write(const_buffer(*header),
			[this, header, transferring, callback](error_code err)
		{
			if (err)
			{
				reset_send();
				(*callback)(err, 0);
				return;
			}
			header_sent_ = true;
			(*callback)(0, transferring);
		});
		return;
	}
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

void ssr_http_simple_tcp_socket::recv(mutable_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	if (!header_received_)
	{
		wait_header(err);
		if (err)
			return;
	}
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

void ssr_http_simple_tcp_socket::async_recv(mutable_buffer buffer, transfer_callback &&complete_handler)
{
	if (!header_received_)
	{
		std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
		async_wait_header([this, buffer, callback](error_code err)
		{
			if (err)
				(*callback)(err, 0);
			else
				async_recv(buffer, std::move(*callback));
		});
		return;
	}
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

void ssr_http_simple_tcp_socket::read(mutable_buffer_sequence &&buffer, error_code &err)
{
	err = 0;
	if (!header_received_)
	{
		wait_header(err);
		if (err)
			return;
	}
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

void ssr_http_simple_tcp_socket::async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	if (!header_received_)
	{
		std::shared_ptr<mutable_buffer_sequence> buffer_ptr = std::make_shared<mutable_buffer_sequence>(std::move(buffer));
		std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
		async_wait_header([this, buffer_ptr, callback](error_code err)
		{
			if (err)
				(*callback)(err);
			else
				async_read(std::move(*buffer_ptr), std::move(*callback));
		});
		return;
	}
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

void ssr_http_simple_tcp_socket::write(const_buffer_sequence &&buffer, error_code &err)
{
	err = 0;
	if (!header_sent_)
	{
		std::string header;
		size_t transferring = make_header(header, buffer.empty() ? const_buffer(nullptr, 0) : buffer.front());
		socket_->write(const_buffer(header), err);
		if (err)
		{
			reset_send();
			return;
		}
		header_sent_ = true;
		buffer.consume_front(transferring);
	}
	socket_->write(std::move(buffer), err);
	if (err)
		reset_send();
}

void ssr_http_simple_tcp_socket::async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	if (!header_sent_)
	{
		std::shared_ptr<std::string> header = std::make_shared<std::string>();
		size_t transferring = make_header(*header, buffer.empty() ? const_buffer(nullptr, 0) : buffer.front());
		buffer.consume_front(transferring);
		std::shared_ptr<const_buffer_sequence> buffer_ptr = std::make_shared<const_buffer_sequence>(std::move(buffer));
		socket_->async_write(const_buffer(*header),
			[this, header, buffer_ptr, callback](error_code err)
		{
			if (err)
			{
				reset_send();
				(*callback)(err);
				return;
			}
			header_sent_ = true;
			async_write(std::move(*buffer_ptr), std::move(*callback));
		});
		return;
	}
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

void ssr_http_simple_tcp_socket::shutdown(shutdown_type type, error_code &ec)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->shutdown(type, ec);
}

void ssr_http_simple_tcp_socket::async_shutdown(shutdown_type type, null_callback &&complete_handler)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->async_shutdown(type, std::move(complete_handler));
}

void ssr_http_simple_tcp_socket::close(error_code &ec)
{
	reset();
	return socket_->close(ec);
}

void ssr_http_simple_tcp_socket::async_close(null_callback &&complete_handler)
{
	reset();
	socket_->async_close(std::move(complete_handler));
}

size_t ssr_http_simple_tcp_socket::make_header(std::string &dst, const_buffer payload)
{
	static constexpr const char hex_table[] = "0123456789ABCDEF";
	static constexpr const char *user_agents[] = {
		"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
		"Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
		"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
		"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3"
	};

	size_t actual_payload_size = payload.size() > 80 ? rand() % 64 + 16 : payload.size();
	dst.clear();
	dst.reserve(48 + actual_payload_size * 3);
	dst.append("GET /");
	for (size_t i = 0; i < actual_payload_size; ++i)
	{
		dst.push_back('%');
		dst.push_back(hex_table[(uint8_t)payload.data()[i] / 16]);
		dst.push_back(hex_table[(uint8_t)payload.data()[i] % 16]);
	}
	dst.append(" HTTP/1.1\r\n");
	dst.append("Host: ");
	dst.append(host_);
	error_code err;
	endpoint remote_ep;
	socket_->remote_endpoint(remote_ep, err);
	if (!err && remote_ep.port() != 80)
	{
		dst.push_back(':');
		dst.append(std::to_string(remote_ep.port()));
	}
	dst.append("\r\n");
	if (custom_body_)
	{
		dst.append(body_);
		dst.append("\r\n");
	}
	else
	{
		dst.append("User-Agent: ");
		dst.append(user_agents[rand() % std::extent<decltype(user_agents)>::value]);
		dst.append("\r\n");
		dst.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\n\r\n");
	}

	return actual_payload_size;
}

void ssr_http_simple_tcp_socket::wait_header(error_code &err)
{
	assert(!header_received_);
	static constexpr const char delim_end[] = "\r\n\r\n";
	static constexpr size_t delim_end_size = sizeof(delim_end) - 1;
	size_t matched = 0;
	while (matched < delim_end_size)
	{
		if (recv_buf_ptr_end_ >= RECV_BUF_SIZE)
		{
			shutdown(shutdown_receive, err);
			err = ERR_OPERATION_FAILURE;
			return;
		}
		size_t transferred;
		socket_->recv(mutable_buffer(recv_buf_.get() + recv_buf_ptr_end_, RECV_BUF_SIZE - recv_buf_ptr_end_), transferred, err);
		if (err)
		{
			reset_recv();
			return;
		}
		recv_buf_ptr_end_ += transferred;

		for (; recv_buf_ptr_ < recv_buf_ptr_end_ && matched < delim_end_size;)
		{
			if (recv_buf_[recv_buf_ptr_] == delim_end[matched])
				++matched, ++recv_buf_ptr_;
			else
				matched == 0 ? ++recv_buf_ptr_ : matched = 0;
		}
	}
	header_received_ = true;
	err = 0;
}

void ssr_http_simple_tcp_socket::async_wait_header(null_callback &&complete_handler)
{
	assert(recv_buf_ptr_ == 0 && recv_buf_ptr_end_ == 0);
	async_wait_header(std::make_shared<null_callback>(std::move(complete_handler)));
}

void ssr_http_simple_tcp_socket::async_wait_header(const std::shared_ptr<null_callback> &callback, size_t matched_old)
{
	assert(!header_received_);
	socket_->async_recv(mutable_buffer(recv_buf_.get() + recv_buf_ptr_end_, RECV_BUF_SIZE - recv_buf_ptr_end_),
		[this, callback, matched_old](error_code err, size_t transferred)
	{
		if (err)
		{
			reset_recv();
			(*callback)(err);
			return;
		}
		recv_buf_ptr_end_ += transferred;

		static constexpr const char delim_end[] = "\r\n\r\n";
		static constexpr size_t delim_end_size = sizeof(delim_end) - 1;
		size_t matched = matched_old;
		for (; recv_buf_ptr_ < recv_buf_ptr_end_ && matched < delim_end_size;)
		{
			if (recv_buf_[recv_buf_ptr_] == delim_end[matched])
				++matched, ++recv_buf_ptr_;
			else
				matched == 0 ? ++recv_buf_ptr_ : matched = 0;
		}
		if (matched == delim_end_size)
		{
			header_received_ = true;
			(*callback)(0);
			return;
		}
		if (recv_buf_ptr_end_ >= RECV_BUF_SIZE)
		{
			async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}
		async_wait_header(callback, matched);
	});
}
