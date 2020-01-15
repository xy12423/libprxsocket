#include "stdafx.h"
#include "socket_http.h"

void http_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	socket->connect(server_ep, err);
	if (err)
		return;

	try
	{
		std::string host = ep.addr().to_string();
		host.push_back(':');
		host.append(std::to_string(ep.port()));
		std::string http_req;
		http_req.append("CONNECT ");
		http_req.append(host);
		http_req.append(" HTTP/1.1\r\nHost: ");
		http_req.append(host);
		http_req.append("\r\n\r\n");

		write(*socket, const_buffer(http_req), err);
		if (err)
		{
			close();
			return;
		}

		http_header header;
		size_t size_read, size_parsed;
		bool finished;
		recv_buf_ptr = recv_buf_ptr_end = 0;
		while (finished = header.parse(recv_buf.get() + recv_buf_ptr, recv_buf_ptr_end - recv_buf_ptr, size_parsed), recv_buf_ptr += size_parsed, !finished)
		{
			if (recv_buf_ptr_end >= recv_buf_size)
				throw(std::runtime_error("HTTP response too long"));
			socket->recv(mutable_buffer(recv_buf.get() + recv_buf_ptr_end, recv_buf_size - recv_buf_ptr_end), size_read, err);
			if (err)
			{
				close();
				return;
			}
			recv_buf_ptr_end += size_read;
		}

		if (header.at(http_header::NAME_STATUS_CODE) != "200")
			throw(std::runtime_error("HTTP request failed"));
	}
	catch (std::exception &)
	{
		close();
		err = ERR_OPERATION_FAILURE;
		return;
	}

	remote_ep = ep;
	state = STATE_OK;
}

void http_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	remote_ep = ep;
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket->async_connect(server_ep,
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
		std::string host = remote_ep.addr().to_string();
		host.push_back(':');
		host.append(std::to_string(remote_ep.port()));

		http_req->append("CONNECT ");
		http_req->append(host);
		http_req->append(" HTTP/1.1\r\nHost: ");
		http_req->append(host);
		http_req->append("\r\n\r\n");
	}
	catch (std::exception &)
	{
		async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		return;
	}

	async_write(*socket, const_buffer(*http_req),
		[this, http_req, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}
		recv_buf_ptr = recv_buf_ptr_end = 0;
		recv_http_resp(callback, std::make_shared<http_header>());
	});
}

void http_tcp_socket::recv_http_resp(const std::shared_ptr<null_callback> &callback, const std::shared_ptr<http_header> &header)
{
	socket->async_recv(mutable_buffer(recv_buf.get() + recv_buf_ptr_end, recv_buf_size - recv_buf_ptr_end),
		[this, callback, header](error_code err, size_t transferred)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}

		try
		{
			recv_buf_ptr_end += transferred;
			size_t size_parsed;
			bool finished = header->parse(recv_buf.get() + recv_buf_ptr, recv_buf_ptr_end - recv_buf_ptr, size_parsed);
			recv_buf_ptr += size_parsed;
			if (!finished)
			{
				if (recv_buf_ptr_end >= recv_buf_size)
					throw(std::runtime_error("HTTP response too long"));
				recv_http_resp(callback, header);
				return;
			}

			if (header->at(http_header::NAME_STATUS_CODE) != "200")
				throw(std::runtime_error("HTTP request failed"));
			state = STATE_OK;
			(*callback)(0);
		}
		catch (std::exception &)
		{
			async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		}
	});
}

void http_tcp_socket::send(const const_buffer &buffer, size_t &transferred, error_code &err)
{
	err = 0;
	if (!is_connected())
	{
		transferred = 0;
		err = ERR_OPERATION_FAILURE;
		return;
	}
	socket->send(buffer, transferred, err);
	if (err)
		close();
}

void http_tcp_socket::async_send(const const_buffer &buffer, transfer_callback &&complete_handler)
{
	if (!is_connected())
	{
		complete_handler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socket->async_send(buffer,
		[this, callback](error_code err, size_t transferred)
	{
		if (err)
			async_close([callback, err, transferred](error_code) { (*callback)(err, transferred); });
		else
			(*callback)(0, transferred);
	});
}

void http_tcp_socket::recv(const mutable_buffer &buffer, size_t &transferred, error_code &err)
{
	err = 0;
	if (!is_connected())
	{
		transferred = 0;
		err = ERR_OPERATION_FAILURE;
		return;
	}
	if (recv_buf_ptr < recv_buf_ptr_end)
	{
		transferred = std::min(buffer.size(), recv_buf_ptr_end - recv_buf_ptr);
		memcpy(buffer.access_data(), recv_buf.get() + recv_buf_ptr, transferred);
		recv_buf_ptr += transferred;
		return;
	}
	socket->recv(buffer, transferred, err);
	if (err)
		close();
}

void http_tcp_socket::async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler)
{
	if (!is_connected())
	{
		complete_handler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	if (recv_buf_ptr < recv_buf_ptr_end)
	{
		size_t transferred = std::min(buffer.size(), recv_buf_ptr_end - recv_buf_ptr);
		memcpy(buffer.access_data(), recv_buf.get() + recv_buf_ptr, transferred);
		recv_buf_ptr += transferred;
		complete_handler(0, transferred);
		return;
	}
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socket->async_recv(buffer,
		[this, callback](error_code err, size_t transferred)
	{
		if (err)
			async_close([callback, err, transferred](error_code) { (*callback)(err, transferred); });
		else
			(*callback)(0, transferred);
	});
}
