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

#ifndef LIBPRXSOCKET_H_SOCKET_HTTP
#define LIBPRXSOCKET_H_SOCKET_HTTP

#include "socket_base.h"
#include "http_header.h"

namespace prxsocket
{

	class http_tcp_socket final : public prx_tcp_socket
	{
		enum { STATE_INIT, STATE_OK };
		static constexpr size_t RECV_BUF_SIZE = 0x400;
	public:
		http_tcp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, const endpoint &server_endpoint)
			:socket_(std::move(base_socket)), server_ep_(server_endpoint), recv_buf_(std::make_unique<char[]>(RECV_BUF_SIZE))
		{
		}
		virtual ~http_tcp_socket() override {}

		virtual bool is_open() override { return socket_->is_open(); }
		virtual bool is_connected() override { return state_ >= STATE_OK && socket_->is_connected(); }

		virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = ERR_UNSUPPORTED; }
		virtual void remote_endpoint(endpoint &ep, error_code &ec) override { ec = 0; if (!is_connected()) { ec = ERR_OPERATION_FAILURE; return; } ep = remote_ep_; }

		virtual void open(error_code &ec) override { return socket_->open(ec); }
		virtual void async_open(null_callback &&complete_handler) override { socket_->async_open(std::move(complete_handler)); }

		virtual void bind(const endpoint &endpoint, error_code &ec) override { return socket_->bind(endpoint, ec); }
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { socket_->async_bind(endpoint, std::move(complete_handler)); }

		virtual void connect(const endpoint &endpoint, error_code &ec) override;
		virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override;

		virtual void send(const const_buffer &buffer, size_t &transferred, error_code &ec) override;
		virtual void async_send(const const_buffer &buffer, transfer_callback &&complete_handler) override;
		virtual void recv(const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
		virtual void async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
		virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override;
		virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
		virtual void write(const_buffer_sequence &&buffer, error_code &ec) override;
		virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

		virtual void shutdown(shutdown_type type, error_code &ec) override;
		virtual void async_shutdown(shutdown_type type, null_callback &&complete_handler) override;
		virtual void close(error_code &ec) override;
		virtual void async_close(null_callback &&complete_handler) override;
	private:
		void reset_send() {}
		void reset_recv() { recv_buf_ptr_ = recv_buf_ptr_end_ = 0; }
		void reset() { reset_send(); reset_recv(); state_ = STATE_INIT; }
		void send_http_req(const std::shared_ptr<null_callback> &callback);
		void recv_http_resp(const std::shared_ptr<null_callback> &callback, const std::shared_ptr<http_helper::http_header> &header);

		int state_ = STATE_INIT;

		std::unique_ptr<prx_tcp_socket> socket_;
		endpoint server_ep_, remote_ep_;
		std::unique_ptr<char[]> recv_buf_;
		size_t recv_buf_ptr_ = 0, recv_buf_ptr_end_ = 0;
	};

}

#endif
