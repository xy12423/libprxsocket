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

#ifndef LIBPRXSOCKET_H_SOCKET_SS
#define LIBPRXSOCKET_H_SOCKET_SS

#include "socket_base.h"

namespace prxsocket
{
	namespace ss
	{

		class ss_tcp_socket final : public prx_tcp_socket
		{
		public:
			ss_tcp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, const endpoint &server_endpoint)
				:socket_(std::move(base_socket)), server_ep_(server_endpoint)
			{
			}
			virtual ~ss_tcp_socket() override {}

			virtual bool is_open() override { return socket_->is_open(); }
			virtual bool is_connected() override { return remote_ep_sent_ && socket_->is_connected(); }

			virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = ERR_UNSUPPORTED; }
			virtual void remote_endpoint(endpoint &ep, error_code &ec) override { ec = 0; if (!is_connected()) { ec = ERR_OPERATION_FAILURE; return; } ep = remote_ep_; }

			virtual void open(error_code &ec) override { return socket_->open(ec); }
			virtual void async_open(null_callback &&complete_handler) override { socket_->async_open(std::move(complete_handler)); }

			virtual void bind(const endpoint &endpoint, error_code &ec) override { ec = ERR_UNSUPPORTED; }
			virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { complete_handler(ERR_UNSUPPORTED); }

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
			void reset() { remote_ep_sent_ = false; }

			std::unique_ptr<prx_tcp_socket> socket_;
			endpoint server_ep_, remote_ep_;
			bool remote_ep_sent_ = false;
		};

		class ss_udp_socket final : public prx_udp_socket
		{
			static constexpr size_t UDP_BUF_SIZE = 0x10000;
		public:
			ss_udp_socket(std::unique_ptr<prx_udp_socket> &&base_udp_socket, const endpoint &_udp_server_ep)
				:udp_socket_(std::move(base_udp_socket)), udp_server_ep_(_udp_server_ep), udp_recv_buf_(std::make_unique<char[]>(UDP_BUF_SIZE))
			{
			}
			virtual ~ss_udp_socket() override {}

			virtual bool is_open() override { return udp_socket_->is_open(); }

			virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = ERR_UNSUPPORTED; }

			virtual void open(error_code &ec) override { return udp_socket_->open(ec); }
			virtual void async_open(null_callback &&complete_handler) override { udp_socket_->async_open(std::move(complete_handler)); }

			virtual void bind(const endpoint &endpoint, error_code &ec) override { ec = ERR_UNSUPPORTED; }
			virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { complete_handler(ERR_UNSUPPORTED); }

			virtual void send_to(const endpoint &endpoint, const const_buffer &buffer, error_code &ec) override;
			virtual void async_send_to(const endpoint &endpoint, const const_buffer &buffer, null_callback &&complete_handler) override;
			virtual void recv_from(endpoint &endpoint, const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
			virtual void async_recv_from(endpoint &endpoint, const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
			virtual void send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, null_callback &&complete_handler) override;
			virtual void recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, size_t &transferred, error_code &ec) override;
			virtual void async_recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, transfer_callback &&complete_handler) override;

			virtual void close(error_code &ec) override { reset(); udp_socket_->close(ec); }
			virtual void async_close(null_callback &&complete_handler) override { reset(); udp_socket_->async_close(std::move(complete_handler)); }
		private:
			void reset() {}

			std::unique_ptr<prx_udp_socket> udp_socket_;
			endpoint udp_server_ep_, udp_recv_ep_;
			std::unique_ptr<char[]> udp_recv_buf_;
		};

	}
}

#endif
