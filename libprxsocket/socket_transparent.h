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

#ifndef LIBPRXSOCKET_H_SOCKET_TRANSPARENT
#define LIBPRXSOCKET_H_SOCKET_TRANSPARENT

#include "socket_base.h"

namespace prxsocket
{

	template <typename BaseTcpSocket>
	class transparent_tcp_socket_template : public prx_tcp_socket
	{
	public:
		transparent_tcp_socket_template(std::unique_ptr<BaseTcpSocket> &&base_socket)
			:socket_(std::move(base_socket))
		{
		}
		virtual ~transparent_tcp_socket_template() override {}

		virtual bool is_open() override { return socket_->is_open(); }
		virtual bool is_connected() override { return socket_->is_connected(); }

		virtual void local_endpoint(endpoint &endpoint, error_code &ec) override { return socket_->local_endpoint(endpoint, ec); }
		virtual void remote_endpoint(endpoint &endpoint, error_code &ec) override { return socket_->remote_endpoint(endpoint, ec); }

		virtual void open(error_code &ec) override { return socket_->open(ec); }
		virtual void async_open(null_callback &&complete_handler) override { socket_->async_open(std::move(complete_handler)); }

		virtual void bind(const endpoint &endpoint, error_code &ec) override { return socket_->bind(endpoint, ec); }
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { socket_->async_bind(endpoint, std::move(complete_handler)); }

		virtual void connect(const endpoint &endpoint, error_code &ec) override { return socket_->connect(endpoint, ec); }
		virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override { socket_->async_connect(endpoint, std::move(complete_handler)); }

		virtual void send(const_buffer buffer, size_t &transferred, error_code &ec) override { return socket_->send(buffer, transferred, ec); }
		virtual void async_send(const_buffer buffer, transfer_callback &&complete_handler) override { socket_->async_send(buffer, std::move(complete_handler)); }
		virtual void recv(mutable_buffer buffer, size_t &transferred, error_code &ec) override { return socket_->recv(buffer, transferred, ec); }
		virtual void async_recv(mutable_buffer buffer, transfer_callback &&complete_handler) override { socket_->async_recv(buffer, std::move(complete_handler)); }
		virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override { return socket_->read(std::move(buffer), ec); }
		virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override { socket_->async_read(std::move(buffer), std::move(complete_handler)); }
		virtual void write(const_buffer_sequence &&buffer, error_code &ec) override { return socket_->write(std::move(buffer), ec); }
		virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override { socket_->async_write(std::move(buffer), std::move(complete_handler)); }

		virtual void shutdown(shutdown_type type, error_code &ec) override { return socket_->shutdown(type, ec); }
		virtual void async_shutdown(shutdown_type type, null_callback &&complete_handler) override { socket_->async_shutdown(type, std::move(complete_handler)); }
		virtual void close(error_code &ec) override { return socket_->close(ec); }
		virtual void async_close(null_callback &&complete_handler) override { socket_->async_close(std::move(complete_handler)); }
	protected:
		std::unique_ptr<BaseTcpSocket> socket_;
	};
	using transparent_tcp_socket = transparent_tcp_socket_template<prx_tcp_socket>;

	template <typename BaseUdpSocket>
	class transparent_udp_socket_template : public prx_udp_socket
	{
	public:
		transparent_udp_socket_template(std::unique_ptr<BaseUdpSocket> &&base_udp_socket)
			:udp_socket_(std::move(base_udp_socket))
		{
		}
		virtual ~transparent_udp_socket_template() override {}

		virtual bool is_open() override { return udp_socket_->is_open(); }

		virtual void local_endpoint(endpoint &endpoint, error_code &ec) override { return udp_socket_->local_endpoint(endpoint, ec); }

		virtual void open(error_code &ec) override { return udp_socket_->open(ec); }
		virtual void async_open(null_callback &&complete_handler) override { udp_socket_->async_open(std::move(complete_handler)); }

		virtual void bind(const endpoint &endpoint, error_code &ec) override { return udp_socket_->bind(endpoint, ec); }
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { udp_socket_->async_bind(endpoint, std::move(complete_handler)); }

		virtual void send_to(const endpoint &endpoint, const_buffer buffer, error_code &ec) override { return udp_socket_->send_to(endpoint, buffer, ec); }
		virtual void async_send_to(const endpoint &endpoint, const_buffer buffer, null_callback &&complete_handler) override { udp_socket_->async_send_to(endpoint, buffer, std::move(complete_handler)); }
		virtual void recv_from(endpoint &endpoint, mutable_buffer buffer, size_t &transferred, error_code &ec) override { return udp_socket_->recv_from(endpoint, buffer, transferred, ec); }
		virtual void async_recv_from(endpoint &endpoint, mutable_buffer buffer, transfer_callback &&complete_handler) override { udp_socket_->async_recv_from(endpoint, buffer, std::move(complete_handler)); }
		virtual void send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, error_code &ec) override { return udp_socket_->send_to(endpoint, std::move(buffer), ec); }
		virtual void async_send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, null_callback &&complete_handler) override { udp_socket_->async_send_to(endpoint, std::move(buffer), std::move(complete_handler)); }
		virtual void recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, size_t &transferred, error_code &ec) override { return udp_socket_->recv_from(endpoint, std::move(buffer), transferred, ec); }
		virtual void async_recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, transfer_callback &&complete_handler) override { udp_socket_->async_recv_from(endpoint, std::move(buffer), std::move(complete_handler)); }

		virtual void close(error_code &ec) override { return udp_socket_->close(ec); }
		virtual void async_close(null_callback &&complete_handler) override { udp_socket_->async_close(std::move(complete_handler)); }
	protected:
		std::unique_ptr<BaseUdpSocket> udp_socket_;
	};
	using transparent_udp_socket = transparent_udp_socket_template<prx_udp_socket>;

	template <typename BaseListener>
	class transparent_listener_template : public prx_listener
	{
	public:
		transparent_listener_template(std::unique_ptr<BaseListener> &&base_acceptor)
			:acceptor_(std::move(base_acceptor))
		{
		}
		virtual ~transparent_listener_template() override {}

		virtual bool is_open() override { return acceptor_->is_open(); }
		virtual bool is_listening() override { return acceptor_->is_listening(); }

		virtual void local_endpoint(endpoint &endpoint, error_code &ec) override { return acceptor_->local_endpoint(endpoint, ec); }

		virtual void open(error_code &ec) override { return acceptor_->open(ec); }
		virtual void async_open(null_callback &&complete_handler) override { acceptor_->async_open(std::move(complete_handler)); }

		virtual void bind(const endpoint &endpoint, error_code &ec) override { return acceptor_->bind(endpoint, ec); }
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { acceptor_->async_bind(endpoint, std::move(complete_handler)); }

		virtual void listen(error_code &ec) override { return acceptor_->listen(ec); }
		virtual void async_listen(null_callback &&complete_handler) override { acceptor_->async_listen(std::move(complete_handler)); }

		virtual void accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &ec) override { return acceptor_->accept(socket, ec); }
		virtual void async_accept(accept_callback &&complete_handler) override { acceptor_->async_accept(std::move(complete_handler)); }

		virtual void close(error_code &ec) override { return acceptor_->close(ec); }
		virtual void async_close(null_callback &&complete_handler) override { acceptor_->async_close(std::move(complete_handler)); }
	protected:
		std::unique_ptr<BaseListener> acceptor_;
	};
	using transparent_listener = transparent_listener_template<prx_listener>;

}

#endif
