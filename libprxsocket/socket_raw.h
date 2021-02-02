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

#ifndef LIBPRXSOCKET_H_SOCKET_RAW
#define LIBPRXSOCKET_H_SOCKET_RAW

#include "socket_base.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <boost/asio.hpp>
#endif

namespace prxsocket
{

	class raw_tcp_socket final : public prx_tcp_socket
	{
	public:
		raw_tcp_socket(boost::asio::io_context &iosrv) :socket_(iosrv), resolver_(iosrv) {}
		raw_tcp_socket(boost::asio::ip::tcp::socket &&native_socket, bool is_connected = false) :socket_(std::move(native_socket)), resolver_(socket_.get_executor()), connected_(is_connected) { set_keep_alive(); }
		virtual ~raw_tcp_socket() override {}

		virtual bool is_open() override { return socket_.is_open(); }
		virtual bool is_connected() override { return connected_ && is_open(); }

		virtual void local_endpoint(endpoint &ep, error_code &err) override;
		virtual void remote_endpoint(endpoint &ep, error_code &err) override;

		virtual void open(error_code &err) override;
		virtual void async_open(null_callback &&complete_handler) override;

		virtual void bind(const endpoint &endpoint, error_code &err) override;
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override;

		virtual void connect(const endpoint &endpoint, error_code &err) override;
		virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override;

		virtual void send(const_buffer buffer, size_t &transferred, error_code &err) override;
		virtual void async_send(const_buffer buffer, transfer_callback &&complete_handler) override;
		virtual void recv(mutable_buffer buffer, size_t &transferred, error_code &err) override;
		virtual void async_recv(mutable_buffer buffer, transfer_callback &&complete_handler) override;
		virtual void read(mutable_buffer buffer, error_code &ec) override;
		virtual void async_read(mutable_buffer buffer, null_callback &&complete_handler) override;
		virtual void write(const_buffer buffer, error_code &ec) override;
		virtual void async_write(const_buffer buffer, null_callback &&complete_handler) override;
		virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override;
		virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
		virtual void write(const_buffer_sequence &&buffer, error_code &ec) override;
		virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

		virtual void shutdown(shutdown_type type, error_code &ec) override;
		virtual void async_shutdown(shutdown_type type, null_callback &&complete_handler) override;
		virtual void close(error_code &err) override;
		virtual void async_close(null_callback &&complete_handler) override;
	private:
		void set_keep_alive();

		void check_protocol(const boost::asio::ip::tcp::endpoint::protocol_type &);
		void connect_addr_str(const std::string &addr, port_type port, error_code &err);
		void async_connect_addr_str(const std::string &addr, port_type port, const std::shared_ptr<null_callback> &callback);

		thread_local static boost::system::error_code ec;
		boost::asio::ip::tcp::socket socket_;
		boost::asio::ip::tcp::resolver resolver_;

		bool binded_ = false, connected_ = false;
	};

	class raw_udp_socket final : public prx_udp_socket
	{
	public:
		raw_udp_socket(boost::asio::io_context &iosrv) :socket_(iosrv), resolver_(iosrv) {}
		virtual ~raw_udp_socket() override {}

		virtual bool is_open() override { return socket_.is_open(); }

		virtual void local_endpoint(endpoint &ep, error_code &err) override;

		virtual void open(error_code &err) override;
		virtual void async_open(null_callback &&complete_handler) override;

		virtual void bind(const endpoint &endpoint, error_code &err) override;
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override;

		virtual void send_to(const endpoint &endpoint, const_buffer buffer, error_code &err) override;
		virtual void async_send_to(const endpoint &endpoint, const_buffer buffer, null_callback &&complete_handler) override;
		virtual void recv_from(endpoint &endpoint, mutable_buffer buffer, size_t &transferred, error_code &err) override;
		virtual void async_recv_from(endpoint &endpoint, mutable_buffer buffer, transfer_callback &&complete_handler) override;
		virtual void send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, error_code &ec) override;
		virtual void async_send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, null_callback &&complete_handler) override;
		virtual void recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, size_t &transferred, error_code &ec) override;
		virtual void async_recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, transfer_callback &&complete_handler) override;

		virtual void close(error_code &err) override;
		virtual void async_close(null_callback &&complete_handler) override;
	private:
		error_code to_udp_ep(const endpoint &ep, boost::asio::ip::udp::endpoint &result);
		void async_to_udp_ep(const endpoint &ep, std::function<void(error_code, const boost::asio::ip::udp::endpoint &)> &&complete_handler);

		thread_local static boost::system::error_code ec;
		boost::asio::ip::udp::socket socket_;
		boost::asio::ip::udp::endpoint recv_ep_;
		boost::asio::ip::udp::resolver resolver_;
	};

	class raw_listener final : public prx_listener
	{
	public:
		raw_listener(boost::asio::io_context &_iosrv) :iosrv_(_iosrv), acceptor_(iosrv_) {}
		virtual ~raw_listener() override {}

		virtual bool is_open() override { return acceptor_.is_open(); }
		virtual bool is_listening() override { return listening_ && acceptor_.is_open(); }

		virtual void local_endpoint(endpoint &ep, error_code &err) override;

		virtual void open(error_code &err) override;
		virtual void async_open(null_callback &&complete_handler) override;

		virtual void bind(const endpoint &endpoint, error_code &err) override;
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override;

		virtual void listen(error_code &err) override;
		virtual void async_listen(null_callback &&complete_handler) override;

		virtual void accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &err) override;
		virtual void async_accept(accept_callback &&complete_handler) override;

		virtual void close(error_code &err) override;
		virtual void async_close(null_callback &&complete_handler) override;
	private:
		thread_local static boost::system::error_code ec;
		boost::asio::io_context &iosrv_;
		boost::asio::ip::tcp::acceptor acceptor_;

		bool listening_ = false;
	};

}

#endif
