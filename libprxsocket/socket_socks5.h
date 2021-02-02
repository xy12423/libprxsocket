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

#ifndef LIBPRXSOCKET_H_SOCKET_SOCKS5
#define LIBPRXSOCKET_H_SOCKET_SOCKS5

#include "socks5_base.h"

namespace prxsocket
{

	class socks5_tcp_socket final : public prx_tcp_socket, private socks5_helper::socks5_base
	{
		enum { STATE_INIT, STATE_OPEN, STATE_CONNECTED };

		friend class socks5_listener;
	public:
		socks5_tcp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, const endpoint &server_endpoint)
			:socks5_base(std::move(base_socket)), server_ep_(server_endpoint)
		{
		}
		socks5_tcp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, const endpoint &server_endpoint, const std::string &methods)
			:socks5_base(std::move(base_socket), methods), server_ep_(server_endpoint)
		{
		}
		virtual ~socks5_tcp_socket() override {}

		virtual bool is_open() override { return state_ >= STATE_OPEN && socket_->is_connected(); }
		virtual bool is_connected() override { return state_ >= STATE_CONNECTED && socket_->is_connected(); }

		virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = 0; if (!is_connected()) { ec = ERR_OPERATION_FAILURE; return; } ep = local_ep_; }
		virtual void remote_endpoint(endpoint &ep, error_code &ec) override { ec = 0; if (!is_connected()) { ec = ERR_OPERATION_FAILURE; return; } ep = remote_ep_; }

		virtual void open(error_code &ec) override;
		virtual void async_open(null_callback &&complete_handler) override;

		virtual void bind(const endpoint &endpoint, error_code &ec) override { ec = ERR_UNSUPPORTED; }
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { complete_handler(ERR_UNSUPPORTED); }

		virtual void connect(const endpoint &endpoint, error_code &ec) override;
		virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override;

		virtual void send(const_buffer buffer, size_t &transferred, error_code &ec) override;
		virtual void async_send(const_buffer buffer, transfer_callback &&complete_handler) override;
		virtual void recv(mutable_buffer buffer, size_t &transferred, error_code &ec) override;
		virtual void async_recv(mutable_buffer buffer, transfer_callback &&complete_handler) override;
		virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override;
		virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
		virtual void write(const_buffer_sequence &&buffer, error_code &ec) override;
		virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

		virtual void shutdown(shutdown_type type, error_code &ec) override;
		virtual void async_shutdown(shutdown_type type, null_callback &&complete_handler) override;
		virtual void close(error_code &ec) override;
		virtual void async_close(null_callback &&complete_handler) override;
	private:
		void reset() { state_ = STATE_INIT; }

		int state_ = STATE_INIT;

		endpoint server_ep_, local_ep_, remote_ep_;
	};

	class socks5_udp_socket final : public prx_udp_socket, private socks5_helper::socks5_base
	{
		enum { STATE_INIT, STATE_ASSOCIATED };

		static constexpr size_t UDP_BUF_SIZE = 0x10000;
	public:
		socks5_udp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, std::unique_ptr<prx_udp_socket> &&base_udp_socket, const endpoint &_server_ep)
			:socks5_base(std::move(base_socket), "\x80\x00", 2), server_ep_(_server_ep), udp_socket_(std::move(base_udp_socket)), udp_recv_buf_(std::make_unique<char[]>(UDP_BUF_SIZE))
		{
		}
		socks5_udp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, const endpoint &_server_ep)
			:socks5_base(std::move(base_socket), "\x80", 1), server_ep_(_server_ep), udp_recv_buf_(std::make_unique<char[]>(UDP_BUF_SIZE))
		{
		}
		virtual ~socks5_udp_socket() override {}

		virtual bool is_open() override { return state_ >= STATE_ASSOCIATED && socket_->is_connected() && (!udp_socket_ || udp_socket_->is_open()); }

		virtual void local_endpoint(endpoint &ep, error_code &ec) override;

		virtual void open(error_code &ec) override;
		virtual void async_open(null_callback &&complete_handler) override;

		virtual void bind(const endpoint &endpoint, error_code &ec) override;
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override;

		virtual void send_to(const endpoint &endpoint, const_buffer buffer, error_code &ec) override;
		virtual void async_send_to(const endpoint &endpoint, const_buffer buffer, null_callback &&complete_handler) override;
		virtual void recv_from(endpoint &endpoint, mutable_buffer buffer, size_t &transferred, error_code &ec) override;
		virtual void async_recv_from(endpoint &endpoint, mutable_buffer buffer, transfer_callback &&complete_handler) override;
		virtual void send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, error_code &ec) override;
		virtual void async_send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, null_callback &&complete_handler) override;
		virtual void recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, size_t &transferred, error_code &ec) override;
		virtual void async_recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, transfer_callback &&complete_handler) override;

		virtual void close(error_code &ec) override;
		virtual void async_close(null_callback &&complete_handler) override;
	private:
		void reset() { state_ = STATE_INIT; }

		void open(const endpoint &endpoint, error_code &ec);
		void async_open(const endpoint &endpoint, null_callback &&complete_handler);
		void async_open_continue(const endpoint &endpoint, const std::shared_ptr<null_callback> &callback);
		void async_skip(size_t size, const std::shared_ptr<transfer_callback> &callback);
		error_code parse_udp(size_t udp_recv_size, endpoint &ep, mutable_buffer buffer, size_t &transferred);
		error_code parse_udp(size_t udp_recv_size, endpoint &ep, mutable_buffer_sequence &&buffer, size_t &transferred);

		int state_ = STATE_INIT;

		endpoint server_ep_, udp_server_ep_, udp_recv_ep_, udp_local_ep_;
		std::unique_ptr<prx_udp_socket> udp_socket_;
		std::unique_ptr<char[]> udp_recv_buf_;
	};

	class socks5_listener final : public prx_listener
	{
	public:
		socks5_listener(std::function<std::unique_ptr<prx_tcp_socket>()> &&_gen_socket, const endpoint &_server_ep)
			:server_ep_(_server_ep), local_ep_(0ul, 0), methods_("\x80\x00", 2), gen_socket_(std::move(_gen_socket))
		{
		}
		virtual ~socks5_listener() override {}

		virtual bool is_open() override { return cur_socket_ && cur_socket_->is_open(); }
		virtual bool is_listening() override { return listening_ && is_open(); }

		virtual void local_endpoint(endpoint &ep, error_code &ec) override { ep = local_ep_; ec = 0; }

		virtual void open(error_code &ec) override;
		virtual void async_open(null_callback &&complete_handler) override;

		virtual void bind(const endpoint &endpoint, error_code &ec) override;
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override;

		virtual void listen(error_code &ec) override;
		virtual void async_listen(null_callback &&complete_handler) override;

		virtual void accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &err) override;
		virtual void async_accept(accept_callback &&complete_handler) override;

		virtual void close(error_code &err) override;
		virtual void async_close(null_callback &&complete_handler) override;
	private:
		void reset() { listening_ = false; }

		bool listening_ = false;

		endpoint server_ep_, local_ep_;
		std::string methods_;

		std::function<std::unique_ptr<prx_tcp_socket>()> gen_socket_;
		std::unique_ptr<socks5_tcp_socket> cur_socket_;
	};

}

#endif
