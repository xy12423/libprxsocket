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

#ifndef LIBPRXSOCKET_H_SOCKET_OBFS_WEBSOCK
#define LIBPRXSOCKET_H_SOCKET_OBFS_WEBSOCK

#include "socket_base.h"
#include "http_header.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#endif

namespace prxsocket
{

	class obfs_websock_tcp_socket final : public prx_tcp_socket
	{
		enum { STATE_INIT, STATE_OK };
		static constexpr size_t SYM_BLOCK_SIZE = 16;
		static constexpr size_t SHA1_SIZE = 20;
		static constexpr size_t SEND_SIZE_PREF = 0x1F00;
		static constexpr size_t SEND_SIZE_MAX = 0x1F80;
		static constexpr size_t RECV_BUF_SIZE = 0x2000;

		static constexpr size_t transfer_size(size_t buffer_size) { return buffer_size > SEND_SIZE_MAX ? SEND_SIZE_PREF : buffer_size; }
	public:
		obfs_websock_tcp_socket(std::unique_ptr<prx_tcp_socket> &&_socket, const std::string &_key)
			:socket_(std::move(_socket)), recv_buf_(std::make_unique<char[]>(RECV_BUF_SIZE)),
			key_(SYM_BLOCK_SIZE), iv_(SYM_BLOCK_SIZE)
		{
			constexpr size_t block_size = SYM_BLOCK_SIZE;
			memcpy(key_.data(), _key.data(), std::min(block_size, _key.size()));
		}
		obfs_websock_tcp_socket(std::unique_ptr<prx_tcp_socket> &&_socket, const std::string &_key, const std::string &_iv)
			:state_(STATE_OK),
			socket_(std::move(_socket)), recv_buf_(std::make_unique<char[]>(RECV_BUF_SIZE)),
			key_(SYM_BLOCK_SIZE), iv_(SYM_BLOCK_SIZE)
		{
			constexpr size_t block_size = SYM_BLOCK_SIZE;
			memcpy(key_.data(), _key.data(), std::min(block_size, _key.size()));
			memcpy(iv_.data(), _iv.data(), std::min(block_size, _iv.size()));
			e_.SetKeyWithIV(key_, SYM_BLOCK_SIZE, iv_);
			d_.SetKeyWithIV(key_, SYM_BLOCK_SIZE, iv_);
		}
		virtual ~obfs_websock_tcp_socket() override {}

		virtual bool is_open() override { return socket_->is_open(); }
		virtual bool is_connected() override { return state_ >= STATE_OK && socket_->is_connected(); }

		virtual void local_endpoint(endpoint &ep, error_code &ec) override { return socket_->local_endpoint(ep, ec); }
		virtual void remote_endpoint(endpoint &ep, error_code &ec) override { return socket_->remote_endpoint(ep, ec); }

		virtual void open(error_code &ec) override { return socket_->open(ec); }
		virtual void async_open(null_callback &&complete_handler) override { socket_->async_open(std::move(complete_handler)); }

		virtual void bind(const endpoint &endpoint, error_code &ec) override { return socket_->bind(endpoint, ec); }
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { socket_->async_bind(endpoint, std::move(complete_handler)); }

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
		void reset_send() {}
		void reset_recv() { dec_buf_.clear(); dec_ptr_ = 0; }
		void reset() { reset_send(); reset_recv(); state_ = STATE_INIT; }

		void encode(std::string &dst, const char *src, size_t size);
		void decode(std::string &dst, const char *src, size_t size);

		void send_websocket_req(const std::shared_ptr<null_callback> &callback);
		void recv_websocket_resp(const std::shared_ptr<null_callback> &callback, const std::shared_ptr<http_helper::http_header> &header, size_t recv_buf_ptr = 0, size_t recv_buf_ptr_end = 0);

		error_code recv_data();
		void async_recv_data(null_callback &&complete_handler);
		void async_recv_data_size_16(const std::shared_ptr<null_callback> &callback);
		void async_recv_data_size_64(const std::shared_ptr<null_callback> &callback);
		void async_recv_data_body(const std::shared_ptr<null_callback> &callback, size_t size);
		size_t read_data(char *buf, size_t size);

		void async_read(const std::shared_ptr<mutable_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);
		void async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);

		int state_ = STATE_INIT;

		std::unique_ptr<prx_tcp_socket> socket_;
		std::string send_buf_;
		std::unique_ptr<char[]> recv_buf_;
		std::string dec_buf_;
		size_t dec_ptr_ = 0;

		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e_;
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d_;
		CryptoPP::SecByteBlock key_, iv_;
	};

	class obfs_websock_listener final : public prx_listener
	{
	private:
		static constexpr size_t SYM_BLOCK_SIZE = 16;
		static constexpr size_t RECV_BUF_SIZE = 0x400;

		struct accept_session {
			accept_session(std::unique_ptr<prx_tcp_socket> &&socket);

			std::unique_ptr<prx_tcp_socket> socket_accept;

			std::unique_ptr<char[]> recv_buf;
			size_t recv_buf_ptr, recv_buf_ptr_end;

			http_helper::http_header header;
			std::string iv, sec_accept;
		};
	public:
		obfs_websock_listener(std::unique_ptr<prx_listener> &&_acceptor, const std::string &_key)
			:acceptor_(std::move(_acceptor)),
			key_(_key)
		{
		}
		virtual ~obfs_websock_listener() override {}

		virtual bool is_open() override { return acceptor_->is_open(); }
		virtual bool is_listening() override { return acceptor_->is_listening(); }

		virtual void local_endpoint(endpoint &ep, error_code &ec) override { return acceptor_->local_endpoint(ep, ec); }

		virtual void open(error_code &ec) override { return acceptor_->open(ec); }
		virtual void async_open(null_callback &&complete_handler) override { acceptor_->async_open(std::move(complete_handler)); }

		virtual void bind(const endpoint &endpoint, error_code &ec) override { return acceptor_->bind(endpoint, ec); }
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { acceptor_->async_bind(endpoint, std::move(complete_handler)); }

		virtual void listen(error_code &ec) override { return acceptor_->listen(ec); }
		virtual void async_listen(null_callback &&complete_handler) override { acceptor_->async_listen(std::move(complete_handler)); }

		virtual void accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &ec) override;
		virtual void async_accept(accept_callback &&complete_handler) override;

		virtual void close(error_code &ec) override { return acceptor_->close(ec); }
		virtual void async_close(null_callback &&complete_handler) override { acceptor_->async_close(std::move(complete_handler)); }
	private:
		void recv_websocket_req(
			const std::shared_ptr<accept_callback> &callback,
			const std::shared_ptr<accept_session> &accept_session
		);
		void send_websocket_resp(const std::shared_ptr<accept_callback> &callback, const std::shared_ptr<accept_session> &accept_session);

		std::unique_ptr<prx_listener> acceptor_;

		std::string key_;
	};

}

#endif
