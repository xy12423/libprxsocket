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
#include "crypto_evp.h"

#ifndef _LIBPRXSOCKET_BUILD

#include <array>

#endif

namespace prxsocket
{

	class obfs_websock_tcp_socket final : public prx_tcp_socket
	{
		enum { STATE_INIT, STATE_OK };
		static constexpr size_t SYM_KEY_SIZE = 32, SYM_IV_SIZE = 16, SYM_BLOCK_SIZE = 16;
		static constexpr size_t WS_FRAME_PAYLOAD_LENGTH_MAX = 0x100000;

		struct ws_unpack_state
		{
			struct
			{
				byte data[14];
				size_t size_read = 0;
			} header_temp;

			size_t payload_length = 0;
			bool mask = false;

			struct
			{
				size_t size_left;
				std::array<byte, 4> masking_key;
			} payload_temp;

			std::vector<byte> payload;
		};

	public:
		obfs_websock_tcp_socket(std::unique_ptr<prx_tcp_socket> &&_socket, const std::vector<byte> &_key)
			:socket_(std::move(_socket)), key_{}, iv_{}
		{
			memcpy(key_, _key.data(), std::min(sizeof(key_), _key.size()));
		}
		obfs_websock_tcp_socket(std::unique_ptr<prx_tcp_socket> &&_socket, const std::vector<byte> &_key, const std::vector<byte> &_iv, buffer_with_data_store &&left_over)
			:state_(STATE_OK), mask_send_(false),
			socket_(std::move(_socket)), key_{}, iv_{},
			recv_buf_(std::move(left_over))
		{
			memcpy(key_, _key.data(), std::min(sizeof(key_), _key.size()));
			memcpy(iv_, _iv.data(), std::min(sizeof(iv_), _iv.size()));
			encryptor_.init(key_, sizeof(key_), iv_, sizeof(iv_));
			decryptor_.init(key_, sizeof(key_), iv_, sizeof(iv_));
		}
		~obfs_websock_tcp_socket() override {}

		virtual bool is_open() override { return socket_->is_open(); }
		virtual bool is_connected() override { return state_ >= STATE_OK && socket_->is_connected(); }

		virtual void local_endpoint(endpoint &endpoint, error_code &ec) override { return socket_->local_endpoint(endpoint, ec); }
		virtual void remote_endpoint(endpoint &endpoint, error_code &ec) override { return socket_->remote_endpoint(endpoint, ec); }

		virtual void open(error_code &ec) override { return socket_->open(ec); }
		virtual void async_open(null_callback &&complete_handler) override { return socket_->async_open(std::move(complete_handler)); }

		virtual void bind(const endpoint &endpoint, error_code &ec) override { return socket_->bind(endpoint, ec); }
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { return socket_->async_bind(endpoint, std::move(complete_handler)); }

		virtual void connect(const endpoint &endpoint, error_code &ec) override;
		virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override;

		virtual size_t send_size_max() override;
		virtual void send(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, error_code &ec) override;
		virtual void async_send(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, null_callback &&complete_handler) override;
		virtual void send_partial(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, error_code &ec) override;
		virtual void async_send_partial(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, null_callback &&complete_handler) override;

		virtual void recv(const_buffer &buffer, buffer_data_store_holder &buffer_data_holder, error_code &ec) override;
		virtual void async_recv(transfer_data_callback &&complete_handler) override;

		virtual void shutdown(shutdown_type type, error_code &ec) override;
		virtual void async_shutdown(shutdown_type type, null_callback &&complete_handler) override;
		virtual void close(error_code &ec) override;
		virtual void async_close(null_callback &&complete_handler) override;
	private:
		void send_websocket_req(const std::shared_ptr<null_callback> &callback);
		void recv_websocket_resp(const std::shared_ptr<http::http_header> &header, const std::shared_ptr<null_callback> &callback);

		static std::vector<byte> pack_ws_frame_header(size_t payload_length, std::array<byte, 4> *mask);
		std::vector<byte> pack_ws_frame(const_buffer payload_final);

		bool unpack_ws_frame_header(ws_unpack_state &state, const_buffer &payload);
		bool unpack_ws_frame_payload(ws_unpack_state &state, const_buffer &payload);
		void async_recv_process_frame_header(const std::shared_ptr<ws_unpack_state> &state, const_buffer buffer, buffer_data_store_holder &&buffer_holder, const std::shared_ptr<transfer_data_callback> &callback);
		void async_recv_process_frame_payload(const std::shared_ptr<ws_unpack_state> &state, const_buffer buffer, buffer_data_store_holder &&buffer_holder, const std::shared_ptr<transfer_data_callback> &callback);

		template <class T> static void final_crypto(T &crypto)
		{
			byte final[SYM_BLOCK_SIZE]{};
			size_t final_size = sizeof(final);
			if (!crypto.final(final, final_size)) [[unlikely]]
			{
				std::vector<byte> final_vec;
				crypto.final(final_vec);
			}
		}
		void reset_send() { send_buf_.clear(); final_crypto(encryptor_); }
		void reset_recv() { recv_buf_.buffer = const_buffer(); recv_buf_.holder.reset(); final_crypto(decryptor_); }
		void reset() { reset_send(); reset_recv(); state_ = STATE_INIT; }

		int state_ = STATE_INIT;
		bool mask_send_ = true;

		std::unique_ptr<prx_tcp_socket> socket_;
		byte key_[SYM_KEY_SIZE], iv_[SYM_IV_SIZE];
		evp::encryptor<evp::cipher_aes_256_gcm> encryptor_;
		evp::decryptor<evp::cipher_aes_256_gcm> decryptor_;

		std::vector<buffer_with_data_store> send_buf_;
		buffer_with_data_store recv_buf_;
	};

	class obfs_websock_listener : public prx_listener
	{
	private:
		static constexpr size_t SYM_KEY_SIZE = 32, SYM_IV_SIZE = 16, SYM_BLOCK_SIZE = 16;

		struct accept_session {
			accept_session(std::unique_ptr<prx_tcp_socket> &&socket);

			std::unique_ptr<prx_tcp_socket> socket_accept;

			http::http_header header;
			buffer_with_data_store recv_buf_left_over;
			std::vector<byte> iv_vec;
			std::string sec_accept;
		};
	public:
		obfs_websock_listener(std::unique_ptr<prx_listener> &&_acceptor, const std::vector<byte> &_key)
			:acceptor_(std::move(_acceptor)), key_vec_(_key)
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
		void recv_websocket_req(const std::shared_ptr<accept_session> &accept_session, const std::shared_ptr<accept_callback> &callback);
		void send_websocket_resp(const std::shared_ptr<accept_session> &accept_session, const std::shared_ptr<accept_callback> &callback);

		std::unique_ptr<prx_listener> acceptor_;

		std::vector<byte> key_vec_;
	};

}

#endif
