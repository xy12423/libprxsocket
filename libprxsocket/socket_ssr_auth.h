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

#ifndef LIBPRXSOCKET_H_SOCKET_SSR_AUTH
#define LIBPRXSOCKET_H_SOCKET_SSR_AUTH

#include "socket_ss_crypto.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <mutex>

#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#endif

namespace prxsocket
{
	namespace ssr
	{

		struct ssr_auth_aes128_sha1_shared_server_data
		{
			ssr_auth_aes128_sha1_shared_server_data(const std::string &arg = std::string());
			std::pair<uint32_t, uint32_t> new_id_pair();

			std::mutex lock;
			uint32_t client_id, connection_id;
			const std::string argument;
		};

		class ssr_auth_aes128_sha1_tcp_socket final : public transparent_tcp_socket_template<ss::ss_crypto_tcp_socket>
		{
			static constexpr size_t AUTH_PACK_SIZE = 1200;
			static constexpr size_t PACK_SIZE = 8100;
			static constexpr size_t RECV_BUF_SIZE = 0x2000;
		public:
			ssr_auth_aes128_sha1_tcp_socket(std::unique_ptr<ss::ss_crypto_tcp_socket> &&base_socket, ssr_auth_aes128_sha1_shared_server_data &arg)
				:transparent_tcp_socket_template<ss::ss_crypto_tcp_socket>(std::move(base_socket)),
				server_data_(arg),
				recv_buf_(std::make_unique<char[]>(RECV_BUF_SIZE))
			{
			}
			virtual ~ssr_auth_aes128_sha1_tcp_socket() override {}

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
			void reset_send() { send_id_ = 1; auth_sent_ = false; }
			void reset_recv() { recv_id_ = 1; recv_ptr_ = recv_size_ = 0; recv_pre_buf_type_ = RECV_PRE_BUF_NONE; recv_pre_buf_multiple_.clear(); }
			void reset() { reset_send(); reset_recv(); }

			void async_read(const std::shared_ptr<null_callback> &callback);
			void async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);

			void prepare_send_data_auth(const std::function<void(CryptoPP::HMAC<CryptoPP::SHA1> &hasher)> &src_iter, size_t src_size);
			void prepare_send_data(const std::function<void(CryptoPP::HMAC<CryptoPP::SHA1> &hasher)> &src_iter, size_t src_size);
			size_t prepare_send(const_buffer buffer);
			const_buffer_sequence prepare_send(const_buffer_sequence &buffer);

			bool has_non_empty_pre_buf() const;
			void recv_data(error_code &ec);
			void async_recv_data(null_callback &&complete_handler);
			void async_recv_data_body(size_t total_size, size_t rnd_size, const std::shared_ptr<null_callback> &callback);
			mutable_buffer_sequence prepare_recv_data_body_with_pre_buf(size_t rnd_size, size_t recv_size, std::pair<size_t, size_t> &recv_ptr_on_success, uint16_t &seq_param);
			error_code decode_recv_data(size_t total_size, size_t rnd_size, mutable_buffer_sequence *recv_data = nullptr, uint16_t seq_param = 0);
			bool read_empty();
			size_t read_data(char *dst, size_t dst_size);

			ssr_auth_aes128_sha1_shared_server_data &server_data_;
			std::vector<char> send_hmac_key_, recv_hmac_key_;
			uint32_t send_id_ = 1, recv_id_ = 1;

			bool auth_sent_ = false;
			std::vector<char> send_buf_head_, send_buf_tail_;
			std::unique_ptr<char[]> recv_buf_;
			size_t recv_ptr_ = 0, recv_size_ = 0;
			enum { RECV_PRE_BUF_NONE, RECV_PRE_BUF_SINGLE, RECV_PRE_BUF_MULTIPLE } recv_pre_buf_type_ = RECV_PRE_BUF_NONE;
			mutable_buffer recv_pre_buf_single_;
			mutable_buffer_sequence recv_pre_buf_multiple_;
		};

	}
}

#endif
