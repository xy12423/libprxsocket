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

#ifndef LIBPRXSOCKET_H_SOCKET_SS_CRYPTO
#define LIBPRXSOCKET_H_SOCKET_SS_CRYPTO

#include "socket_transparent.h"
#include "crypto_base.h"

namespace prxsocket
{
	namespace ss
	{

		class ss_crypto_tcp_socket final : public transparent_tcp_socket
		{
			static constexpr size_t SEND_SIZE_PREF = 0x1F80;
			static constexpr size_t SEND_SIZE_MAX = 0x2000;
			static constexpr size_t RECV_BUF_SIZE = 0x2000;

			static constexpr size_t transfer_size(size_t buffer_size) { return buffer_size > SEND_SIZE_MAX ? SEND_SIZE_PREF : buffer_size; }
		public:
			ss_crypto_tcp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, const std::vector<char> &key, std::unique_ptr<encryptor> &&enc, std::unique_ptr<decryptor> &&dec)
				:transparent_tcp_socket(std::move(base_socket)),
				key_(key), enc_(std::move(enc)), enc_iv_size_(enc_->iv_size()), dec_(std::move(dec)), dec_iv_size_(dec_->iv_size()),
				recv_buf_(std::make_unique<char[]>(RECV_BUF_SIZE))
			{
				assert(key_.size() >= enc_->key_size());
				assert(key_.size() >= dec_->key_size());
			}
			virtual ~ss_crypto_tcp_socket() override {}

			virtual void send(const_buffer buffer, size_t &transferred, error_code &ec) override;
			virtual void async_send(const_buffer buffer, transfer_callback &&complete_handler) override;
			virtual void recv(mutable_buffer buffer, size_t &transferred, error_code &ec) override;
			virtual void async_recv(mutable_buffer buffer, transfer_callback &&complete_handler) override;
			virtual void read(mutable_buffer buffer, error_code &ec) override { prx_tcp_socket::read(buffer, ec); }
			virtual void async_read(mutable_buffer buffer, null_callback &&complete_handler) override { prx_tcp_socket::async_read(buffer, std::move(complete_handler)); }
			virtual void write(const_buffer buffer, error_code &ec) override { prx_tcp_socket::write(buffer, ec); }
			virtual void async_write(const_buffer buffer, null_callback &&complete_handler) override { prx_tcp_socket::async_write(buffer, std::move(complete_handler)); }
			virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
			virtual void write(const_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

			virtual void shutdown(shutdown_type type, error_code &ec) override;
			virtual void async_shutdown(shutdown_type type, null_callback &&complete_handler) override;
			virtual void close(error_code &ec) override;
			virtual void async_close(null_callback &&complete_handler) override;

			const std::vector<char> &key() const { return key_; }
			const encryptor &enc() const { return *enc_; }
			const decryptor &dec() const { return *dec_; }
			void init_enc() { if (!iv_init_) { enc_->set_key(key_.data()); iv_init_ = true; } }
		private:
			void reset_send() { iv_init_ = iv_sent_ = false; }
			void reset_recv() { iv_received_ = false; dec_buf_.clear(); dec_ptr_ = 0; dec_pre_buf_type_ = DEC_PRE_BUF_NONE; dec_pre_buf_multiple_.clear(); }
			void reset() { reset_send(); reset_recv(); }

			void async_read(const std::shared_ptr<null_callback> &callback);
			void async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);

			void send_with_iv(const_buffer buffer, size_t &transferred, error_code &ec);
			void async_send_with_iv(const_buffer buffer, transfer_callback &&complete_handler);
			void write_with_iv(const_buffer_sequence &&buffer, error_code &ec);
			void async_write_with_iv(const_buffer_sequence &&buffer, null_callback &&complete_handler);

			size_t prepare_send(const_buffer buffer);
			void prepare_send(const_buffer_sequence &buffer);
			void continue_async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);

			void recv_data(error_code &ec);
			void async_recv_data(null_callback &&complete_handler);
			size_t read_data(char *dst, size_t dst_size);

			const std::vector<char> key_;
			std::unique_ptr<encryptor> enc_;
			size_t enc_iv_size_;
			std::unique_ptr<decryptor> dec_;
			size_t dec_iv_size_;

			std::vector<char> send_buf_;
			bool iv_init_ = false, iv_sent_ = false;

			std::unique_ptr<char[]> recv_buf_;
			bool iv_received_ = false;
			std::vector<char> dec_buf_;
			size_t dec_ptr_ = 0;
			enum { DEC_PRE_BUF_NONE, DEC_PRE_BUF_SINGLE, DEC_PRE_BUF_MULTIPLE } dec_pre_buf_type_ = DEC_PRE_BUF_NONE;
			mutable_buffer dec_pre_buf_single_;
			mutable_buffer_sequence dec_pre_buf_multiple_;
		};

		class ss_crypto_udp_socket final : public transparent_udp_socket
		{
			static constexpr size_t UDP_BUF_SIZE = 0x10000;
		public:
			ss_crypto_udp_socket(std::unique_ptr<prx_udp_socket> &&base_udp_socket, const std::vector<char> &key, std::unique_ptr<encryptor> &&enc, std::unique_ptr<decryptor> &&dec)
				:transparent_udp_socket(std::move(base_udp_socket)),
				key_(key), enc_(std::move(enc)), enc_iv_size_(enc_->iv_size()), dec_(std::move(dec)), dec_iv_size_(dec_->iv_size()),
				udp_recv_buf_(std::make_unique<char[]>(UDP_BUF_SIZE))
			{
				assert(key_.size() >= enc_->key_size());
				assert(key_.size() >= dec_->key_size());
			}
			virtual ~ss_crypto_udp_socket() override {}

			virtual void send_to(const endpoint &endpoint, const_buffer buffer, error_code &ec) override;
			virtual void async_send_to(const endpoint &endpoint, const_buffer buffer, null_callback &&complete_handler) override;
			virtual void recv_from(endpoint &endpoint, mutable_buffer buffer, size_t &transferred, error_code &ec) override;
			virtual void async_recv_from(endpoint &endpoint, mutable_buffer buffer, transfer_callback &&complete_handler) override;
			virtual void send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, null_callback &&complete_handler) override;
			virtual void recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, size_t &transferred, error_code &ec) override;
			virtual void async_recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, transfer_callback &&complete_handler) override;

			const std::vector<char> &key() const { return key_; }
			const encryptor &enc() const { return *enc_; }
			const decryptor &dec() const { return *dec_; }
		private:
			void reset() {}

			void encode(std::vector<char> &dst, const char *src, size_t src_size);
			void encode(std::vector<char> &dst, const_buffer_sequence &src);
			size_t decode(mutable_buffer dst, const char *src, size_t src_size);
			void decode(mutable_buffer_sequence &dst, const char *src, size_t src_size);

			std::vector<char> key_;
			std::unique_ptr<encryptor> enc_;
			size_t enc_iv_size_;
			std::unique_ptr<decryptor> dec_;
			size_t dec_iv_size_;

			std::vector<char> udp_send_buf_;
			std::unique_ptr<char[]> udp_recv_buf_;
		};

	}
}

#endif
