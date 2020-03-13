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
			static constexpr size_t send_size_pref = 0xF80;
			static constexpr size_t send_size_max = 0x1000;
			static constexpr size_t recv_buf_size = 0x1000;

			static constexpr size_t transfer_size(size_t buffer_size) { return buffer_size > send_size_max ? send_size_pref : buffer_size; }
			void reset() { iv_init_ = iv_sent_ = iv_received_ = false; dec_buf_.clear(); dec_ptr_ = 0; }
		public:
			ss_crypto_tcp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, const std::vector<char> &key, std::unique_ptr<encryptor> &&enc, std::unique_ptr<decryptor> &&dec)
				:transparent_tcp_socket(std::move(base_socket)),
				key_(key), enc_(std::move(enc)), enc_iv_size_(enc_->iv_size()), dec_(std::move(dec)), dec_iv_size_(dec_->iv_size()),
				recv_buf_(std::make_unique<char[]>(recv_buf_size))
			{
				assert(key_.size() >= enc_->key_size());
				assert(key_.size() >= dec_->key_size());
			}
			virtual ~ss_crypto_tcp_socket() override {}

			virtual void send(const const_buffer &buffer, size_t &transferred, error_code &ec) override;
			virtual void async_send(const const_buffer &buffer, transfer_callback &&complete_handler) override;
			virtual void recv(const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
			virtual void async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
			virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
			virtual void write(const_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

			virtual void close(error_code &ec) override { reset(); socket_->close(ec); }
			virtual void async_close(null_callback &&complete_handler) override { reset(); socket_->async_close(std::move(complete_handler)); }

			const std::vector<char> &key() const { return key_; }
			const encryptor &enc() const { return *enc_; }
			const decryptor &dec() const { return *dec_; }
			void init_enc() { if (!iv_init_) { enc_->set_key(key_.data()); iv_init_ = true; } }
		private:
			void close() { error_code ec; close(ec); }

			void async_read(const std::shared_ptr<mutable_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);
			void async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);

			void send_with_iv(const const_buffer &buffer, size_t &transferred, error_code &ec);
			void async_send_with_iv(const const_buffer &buffer, transfer_callback &&complete_handler);
			void write_with_iv(const_buffer_sequence &&buffer, error_code &ec);
			void async_write_with_iv(const_buffer_sequence &&buffer, null_callback &&complete_handler);

			size_t prepare_send(const const_buffer &buffer);
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
		};

		class ss_crypto_udp_socket final : public transparent_udp_socket
		{
			static constexpr size_t udp_buf_size = 0x10000;
		public:
			ss_crypto_udp_socket(std::unique_ptr<prx_udp_socket> &&base_udp_socket, const std::vector<char> &key, std::unique_ptr<encryptor> &&enc, std::unique_ptr<decryptor> &&dec)
				:transparent_udp_socket(std::move(base_udp_socket)),
				key_(key), enc_(std::move(enc)), enc_iv_size_(enc_->iv_size()), dec_(std::move(dec)), dec_iv_size_(dec_->iv_size()),
				udp_recv_buf_(std::make_unique<char[]>(udp_buf_size))
			{
				assert(key_.size() >= enc_->key_size());
				assert(key_.size() >= dec_->key_size());
			}
			virtual ~ss_crypto_udp_socket() override {}

			virtual void send_to(const endpoint &endpoint, const const_buffer &buffer, error_code &ec) override;
			virtual void async_send_to(const endpoint &endpoint, const const_buffer &buffer, null_callback &&complete_handler) override;
			virtual void recv_from(endpoint &endpoint, const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
			virtual void async_recv_from(endpoint &endpoint, const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
			virtual void send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, null_callback &&complete_handler) override;
			virtual void recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, size_t &transferred, error_code &ec) override;
			virtual void async_recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, transfer_callback &&complete_handler) override;

			const std::vector<char> &key() const { return key_; }
			const encryptor &enc() const { return *enc_; }
			const decryptor &dec() const { return *dec_; }
		private:
			void close() { error_code ec; transparent_udp_socket::close(ec); }

			void encode(std::vector<char> &dst, const char *src, size_t src_size);
			//Returns thread_local buffer. Use with caution.
			std::vector<char> &decode(const char *src, size_t src_size);

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
