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
			static constexpr size_t auth_pack_size = 1200;
			static constexpr size_t pack_size = 8100;
			static constexpr size_t recv_buf_size = 0x2000;

			void reset() { send_id_ = recv_id_ = 1; auth_sent_ = false; recv_ptr_ = recv_size_ = 0; }
		public:
			ssr_auth_aes128_sha1_tcp_socket(std::unique_ptr<ss::ss_crypto_tcp_socket> &&base_socket, ssr_auth_aes128_sha1_shared_server_data &arg)
				:transparent_tcp_socket_template<ss::ss_crypto_tcp_socket>(std::move(base_socket)),
				server_data_(arg),
				recv_buf_(std::make_unique<char[]>(recv_buf_size))
			{
			}
			virtual ~ssr_auth_aes128_sha1_tcp_socket() override {}

			virtual void send(const const_buffer &buffer, size_t &transferred, error_code &ec) override;
			virtual void async_send(const const_buffer &buffer, transfer_callback &&complete_handler) override;
			virtual void recv(const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
			virtual void async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
			virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
			virtual void write(const_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

			virtual void close(error_code &ec) override { reset(); return socket_->close(ec); }
			virtual void async_close(null_callback &&complete_handler) override { reset(); socket_->async_close(std::move(complete_handler)); }
		private:
			void close() { error_code ec; close(ec); }

			void async_read(const std::shared_ptr<mutable_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);
			void async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);

			void prepare_send_data_auth(const std::function<void(CryptoPP::HMAC<CryptoPP::SHA1> &hasher)> &src_iter, size_t src_size);
			void prepare_send_data(const std::function<void(CryptoPP::HMAC<CryptoPP::SHA1> &hasher)> &src_iter, size_t src_size);
			size_t prepare_send(const const_buffer &buffer);
			const_buffer_sequence prepare_send(const_buffer_sequence &buffer);

			void recv_data(error_code &ec);
			void async_recv_data(null_callback &&complete_handler);
			void async_recv_data_body(size_t total_size, const std::shared_ptr<null_callback> &callback);
			error_code decode_recv_data(size_t total_size);
			bool read_empty();
			size_t read_data(char *dst, size_t dst_size);

			ssr_auth_aes128_sha1_shared_server_data &server_data_;
			std::vector<char> send_key_, recv_key_;
			uint32_t send_id_ = 1, recv_id_ = 1;

			std::vector<char> send_buf_head_, send_buf_tail_;
			bool auth_sent_ = false;
			std::unique_ptr<char[]> recv_buf_;
			size_t recv_ptr_ = 0, recv_size_ = 0;
		};

	}
}

#endif
