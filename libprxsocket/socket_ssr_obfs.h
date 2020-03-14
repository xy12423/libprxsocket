#ifndef LIBPRXSOCKET_H_SOCKET_SSR_OBFS
#define LIBPRXSOCKET_H_SOCKET_SSR_OBFS

#include "socket_transparent.h"

namespace prxsocket
{
	namespace ssr
	{

		class ssr_http_simple_tcp_socket final : public transparent_tcp_socket
		{
			static constexpr size_t recv_buf_size = 0x800;

			void reset() { header_sent_ = header_received_ = false; recv_buf_ptr_ = recv_buf_ptr_end_ = 0; }
		public:
			ssr_http_simple_tcp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, const std::string &arg);
			virtual ~ssr_http_simple_tcp_socket() override {}

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

			size_t make_header(std::string &dst, const const_buffer &payload);
			void wait_header(error_code &err);
			void async_wait_header(null_callback &&complete_handler);
			void async_wait_header(const std::shared_ptr<null_callback> &callback, size_t matched = 0);

			bool custom_body_ = false;
			std::string host_, body_;

			bool header_sent_ = false, header_received_ = false;
			std::unique_ptr<char[]> recv_buf_;
			size_t recv_buf_ptr_ = 0, recv_buf_ptr_end_ = 0;
		};

	}
}

#endif
