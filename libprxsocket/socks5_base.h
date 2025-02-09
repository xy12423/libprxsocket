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

#ifndef LIBPRXSOCKET_H_SOCKS5_BASE
#define LIBPRXSOCKET_H_SOCKS5_BASE

#include "socket_base.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <array>
#endif

namespace prxsocket
{
	namespace socks5
	{
		using sockssel_callback = std::function<uint8_t(int, const uint8_t *)>;
		using socksreq_callback = std::function<void(error_code, uint8_t, const endpoint &)>;

		class socks5_base
		{
			static constexpr unsigned int SOCKS_VERSION = 5;
		public:
			enum { CONNECT = 1, BIND = 2, UDP_ASSOCIATE = 3 };

			socks5_base(std::unique_ptr<prx_tcp_socket> &&arg)
				:socket_(std::move(arg)), available_methods_{ byte{0} }
			{
			}
			template <typename... T>
			socks5_base(std::unique_ptr<prx_tcp_socket> &&arg, T &&...args)
				: socket_(std::move(arg)), available_methods_(std::forward<T>(args)...)
			{
			}

			error_code auth();
			void async_auth(null_callback &&complete_handler);

			error_code open_and_auth(const endpoint &server_ep);
			void async_open_and_auth(const endpoint &server_ep, null_callback &&complete_handler);

			uint8_t get_auth_method() const { return auth_method_; }

			static void make_s5_header(std::vector<byte> &req, uint8_t type, const endpoint &ep);

			error_code recv_s5(uint8_t &resp, endpoint &result);
			void async_recv_s5(socksreq_callback &&complete_handler);

			static error_code parse_udp(const byte *recv, size_t recv_size, endpoint &ep, const byte *&data_start_at, size_t &data_size);
		protected:
			void read(mutable_buffer buffer, error_code &ec);
			void async_read(mutable_buffer buffer, null_callback &&complete_handler);

			void reset() { socket_recv_buf_.buffer = const_buffer(); socket_recv_buf_.holder.reset(); auth_method_ = 0xFF; }

			std::unique_ptr<prx_tcp_socket> socket_;
			buffer_with_data_store socket_recv_buf_;
		private:
			void async_auth_recv(const std::shared_ptr<null_callback> &callback);

			void close() { reset(); error_code err; socket_->close(err); }

			std::vector<byte> available_methods_;
			uint8_t auth_method_ = 0xFF;
		};

		class socks5_error : public std::runtime_error
		{
		public:
			socks5_error(error_code _err) :std::runtime_error("SOCKS5 error"), err(_err) {}

			error_code get_err() const { return err; }
		private:
			error_code err;
		};

	}
}
#endif
