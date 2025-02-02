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

#ifndef LIBPRXSOCKET_H_SOCKET_BASE
#define LIBPRXSOCKET_H_SOCKET_BASE

#include "endpoint.h"
#include "buffer.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <functional>
#include <memory>
#include <stdexcept>
#endif

namespace prxsocket
{

	using error_code = int;
	struct error_code_or_op_result
	{
		int code;
	};
	using null_callback = std::function<void(error_code)>;

	enum
	{
		ERR_OPERATION_FAILURE = 1,
		ERR_UNRESOLVED_HOST = 4,
		ERR_CONNECTION_REFUSED = 5,
		ERR_UNSUPPORTED = 7,
		ERR_BAD_ARG_LOCAL = 9,
		ERR_BAD_ARG_REMOTE = 10,
		ERR_ALREADY_IN_STATE = 11,
	};
	enum
	{
		OPRESULT_CONTINUE = 0,
		OPRESULT_COMPLETED = -1,
		OPRESULT_ERROR = -2,
	};

	class socket_exception : public std::runtime_error
	{
	public:
		socket_exception(const error_code &ec) :std::runtime_error("SOCK ERR " + std::to_string(ec)) {}
	};

	class prx_tcp_socket
	{
	public:
		static constexpr size_t transfer_size_unlimited = std::numeric_limits<size_t>::max();
		using transfer_data_callback = std::function<void(error_code, const_buffer, buffer_data_store_holder &&)>;

		enum shutdown_type : uint_fast32_t
		{
			shutdown_send    = 0x01,
			shutdown_receive = 0x02,
			shutdown_both    = shutdown_send | shutdown_receive,
		};

		prx_tcp_socket() = default;
		prx_tcp_socket(const prx_tcp_socket &) = delete;
		prx_tcp_socket(prx_tcp_socket &&) = default;
		virtual ~prx_tcp_socket() = default;

		virtual bool is_open() = 0;
		virtual bool is_connected() = 0;

		virtual void local_endpoint(endpoint &endpoint, error_code &ec) = 0;
		virtual void remote_endpoint(endpoint &endpoint, error_code &ec) = 0;

		virtual void open(error_code &ec) = 0;
		virtual void async_open(null_callback &&complete_handler) = 0;

		virtual void bind(const endpoint &endpoint, error_code &ec) = 0;
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) = 0;

		virtual void connect(const endpoint &endpoint, error_code &ec) = 0;
		virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) = 0;

		virtual size_t send_size_max() = 0;
		virtual void send(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, error_code &ec) = 0;
		virtual void async_send(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, null_callback &&complete_handler) = 0;
		virtual void send_partial(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, error_code &ec) = 0;
		virtual void async_send_partial(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, null_callback &&complete_handler) = 0;

		virtual void recv(const_buffer &buffer, buffer_data_store_holder &buffer_data_holder, error_code &ec) = 0;
		virtual void async_recv(transfer_data_callback &&complete_handler) = 0;
		virtual void recv_until(buffer_with_data_store &leftover, std::function<error_code_or_op_result(const_buffer &)> &&data_handler, error_code_or_op_result &ec_or_result);
		virtual void async_recv_until(buffer_with_data_store &&leftover, std::function<error_code_or_op_result(const_buffer &)> &&data_handler, std::function<void(error_code_or_op_result, buffer_with_data_store &&)> &&complete_handler);

		virtual void shutdown(shutdown_type type, error_code &ec) = 0;
		virtual void async_shutdown(shutdown_type type, null_callback &&complete_handler) = 0;
		virtual void close(error_code &ec) = 0;
		virtual void async_close(null_callback &&complete_handler) = 0;
	};

	class prx_udp_socket
	{
	public:
		using transfer_callback = std::function<void(error_code, size_t)>;

		prx_udp_socket() = default;
		prx_udp_socket(const prx_udp_socket &) = delete;
		prx_udp_socket(prx_udp_socket &&) = default;
		virtual ~prx_udp_socket() {}

		virtual bool is_open() = 0;

		virtual void local_endpoint(endpoint &endpoint, error_code &ec) = 0;

		virtual void open(error_code &ec) = 0;
		virtual void async_open(null_callback &&complete_handler) = 0;

		virtual void bind(const endpoint &endpoint, error_code &ec) = 0;
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) = 0;

		virtual void send_to(const endpoint &endpoint, const_buffer buffer, error_code &ec) = 0;
		virtual void async_send_to(const endpoint &endpoint, const_buffer buffer, null_callback &&complete_handler) = 0;
		virtual void recv_from(endpoint &endpoint, mutable_buffer buffer, size_t &transferred, error_code &ec) = 0;
		virtual void async_recv_from(endpoint &endpoint, mutable_buffer buffer, transfer_callback &&complete_handler) = 0;
		virtual void send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, error_code &ec) = 0;
		virtual void async_send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, null_callback &&complete_handler) = 0;
		virtual void recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, size_t &transferred, error_code &ec) = 0;
		virtual void async_recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, transfer_callback &&complete_handler) = 0;

		virtual void close(error_code &ec) = 0;
		virtual void async_close(null_callback &&complete_handler) = 0;
	};

	class prx_listener
	{
	public:
		using accept_callback = std::function<void(error_code, std::unique_ptr<prx_tcp_socket> &&)>;

		prx_listener() = default;
		prx_listener(const prx_listener &) = delete;
		prx_listener(prx_listener &&) = default;
		virtual ~prx_listener() {}

		virtual bool is_open() = 0;
		virtual bool is_listening() = 0;

		virtual void local_endpoint(endpoint &endpoint, error_code &ec) = 0;

		virtual void open(error_code &ec) = 0;
		virtual void async_open(null_callback &&complete_handler) = 0;

		virtual void bind(const endpoint &endpoint, error_code &ec) = 0;
		virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) = 0;

		virtual void listen(error_code &ec) = 0;
		virtual void async_listen(null_callback &&complete_handler) = 0;

		virtual void accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &ec) = 0;
		virtual void async_accept(accept_callback &&complete_handler) = 0;

		virtual void close(error_code &ec) = 0;
		virtual void async_close(null_callback &&complete_handler) = 0;
	};

}

#endif
