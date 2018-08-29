#ifndef _H_SOCKET
#define _H_SOCKET

#include "endpoint.h"
#include "buffer.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <functional>
#endif

typedef int err_type;
typedef std::function<void(err_type)> null_callback;
typedef std::function<void(err_type, size_t)> transfer_callback;

enum {
	WARN_ALREADY_IN_STATE  = -11,
	WARN_UNSUPPORTED       = -7,
	WARN_OPERATION_FAILURE = -1,
	ERR_OPERATION_FAILURE  = 1,
	ERR_UNRESOLVED_HOST    = 4,
	ERR_CONNECTION_REFUSED = 5,
	ERR_UNSUPPORTED        = 7,
	ERR_BAD_ARG_LOCAL      = 9,
	ERR_BAD_ARG_REMOTE     = 10,
	ERR_ALREADY_IN_STATE   = 11,
};

class prx_tcp_socket_base
{
public:
	prx_tcp_socket_base() = default;
	prx_tcp_socket_base(const prx_tcp_socket_base&) = delete;
	prx_tcp_socket_base(prx_tcp_socket_base&&) = default;
	virtual ~prx_tcp_socket_base() {}

	virtual bool is_open() = 0;

	virtual err_type local_endpoint(endpoint& ep) = 0;
	virtual err_type remote_endpoint(endpoint& ep) = 0;

	virtual err_type open() = 0;
	virtual void async_open(null_callback&& complete_handler) = 0;

	virtual err_type bind(const endpoint& endpoint) = 0;
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) = 0;

	virtual err_type connect(const endpoint& endpoint) = 0;
	virtual void async_connect(const endpoint& endpoint, null_callback&& complete_handler) = 0;

	virtual err_type send(const const_buffer& buffer, size_t& transferred) = 0;
	virtual void async_send(const const_buffer& buffer, transfer_callback&& complete_handler) = 0;
	virtual err_type recv(const mutable_buffer& buffer, size_t& transferred) = 0;
	virtual void async_recv(const mutable_buffer& buffer, transfer_callback&& complete_handler) = 0;

	virtual err_type close() = 0;
	virtual void async_close(null_callback&& complete_handler) = 0;
};

err_type read(prx_tcp_socket_base& socket, const mutable_buffer& buffer);
void async_read(prx_tcp_socket_base& socket, const mutable_buffer& buffer, null_callback&& complete_handler);
err_type write(prx_tcp_socket_base& socket, const const_buffer& buffer);
void async_write(prx_tcp_socket_base& socket, const const_buffer& buffer, null_callback&& complete_handler);

class prx_udp_socket_base
{
public:
	prx_udp_socket_base() = default;
	prx_udp_socket_base(const prx_udp_socket_base&) = delete;
	prx_udp_socket_base(prx_udp_socket_base&&) = default;
	virtual ~prx_udp_socket_base() {}

	virtual bool is_open() = 0;

	virtual err_type local_endpoint(endpoint& ep) = 0;

	virtual err_type open() = 0;
	virtual void async_open(null_callback&& complete_handler) = 0;

	virtual err_type bind(const endpoint& endpoint) = 0;
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) = 0;

	virtual err_type send_to(const endpoint& endpoint, const const_buffer& buffer) = 0;
	virtual void async_send_to(const endpoint& endpoint, const const_buffer& buffer, null_callback&& complete_handler) = 0;
	virtual err_type recv_from(endpoint& endpoint, const mutable_buffer& buffer, size_t& transferred) = 0;
	virtual void async_recv_from(endpoint& endpoint, const mutable_buffer& buffer, transfer_callback&& complete_handler) = 0;

	virtual err_type close() = 0;
	virtual void async_close(null_callback&& complete_handler) = 0;
};

class prx_listener_base
{
public:
	typedef std::function<void(err_type, prx_tcp_socket_base*)> accept_callback;

	prx_listener_base() = default;
	prx_listener_base(const prx_listener_base&) = delete;
	prx_listener_base(prx_listener_base&&) = default;
	virtual ~prx_listener_base() {}

	virtual bool is_open() = 0;

	virtual err_type local_endpoint(endpoint& ep) = 0;

	virtual err_type open() = 0;
	virtual void async_open(null_callback&& complete_handler) = 0;

	virtual err_type bind(const endpoint& endpoint) = 0;
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) = 0;

	virtual err_type listen() = 0;

	virtual prx_tcp_socket_base* accept() = 0;
	virtual void async_accept(accept_callback&& complete_handler) = 0;

	virtual err_type close() = 0;
	virtual void async_close(null_callback&& complete_handler) = 0;
};

#endif
