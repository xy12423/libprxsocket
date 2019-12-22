#pragma once

#include "socket_base.h"

#ifndef _LIBPRXSOCKET_BUILD
#endif

class http_tcp_socket :public prx_tcp_socket
{
	enum { STATE_INIT, STATE_OK };
	static constexpr size_t recv_buf_size = 0x800;
public:
	http_tcp_socket(const endpoint &server_endpoint, std::unique_ptr<prx_tcp_socket> &&base_socket) :server_ep(server_endpoint), socket(std::move(base_socket)) {}
	virtual ~http_tcp_socket() {}

	virtual bool is_open() override { return socket->is_open(); }
	virtual bool is_connected() override { return state >= STATE_OK && socket->is_connected(); }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void remote_endpoint(endpoint &ep, error_code &ec) override { ec = 0; if (!is_connected()) { ec = ERR_OPERATION_FAILURE; return; } ep = remote_ep; }

	virtual void open(error_code &ec) override { return socket->open(ec); }
	virtual void async_open(null_callback &&complete_handler) override { socket->async_open(std::move(complete_handler)); }

	virtual void bind(const endpoint &endpoint, error_code &ec) override { return socket->bind(endpoint, ec); }
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { socket->async_bind(endpoint, std::move(complete_handler)); }

	virtual void connect(const endpoint &endpoint, error_code &ec) override;
	virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override;

	virtual void send(const const_buffer &buffer, size_t &transferred, error_code &ec) override;
	virtual void async_send(const const_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void recv(const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
	virtual void async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler) override;

	virtual void close(error_code &ec) override { state = STATE_INIT; return socket->close(ec); }
	virtual void async_close(null_callback &&complete_handler) override { state = STATE_INIT; socket->async_close(std::move(complete_handler)); }
private:
	void close() { state = STATE_INIT; error_code ec; socket->close(ec); }
	void send_http_req(const std::shared_ptr<null_callback> &callback);
	void recv_http_resp(const std::shared_ptr<null_callback> &callback);

	int state = STATE_INIT;

	std::unique_ptr<prx_tcp_socket> socket;
	endpoint server_ep, remote_ep;
	std::unique_ptr<char[]> recv_buf;
	size_t recv_buf_ptr, recv_buf_ptr_end;
};
