#ifndef _H_SOCKET_SOCKS5
#define _H_SOCKET_SOCKS5

#include "socket_base.h"
#include "socks5_base.h"

class socks5_tcp_socket :public prx_tcp_socket_base, private socks5_base
{
	enum { STATE_INIT, STATE_OPEN, STATE_CONNECTED };

	friend class socks5_listener;
public:
	socks5_tcp_socket(const endpoint& _server_ep, std::unique_ptr<prx_tcp_socket_base>&& arg1)
		:socks5_base(std::move(arg1)), server_ep(_server_ep)
	{}
	socks5_tcp_socket(const endpoint& _server_ep, std::unique_ptr<prx_tcp_socket_base>&& arg1, const std::string& arg2)
		:socks5_base(std::move(arg1), arg2), server_ep(_server_ep)
	{}
	virtual ~socks5_tcp_socket() { if (state >= STATE_OPEN) socks5_base::close(); }

	virtual bool is_open() override { return state >= STATE_OPEN; }

	virtual err_type local_endpoint(endpoint& ep) override { if (state < STATE_CONNECTED) return ERR_OPERATION_FAILURE; ep = local_ep; return 0; }
	virtual err_type remote_endpoint(endpoint& ep) override { if (state < STATE_CONNECTED) return ERR_OPERATION_FAILURE; ep = remote_ep; return 0; }

	virtual err_type open() override;
	virtual void async_open(null_callback&& complete_handler) override;

	virtual err_type bind(const endpoint& endpoint) override { return ERR_UNSUPPORTED; }
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) override { complete_handler(ERR_UNSUPPORTED); }

	virtual err_type connect(const endpoint& endpoint) override;
	virtual void async_connect(const endpoint& endpoint, null_callback&& complete_handler) override;

	virtual err_type send(const const_buffer& buffer, size_t& transferred) override;
	virtual void async_send(const const_buffer& buffer, transfer_callback&& complete_handler) override;
	virtual err_type recv(const mutable_buffer& buffer, size_t& transferred) override;
	virtual void async_recv(const mutable_buffer& buffer, transfer_callback&& complete_handler) override;

	virtual err_type close() override { state = STATE_INIT; return socks5_base::close(); }
	virtual void async_close(null_callback&& complete_handler) override { state = STATE_INIT; socks5_base::async_close(std::move(complete_handler)); }
private:
	endpoint server_ep, local_ep, remote_ep;

	int state = STATE_INIT;
};

class socks5_udp_socket :public prx_udp_socket_base, private socks5_base
{
	enum { STATE_INIT, STATE_ASSOCIATED };

	static constexpr size_t udp_buf_size = 0x10000;
public:
	socks5_udp_socket(const endpoint& _server_ep, std::unique_ptr<prx_tcp_socket_base>&& arg1, std::unique_ptr<prx_udp_socket_base>&& arg2)
		:socks5_base(std::move(arg1), "\x80\x00", 2), server_ep(_server_ep), udp_socket(std::move(arg2)), udp_recv_buf(std::make_unique<char[]>(udp_buf_size))
	{
	}
	socks5_udp_socket(const endpoint& _server_ep, std::unique_ptr<prx_tcp_socket_base>&& arg1)
		:socks5_base(std::move(arg1), "\x80", 1), server_ep(_server_ep), udp_recv_buf(std::make_unique<char[]>(udp_buf_size))
	{
	}
	virtual ~socks5_udp_socket() { if (udp_socket) udp_socket->close(); if (state > STATE_INIT) socks5_base::close(); }

	virtual bool is_open() override { return state > STATE_INIT; }

	virtual err_type local_endpoint(endpoint& ep) override;

	virtual err_type open() override;
	virtual void async_open(null_callback&& complete_handler) override;

	virtual err_type bind(const endpoint& endpoint) override;
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) override;

	virtual err_type send_to(const endpoint& endpoint, const const_buffer& buffer) override;
	virtual void async_send_to(const endpoint& endpoint, const const_buffer& buffer, null_callback&& complete_handler) override;
	virtual err_type recv_from(endpoint& endpoint, const mutable_buffer& buffer, size_t& transferred) override;
	virtual void async_recv_from(endpoint& endpoint, const mutable_buffer& buffer, transfer_callback&& complete_handler) override;

	virtual err_type close() override { state = STATE_INIT; return socks5_base::close(); }
	virtual void async_close(null_callback&& complete_handler) override { state = STATE_INIT; socks5_base::async_close(std::move(complete_handler)); }
private:
	err_type open(const endpoint& endpoint);
	void async_open(const endpoint& endpoint, null_callback&& complete_handler);
	void udp_alive();
	void async_skip(size_t size, const std::shared_ptr<transfer_callback>& callback);
	err_type parse_udp(size_t udp_recv_size, endpoint& ep, const mutable_buffer& buffer, size_t& transferred);

	endpoint server_ep, udp_server_ep, udp_recv_ep, udp_local_ep;
	std::unique_ptr<prx_udp_socket_base> udp_socket;
	std::unique_ptr<char[]> udp_recv_buf;
	char udp_alive_buf;

	int state = STATE_INIT;
};

class socks5_listener :public prx_listener_base
{
public:
	socks5_listener(const endpoint& _server_ep, std::function<prx_tcp_socket_base*()>&& _gen_socket)
		:server_ep(_server_ep), local_ep(0ul, 0), methods("\x80\x00", 2), gen_socket(std::move(_gen_socket))
	{}
	virtual ~socks5_listener() {}

	virtual bool is_open() override { return cur_socket && cur_socket->is_open(); }

	virtual err_type local_endpoint(endpoint& ep) override { ep = local_ep; return 0; }

	virtual err_type open();
	virtual void async_open(null_callback&& complete_handler);

	virtual err_type bind(const endpoint& endpoint) override;
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler);

	virtual err_type listen() override;
	virtual void async_listen(null_callback&& complete_handler) override;

	virtual prx_tcp_socket_base* accept() override;
	virtual void async_accept(accept_callback&& complete_handler) override;

	virtual err_type close() override;
	virtual void async_close(null_callback&& complete_handler) override;
private:
	endpoint server_ep, local_ep;
	std::string methods;

	std::function<prx_tcp_socket_base*()> gen_socket;
	std::unique_ptr<socks5_tcp_socket> cur_socket;

	bool listening = false;
};

#endif
