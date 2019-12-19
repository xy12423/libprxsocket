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
	virtual ~socks5_tcp_socket() {}

	virtual bool is_open() override { return state >= STATE_OPEN; }
	virtual bool is_connected() override { return state >= STATE_CONNECTED; }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = 0; if (!is_connected()) { ec = ERR_OPERATION_FAILURE; return; } ep = local_ep; }
	virtual void remote_endpoint(endpoint &ep, error_code &ec) override { ec = 0; if (!is_connected()) { ec = ERR_OPERATION_FAILURE; return; } ep = remote_ep; }

	virtual void open(error_code &ec) override;
	virtual void async_open(null_callback &&complete_handler) override;

	virtual void bind(const endpoint &endpoint, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void async_bind(const endpoint &endpoint, null_callback&& complete_handler) override { complete_handler(ERR_UNSUPPORTED); }

	virtual void connect(const endpoint &endpoint, error_code &ec) override;
	virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override;

	virtual void send(const const_buffer &buffer, size_t &transferred, error_code &ec) override;
	virtual void async_send(const const_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void recv(const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
	virtual void async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler) override;

	virtual void close(error_code &ec) override { state = STATE_INIT; socks5_base::close(ec); }
	virtual void async_close(null_callback &&complete_handler) override { state = STATE_INIT; socks5_base::async_close(std::move(complete_handler)); }
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
	virtual ~socks5_udp_socket() {}

	virtual bool is_open() override { return state >= STATE_ASSOCIATED; }

	virtual void local_endpoint(endpoint& ep, error_code &ec) override;

	virtual void open(error_code &ec) override;
	virtual void async_open(null_callback&& complete_handler) override;

	virtual void bind(const endpoint& endpoint, error_code &ec) override;
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) override;

	virtual void send_to(const endpoint& endpoint, const const_buffer& buffer, error_code &ec) override;
	virtual void async_send_to(const endpoint& endpoint, const const_buffer& buffer, null_callback&& complete_handler) override;
	virtual void recv_from(endpoint& endpoint, const mutable_buffer& buffer, size_t& transferred, error_code &ec) override;
	virtual void async_recv_from(endpoint& endpoint, const mutable_buffer& buffer, transfer_callback&& complete_handler) override;

	virtual void close(error_code &ec) override { state = STATE_INIT; return socks5_base::close(ec); }
	virtual void async_close(null_callback&& complete_handler) override { state = STATE_INIT; socks5_base::async_close(std::move(complete_handler)); }
private:
	void open(const endpoint& endpoint, error_code &ec);
	void async_open(const endpoint& endpoint, null_callback&& complete_handler);
	void close() { error_code ec; state = STATE_INIT; return socks5_base::close(ec); }
	void udp_alive();
	void async_skip(size_t size, const std::shared_ptr<transfer_callback>& callback);
	error_code parse_udp(size_t udp_recv_size, endpoint& ep, const mutable_buffer& buffer, size_t& transferred);

	endpoint server_ep, udp_server_ep, udp_recv_ep, udp_local_ep;
	std::unique_ptr<prx_udp_socket_base> udp_socket;
	std::unique_ptr<char[]> udp_recv_buf;
	char udp_alive_buf;

	int state = STATE_INIT;
};

class socks5_listener :public prx_listener_base
{
public:
	socks5_listener(const endpoint& _server_ep, std::function<std::unique_ptr<prx_tcp_socket_base>()>&& _gen_socket)
		:server_ep(_server_ep), local_ep(0ul, 0), methods("\x80\x00", 2), gen_socket(std::move(_gen_socket))
	{}
	virtual ~socks5_listener() {}

	virtual bool is_open() override { return cur_socket && cur_socket->is_open(); }
	virtual bool is_listening() override { return listening && is_open(); }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { ep = local_ep; ec = 0; }

	virtual void open(error_code &ec) override;
	virtual void async_open(null_callback&& complete_handler) override;

	virtual void bind(const endpoint& endpoint, error_code &ec) override;
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler);

	virtual void listen(error_code &ec) override;
	virtual void async_listen(null_callback&& complete_handler) override;

	virtual void accept(std::unique_ptr<prx_tcp_socket_base> &socket, error_code &err) override;
	virtual void async_accept(accept_callback&& complete_handler) override;

	virtual void close(error_code &err) override;
	virtual void async_close(null_callback&& complete_handler) override;
private:
	void close() { error_code err; close(err); }

	endpoint server_ep, local_ep;
	std::string methods;

	std::function<std::unique_ptr<prx_tcp_socket_base>()> gen_socket;
	std::unique_ptr<socks5_tcp_socket> cur_socket;

	bool listening = false;
};

#endif
