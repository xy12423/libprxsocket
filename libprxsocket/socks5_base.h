#ifndef _H_SOCKS5_BASE
#define _H_SOCKS5_BASE

#include "socket_base.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <array>
#include <memory>
#include <stdexcept>
#endif

typedef std::function<uint8_t(int, const uint8_t *)> sockssel_callback;
typedef std::function<void(error_code, uint8_t, const endpoint&)> socksreq_callback;

class socks5_base
{
	static constexpr char socks_version = 5;
	std::string available_methods;

public:
	enum { CONNECT = 1, BIND = 2, UDP_ASSOCIATE = 3 };

	socks5_base(std::unique_ptr<prx_tcp_socket> &&arg)
		:socket(std::move(arg)), available_methods("\x00", 1)
	{}
	template <typename... T>
	socks5_base(std::unique_ptr<prx_tcp_socket> &&arg, T &&...args)
		:socket(std::move(arg)), available_methods(std::forward<T>(args)...)
	{}

	template <typename... T> void open(T &&...args) { return socket->open(std::forward<T>(args)...); }
	template <typename... T> void async_open(T &&...args) { socket->async_open(std::forward<T>(args)...); }

	template <typename... T> void connect(T &&...args) { return socket->connect(std::forward<T>(args)...); }
	template <typename... T> void async_connect(T &&...args) { socket->async_connect(std::forward<T>(args)...); }

	error_code auth();
	void async_auth(null_callback &&complete_handler);

	error_code select(sockssel_callback &&selector);
	void async_select(sockssel_callback &&selector, null_callback &&complete_handler);

	error_code open_and_auth(const endpoint &server_ep);
	void async_open_and_auth(const endpoint &server_ep, null_callback &&complete_handler);

	uint8_t get_auth_method() const { return auth_method; }

	error_code send_s5(uint8_t type, const endpoint &ep);
	void async_send_s5(uint8_t type, const endpoint &ep, null_callback &&complete_handler);

	error_code recv_s5(uint8_t &resp, endpoint &result);
	void async_recv_s5(socksreq_callback &&complete_handler);

	static error_code parse_udp(const char *recv, size_t recv_size, endpoint &ep, const char *&data_start_at, size_t &data_size);
	
	prx_tcp_socket &access_socket() { return *socket; }

	template <typename... T> void recv(T &&...args) { return socket->recv(std::forward<T>(args)...); }
	template <typename... T> void async_recv(T &&...args) { return socket->async_recv(std::forward<T>(args)...); }

	template <typename... T> void send(T &&...args) { return socket->send(std::forward<T>(args)...); }
	template <typename... T> void async_send(T &&...args) { return socket->async_send(std::forward<T>(args)...); }

	template <typename... T> void close(T &&...args) { auth_method = 0xFF; return socket->close(std::forward<T>(args)...); }
	template <typename... T> void async_close(T &&...args) { auth_method = 0xFF; return socket->async_close(std::forward<T>(args)...); }
private:
	void async_auth_recv(const std::shared_ptr<null_callback> &callback);
	void async_select_recv_body(const std::shared_ptr<sockssel_callback> &selector, const std::shared_ptr<std::array<char, 257>> &method_avail, const std::shared_ptr<null_callback> &callback);
	void async_select_send(const std::shared_ptr<null_callback> &callback);
	void async_recv_s5_body(const std::shared_ptr<std::array<char, 263>> &resp_data, const std::shared_ptr<socksreq_callback> &callback);

	void close() { error_code err; close(err); }

	std::unique_ptr<prx_tcp_socket> socket;

	uint8_t auth_method = 0xFF;
};

class socks5_error :public std::runtime_error
{
public:
	socks5_error(error_code _err) :std::runtime_error("SOCKS5 error"), err(_err) {}

	error_code get_err() { return err; }
private:
	error_code err;
};

#endif
