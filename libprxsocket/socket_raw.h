#ifndef _H_SOCKET_RAW
#define _H_SOCKET_RAW

#include "socket_base.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <memory>

#include <boost/asio.hpp>
namespace asio = boost::asio;
#endif

class raw_tcp_socket :public prx_tcp_socket
{
public:
	raw_tcp_socket(asio::io_context &iosrv) :socket(iosrv), resolver(iosrv) {}
	raw_tcp_socket(asio::ip::tcp::socket &&native_socket, bool is_connected = false) :socket(std::move(native_socket)), resolver(socket.get_executor()), connected(is_connected) { set_keep_alive(); }
	virtual ~raw_tcp_socket() {}

	virtual bool is_open() override { return socket.is_open(); }
	virtual bool is_connected() override { assert(!connected || is_open()); return connected && is_open(); }

	virtual void local_endpoint(endpoint &ep, error_code &err) override;
	virtual void remote_endpoint(endpoint &ep, error_code &err) override;

	virtual void open(error_code &err) override;
	virtual void async_open(null_callback &&complete_handler) override;

	virtual void bind(const endpoint &endpoint, error_code &err) override;
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override;

	virtual void connect(const endpoint &endpoint, error_code &err) override;
	virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override;

	virtual void send(const const_buffer &buffer, size_t &transferred, error_code &err) override;
	virtual void async_send(const const_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void recv(const mutable_buffer &buffer, size_t &transferred, error_code &err) override;
	virtual void async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler) override;

	virtual void close(error_code &err) override;
	virtual void async_close(null_callback &&complete_handler) override;
private:
	void set_keep_alive();

	void check_protocol(const asio::ip::tcp::endpoint::protocol_type &);
	void connect_addr_str(const std::string &addr, port_type port, error_code &err);
	void async_connect_addr_str(const std::string &addr, port_type port, const std::shared_ptr<null_callback> &callback);

	thread_local static boost::system::error_code ec;
	asio::ip::tcp::socket socket;
	asio::ip::tcp::resolver resolver;

	bool binded = false, connected = false;
};

class raw_udp_socket :public prx_udp_socket
{
public:
	raw_udp_socket(asio::io_context &iosrv) :socket(iosrv), resolver(iosrv) {}
	virtual ~raw_udp_socket() {}

	virtual bool is_open() override { return socket.is_open(); }
	
	virtual void local_endpoint(endpoint &ep, error_code &err) override;

	virtual void open(error_code &err) override;
	virtual void async_open(null_callback &&complete_handler) override;

	virtual void bind(const endpoint &endpoint, error_code &err) override;
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override;

	virtual void send_to(const endpoint &endpoint, const const_buffer &buffer, error_code &err) override;
	virtual void async_send_to(const endpoint &endpoint, const const_buffer &buffer, null_callback &&complete_handler) override;
	virtual void recv_from(endpoint &endpoint, const mutable_buffer &buffer, size_t &transferred, error_code &err) override;
	virtual void async_recv_from(endpoint &endpoint, const mutable_buffer &buffer, transfer_callback &&complete_handler) override;

	virtual void close(error_code &err) override;
	virtual void async_close(null_callback &&complete_handler) override;
private:
	error_code to_udp_ep(const endpoint &ep, asio::ip::udp::endpoint &result);
	void async_to_udp_ep(const endpoint &ep, std::function<void(error_code, const asio::ip::udp::endpoint &)> &&complete_handler);

	thread_local static boost::system::error_code ec;
	asio::ip::udp::socket socket;
	asio::ip::udp::endpoint recv_ep;
	asio::ip::udp::resolver resolver;
};

class raw_listener :public prx_listener
{
public:
	raw_listener(asio::io_context &_iosrv) :iosrv(_iosrv), acceptor(iosrv) {}
	virtual ~raw_listener() {}

	virtual bool is_open() override { return acceptor.is_open(); }
	virtual bool is_listening() override { return listening && acceptor.is_open(); }

	virtual void local_endpoint(endpoint &ep, error_code &err) override;

	virtual void open(error_code &err) override;
	virtual void async_open(null_callback &&complete_handler) override;

	virtual void bind(const endpoint &endpoint, error_code &err) override;
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override;

	virtual void listen(error_code &err) override;
	virtual void async_listen(null_callback &&complete_handler) override;

	virtual void accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &err) override;
	virtual void async_accept(accept_callback &&complete_handler) override;

	virtual void close(error_code &err) override;
	virtual void async_close(null_callback &&complete_handler) override;
private:
	thread_local static boost::system::error_code ec;
	asio::io_context &iosrv;
	asio::ip::tcp::acceptor acceptor;

	bool listening = false;
};

#endif
