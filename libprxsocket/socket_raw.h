#ifndef _H_SOCKET_RAW
#define _H_SOCKET_RAW

#include "socket_base.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <memory>

#include <boost/asio.hpp>
namespace asio = boost::asio;
#endif

class raw_tcp_socket :public prx_tcp_socket_base
{
public:
	raw_tcp_socket(asio::io_context& iosrv) :socket(iosrv), resolver(iosrv) { set_keep_alive(); }
	raw_tcp_socket(asio::ip::tcp::socket&& native_socket) :socket(std::move(native_socket)), resolver(socket.get_executor().context()) { set_keep_alive(); }
	virtual ~raw_tcp_socket() {}

	virtual bool is_open() override { return socket.is_open(); }

	virtual err_type local_endpoint(endpoint& ep) override;
	virtual err_type remote_endpoint(endpoint& ep) override;

	virtual err_type open() override { socket.open(asio::ip::tcp::v4(), ec); binded = false; return (ec ? ERR_OPERATION_FAILURE : 0); }
	virtual void async_open(null_callback&& complete_handler) override { socket.open(asio::ip::tcp::v4(), ec); binded = false; complete_handler(ec ? ERR_OPERATION_FAILURE : 0); }

	virtual err_type bind(const endpoint& endpoint) override;
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) override;

	virtual err_type connect(const endpoint& endpoint) override;
	virtual void async_connect(const endpoint& endpoint, null_callback&& complete_handler) override;

	virtual err_type send(const const_buffer& buffer, size_t& transferred) override;
	virtual void async_send(const const_buffer& buffer, transfer_callback&& complete_handler) override;
	virtual err_type recv(const mutable_buffer& buffer, size_t& transferred) override;
	virtual void async_recv(const mutable_buffer& buffer, transfer_callback&& complete_handler) override;

	virtual err_type close() override;
	virtual void async_close(null_callback&& complete_handler) override;
private:
	void set_keep_alive();

	void check_protocol(const asio::ip::tcp::endpoint::protocol_type&);
	err_type connect_addr_str(const std::string& addr, port_type port);
	void async_connect_addr_str(const std::string& addr, port_type port, const std::shared_ptr<null_callback>& callback);

	boost::system::error_code ec;
	asio::ip::tcp::socket socket;
	asio::ip::tcp::resolver resolver;

	bool binded = false;
};

class raw_udp_socket :public prx_udp_socket_base
{
public:
	raw_udp_socket(asio::io_context& iosrv) :socket(iosrv), resolver(iosrv) {}
	virtual ~raw_udp_socket() {}

	virtual bool is_open() override { return socket.is_open(); }
	
	virtual err_type local_endpoint(endpoint& ep) override;

	virtual err_type open() override;
	virtual void async_open(null_callback&& complete_handler) override;

	virtual err_type bind(const endpoint& endpoint) override;
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) override;

	virtual err_type send_to(const endpoint& endpoint, const const_buffer& buffer) override;
	virtual void async_send_to(const endpoint& endpoint, const const_buffer& buffer, null_callback&& complete_handler) override;
	virtual err_type recv_from(endpoint& endpoint, const mutable_buffer& buffer, size_t& transferred) override;
	virtual void async_recv_from(endpoint& endpoint, const mutable_buffer& buffer, transfer_callback&& complete_handler) override;

	virtual err_type close() override;
	virtual void async_close(null_callback&& complete_handler) override;
private:
	err_type to_udp_ep(const endpoint& ep, asio::ip::udp::endpoint& result);
	void async_to_udp_ep(const endpoint& ep, std::function<void(err_type, const asio::ip::udp::endpoint&)>&& complete_handler);

	boost::system::error_code ec;
	asio::ip::udp::socket socket;
	asio::ip::udp::endpoint recv_ep;
	asio::ip::udp::resolver resolver;
};

class raw_listener :public prx_listener_base
{
public:
	raw_listener(asio::io_context& _iosrv) :iosrv(_iosrv), acceptor(iosrv) {}
	virtual ~raw_listener() {}

	virtual bool is_open() override { return acceptor.is_open(); }

	virtual err_type local_endpoint(endpoint& ep);

	virtual err_type open() override { acceptor.open(asio::ip::tcp::v4(), ec); return (ec ? ERR_OPERATION_FAILURE : 0); }
	virtual void async_open(null_callback&& complete_handler) override { acceptor.open(asio::ip::tcp::v4(), ec); complete_handler(ec ? ERR_OPERATION_FAILURE : 0); }

	virtual err_type bind(const endpoint& endpoint) override;
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) override;

	virtual err_type listen() override;

	virtual prx_tcp_socket_base* accept() override;
	virtual void async_accept(accept_callback&& complete_handler) override;

	virtual err_type close() override { acceptor.close(ec); return (ec ? ERR_OPERATION_FAILURE : 0);  }
	virtual void async_close(null_callback&& complete_handler) override { acceptor.close(ec); complete_handler(ec ? ERR_OPERATION_FAILURE : 0); }
private:
	boost::system::error_code ec;
	asio::io_context &iosrv;
	asio::ip::tcp::acceptor acceptor;
};

#endif
