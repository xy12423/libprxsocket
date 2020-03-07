#ifndef LIBPRXSOCKET_H_SOCKET_SS
#define LIBPRXSOCKET_H_SOCKET_SS

#include "socket_base.h"

class ss_tcp_socket : public prx_tcp_socket
{
	enum { STATE_INIT, STATE_OK };
	static constexpr size_t recv_buf_size = 0x800;
public:
	ss_tcp_socket(const endpoint &server_endpoint, std::unique_ptr<prx_tcp_socket> &&base_socket)
		:socket(std::move(base_socket)), server_ep(server_endpoint), recv_buf(std::make_unique<char[]>(recv_buf_size))
	{}
	virtual ~ss_tcp_socket() override {}

	virtual bool is_open() override { return socket->is_open(); }
	virtual bool is_connected() override { return state >= STATE_OK && socket->is_connected(); }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void remote_endpoint(endpoint &ep, error_code &ec) override { ec = 0; if (!is_connected()) { ec = ERR_OPERATION_FAILURE; return; } ep = remote_ep; }

	virtual void open(error_code &ec) override { return socket->open(ec); }
	virtual void async_open(null_callback &&complete_handler) override { socket->async_open(std::move(complete_handler)); }

	virtual void bind(const endpoint &endpoint, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { complete_handler(ERR_UNSUPPORTED); }

	virtual void connect(const endpoint &endpoint, error_code &ec) override;
	virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override;

	virtual void send(const const_buffer &buffer, size_t &transferred, error_code &ec) override;
	virtual void async_send(const const_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void recv(const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
	virtual void async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override;
	virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
	virtual void write(const_buffer_sequence &&buffer, error_code &ec) override;
	virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

	virtual void close(error_code &ec) override { state = STATE_INIT; socket->close(ec); }
	virtual void async_close(null_callback &&complete_handler) override { state = STATE_INIT; socket->async_close(std::move(complete_handler)); }
private:
	void close() { error_code ec; close(ec); }

	int state = STATE_INIT;

	std::unique_ptr<prx_tcp_socket> socket;
	endpoint server_ep, remote_ep;
	std::unique_ptr<char[]> recv_buf;
};

class ss_udp_socket : public prx_udp_socket
{
	static constexpr size_t udp_buf_size = 0x10000;
public:
	ss_udp_socket(const endpoint &_udp_server_ep, std::unique_ptr<prx_udp_socket> &&base_udp_socket)
		:udp_socket(std::move(base_udp_socket)), udp_server_ep(_udp_server_ep), udp_recv_buf(std::make_unique<char[]>(udp_buf_size))
	{
	}
	virtual ~ss_udp_socket() override {}

	virtual bool is_open() override { return udp_socket->is_open(); }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = ERR_UNSUPPORTED; }

	virtual void open(error_code &ec) override { return udp_socket->open(ec); }
	virtual void async_open(null_callback &&complete_handler) override { udp_socket->async_open(std::move(complete_handler)); }

	virtual void bind(const endpoint &endpoint, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { complete_handler(ERR_UNSUPPORTED); }

	virtual void send_to(const endpoint &endpoint, const const_buffer &buffer, error_code &ec) override;
	virtual void async_send_to(const endpoint &endpoint, const const_buffer &buffer, null_callback &&complete_handler) override;
	virtual void recv_from(endpoint &endpoint, const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
	virtual void async_recv_from(endpoint &endpoint, const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, error_code &ec) override;
	virtual void async_send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, null_callback &&complete_handler) override;
	virtual void recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, size_t &transferred, error_code &ec) override;
	virtual void async_recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, transfer_callback &&complete_handler) override;

	virtual void close(error_code &ec) override { udp_socket->close(ec); }
	virtual void async_close(null_callback &&complete_handler) override { udp_socket->async_close(std::move(complete_handler)); }
private:
	std::unique_ptr<prx_udp_socket> udp_socket;
	endpoint udp_server_ep, udp_recv_ep;
	std::unique_ptr<char[]> udp_recv_buf;
};

#endif
