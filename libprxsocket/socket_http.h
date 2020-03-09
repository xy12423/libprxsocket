#ifndef LIBPRXSOCKET_H_SOCKET_HTTP
#define LIBPRXSOCKET_H_SOCKET_HTTP

#include "socket_base.h"
#include "http_header.h"

class http_tcp_socket final : public prx_tcp_socket
{
	enum { STATE_INIT, STATE_OK };
	static constexpr size_t recv_buf_size = 0x800;
public:
	http_tcp_socket(const endpoint &server_endpoint, std::unique_ptr<prx_tcp_socket> &&base_socket)
		:socket(std::move(base_socket)), server_ep(server_endpoint), recv_buf(std::make_unique<char[]>(recv_buf_size))
	{
	}
	virtual ~http_tcp_socket() override {}

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
	virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override;
	virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
	virtual void write(const_buffer_sequence &&buffer, error_code &ec) override;
	virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

	virtual void close(error_code &ec) override { state = STATE_INIT; recv_buf_ptr = recv_buf_ptr_end = 0; return socket->close(ec); }
	virtual void async_close(null_callback &&complete_handler) override { state = STATE_INIT; recv_buf_ptr = recv_buf_ptr_end = 0; socket->async_close(std::move(complete_handler)); }
private:
	void close() { error_code ec; close(ec); }
	void send_http_req(const std::shared_ptr<null_callback> &callback);
	void recv_http_resp(const std::shared_ptr<null_callback> &callback, const std::shared_ptr<http_header> &header);

	int state = STATE_INIT;

	std::unique_ptr<prx_tcp_socket> socket;
	endpoint server_ep, remote_ep;
	std::unique_ptr<char[]> recv_buf;
	size_t recv_buf_ptr = 0, recv_buf_ptr_end = 0;
};

#endif
