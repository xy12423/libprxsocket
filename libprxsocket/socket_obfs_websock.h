#ifndef LIBPRXSOCKET_H_SOCKET_OBFS_WEBSOCK
#define LIBPRXSOCKET_H_SOCKET_OBFS_WEBSOCK

#include "socket_base.h"
#include "http_header.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <list>
#include <mutex>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/modes.h>
#endif

class obfs_websock_tcp_socket :public prx_tcp_socket
{
	enum { STATE_INIT, STATE_OK };
	static constexpr size_t sym_block_size = 16;
	static constexpr size_t sha1_size = 20;
	static constexpr size_t recv_buf_size = 0x800;
public:
	obfs_websock_tcp_socket(std::unique_ptr<prx_tcp_socket> &&_socket, const std::string &_key)
		:socket(std::move(_socket)), recv_buf(std::make_unique<char[]>(recv_buf_size)),
		key(sym_block_size), iv(sym_block_size)
	{
		constexpr size_t block_size = sym_block_size;
		memcpy(key.data(), _key.data(), std::min(block_size, _key.size()));
	}
	obfs_websock_tcp_socket(std::unique_ptr<prx_tcp_socket> &&_socket, const std::string &_key, const std::string &_iv)
		:state(STATE_OK),
		socket(std::move(_socket)), recv_buf(std::make_unique<char[]>(recv_buf_size)),
		key(sym_block_size), iv(sym_block_size)
	{
		constexpr size_t block_size = sym_block_size;
		memcpy(key.data(), _key.data(), std::min(block_size, _key.size()));
		memcpy(iv.data(), _iv.data(), std::min(block_size, _iv.size()));
		e.SetKeyWithIV(key, sym_block_size, iv);
		d.SetKeyWithIV(key, sym_block_size, iv);
	}
	virtual ~obfs_websock_tcp_socket() override {}

	virtual bool is_open() override { return socket->is_open(); }
	virtual bool is_connected() override { return state >= STATE_OK && socket->is_connected(); }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { return socket->local_endpoint(ep, ec); }
	virtual void remote_endpoint(endpoint &ep, error_code &ec) override { return socket->remote_endpoint(ep, ec); }

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

	void encode(std::string &dst, const char *src, size_t size);
	void decode(std::string &dst, const char *src, size_t size);

	void send_websocket_req(const std::shared_ptr<null_callback> &callback);
	void recv_websocket_resp(const std::shared_ptr<null_callback> &callback, const std::shared_ptr<http_header> &header, size_t recv_buf_ptr = 0, size_t recv_buf_ptr_end = 0);

	error_code recv_data();
	void async_recv_data(null_callback &&complete_handler);
	void async_recv_data_size_16(const std::shared_ptr<null_callback> &callback);
	void async_recv_data_size_64(const std::shared_ptr<null_callback> &callback);
	void async_recv_data_body(const std::shared_ptr<null_callback> &callback, size_t size);
	size_t read_data(char *buf, size_t size);

	int state = STATE_INIT;

	std::unique_ptr<prx_tcp_socket> socket;
	std::unique_ptr<char[]> recv_buf;
	std::list<std::string> recv_que;
	size_t ptr_head = 0;

	CryptoPP::AutoSeededRandomPool prng;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
	CryptoPP::SecByteBlock key, iv;
	std::mutex enc_mutex, dec_mutex;
};

class obfs_websock_listener :public prx_listener
{
private:
	static constexpr size_t sym_block_size = 16;
	static constexpr size_t recv_buf_size = 0x800;
public:
	obfs_websock_listener(std::unique_ptr<prx_listener> &&_acceptor, const std::string &_key)
		:acceptor(std::move(_acceptor)), recv_buf(std::make_unique<char[]>(recv_buf_size)),
		key(_key)
	{}
	virtual ~obfs_websock_listener() override {}

	virtual bool is_open() override { return acceptor->is_open(); }
	virtual bool is_listening() override { return acceptor->is_listening(); }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { return acceptor->local_endpoint(ep, ec); }

	virtual void open(error_code &ec) override { return acceptor->open(ec); }
	virtual void async_open(null_callback &&complete_handler) override { acceptor->async_open(std::move(complete_handler)); }

	virtual void bind(const endpoint &endpoint, error_code &ec) override { return acceptor->bind(endpoint, ec); }
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { acceptor->async_bind(endpoint, std::move(complete_handler)); }

	virtual void listen(error_code &ec) override { return acceptor->listen(ec); }
	virtual void async_listen(null_callback &&complete_handler) override { acceptor->async_listen(std::move(complete_handler)); }

	virtual void accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &ec) override;
	virtual void async_accept(accept_callback &&complete_handler) override;

	virtual void close(error_code &ec) override { return acceptor->close(ec); }
	virtual void async_close(null_callback &&complete_handler) override { acceptor->async_close(std::move(complete_handler)); }
private:
	void recv_websocket_req(const std::shared_ptr<accept_callback> &callback, const std::shared_ptr<http_header> &header, size_t recv_buf_ptr = 0, size_t recv_buf_ptr_end = 0);
	void send_websocket_resp(const std::shared_ptr<accept_callback> &callback);

	std::unique_ptr<prx_listener> acceptor;
	std::unique_ptr<char[]> recv_buf;
	std::unique_ptr<prx_tcp_socket> socket_accept;

	std::string key, iv, sec_accept;
};

#endif
