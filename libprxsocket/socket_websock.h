#ifndef _H_SOCKET_WEBSOCK
#define _H_SOCKET_WEBSOCK

#include "socket_base.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <algorithm>
#include <list>
#include <memory>
#include <mutex>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/modes.h>
#endif

class websock_tcp_socket :public prx_tcp_socket_base
{
	enum { STATE_INIT, STATE_OK };
	static constexpr size_t sym_block_size = 16;
	static constexpr size_t sha1_size = 20;
	static constexpr size_t recv_buf_size = 0x800;
public:
	websock_tcp_socket(std::unique_ptr<prx_tcp_socket_base>&& _socket, const std::string& _key)
		:socket(std::move(_socket)), recv_buf(std::make_unique<char[]>(recv_buf_size)),
		key(sym_block_size), iv(sym_block_size)
	{
		constexpr size_t block_size = sym_block_size;
		memcpy(key.data(), _key.data(), std::min(block_size, _key.size()));
	}
	websock_tcp_socket(std::unique_ptr<prx_tcp_socket_base>&& _socket, const std::string& _key, const std::string& _iv)
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
	virtual ~websock_tcp_socket() {}

	virtual bool is_open() override { return socket->is_open(); }

	virtual err_type local_endpoint(endpoint& ep) override { return socket->local_endpoint(ep); }
	virtual err_type remote_endpoint(endpoint& ep) override { return socket->remote_endpoint(ep); }

	virtual err_type open() override { return socket->open(); }
	virtual void async_open(null_callback&& complete_handler) override { socket->async_open(std::move(complete_handler)); }

	virtual err_type bind(const endpoint& endpoint) override { return socket->bind(endpoint); }
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) override { socket->async_bind(endpoint, std::move(complete_handler)); }

	virtual err_type connect(const endpoint& endpoint) override;
	virtual void async_connect(const endpoint& endpoint, null_callback&& complete_handler) override;

	virtual err_type send(const const_buffer& buffer, size_t& transferred) override;
	virtual void async_send(const const_buffer& buffer, transfer_callback&& complete_handler) override;
	virtual err_type recv(const mutable_buffer& buffer, size_t& transferred) override;
	virtual void async_recv(const mutable_buffer& buffer, transfer_callback&& complete_handler) override;

	virtual err_type close() override { state = STATE_INIT; return socket->close(); }
	virtual void async_close(null_callback&& complete_handler) override { state = STATE_INIT; socket->async_close(std::move(complete_handler)); }
private:
	void encode(std::string& dst, const char* src, size_t size);
	void decode(std::string& dst, const char* src, size_t size);

	void send_websocket_req(const std::shared_ptr<null_callback>& callback);
	void recv_websocket_resp(const std::shared_ptr<null_callback>& callback, const std::shared_ptr<std::string>& buf);

	err_type recv_data();
	void async_recv_data(null_callback&& complete_handler);
	void async_recv_data_size_16(const std::shared_ptr<null_callback>& callback);
	void async_recv_data_size_64(const std::shared_ptr<null_callback>& callback);
	void async_recv_data_body(const std::shared_ptr<null_callback>& callback, size_t size);
	size_t read_data(char* buf, size_t size);

	int state = STATE_INIT;
	std::unique_ptr<prx_tcp_socket_base> socket;
	std::unique_ptr<char[]> recv_buf;
	std::list<std::string> recv_que;
	size_t ptr_head = 0;

	CryptoPP::AutoSeededRandomPool prng;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
	CryptoPP::SecByteBlock key, iv;
	std::mutex enc_mutex, dec_mutex;
};

/*
class websock_udp_socket :public prx_udp_socket_base
{
public:
	websock_udp_socket() {}
	virtual ~websock_udp_socket() {}

	virtual bool is_open() override;

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
};
*/

class websock_listener :public prx_listener_base
{
private:
	static constexpr size_t sym_block_size = 16;
	static constexpr size_t recv_buf_size = 0x800;
public:
	websock_listener(std::unique_ptr<prx_listener_base>&& _acceptor, const std::string& _key)
		:acceptor(std::move(_acceptor)), recv_buf(std::make_unique<char[]>(recv_buf_size)),
		key(_key)
	{}
	virtual ~websock_listener() {}

	virtual bool is_open() override { return acceptor->is_open(); }

	virtual err_type local_endpoint(endpoint& ep) { return acceptor->local_endpoint(ep); }

	virtual err_type open() override { return acceptor->open(); }
	virtual void async_open(null_callback&& complete_handler) override { acceptor->async_open(std::move(complete_handler)); }

	virtual err_type bind(const endpoint& endpoint) override { return acceptor->bind(endpoint); }
	virtual void async_bind(const endpoint& endpoint, null_callback&& complete_handler) override { acceptor->async_bind(endpoint, std::move(complete_handler)); }

	virtual err_type listen() override { return acceptor->listen(); }
	virtual void async_listen(null_callback&& complete_handler) override { acceptor->async_listen(std::move(complete_handler)); }

	virtual prx_tcp_socket_base* accept() override;
	virtual void async_accept(accept_callback&& complete_handler) override;

	virtual err_type close() override { return acceptor->close(); }
	virtual void async_close(null_callback&& complete_handler) override { acceptor->async_close(std::move(complete_handler)); }
private:
	void recv_websocket_req(const std::shared_ptr<accept_callback>& callback, const std::shared_ptr<std::string>& buf);
	void send_websocket_resp(const std::shared_ptr<accept_callback>& callback);

	std::unique_ptr<prx_listener_base> acceptor;
	std::unique_ptr<char[]> recv_buf;
	std::unique_ptr<prx_tcp_socket_base> socket_accept;

	std::string key, iv, sec_accept;
};

#endif
