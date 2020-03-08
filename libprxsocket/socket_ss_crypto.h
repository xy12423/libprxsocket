#ifndef LIBPRXSOCKET_H_SOCKET_SS_CRYPTO
#define LIBPRXSOCKET_H_SOCKET_SS_CRYPTO

#include "socket_base.h"
#include "crypto_base.h"

class ss_crypto_tcp_socket : public prx_tcp_socket
{
	static constexpr size_t send_size_pref = 1320;
	static constexpr size_t send_size_max = 1400;
	static constexpr size_t recv_buf_size = 0x800;

	static constexpr size_t transfer_size(size_t buffer_size) { return buffer_size > send_size_max ? send_size_pref : buffer_size; }
public:
	ss_crypto_tcp_socket(std::unique_ptr<prx_tcp_socket> &&base_socket, const std::vector<char> &key, std::unique_ptr<encryptor> &&enc, std::unique_ptr<decryptor> &&dec)
		:socket_(std::move(base_socket)),
		key_(key), enc_(std::move(enc)), enc_iv_size_(enc_->iv_size()), dec_(std::move(dec)), dec_iv_size_(dec_->iv_size()),
		recv_buf_(std::make_unique<char[]>(recv_buf_size))
	{
		assert(key_.size() == enc->key_size());
		assert(key_.size() == dec->key_size());
	}
	virtual ~ss_crypto_tcp_socket() override {}

	virtual bool is_open() override { return socket_->is_open(); }
	virtual bool is_connected() override { return socket_->is_connected(); }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { return socket_->local_endpoint(ep, ec); }
	virtual void remote_endpoint(endpoint &ep, error_code &ec) override { return socket_->remote_endpoint(ep, ec); }

	virtual void open(error_code &ec) override { return socket_->open(ec); }
	virtual void async_open(null_callback &&complete_handler) override { socket_->async_open(std::move(complete_handler)); }

	virtual void bind(const endpoint &endpoint, error_code &ec) override { return socket_->bind(endpoint, ec); }
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { socket_->async_bind(endpoint, std::move(complete_handler)); }

	virtual void connect(const endpoint &endpoint, error_code &ec) override { return socket_->connect(endpoint, ec); }
	virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override { socket_->async_connect(endpoint, std::move(complete_handler)); }

	virtual void send(const const_buffer &buffer, size_t &transferred, error_code &ec) override;
	virtual void async_send(const const_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void recv(const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
	virtual void async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override;
	virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
	virtual void write(const_buffer_sequence &&buffer, error_code &ec) override;
	virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

	virtual void close(error_code &ec) override { iv_sent_ = iv_received_ = false; dec_buf_.clear(); dec_ptr_ = 0; socket_->close(ec); }
	virtual void async_close(null_callback &&complete_handler) override { iv_sent_ = iv_received_ = false; dec_buf_.clear(); dec_ptr_ = 0; socket_->async_close(std::move(complete_handler)); }
private:
	void close() { error_code ec; close(ec); }

	void recv_data(error_code &ec);
	void async_recv_data(null_callback &&complete_handler);
	size_t read_data(char *dst, size_t dst_size);

	void async_read(const std::shared_ptr<mutable_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);
	void async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);

	std::unique_ptr<prx_tcp_socket> socket_;
	std::vector<char> key_;
	std::unique_ptr<encryptor> enc_;
	size_t enc_iv_size_;
	std::unique_ptr<decryptor> dec_;
	size_t dec_iv_size_;

	std::vector<char> send_buf_;
	bool iv_sent_ = false;
	std::unique_ptr<char[]> recv_buf_;
	bool iv_received_ = false;
	std::vector<char> dec_buf_;
	size_t dec_ptr_ = 0;
};

class ss_crypto_udp_socket : public prx_udp_socket
{
	static constexpr size_t udp_buf_size = 0x10000;
public:
	ss_crypto_udp_socket(std::unique_ptr<prx_udp_socket> &&base_udp_socket, const std::vector<char> &key, std::unique_ptr<encryptor> &&enc, std::unique_ptr<decryptor> &&dec)
		:udp_socket_(std::move(base_udp_socket)),
		key_(key), enc_(std::move(enc)), enc_iv_size_(enc_->iv_size()), dec_(std::move(dec)), dec_iv_size_(dec_->iv_size()),
		udp_recv_buf_(std::make_unique<char[]>(udp_buf_size))
	{
		assert(key_.size() == enc->key_size());
		assert(key_.size() == dec->key_size());
	}
	virtual ~ss_crypto_udp_socket() override {}

	virtual bool is_open() override { return udp_socket_->is_open(); }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { return udp_socket_->local_endpoint(ep, ec); }

	virtual void open(error_code &ec) override { return udp_socket_->open(ec); }
	virtual void async_open(null_callback &&complete_handler) override { udp_socket_->async_open(std::move(complete_handler)); }

	virtual void bind(const endpoint &endpoint, error_code &ec) override { return udp_socket_->bind(endpoint, ec); }
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { udp_socket_->async_bind(endpoint, std::move(complete_handler)); }

	virtual void send_to(const endpoint &endpoint, const const_buffer &buffer, error_code &ec) override;
	virtual void async_send_to(const endpoint &endpoint, const const_buffer &buffer, null_callback &&complete_handler) override;
	virtual void recv_from(endpoint &endpoint, const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
	virtual void async_recv_from(endpoint &endpoint, const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, error_code &ec) override;
	virtual void async_send_to(const endpoint &endpoint, const_buffer_sequence &&buffer, null_callback &&complete_handler) override;
	virtual void recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, size_t &transferred, error_code &ec) override;
	virtual void async_recv_from(endpoint &endpoint, mutable_buffer_sequence &&buffer, transfer_callback &&complete_handler) override;

	virtual void close(error_code &ec) override { udp_socket_->close(ec); }
	virtual void async_close(null_callback &&complete_handler) override { udp_socket_->async_close(std::move(complete_handler)); }
private:
	void close() { error_code ec; close(ec); }

	void encode(std::vector<char> &dst, const char *src, size_t src_size);
	//Returns thread_local buffer. Use with caution.
	std::vector<char> &decode(const char *src, size_t src_size);

	std::unique_ptr<prx_udp_socket> udp_socket_;
	std::vector<char> key_;
	std::unique_ptr<encryptor> enc_;
	size_t enc_iv_size_;
	std::unique_ptr<decryptor> dec_;
	size_t dec_iv_size_;

	std::vector<char> udp_send_buf_;
	std::unique_ptr<char[]> udp_recv_buf_;
};

#endif
