/*
Copyright (c) 2020 xy12423

This file is part of libprxsocket.

libprxsocket is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

libprxsocket is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libprxsocket. If not, see <https://www.gnu.org/licenses/>.
*/

#include "stdafx.h"
#include "socket_ss_crypto.h"

using namespace prxsocket;
using namespace prxsocket::ss;

void ss_crypto_tcp_socket::send(const_buffer buffer, size_t &transferred, error_code &err)
{
	if (!iv_sent_)
		return send_with_iv(buffer, transferred, err);

	err = 0;
	transferred = 0;

	size_t transferring;
	try
	{
		transferring = prepare_send(buffer);
	}
	catch (const std::exception &)
	{
		shutdown(shutdown_send, err);
		err = ERR_OPERATION_FAILURE;
		return;
	}

	socket_->write(const_buffer(send_buf_), err);
	if (err)
	{
		reset_send();
		return;
	}
	transferred = transferring;
}

void ss_crypto_tcp_socket::send_with_iv(const_buffer buffer, size_t &transferred, error_code &err)
{
	assert(!iv_sent_);
	iv_sent_ = true;
	err = 0;
	transferred = 0;

	init_enc();
	if (buffer.size() == 0)
	{
		socket_->write(const_buffer(enc_->iv(), enc_iv_size_), err);
		if (err)
		{
			reset_send();
			return;
		}
		return;
	}

	size_t transferring;
	try
	{
		transferring = prepare_send(buffer);
	}
	catch (const std::exception &)
	{
		shutdown(shutdown_send, err);
		err = ERR_OPERATION_FAILURE;
		return;
	}

	const_buffer_sequence iv_seq(const_buffer(enc_->iv(), enc_iv_size_));
	iv_seq.push_back(const_buffer(send_buf_));
	socket_->write(std::move(iv_seq), err);
	if (err)
	{
		reset_send();
		return;
	}

	transferred = transferring;
}

void ss_crypto_tcp_socket::async_send(const_buffer buffer, transfer_callback &&complete_handler)
{
	if (!iv_sent_)
		return async_send_with_iv(buffer, std::move(complete_handler));

	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	size_t transferring;
	try
	{
		transferring = prepare_send(buffer);
	}
	catch (const std::exception &)
	{
		async_shutdown(shutdown_send, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE, 0); });
		return;
	}

	socket_->async_write(const_buffer(send_buf_),
		[this, transferring, callback](error_code err)
	{
		if (err)
		{
			reset_send();
			(*callback)(err, 0);
			return;
		}
		(*callback)(0, transferring);
	});
}

void ss_crypto_tcp_socket::async_send_with_iv(const_buffer buffer, transfer_callback &&complete_handler)
{
	assert(!iv_sent_);
	iv_sent_ = true;
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	init_enc();
	if (buffer.size() == 0)
	{
		socket_->async_write(const_buffer(enc_->iv(), enc_iv_size_),
			[this, callback](error_code err)
		{
			if (err)
			{
				reset_send();
				(*callback)(err, 0);
				return;
			}
			(*callback)(0, 0);
		});
		return;
	}

	size_t transferring;
	try
	{
		transferring = prepare_send(buffer);
	}
	catch (const std::exception &)
	{
		async_shutdown(shutdown_send, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE, 0); });
		return;
	}

	const_buffer_sequence iv_seq(const_buffer(enc_->iv(), enc_iv_size_));
	iv_seq.push_back(const_buffer(send_buf_));
	socket_->async_write(std::move(iv_seq),
		[this, transferring, callback](error_code err)
	{
		if (err)
		{
			reset_send();
			(*callback)(err, 0);
			return;
		}
		(*callback)(0, transferring);
	});
}

void ss_crypto_tcp_socket::recv(mutable_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;
	if (dec_buf_.empty())
	{
		recv_data(err);
		if (err)
			return;
	}
	transferred = read_data(buffer.data(), buffer.size());
}

void ss_crypto_tcp_socket::async_recv(mutable_buffer buffer, transfer_callback &&complete_handler)
{
	if (dec_buf_.empty())
	{
		std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
		async_recv_data([this, buffer, callback](error_code err)
		{
			if (err)
			{
				(*callback)(err, 0);
				return;
			}
			size_t transferred = read_data(buffer.data(), buffer.size());
			(*callback)(0, transferred);
		});
		return;
	}
	size_t transferred = read_data(buffer.data(), buffer.size());
	complete_handler(0, transferred);
}

void ss_crypto_tcp_socket::read(mutable_buffer_sequence &&buffer, error_code &err)
{
	err = 0;
	while (!buffer.empty())
	{
		if (dec_buf_.empty())
		{
			recv_data(err);
			if (err)
				return;
		}
		size_t transferred = read_data(buffer.front().data(), buffer.front().size());
		buffer.consume(transferred);
	}
}

void ss_crypto_tcp_socket::async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	while (!buffer.empty())
	{
		if (dec_buf_.empty())
		{
			std::shared_ptr<mutable_buffer_sequence> buffer_ptr = std::make_shared<mutable_buffer_sequence>(std::move(buffer));
			std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
			async_recv_data([this, buffer_ptr, callback](error_code err)
			{
				if (err)
				{
					(*callback)(err);
					return;
				}
				async_read(buffer_ptr, callback);
			});
			return;
		}
		size_t transferred = read_data(buffer.front().data(), buffer.front().size());
		buffer.consume(transferred);
	}
	complete_handler(0);
}

void ss_crypto_tcp_socket::async_read(const std::shared_ptr<mutable_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback)
{
	while (!buffer->empty())
	{
		if (dec_buf_.empty())
		{
			async_recv_data([this, buffer, callback](error_code err)
			{
				if (err)
				{
					(*callback)(err);
					return;
				}
				async_read(buffer, callback);
			});
			return;
		}
		size_t transferred = read_data(buffer->front().data(), buffer->front().size());
		buffer->consume(transferred);
	}
	(*callback)(0);
}

void ss_crypto_tcp_socket::write(const_buffer_sequence &&buffer, error_code &err)
{
	if (buffer.count() == 1)
		return prx_tcp_socket::write(buffer.front(), err);
	if (!iv_sent_)
		return write_with_iv(std::move(buffer), err);
	err = 0;
	if (buffer.empty())
		return;

	while (!buffer.empty())
	{
		try
		{
			prepare_send(buffer);
		}
		catch (const std::exception &)
		{
			shutdown(shutdown_send, err);
			err = ERR_OPERATION_FAILURE;
			return;
		}
		socket_->write(const_buffer(send_buf_), err);
		if (err)
		{
			reset_send();
			return;
		}
	}
}

void ss_crypto_tcp_socket::write_with_iv(const_buffer_sequence &&buffer, error_code &err)
{
	assert(!iv_sent_);
	iv_sent_ = true;
	err = 0;

	init_enc();
	if (buffer.empty())
	{
		socket_->write(const_buffer(enc_->iv(), enc_iv_size_), err);
		if (err)
		{
			reset_send();
			return;
		}
		return;
	}

	try
	{
		prepare_send(buffer);
	}
	catch (const std::exception &)
	{
		shutdown(shutdown_send, err);
		err = ERR_OPERATION_FAILURE;
		return;
	}

	const_buffer_sequence iv_seq(const_buffer(enc_->iv(), enc_iv_size_));
	iv_seq.push_back(const_buffer(send_buf_));
	socket_->write(std::move(iv_seq), err);
	if (err)
	{
		reset_send();
		return;
	}

	if (!buffer.empty())
		return write(std::move(buffer), err);
}

void ss_crypto_tcp_socket::async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	if (buffer.count() == 1)
		return prx_tcp_socket::async_write(buffer.front(), std::move(complete_handler));
	if (!iv_sent_)
		return async_write_with_iv(std::move(buffer), std::move(complete_handler));
	if (buffer.empty())
		return complete_handler(0);

	async_write(std::make_shared<const_buffer_sequence>(std::move(buffer)), std::make_shared<null_callback>(std::move(complete_handler)));
}

void ss_crypto_tcp_socket::async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback)
{
	assert(iv_sent_);

	try
	{
		prepare_send(*buffer);
	}
	catch (const std::exception &)
	{
		async_shutdown(shutdown_send, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		return;
	}

	socket_->async_write(const_buffer(send_buf_),
		[this, buffer, callback](error_code err)
	{
		if (err)
		{
			reset_send();
			(*callback)(err);
			return;
		}
		continue_async_write(buffer, callback);
	});
}

void ss_crypto_tcp_socket::async_write_with_iv(const_buffer_sequence &&buffer_obj, null_callback &&complete_handler)
{
	assert(!iv_sent_);
	iv_sent_ = true;
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	init_enc();
	if (buffer_obj.empty())
	{
		socket_->async_write(const_buffer(enc_->iv(), enc_iv_size_),
			[this, callback](error_code err)
		{
			if (err)
			{
				reset_send();
				(*callback)(err);
				return;
			}
			(*callback)(0);
		});
		return;
	}
	std::shared_ptr<const_buffer_sequence> buffer = std::make_shared<const_buffer_sequence>(std::move(buffer_obj));

	try
	{
		prepare_send(*buffer);
	}
	catch (const std::exception &)
	{
		async_shutdown(shutdown_send, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		return;
	}

	const_buffer_sequence iv_seq(const_buffer(enc_->iv(), enc_iv_size_));
	iv_seq.push_back(const_buffer(send_buf_));
	socket_->async_write(std::move(iv_seq),
		[this, buffer, callback](error_code err)
	{
		if (err)
		{
			reset_send();
			(*callback)(err);
			return;
		}
		continue_async_write(buffer, callback);
	});
}

void ss_crypto_tcp_socket::continue_async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback)
{
	if (buffer->count() == 1)
	{
		prx_tcp_socket::async_write(buffer->front(), std::move(*callback));
		return;
	}
	if (buffer->empty())
	{
		(*callback)(0);
		return;
	}
	async_write(buffer, callback);
}

void ss_crypto_tcp_socket::shutdown(shutdown_type type, error_code &ec)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->shutdown(type, ec);
}

void ss_crypto_tcp_socket::async_shutdown(shutdown_type type, null_callback &&complete_handler)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->async_shutdown(type, std::move(complete_handler));
}

void ss_crypto_tcp_socket::close(error_code &ec)
{
	reset();
	socket_->close(ec);
}

void ss_crypto_tcp_socket::async_close(null_callback &&complete_handler)
{
	reset();
	socket_->async_close(std::move(complete_handler));
}

size_t ss_crypto_tcp_socket::prepare_send(const_buffer buffer)
{
	size_t transferring = transfer_size(buffer.size());
	send_buf_.clear();
	enc_->encrypt(send_buf_, buffer.data(), transferring);
	return transferring;
}

void ss_crypto_tcp_socket::prepare_send(const_buffer_sequence &buffer)
{
	thread_local std::unique_ptr<char[]> buf = std::make_unique<char[]>(SEND_SIZE_MAX);

	size_t transferring = transfer_size(buffer.size_total());
	size_t copied = buffer.gather(buf.get(), transferring);
	send_buf_.clear();
	enc_->encrypt(send_buf_, buf.get(), copied);
}

void ss_crypto_tcp_socket::recv_data(error_code &err)
{
	if (!iv_received_)
	{
		assert(dec_iv_size_ <= RECV_BUF_SIZE);
		socket_->read(mutable_buffer(recv_buf_.get(), dec_iv_size_), err);
		if (err)
		{
			reset_recv();
			return;
		}
		iv_received_ = true;
		dec_->set_key_iv(key_.data(), recv_buf_.get());
	}

	size_t transferred;
	socket_->recv(mutable_buffer(recv_buf_.get(), RECV_BUF_SIZE), transferred, err);
	if (err)
	{
		reset_recv();
		return;
	}

	try
	{
		assert(dec_buf_.empty());
		dec_->decrypt(dec_buf_, recv_buf_.get(), transferred);
	}
	catch (const std::exception &)
	{
		shutdown(shutdown_receive, err);
		err = ERR_OPERATION_FAILURE;
		return;
	}
}

void ss_crypto_tcp_socket::async_recv_data(null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	if (!iv_received_)
	{
		assert(dec_iv_size_ <= RECV_BUF_SIZE);
		socket_->async_read(mutable_buffer(recv_buf_.get(), dec_iv_size_),
			[this, callback](error_code err)
		{
			if (err)
			{
				reset_recv();
				(*callback)(err);
				return;
			}
			iv_received_ = true;
			dec_->set_key_iv(key_.data(), recv_buf_.get());
			async_recv_data(std::move(*callback));
		});
		return;
	}

	socket_->async_recv(mutable_buffer(recv_buf_.get(), RECV_BUF_SIZE),
		[this, callback](error_code err, size_t transferred)
	{
		if (err)
		{
			reset_recv();
			(*callback)(err);
			return;
		}

		try
		{
			assert(dec_buf_.empty());
			dec_->decrypt(dec_buf_, recv_buf_.get(), transferred);
		}
		catch (const std::exception &)
		{
			async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}

		(*callback)(0);
	});
}

size_t ss_crypto_tcp_socket::read_data(char *dst, size_t dst_size)
{
	assert(dec_ptr_ <= dec_buf_.size());
	size_t size_cpy = std::min(dec_buf_.size() - dec_ptr_, dst_size);
	memcpy(dst, dec_buf_.data() + dec_ptr_, size_cpy);
	dec_ptr_ += size_cpy;
	assert(dec_ptr_ <= dec_buf_.size());
	if (dec_ptr_ == dec_buf_.size())
	{
		dec_buf_.clear();
		dec_ptr_ = 0;
	}

	return size_cpy;
}

void ss_crypto_udp_socket::send_to(const endpoint &ep, const_buffer buffer, error_code &err)
{
	err = 0;

	try
	{
		encode(udp_send_buf_, buffer.data(), buffer.size());
	}
	catch (const std::exception &)
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}
	udp_socket_->send_to(ep, const_buffer(udp_send_buf_), err);
	if (err && !udp_socket_->is_open())
		reset();
}

void ss_crypto_udp_socket::async_send_to(const endpoint &ep, const_buffer buffer, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	try
	{
		encode(udp_send_buf_, buffer.data(), buffer.size());
	}
	catch (const std::exception &)
	{
		(*callback)(ERR_OPERATION_FAILURE);
		return;
	}

	udp_socket_->async_send_to(ep, const_buffer(udp_send_buf_),
		[this, callback](error_code err)
	{
		if (err && !udp_socket_->is_open())
			reset();
		(*callback)(err);
	});
}

void ss_crypto_udp_socket::recv_from(endpoint &ep, mutable_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t udp_recv_size;
	udp_socket_->recv_from(ep, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE), udp_recv_size, err);
	if (err)
	{
		if (!udp_socket_->is_open())
			reset();
		return;
	}

	try
	{
		std::vector<char> &dec_buf = decode(udp_recv_buf_.get(), udp_recv_size);
		transferred = std::min(buffer.size(), dec_buf.size());
		memcpy(buffer.data(), dec_buf.data(), transferred);
	}
	catch (const std::exception &)
	{
		err = ERR_OPERATION_FAILURE;
		transferred = 0;
		return;
	}
}

void ss_crypto_udp_socket::async_recv_from(endpoint &ep, mutable_buffer buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	udp_socket_->async_recv_from(ep, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE),
		[this, buffer, callback](error_code err, size_t udp_recv_size)
	{
		if (err)
		{
			if (!udp_socket_->is_open())
				reset();
			(*callback)(err, 0);
			return;
		}

		size_t transferred = 0;
		try
		{
			std::vector<char> &dec_buf = decode(udp_recv_buf_.get(), udp_recv_size);
			transferred = std::min(buffer.size(), dec_buf.size());
			memcpy(buffer.data(), dec_buf.data(), transferred);
		}
		catch (const std::exception &)
		{
			(*callback)(ERR_OPERATION_FAILURE, 0);
			return;
		}

		(*callback)(0, transferred);
	});
}

void ss_crypto_udp_socket::send_to(const endpoint &ep, const_buffer_sequence &&buffers, error_code &err)
{
	err = 0;

	thread_local std::vector<char> enc_buf;
	try
	{
		enc_buf.resize(buffers.size_total());
		buffers.gather(enc_buf.data(), enc_buf.size());
		encode(udp_send_buf_, enc_buf.data(), enc_buf.size());
	}
	catch (const std::exception &)
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}
	udp_socket_->send_to(ep, const_buffer(udp_send_buf_), err);
	if (err && !udp_socket_->is_open())
		reset();
}

void ss_crypto_udp_socket::async_send_to(const endpoint &ep, const_buffer_sequence &&buffers, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	thread_local std::vector<char> enc_buf;
	try
	{
		enc_buf.resize(buffers.size_total());
		buffers.gather(enc_buf.data(), enc_buf.size());
		encode(udp_send_buf_, enc_buf.data(), enc_buf.size());
	}
	catch (const std::exception &)
	{
		(*callback)(ERR_OPERATION_FAILURE);
		return;
	}

	udp_socket_->async_send_to(ep, const_buffer(udp_send_buf_),
		[this, callback](error_code err)
	{
		if (err && !udp_socket_->is_open())
			reset();
		(*callback)(err);
	});
}

void ss_crypto_udp_socket::recv_from(endpoint &ep, mutable_buffer_sequence &&buffers, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t udp_recv_size;
	udp_socket_->recv_from(ep, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE), udp_recv_size, err);
	if (err)
	{
		if (!udp_socket_->is_open())
			reset();
		return;
	}

	try
	{
		std::vector<char> &dec_buf = decode(udp_recv_buf_.get(), udp_recv_size);
		transferred = buffers.scatter(dec_buf.data(), dec_buf.size());
	}
	catch (const std::exception &)
	{
		err = ERR_OPERATION_FAILURE;
		transferred = 0;
		return;
	}
}

void ss_crypto_udp_socket::async_recv_from(endpoint &ep, mutable_buffer_sequence &&buffers, transfer_callback &&complete_handler)
{
	std::shared_ptr<mutable_buffer_sequence> buffer = std::make_shared<mutable_buffer_sequence>(std::move(buffers));
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	udp_socket_->async_recv_from(ep, mutable_buffer(udp_recv_buf_.get(), UDP_BUF_SIZE),
		[this, buffer, callback](error_code err, size_t udp_recv_size)
	{
		if (err)
		{
			if (!udp_socket_->is_open())
				reset();
			(*callback)(err, 0);
			return;
		}

		size_t transferred = 0;
		try
		{
			std::vector<char> &dec_buf = decode(udp_recv_buf_.get(), udp_recv_size);
			transferred = buffer->scatter(dec_buf.data(), dec_buf.size());
		}
		catch (const std::exception &)
		{
			(*callback)(ERR_OPERATION_FAILURE, 0);
			return;
		}

		(*callback)(0, transferred);
	});
}

void ss_crypto_udp_socket::encode(std::vector<char> &dst, const char *src, size_t src_size)
{
	dst.clear();
	enc_->set_key(key_.data());
	dst.assign(enc_->iv(), enc_->iv() + enc_iv_size_);
	enc_->encrypt(dst, src, src_size);
}

std::vector<char> &ss_crypto_udp_socket::decode(const char *src, size_t src_size)
{
	thread_local std::vector<char> dec_buf;
	dec_buf.clear();

	size_t iv_size = dec_iv_size_;
	if (src_size < iv_size)
		return dec_buf;
	dec_->set_key_iv(key_.data(), src);
	dec_->decrypt(dec_buf, src + iv_size, src_size - iv_size);
	return dec_buf;
}
