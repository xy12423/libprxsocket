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
#include "socket_ssr_auth.h"
#include "random_generator.h"

using namespace prxsocket;
using namespace prxsocket::ssr;

namespace
{

	double trapizoid_random_double(double d)
	{
		double s = random_generator::random_double();
		if (d == 0)
			return s;
		double a = 1 - d;
		return (sqrt(a * a + 4 * d * s) - a) / (2 * d);
	}

	size_t trapezoid_random_int(size_t max, double d)
	{
		return (size_t)(max * trapizoid_random_double(d));
	}

	size_t rnd_data_size(size_t src_size)
	{
		static constexpr size_t tcp_mss = 1440;
		size_t effective = src_size + 9;
		if (effective == tcp_mss)
			return 0;
		if (effective > tcp_mss)
		{
			if (effective < 2 * tcp_mss)
				return trapezoid_random_int(2 * tcp_mss - effective, -0.3);
			return random_generator::random_int<uint8_t>() % 32;
		}
		if (src_size > 900)
			return random_generator::random_int<uint16_t>() % src_size;
		return trapezoid_random_int(tcp_mss - effective, -0.3);
	}

	void rnd_data(std::vector<char> &dst, size_t src_size)
	{
		size_t rnd_size = rnd_data_size(src_size);
		assert(rnd_size + 1 < 0x10000);
		if (rnd_size < 128)
		{
			dst.push_back((uint8_t)(rnd_size + 1));
			random_generator::random_bytes(dst, rnd_size);
		}
		else
		{
			size_t rnd_size_begin = dst.size();
			dst.resize(dst.size() + 3);
			dst[rnd_size_begin] = '\xFF';
			uint16_t rnd_size_le = boost::endian::native_to_little((uint16_t)(rnd_size + 1));
			memcpy(dst.data() + rnd_size_begin + 1, (char *)&rnd_size_le, sizeof(rnd_size_le));
			random_generator::random_bytes(dst, rnd_size - 2);
		}
	}

	CryptoPP::Weak::MD5 &md5_hasher()
	{
		thread_local CryptoPP::Weak::MD5 md5;
		return md5;
	}

	template <size_t N>
	void str_to_key(char(&dst)[N], const char *src, size_t src_size)
	{
		static_assert(N > 0 && N % 16 == 0, "str_to_key doesn't support dst with any size");
		CryptoPP::Weak::MD5 &md5 = md5_hasher();

		size_t i = 0;
		while (i < N)
		{
			if (i == 0)
			{
				md5.CalculateDigest((CryptoPP::byte *)dst, (const CryptoPP::byte *)src, src_size);
			}
			else
			{
				md5.Update((const CryptoPP::byte *)dst + i - md5.DIGESTSIZE, md5.DIGESTSIZE);
				md5.Update((const CryptoPP::byte *)src, src_size);
				md5.Final((CryptoPP::byte *)dst + i);
			}
			i += md5.DIGESTSIZE;
		}
	}

}

ssr_auth_aes128_sha1_shared_server_data::ssr_auth_aes128_sha1_shared_server_data(const std::string &arg)
	:client_id(random_generator::random_int<uint32_t>()), connection_id(random_generator::random_int<uint32_t>() % 0xFFFFFD), argument(arg)
{
}

std::pair<uint32_t, uint32_t> ssr_auth_aes128_sha1_shared_server_data::new_id_pair()
{
	std::lock_guard<std::mutex> guard(lock);
	if (connection_id > 0xFF000000)
	{
		client_id = random_generator::random_int<uint32_t>();
		connection_id = random_generator::random_int<uint32_t>() % 0xFFFFFD;
	}
	return std::pair<uint32_t, uint32_t>(boost::endian::native_to_little(client_id), boost::endian::native_to_little(++connection_id));
}

void ssr_auth_aes128_sha1_tcp_socket::send(const_buffer buffer, size_t &transferred, error_code &err)
{
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
	const_buffer_sequence send_seq;
	send_seq.push_back(const_buffer(send_buf_head_));
	if (transferring > 0)
		send_seq.push_back(const_buffer(buffer.data(), transferring));
	send_seq.push_back(const_buffer(send_buf_tail_));
	socket_->write(std::move(send_seq), err);
	if (err)
	{
		reset_send();
		return;
	}
	transferred = transferring;
}

void ssr_auth_aes128_sha1_tcp_socket::async_send(const_buffer buffer, transfer_callback &&complete_handler)
{
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

	const_buffer_sequence send_seq;
	send_seq.push_back(const_buffer(send_buf_head_));
	if (transferring > 0)
		send_seq.push_back(const_buffer(buffer.data(), transferring));
	send_seq.push_back(const_buffer(send_buf_tail_));
	socket_->async_write(std::move(send_seq),
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

void ssr_auth_aes128_sha1_tcp_socket::recv(mutable_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;
	if (read_empty())
	{
		recv_pre_buf_type_ = RECV_PRE_BUF_SINGLE;
		recv_pre_buf_single_ = buffer;
		recv_data(err);
		if (!err)
			transferred = buffer.size() - recv_pre_buf_single_.size();
		return;
	}
	transferred = read_data(buffer.data(), buffer.size());
}

void ssr_auth_aes128_sha1_tcp_socket::async_recv(mutable_buffer buffer, transfer_callback &&complete_handler)
{
	if (read_empty())
	{
		recv_pre_buf_type_ = RECV_PRE_BUF_SINGLE;
		recv_pre_buf_single_ = buffer;
		std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
		async_recv_data([this, buffer, callback](error_code err)
		{
			if (err)
				(*callback)(err, 0);
			else
				(*callback)(err, buffer.size() - recv_pre_buf_single_.size());
		});
		return;
	}
	size_t transferred = read_data(buffer.data(), buffer.size());
	complete_handler(0, transferred);
}

void ssr_auth_aes128_sha1_tcp_socket::read(mutable_buffer_sequence &&buffer, error_code &err)
{
	err = 0;
	while (!buffer.empty())
	{
		if (read_empty())
		{
			recv_pre_buf_multiple_ = std::move(buffer);
			do
			{
				recv_pre_buf_type_ = RECV_PRE_BUF_MULTIPLE;
				recv_data(err);
				if (err)
					return;
			} while (!recv_pre_buf_multiple_.empty());
			return;
		}
		size_t transferred = read_data(buffer.front().data(), buffer.front().size());
		buffer.consume_front(transferred);
	}
}

void ssr_auth_aes128_sha1_tcp_socket::async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	while (!buffer.empty())
	{
		if (read_empty())
		{
			recv_pre_buf_multiple_ = std::move(buffer);
			std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
			async_read(callback);
			return;
		}
		size_t transferred = read_data(buffer.front().data(), buffer.front().size());
		buffer.consume_front(transferred);
	}
	complete_handler(0);
}

void ssr_auth_aes128_sha1_tcp_socket::async_read(const std::shared_ptr<null_callback> &callback)
{
	recv_pre_buf_type_ = RECV_PRE_BUF_MULTIPLE;
	async_recv_data([this, callback](error_code err)
	{
		if (err)
		{
			(*callback)(err);
			return;
		}
		if (recv_pre_buf_multiple_.empty())
		{
			(*callback)(0);
			return;
		}
		async_read(callback);
	});
}

void ssr_auth_aes128_sha1_tcp_socket::write(const_buffer_sequence &&buffer, error_code &err)
{
	if (buffer.count() == 1)
		return prx_tcp_socket::write(buffer.front(), err);
	err = 0;
	if (buffer.empty())
		return;

	while (!buffer.empty())
	{
		const_buffer_sequence send_seq;
		try
		{
			send_seq = prepare_send(buffer);
		}
		catch (const std::exception &)
		{
			shutdown(shutdown_send, err);
			err = ERR_OPERATION_FAILURE;
			return;
		}
		send_seq.push_front(const_buffer(send_buf_head_));
		send_seq.push_back(const_buffer(send_buf_tail_));
		socket_->write(std::move(send_seq), err);
		if (err)
		{
			reset_send();
			return;
		}
	}
}

void ssr_auth_aes128_sha1_tcp_socket::async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	if (buffer.count() == 1)
		return prx_tcp_socket::async_write(buffer.front(), std::move(complete_handler));
	if (buffer.empty())
		return complete_handler(0);

	async_write(std::make_shared<const_buffer_sequence>(std::move(buffer)), std::make_shared<null_callback>(std::move(complete_handler)));
}

void ssr_auth_aes128_sha1_tcp_socket::shutdown(shutdown_type type, error_code &ec)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->shutdown(type, ec);
}

void ssr_auth_aes128_sha1_tcp_socket::async_shutdown(shutdown_type type, null_callback &&complete_handler)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->async_shutdown(type, std::move(complete_handler));
}

void ssr_auth_aes128_sha1_tcp_socket::async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback)
{
	const_buffer_sequence send_seq;
	try
	{
		send_seq = prepare_send(*buffer);
	}
	catch (const std::exception &)
	{
		async_shutdown(shutdown_send, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		return;
	}
	send_seq.push_front(const_buffer(send_buf_head_));
	send_seq.push_back(const_buffer(send_buf_tail_));

	socket_->async_write(std::move(send_seq),
		[this, buffer, callback](error_code err)
	{
		if (err)
		{
			reset_send();
			(*callback)(err);
			return;
		}
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
	});
}

void ssr_auth_aes128_sha1_tcp_socket::close(error_code &ec)
{
	reset();
	return socket_->close(ec);
}

void ssr_auth_aes128_sha1_tcp_socket::async_close(null_callback &&complete_handler)
{
	reset();
	socket_->async_close(std::move(complete_handler));
}

void ssr_auth_aes128_sha1_tcp_socket::prepare_send_data_auth(const std::function<void(CryptoPP::HMAC<CryptoPP::SHA1> &hasher)> &src_iter, size_t src_size)
{
	assert(!auth_sent_);
	thread_local CryptoPP::SHA1 hasher;
	thread_local std::vector<char> hmac_key;
	thread_local CryptoPP::HMAC<CryptoPP::SHA1> hmac;
	CryptoPP::byte hmac_digest[hmac.DIGESTSIZE];
	thread_local CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
	thread_local std::vector<char> enc_key_str;
	static constexpr const char enc_key_salt[] = "auth_aes128_sha1";
	static constexpr const CryptoPP::byte enc_iv[16] = { 0 };

	/*
	check_head         1 byte
	check_head_hmac    6 bytes
	uid                4 bytes
	encrypted [
	 utc_time           4 bytes
	 client_id          4 bytes
	 connection_id      4 bytes
	 total_size         2 bytes
	 rnd_size           2 bytes
	]                  16 bytes
	uid_encrypted_hmac 4 bytes
	rnd                rnd_size bytes
	src                src_size bytes
	complete_hmac      4 bytes
	*/

	socket_->init_enc();
	size_t key_size = socket_->key().size(), iv_size = socket_->enc().iv_size();
	hmac_key.resize(iv_size + key_size);
	memcpy(hmac_key.data(), socket_->enc().iv(), iv_size);
	memcpy(hmac_key.data() + iv_size, socket_->key().data(), key_size);
	hmac.SetKey((const CryptoPP::byte *)hmac_key.data(), hmac_key.size());
	hmac.Restart();

	bool uid_key_set = false;
	uint32_t uid;
	try
	{
		const std::string &arg = server_data_.argument;
		size_t delim_pos = arg.find(':');
		if (delim_pos != std::string::npos)
		{
			uid = std::stoi(arg.substr(0, delim_pos));
			send_hmac_key_.resize(hasher.DIGESTSIZE);
			hasher.CalculateDigest((CryptoPP::byte *)send_hmac_key_.data(), (CryptoPP::byte *)arg.data() + delim_pos + 1, arg.size() - (delim_pos + 1));
			uid_key_set = true;
		}
	}
	catch (...) {}
	if (!uid_key_set)
	{
		uid = random_generator::random_int<uint32_t>();
		send_hmac_key_ = socket_->key();
	}

	size_t rnd_size = random_generator::random_int<uint16_t>();
	if (src_size > 400)
		rnd_size %= 512;
	else
		rnd_size %= 1024;
	size_t total_size = 1 + 6 + 4 + 16 + 4 + rnd_size + src_size + 4;

	send_buf_head_.resize(1 + 6 + 4 + 16 + 4 + rnd_size);
	//check_head
	random_generator::random_bytes(send_buf_head_.data(), 1);
	//check_head_hmac
	hmac.CalculateDigest(hmac_digest, (const CryptoPP::byte *)send_buf_head_.data(), 1);
	memcpy(send_buf_head_.data() + 1, hmac_digest, 6);
	//uid
	uint32_t uid_le = boost::endian::native_to_little(uid);
	memcpy(send_buf_head_.data() + 7, &uid_le, 4);

	CryptoPP::byte encrypting_buf[16];
	//utc_time
	uint32_t utc_time_le = boost::endian::native_to_little(
		(uint32_t)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()
	);
	memcpy(encrypting_buf, &utc_time_le, 4);
	//client_id & connection_id
	std::pair<uint32_t, uint32_t> id_pair = server_data_.new_id_pair();
	memcpy(encrypting_buf + 4, &id_pair.first, 4);
	memcpy(encrypting_buf + 8, &id_pair.second, 4);
	//total_size
	uint16_t total_size_le = boost::endian::native_to_little((uint16_t)total_size);
	memcpy(encrypting_buf + 12, &total_size_le, 2);
	//rnd_size
	uint16_t rnd_size_le = boost::endian::native_to_little((uint16_t)rnd_size);
	memcpy(encrypting_buf + 14, &rnd_size_le, 2);
	//encrypted
	enc_key_str.clear();
	CryptoPP::StringSource ss(
		(const CryptoPP::byte *)send_hmac_key_.data(), send_hmac_key_.size(),
		true, 
		new CryptoPP::Base64Encoder(new CryptoPP::StringSinkTemplate<std::vector<char>>(enc_key_str), false)
	);
	enc_key_str.insert(enc_key_str.end(), enc_key_salt, enc_key_salt + sizeof(enc_key_salt) - 1);
	char enc_key[16];
	str_to_key(enc_key, enc_key_str.data(), enc_key_str.size());
	enc.SetKeyWithIV((CryptoPP::byte *)enc_key, 16, enc_iv); //aes-128-cbc
	CryptoPP::ArraySource as(
		encrypting_buf, sizeof(encrypting_buf),
		true,
		new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::ArraySink((CryptoPP::byte *)send_buf_head_.data() + 11, 16))
	);
	//uid_encrypted_hmac
	hmac.CalculateDigest(hmac_digest, (const CryptoPP::byte *)send_buf_head_.data() + 7, 20);
	memcpy(send_buf_head_.data() + 27, hmac_digest, 4);
	//rnd
	random_generator::random_bytes(send_buf_head_.data() + 31, rnd_size);

	//complete_hmac
	hmac.SetKey((const CryptoPP::byte *)send_hmac_key_.data(), send_hmac_key_.size());
	hmac.Update((const CryptoPP::byte *)send_buf_head_.data(), send_buf_head_.size());
	src_iter(hmac);
	hmac.Final(hmac_digest);
	send_buf_tail_.assign((const char *)hmac_digest, (const char *)hmac_digest + 4);

	send_hmac_key_.resize(send_hmac_key_.size() + 4); //Reserved for pack_id_le in key of hmac in prepare_send_data
	recv_hmac_key_ = send_hmac_key_; //Separate send and recv
	auth_sent_ = true;
}

void ssr_auth_aes128_sha1_tcp_socket::prepare_send_data(const std::function<void(CryptoPP::HMAC<CryptoPP::SHA1> &hasher)> &src_iter, size_t src_size)
{
	assert(auth_sent_);
	thread_local CryptoPP::HMAC<CryptoPP::SHA1> hmac;
	CryptoPP::byte hmac_digest[hmac.DIGESTSIZE];

	/*
	total_size         2 bytes
	total_size_hmac    2 bytes
	rnd_data           ? bytes
	src                src_size bytes
	complete_hmac      4 bytes
	*/

	uint32_t pack_id_le = boost::endian::native_to_little(send_id_);
	assert(send_hmac_key_.size() > 4);
	memcpy(send_hmac_key_.data() + send_hmac_key_.size() - 4, &pack_id_le, 4);
	hmac.SetKey((const CryptoPP::byte *)send_hmac_key_.data(), send_hmac_key_.size());
	hmac.Restart();

	send_buf_head_.resize(4); //Reserved for total_size(2 bytes) & total_size_mac(2 bytes)
	rnd_data(send_buf_head_, src_size); //rnd_data
	size_t total_size = send_buf_head_.size() + src_size + 4;
	//total_size
	uint16_t total_size_le = boost::endian::native_to_little((uint16_t)total_size);
	memcpy(send_buf_head_.data(), &total_size_le, 2);
	//total_size_hmac
	hmac.CalculateDigest(hmac_digest, (const CryptoPP::byte *)send_buf_head_.data(), 2);
	send_buf_head_[2] = hmac_digest[0];
	send_buf_head_[3] = hmac_digest[1];

	//complete_hmac
	hmac.Update((const CryptoPP::byte *)send_buf_head_.data(), send_buf_head_.size());
	src_iter(hmac);
	hmac.Final(hmac_digest);
	send_buf_tail_.assign((const char *)hmac_digest, (const char *)hmac_digest + 4);

	++send_id_;
}

size_t ssr_auth_aes128_sha1_tcp_socket::prepare_send(const_buffer buffer)
{
	size_t transferring;
	auto update_func = [&](CryptoPP::HMAC<CryptoPP::SHA1> &hasher) { hasher.Update((CryptoPP::byte *)buffer.data(), transferring); };
	if (!auth_sent_)
	{
		transferring = std::min(AUTH_PACK_SIZE, buffer.size());
		prepare_send_data_auth(update_func, transferring);
	}
	else
	{
		transferring = std::min(PACK_SIZE, buffer.size());
		prepare_send_data(update_func, transferring);
	}
	return transferring;
}

const_buffer_sequence ssr_auth_aes128_sha1_tcp_socket::prepare_send(const_buffer_sequence &buffer)
{
	const_buffer_sequence seq;
	auto update_func = [&](CryptoPP::HMAC<CryptoPP::SHA1> &hasher)
	{
		for (const auto &item : seq)
			hasher.Update((CryptoPP::byte *)item.data(), item.size());
	};

	size_t prepare_pack_size;
	if (!auth_sent_)
		prepare_pack_size = AUTH_PACK_SIZE;
	else
		prepare_pack_size = PACK_SIZE;

	if (buffer.size_total() <= prepare_pack_size)
	{
		seq = std::move(buffer);
		buffer.clear();
	}
	else
	{
		buffer.truncate(seq, prepare_pack_size);
	}

	if (!auth_sent_)
		prepare_send_data_auth(update_func, seq.size_total());
	else
		prepare_send_data(update_func, seq.size_total());

	return seq;
}

bool ssr_auth_aes128_sha1_tcp_socket::has_non_empty_pre_buf() const
{
	switch (recv_pre_buf_type_)
	{
	case RECV_PRE_BUF_SINGLE:
		return recv_pre_buf_single_.size() > 0;
	case RECV_PRE_BUF_MULTIPLE:
		return !recv_pre_buf_multiple_.empty();
	}
	return false;
}

void ssr_auth_aes128_sha1_tcp_socket::recv_data(error_code &err)
{
	assert(read_empty());

	socket_->read(mutable_buffer(recv_buf_.get(), 5), err);
	if (err)
	{
		reset_recv();
		return;
	}
	size_t total_size = ((uint8_t)recv_buf_[0] | ((uint8_t)recv_buf_[1] << 8));
	if (total_size < 9 || total_size > RECV_BUF_SIZE)
	{
		shutdown(shutdown_receive, err);
		err = ERR_BAD_ARG_REMOTE;
		return;
	}
	size_t rnd_size = (uint8_t)recv_buf_[4];
	if (rnd_size == 0xFF)
	{
		socket_->read(mutable_buffer(recv_buf_.get() + 5, 2), err);
		if (err)
		{
			reset_recv();
			return;
		}
		rnd_size = ((uint8_t)recv_buf_[5] | ((uint8_t)recv_buf_[6] << 8));
		if (rnd_size <= 128)
		{
			shutdown(shutdown_receive, err);
			err = ERR_BAD_ARG_REMOTE;
			return;
		}
	}
	else
	{
		if (rnd_size > 128)
		{
			shutdown(shutdown_receive, err);
			err = ERR_BAD_ARG_REMOTE;
			return;
		}
	}
	if (total_size < 8 + rnd_size) //fixed-size parts and rnd_size
	{
		shutdown(shutdown_receive, err);
		err = ERR_BAD_ARG_REMOTE;
		return;
	}
	size_t recv_size = total_size - 8 - rnd_size;

	if (recv_size > 0 && has_non_empty_pre_buf())
	{
		std::pair<size_t, size_t> recv_ptr_on_success;
		uint16_t seq_param;
		mutable_buffer_sequence recv_seq = prepare_recv_data_body_with_pre_buf(rnd_size, recv_size, recv_ptr_on_success, seq_param);
		socket_->read(mutable_buffer_sequence(recv_seq), err);
		if (err)
		{
			reset_recv();
			return;
		}
		try
		{
			err = decode_recv_data(total_size, rnd_size, &recv_seq, seq_param);
			recv_ptr_ = recv_ptr_on_success.first;
			recv_size_ = recv_ptr_on_success.second;
		}
		catch (const std::exception &)
		{
			err = ERR_OPERATION_FAILURE;
		}
	}
	else
	{
		size_t rnd_read = recv_buf_[4] == '\xFF' ? 3 : 1;
		socket_->read(mutable_buffer(recv_buf_.get() + 4 + rnd_read, total_size - (4 + rnd_read)), err);
		if (err)
		{
			reset_recv();
			return;
		}
		try
		{
			err = decode_recv_data(total_size, rnd_size);
		}
		catch (const std::exception &)
		{
			err = ERR_OPERATION_FAILURE;
		}
	}

	if (err)
	{
		error_code err2;
		shutdown(shutdown_receive, err2);
		return;
	}
}

void ssr_auth_aes128_sha1_tcp_socket::async_recv_data(null_callback &&complete_handler)
{
	assert(read_empty());
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	socket_->async_read(mutable_buffer(recv_buf_.get(), 5),
		[this, callback](error_code err)
	{
		if (err)
		{
			reset_recv();
			(*callback)(err);
			return;
		}

		size_t total_size = ((uint8_t)recv_buf_[0] | ((uint8_t)recv_buf_[1] << 8));
		if (total_size < 9 || total_size > RECV_BUF_SIZE)
		{
			async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
			return;
		}
		size_t rnd_size = (uint8_t)recv_buf_[4];
		if (rnd_size == 0xFF)
		{
			socket_->async_read(mutable_buffer(recv_buf_.get() + 5, 2),
				[this, total_size, callback](error_code err)
			{
				if (err)
				{
					reset_recv();
					(*callback)(err);
					return;
				}
				size_t rnd_size = ((uint8_t)recv_buf_[5] | ((uint8_t)recv_buf_[6] << 8));
				if (rnd_size <= 128)
				{
					async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
					return;
				}
				async_recv_data_body(total_size, rnd_size, callback);
			});
		}
		else
		{
			if (rnd_size > 128)
			{
				async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
				return;
			}
			async_recv_data_body(total_size, rnd_size, callback);
		}
	});
}

void ssr_auth_aes128_sha1_tcp_socket::async_recv_data_body(size_t total_size, size_t rnd_size, const std::shared_ptr<null_callback> &callback)
{
	if (total_size < 8 + rnd_size) //fixed-size parts and rnd_size
	{
		async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
		return;
	}
	size_t recv_size = total_size - 8 - rnd_size;

	if (recv_size > 0 && has_non_empty_pre_buf())
	{
		uint16_t seq_param;
		std::pair<size_t, size_t> recv_ptr_on_success;
		std::shared_ptr<mutable_buffer_sequence> recv_seq = std::make_shared<mutable_buffer_sequence>(prepare_recv_data_body_with_pre_buf(rnd_size, recv_size, recv_ptr_on_success, seq_param));
		socket_->async_read(mutable_buffer_sequence(*recv_seq),
			[this, total_size, rnd_size, recv_seq, seq_param, recv_ptr_on_success, callback](error_code err)
		{
			if (err)
			{
				reset_recv();
				(*callback)(err);
				return;
			}

			try
			{
				err = decode_recv_data(total_size, rnd_size, recv_seq.get(), seq_param);
				recv_ptr_ = recv_ptr_on_success.first;
				recv_size_ = recv_ptr_on_success.second;
			}
			catch (const std::exception &)
			{
				err = ERR_OPERATION_FAILURE;
			}
			if (err)
			{
				async_shutdown(shutdown_receive, [callback, err](error_code) { (*callback)(err); });
				return;
			}

			(*callback)(0);
		});
	}
	else
	{
		size_t rnd_read = recv_buf_[4] == '\xFF' ? 3 : 1;
		socket_->async_read(mutable_buffer(recv_buf_.get() + 4 + rnd_read, total_size - (4 + rnd_read)),
			[this, total_size, rnd_size, callback](error_code err)
		{
			if (err)
			{
				reset_recv();
				(*callback)(err);
				return;
			}

			try
			{
				err = decode_recv_data(total_size, rnd_size);
			}
			catch (const std::exception &)
			{
				err = ERR_OPERATION_FAILURE;
			}
			if (err)
			{
				async_shutdown(shutdown_receive, [callback, err](error_code) { (*callback)(err); });
				return;
			}

			(*callback)(0);
		});
	}
}

mutable_buffer_sequence ssr_auth_aes128_sha1_tcp_socket::prepare_recv_data_body_with_pre_buf(size_t rnd_size, size_t recv_size, std::pair<size_t, size_t> &recv_ptr_on_success, uint16_t &seq_param)
{
	mutable_buffer_sequence recv_seq;
	seq_param = 0;
	switch (recv_pre_buf_type_)
	{
	case RECV_PRE_BUF_SINGLE:
		if (recv_pre_buf_single_.size() >= recv_size)
		{
			recv_seq.push_back(mutable_buffer(recv_pre_buf_single_.data(), recv_size));
			recv_seq.push_back(mutable_buffer(recv_buf_.get() + 4 + rnd_size + recv_size, 4)); //complete_hmac
			recv_pre_buf_single_ = mutable_buffer(recv_pre_buf_single_.data() + recv_size, recv_pre_buf_single_.size() - recv_size);
			recv_ptr_on_success.first = recv_ptr_on_success.second = 0;
		}
		else
		{
			auto pair = std::make_pair<size_t, size_t>(4 + rnd_size + recv_pre_buf_single_.size(), recv_size - recv_pre_buf_single_.size());
			recv_seq.push_back(recv_pre_buf_single_);
			recv_seq.push_back(mutable_buffer(recv_buf_.get() + pair.first, pair.second + 4)); //with complete_hmac
			recv_pre_buf_single_ = mutable_buffer(recv_pre_buf_single_.data() + recv_pre_buf_single_.size(), 0);
			recv_ptr_on_success = pair;
			seq_param |= 0x01;
		}
		break;
	case RECV_PRE_BUF_MULTIPLE:
		if (recv_pre_buf_multiple_.size_total() > recv_size)
		{
			recv_pre_buf_multiple_.truncate(recv_seq, recv_size);
			recv_seq.push_back(mutable_buffer(recv_buf_.get() + 4 + rnd_size + recv_size, 4)); //complete_hmac
			recv_ptr_on_success.first = recv_ptr_on_success.second = 0;
		}
		else
		{
			recv_seq = std::move(recv_pre_buf_multiple_);
			recv_pre_buf_multiple_.clear();
			if (recv_seq.size_total() < recv_size)
			{
				auto pair = std::make_pair<size_t, size_t>(4 + rnd_size + recv_seq.size_total(), recv_size - recv_seq.size_total());
				recv_seq.push_back(mutable_buffer(recv_buf_.get() + pair.first, pair.second + 4)); //with complete_hmac
				recv_ptr_on_success = pair;
				seq_param |= 0x01;
			}
			else
			{
				recv_seq.push_back(mutable_buffer(recv_buf_.get() + 4 + rnd_size + recv_size, 4)); //complete_hmac
				recv_ptr_on_success.first = recv_ptr_on_success.second = 0;
			}
		}
		break;
	default:
		assert(false);
	}

	size_t rnd_read = recv_buf_[4] == '\xFF' ? 3 : 1;
	if (rnd_size > rnd_read)
	{
		recv_seq.push_front(mutable_buffer(recv_buf_.get() + 4 + rnd_read, rnd_size - rnd_read)); //rnd_data
		seq_param |= 0x02;
	}
	return recv_seq;
}

error_code ssr_auth_aes128_sha1_tcp_socket::decode_recv_data(size_t total_size, size_t rnd_size, mutable_buffer_sequence *recv_data, uint16_t seq_param)
{
	assert(total_size >= 9); //fixed-size parts and min rnd_size
	thread_local CryptoPP::HMAC<CryptoPP::SHA1> hmac;
	CryptoPP::byte hmac_digest[hmac.DIGESTSIZE];

	uint32_t recv_id_le = boost::endian::native_to_little(recv_id_);
	assert(recv_hmac_key_.size() > 4);
	memcpy(recv_hmac_key_.data() + recv_hmac_key_.size() - 4, &recv_id_le, 4);
	hmac.SetKey((const CryptoPP::byte *)recv_hmac_key_.data(), recv_hmac_key_.size());
	hmac.Restart();

	assert(((uint8_t)recv_buf_[0] | ((uint8_t)recv_buf_[1] << 8)) == total_size); //total_size
	hmac.CalculateDigest(hmac_digest, (CryptoPP::byte *)recv_buf_.get(), 2);
	if (memcmp(hmac_digest, recv_buf_.get() + 2, 2) != 0) //total_size_hmac
		return ERR_BAD_ARG_REMOTE;

	if ((uint8_t)recv_buf_[4] == 0xFF)
	{
		assert(rnd_size == ((uint8_t)recv_buf_[5] | ((uint8_t)recv_buf_[6] << 8)));
		assert(rnd_size > 128);
	}
	else
	{
		assert(rnd_size <= 128);
	}
	assert(total_size >= 8 + rnd_size);

	if (recv_data != nullptr)
	{
		auto itr = recv_data->begin(), itr_end = recv_data->end();
		--itr_end;

		size_t rnd_read = recv_buf_[4] == '\xFF' ? 3 : 1;
		if (seq_param & 0x02)
		{
			hmac.Update((CryptoPP::byte *)recv_buf_.get(), 4 + rnd_read + itr->size());
			++itr;
		}
		else
		{
			hmac.Update((CryptoPP::byte *)recv_buf_.get(), 4 + rnd_read);
		}

		for (; itr != itr_end; ++itr)
			hmac.Update((CryptoPP::byte *)itr->data(), itr->size());

		assert(itr->data() + itr->size() == recv_buf_.get() + total_size);
		if (seq_param & 0x01)
			hmac.Update((CryptoPP::byte *)itr->data(), itr->size() - 4);

		hmac.Final(hmac_digest);
		if (memcmp(hmac_digest, recv_buf_.get() + total_size - 4, 4) != 0) //complete_hmac
			return ERR_BAD_ARG_REMOTE;
	}
	else
	{
		hmac.CalculateDigest(hmac_digest, (CryptoPP::byte *)recv_buf_.get(), total_size - 4);
		if (memcmp(hmac_digest, recv_buf_.get() + total_size - 4, 4) != 0) //complete_hmac
			return ERR_BAD_ARG_REMOTE;
		recv_ptr_ = 4 + rnd_size;
		recv_size_ = total_size - 8 - rnd_size;
	}

	++recv_id_;
	return 0;
}

bool ssr_auth_aes128_sha1_tcp_socket::read_empty()
{
	return recv_size_ == 0;
}

size_t ssr_auth_aes128_sha1_tcp_socket::read_data(char *dst, size_t dst_size)
{
	size_t size_cpy = std::min(recv_size_, dst_size);
	memcpy(dst, recv_buf_.get() + recv_ptr_, size_cpy);
	recv_ptr_ += size_cpy;
	recv_size_ -= size_cpy;
	return size_cpy;
}
