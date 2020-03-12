#include "stdafx.h"
#include "socket_ssr_auth.h"

static void random_bytes(void *dst, size_t dst_size)
{
	thread_local CryptoPP::AutoSeededRandomPool prng;
	prng.GenerateBlock((CryptoPP::byte *)dst, dst_size);
}

static void random_bytes(std::vector<char> &dst, size_t rnd_size)
{
	size_t rnd_begin = dst.size();
	dst.resize(dst.size() + rnd_size);
	random_bytes(dst.data() + rnd_begin, rnd_size);
}

template <typename T>
static T random_int()
{
	T val;
	random_bytes(&val, sizeof(T));
	return val;
}

static double random()
{
	return random_int<uint32_t>() / 4294967296.0;
}

static double trapizoid_random_float(double d)
{
	double s = random();
	if (d == 0)
		return s;
	double a = 1 - d;
	return (sqrt(a * a + 4 * d * s) - a) / (2 * d);
}

static size_t trapezoid_random_int(size_t max, double d)
{
	return (size_t)(max * trapizoid_random_float(d));
}

static size_t rnd_data_size(size_t src_size)
{
	static constexpr size_t tcp_mss = 1440;
	size_t effective = src_size + 9;
	if (effective == tcp_mss)
		return 0;
	if (effective > tcp_mss)
	{
		if (effective < 2 * tcp_mss)
			return trapezoid_random_int(2 * tcp_mss - effective, -0.3);
		return random_int<uint8_t>() % 32;
	}
	if (src_size > 900)
		return random_int<uint16_t>() % src_size;
	return trapezoid_random_int(tcp_mss - effective, -0.3);
}

static void rnd_data(std::vector<char> &dst, size_t src_size)
{
	size_t rnd_size = rnd_data_size(src_size);
	if (rnd_size < 128)
	{
		dst.push_back((uint8_t)(rnd_size + 1));
		random_bytes(dst, rnd_size);
	}
	else
	{
		dst.push_back('\xFF');
		dst.push_back((uint8_t)(rnd_size + 1));
		dst.push_back((uint8_t)((rnd_size + 1) >> 8));
		random_bytes(dst, rnd_size - 2);
	}
}

static CryptoPP::Weak::MD5 &md5_hasher()
{
	thread_local CryptoPP::Weak::MD5 md5;
	return md5;
}

template <size_t N>
static void str_to_key(char (&dst)[N], const char *src, size_t src_size)
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

ssr_auth_aes128_sha1_shared_server_data::ssr_auth_aes128_sha1_shared_server_data(const std::string &arg)
	:client_id(random_int<uint32_t>()), connection_id(random_int<uint32_t>() & 0xFFFFFF), argument(arg)
{
}

std::pair<uint32_t, uint32_t> ssr_auth_aes128_sha1_shared_server_data::new_id_pair()
{
	std::lock_guard<std::mutex> guard(lock);
	if (connection_id > 0xFF000000)
	{
		client_id = random_int<uint32_t>();
		connection_id = random_int<uint32_t>() & 0xFFFFFF;
	}
	return std::pair<uint32_t, uint32_t>(boost::endian::native_to_little(client_id), boost::endian::native_to_little(++connection_id));
}

void ssr_auth_aes128_sha1_tcp_socket::send(const const_buffer &buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t transferring;
	try
	{
		transferring = prepare_send(buffer);
	}
	catch (std::exception &)
	{
		close();
		err = ERR_OPERATION_FAILURE;
		return;
	}
	const_buffer_sequence send_seq;
	send_seq.push_back(const_buffer(send_buf_head_));
	send_seq.push_back(const_buffer(buffer.data(), transferring));
	send_seq.push_back(const_buffer(send_buf_tail_));
	socket_->write(std::move(send_seq), err);
	if (err)
	{
		close();
		return;
	}
	transferred = transferring;
}

void ssr_auth_aes128_sha1_tcp_socket::async_send(const const_buffer &buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	size_t transferring;
	try
	{
		transferring = prepare_send(buffer);
	}
	catch (std::exception &)
	{
		async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE, 0); });
		return;
	}

	const_buffer_sequence send_seq;
	send_seq.push_back(const_buffer(send_buf_head_));
	send_seq.push_back(const_buffer(buffer.data(), transferring));
	send_seq.push_back(const_buffer(send_buf_tail_));
	socket_->async_write(std::move(send_seq),
		[this, transferring, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err, 0); });
			return;
		}
		(*callback)(0, transferring);
	});
}

void ssr_auth_aes128_sha1_tcp_socket::recv(const mutable_buffer &buffer, size_t &transferred, error_code &err)
{
}

void ssr_auth_aes128_sha1_tcp_socket::async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler)
{
}

void ssr_auth_aes128_sha1_tcp_socket::read(mutable_buffer_sequence &&buffer, error_code &err)
{
}

void ssr_auth_aes128_sha1_tcp_socket::async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler)
{
}

void ssr_auth_aes128_sha1_tcp_socket::async_read(const std::shared_ptr<mutable_buffer_sequence>& buffer, const std::shared_ptr<null_callback>& callback)
{
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
		catch (std::exception &)
		{
			close();
			err = ERR_OPERATION_FAILURE;
			return;
		}
		socket_->write(std::move(send_seq), err);
		if (err)
		{
			close();
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

void ssr_auth_aes128_sha1_tcp_socket::async_write(const std::shared_ptr<const_buffer_sequence>& buffer, const std::shared_ptr<null_callback>& callback)
{
	const_buffer_sequence send_seq;
	try
	{
		send_seq = prepare_send(*buffer);
	}
	catch (std::exception &)
	{
		async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		return;
	}

	socket_->async_write(std::move(send_seq),
		[this, buffer, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
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
	static constexpr CryptoPP::byte enc_iv[16] = { 0 };

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

	bool uid_key_set = false;
	uint32_t uid;
	try
	{
		const std::string &arg = server_data_.argument;
		size_t delim_pos = arg.find(':');
		if (delim_pos != std::string::npos)
		{
			uid = std::stoi(arg.substr(0, delim_pos));
			key_.resize(hasher.DIGESTSIZE);
			hasher.CalculateDigest((CryptoPP::byte *)key_.data(), (CryptoPP::byte *)arg.data() + delim_pos + 1, arg.size() - (delim_pos + 1));
			uid_key_set = true;
		}
	}
	catch (...) {}
	if (!uid_key_set)
	{
		uid = random_int<uint32_t>();
		key_.assign(socket_->key().begin(), socket_->key().end());
	}

	size_t rnd_size = random_int<uint16_t>();
	if (src_size > 400)
		rnd_size %= 512;
	else
		rnd_size %= 1024;
	size_t total_size = 1 + 6 + 4 + 16 + 4 + rnd_size + src_size + 4;

	send_buf_head_.resize(1 + 6 + 4 + 16 + 4 + rnd_size);
	//check_head
	random_bytes(send_buf_head_.data(), 1);
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
	encrypting_buf[12] = (uint8_t)(total_size & 0xFF);
	encrypting_buf[13] = (uint8_t)(total_size >> 8);
	//rnd_size
	encrypting_buf[14] = (uint8_t)(rnd_size & 0xFF);
	encrypting_buf[15] = (uint8_t)(rnd_size >> 8);
	//encrypted
	enc_key_str.clear();
	CryptoPP::StringSource ss(
		(const CryptoPP::byte *)key_.data(), key_.size(),
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
	random_bytes(send_buf_head_.data() + 31, rnd_size);

	//complete_hmac
	hmac.SetKey((const CryptoPP::byte *)key_.data(), key_.size());
	hmac.Update((const CryptoPP::byte *)send_buf_head_.data(), send_buf_head_.size());
	src_iter(hmac);
	hmac.Final(hmac_digest);
	send_buf_tail_.assign((const char *)hmac_digest, (const char *)hmac_digest + 4);

	key_.resize(key_.size() + 4); //Reserved for pack_id_le in key of hmac in prepare_send_data
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

	uint32_t pack_id_le = boost::endian::native_to_little(pack_id_);
	assert(key_.size() > 4);
	memcpy(key_.data() + key_.size() - 4, &pack_id_le, 4);
	hmac.SetKey((const CryptoPP::byte *)key_.data(), key_.size());

	send_buf_head_.resize(4); //Reserved for total_size(2 bytes) & total_size_mac(2 bytes)
	rnd_data(send_buf_head_, src_size); //rnd_data
	size_t total_size = send_buf_head_.size() + src_size + 4;
	//total_size
	send_buf_head_[0] = (uint8_t)(total_size & 0xFF);
	send_buf_head_[1] = (uint8_t)(total_size >> 8);
	//total_size_hmac
	hmac.CalculateDigest(hmac_digest, (const CryptoPP::byte *)send_buf_head_.data(), 2);
	send_buf_head_[2] = hmac_digest[0];
	send_buf_head_[3] = hmac_digest[1];

	//complete_hmac
	hmac.Update((const CryptoPP::byte *)send_buf_head_.data(), send_buf_head_.size());
	src_iter(hmac);
	hmac.Final(hmac_digest);
	send_buf_tail_.assign((const char *)hmac_digest, (const char *)hmac_digest + 4);

	++pack_id_;
}

size_t ssr_auth_aes128_sha1_tcp_socket::prepare_send(const const_buffer &buffer)
{
	size_t transferring;
	auto update_func = [&](CryptoPP::HMAC<CryptoPP::SHA1> &hasher) { hasher.Update((CryptoPP::byte *)buffer.data(), buffer.size()); };
	if (!auth_sent_)
	{
		transferring = std::min(auth_pack_size, buffer.size());
		prepare_send_data_auth(update_func, transferring);
	}
	else
	{
		transferring = std::min(pack_size, buffer.size());
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
	if (!auth_sent_)
	{
		if (buffer.size_total() <= auth_pack_size)
		{
			seq = std::move(buffer);
			buffer.clear();
		}
		else
		{
			while (!buffer.empty() && seq.size_total() + buffer.front().size() <= auth_pack_size)
			{
				seq.push_back(buffer.front());
				buffer.pop_front();
			}
			if (!buffer.empty() && seq.size_total() < auth_pack_size)
			{
				size_t extra = auth_pack_size - seq.size_total();
				seq.push_back(const_buffer(buffer.front().data(), extra));
				buffer.consume(extra);
			}
		}
		prepare_send_data_auth(update_func, seq.size_total());
	}
	else
	{
		if (buffer.size_total() <= pack_size)
		{
			seq = std::move(buffer);
			buffer.clear();
		}
		else
		{
			while (!buffer.empty() && seq.size_total() + buffer.front().size() <= pack_size)
			{
				seq.push_back(buffer.front());
				buffer.pop_front();
			}
			if (!buffer.empty() && seq.size_total() < pack_size)
			{
				size_t extra = pack_size - seq.size_total();
				seq.push_back(const_buffer(buffer.front().data(), extra));
				buffer.consume(extra);
			}
		}
		prepare_send_data(update_func, seq.size_total());
	}

	seq.push_front(const_buffer(send_buf_head_));
	seq.push_back(const_buffer(send_buf_tail_));
	return seq;
}
