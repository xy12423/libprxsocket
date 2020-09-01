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
#include "socket_vmess.h"
#include "random_generator.h"

using namespace prxsocket;
using namespace prxsocket::v2ray;

namespace
{

	constexpr uint32_t FNV1a32(const CryptoPP::byte *data, size_t size)
	{
		uint32_t hash = 0x811C9DC5;
		for (size_t i = 0; i < size; ++i)
		{
			hash = hash ^ (uint8_t)data[i];
			hash = hash * 0x01000193;
		}
		return hash;
	}

}

vmess_tcp_socket::vmess_tcp_socket(
	std::unique_ptr<prx_tcp_socket> &&base_socket, const endpoint &server_endpoint,
	const uint8_t *uid, uint8_t security, std::unique_ptr<encryptor> &&enc, std::unique_ptr<decryptor> &&dec
)
	:socket_(std::move(base_socket)), server_ep_(server_endpoint),
	security_(security), enc_(std::move(enc)), dec_(std::move(dec)),
	recv_buf_(std::make_unique<char[]>(MAX_BLOCK_SIZE))
{
	memcpy(uid_, uid, sizeof(uid_));
}

void vmess_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	socket_->connect(server_ep_, err);
	if (err)
		return;

	remote_ep_ = ep;
	std::vector<char> header;
	try
	{
		encode_header(header);
	}
	catch (...)
	{
		force_close();
		err = ERR_OPERATION_FAILURE;
		return;
	}

	socket_->write(const_buffer(header), err);
	if (err)
	{
		force_close();
		return;
	}
	header_sent_ = true;
}

void vmess_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket_->async_connect(server_ep_,
		[this, ep, callback](error_code err)
	{
		if (err)
		{
			(*callback)(err);
			return;
		}

		remote_ep_ = ep;
		std::shared_ptr<std::vector<char>> header = std::make_shared<std::vector<char>>();
		try
		{
			encode_header(*header);
		}
		catch (...)
		{
			force_async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}

		socket_->async_write(const_buffer(*header),
			[this, header, callback](error_code err)
		{
			if (err)
			{
				force_async_close([callback, err](error_code) { (*callback)(err); });
				return;
			}
			header_sent_ = true;
			(*callback)(0);
		});
	});
}

void vmess_tcp_socket::send(const const_buffer &buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t transferring;
	try
	{
		transferring = encode(buffer);
	}
	catch (const std::exception &)
	{
		force_close();
		err = ERR_OPERATION_FAILURE;
		return;
	}

	socket_->write(const_buffer(send_buf_), err);
	if (err)
	{
		force_close();
		return;
	}
	transferred = transferring;
}

void vmess_tcp_socket::async_send(const const_buffer &buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));

	size_t transferring;
	try
	{
		transferring = encode(buffer);
	}
	catch (const std::exception &)
	{
		force_async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE, 0); });
		return;
	}

	socket_->async_write(const_buffer(send_buf_),
		[this, transferring, callback](error_code err)
	{
		if (err)
		{
			force_async_close([callback, err](error_code) { (*callback)(err, 0); });
			return;
		}
		(*callback)(0, transferring);
	});
}

void vmess_tcp_socket::recv(const mutable_buffer &buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;
	if (read_empty())
	{
		recv_data(err);
		if (err)
			return;
	}
	transferred = read_data(buffer.data(), buffer.size());
}

void vmess_tcp_socket::async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler)
{
	if (read_empty())
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

void vmess_tcp_socket::read(mutable_buffer_sequence &&buffer, error_code &err)
{
	err = 0;
	while (!buffer.empty())
	{
		if (read_empty())
		{
			recv_data(err);
			if (err)
				return;
		}
		size_t transferred = read_data(buffer.front().data(), buffer.front().size());
		buffer.consume(transferred);
	}
}

void vmess_tcp_socket::async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	while (!buffer.empty())
	{
		if (read_empty())
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

void vmess_tcp_socket::async_read(const std::shared_ptr<mutable_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback)
{
	while (!buffer->empty())
	{
		if (read_empty())
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

void vmess_tcp_socket::write(const_buffer_sequence &&buffer, error_code &err)
{
	if (buffer.count() == 1)
		return prx_tcp_socket::write(buffer.front(), err);
	err = 0;
	if (buffer.empty())
		return;

	while (!buffer.empty())
	{
		try
		{
			encode(buffer);
		}
		catch (const std::exception &)
		{
			force_close();
			err = ERR_OPERATION_FAILURE;
			return;
		}
		socket_->write(const_buffer(send_buf_), err);
		if (err)
		{
			force_close();
			return;
		}
	}
}

void vmess_tcp_socket::async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	if (buffer.count() == 1)
		return prx_tcp_socket::async_write(buffer.front(), std::move(complete_handler));
	if (buffer.empty())
		return complete_handler(0);

	async_write(std::make_shared<const_buffer_sequence>(std::move(buffer)), std::make_shared<null_callback>(std::move(complete_handler)));
}

void vmess_tcp_socket::async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback)
{
	try
	{
		encode(*buffer);
	}
	catch (const std::exception &)
	{
		force_async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		return;
	}

	socket_->async_write(const_buffer(send_buf_),
		[this, buffer, callback](error_code err)
	{
		if (err)
		{
			force_async_close([callback, err](error_code) { (*callback)(err); });
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

void vmess_tcp_socket::close(error_code &ec)
{
	bool still_connected = is_connected();
	if (still_connected)
	{
		size_t transferred;
		send(const_buffer(nullptr, 0), transferred, ec);
	}
	force_close(ec);
}

void vmess_tcp_socket::async_close(null_callback &&complete_handler)
{
	bool still_connected = is_connected();
	if (still_connected)
	{
		std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
		async_send(const_buffer(nullptr, 0),
			[this, callback](error_code err, size_t)
		{
			force_async_close(std::move(*callback));
		});
	}
	else
	{
		force_async_close(std::move(complete_handler));
	}
}

void vmess_tcp_socket::force_close(error_code &ec)
{
	header_sent_ = header_received_ = false;
	socket_->close(ec);
}

void vmess_tcp_socket::force_async_close(null_callback &&complete_handler)
{
	header_sent_ = header_received_ = false;
	socket_->async_close(std::move(complete_handler));
}

void vmess_tcp_socket::wait_header(error_code &err)
{
	socket_->read(mutable_buffer(recv_buf_.get(), 4), err);
	if (err)
	{
		force_close();
		return;
	}

	try
	{
		decode_header();
	}
	catch (...)
	{
		force_close();
		err = ERR_OPERATION_FAILURE;
		return;
	}
	header_received_ = true;
	err = 0;
}

void vmess_tcp_socket::async_wait_header(null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket_->async_read(mutable_buffer(recv_buf_.get(), 4),
		[this, callback](error_code err)
	{
		if (err)
		{
			force_async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}

		try
		{
			decode_header();
		}
		catch (...)
		{
			force_async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}
		header_received_ = true;
		(*callback)(0);
		return;
	});
}

void vmess_tcp_socket::recv_data(error_code &err)
{
	if (!header_received_)
	{
		wait_header(err);
		if (err)
		{
			force_close();
			return;
		}
	}

	socket_->read(mutable_buffer(recv_buf_.get(), 2), err);
	if (err)
	{
		force_close();
		return;
	}
	size_t size = decode_size();
	if (size > MAX_BLOCK_SIZE)
	{
		force_close();
		err = ERR_BAD_ARG_REMOTE;
		return;
	}

	socket_->read(mutable_buffer(recv_buf_.get(), size), err);
	if (err)
	{
		force_close();
		return;
	}
	try
	{
		decode(size);
	}
	catch (const std::exception &)
	{
		force_close();
		err = ERR_OPERATION_FAILURE;
		return;
	}
}

void vmess_tcp_socket::async_recv_data(null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));

	if (!header_received_)
	{
		async_wait_header([this, callback](error_code err)
		{
			if (err)
			{
				async_close([callback, err](error_code) { (*callback)(err); });
				return;
			}
			async_recv_data(std::move(*callback));
		});
		return;
	}

	socket_->async_read(mutable_buffer(recv_buf_.get(), 2),
		[this, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}
		size_t size = decode_size();
		async_recv_data_body(size, callback);
	});
}

void vmess_tcp_socket::async_recv_data_body(size_t size, const std::shared_ptr<null_callback> &callback)
{
	if (size > MAX_BLOCK_SIZE)
	{
		async_close([callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
		return;
	}
	socket_->async_read(mutable_buffer(recv_buf_.get(), size),
		[this, size, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}

		try
		{
			decode(size);
		}
		catch (const std::exception &)
		{
			async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}

		(*callback)(0);
	});
}

size_t vmess_tcp_socket::read_data(char *dst, size_t dst_size)
{
	size_t size_cpy = std::min(dec_buf_.size() - dec_ptr_, dst_size);
	memcpy(dst, dec_buf_.data() + dec_ptr_, size_cpy);
	dec_ptr_ += size_cpy;
	if (dec_ptr_ == dec_buf_.size())
	{
		dec_buf_.clear();
		dec_ptr_ = 0;
	}
	return size_cpy;
}

bool vmess_tcp_socket::read_empty()
{
	return dec_buf_.empty();
}

void vmess_tcp_socket::encode_header(std::vector<char> &buf)
{
	thread_local CryptoPP::HMAC<CryptoPP::Weak::MD5> hmac_md5;
	thread_local CryptoPP::Weak::MD5 hasher_md5;
	thread_local CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc_aes_128_cfb;
	static constexpr const char command_salt[] = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

	//Timestamp

	auto utc_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	int shift = random_generator::random_int<uint16_t>() * 60 / 0x10000 - 30;
	uint64_t timestamp_be = boost::endian::native_to_big((uint64_t)(utc_time + shift));

	//Command (plain)

	CryptoPP::byte command_buf[1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 0x100 + 15 + 4];
	size_t command_size;

	//Ver
	command_buf[0] = 1;
	//IV & Key & V, prepare P
	random_generator::random_bytes(command_buf + 1, 16 + 16 + 1 + 1);
	//P & Sec
	uint8_t P = command_buf[34] >> 4;
	command_buf[35] = (command_buf[34] & 0xF0) | (security_ & 0x0F);
	//Opt
	command_buf[34] = 0x01 | 0x04;
	//Rsv
	command_buf[36] = 0;
	//Cmd
	command_buf[37] = 0x01; //TCP

	//Port
	uint16_t port_be = boost::endian::native_to_big((uint16_t)remote_ep_.port());
	memcpy(command_buf + 38, &port_be, 2);
	//T & A, set command_size to size of [Ver, Rnd)
	const address &addr = remote_ep_.addr();
	switch (addr.type())
	{
	case address::V4:
	{
		command_buf[40] = 0x01; //T = IPv4
		memcpy(command_buf + 41, addr.v4().data(), address_v4::ADDR_SIZE); //A
		command_size = 41 + address_v4::ADDR_SIZE;
		break;
	}
	case address::STR:
	{
		const std::string &str = addr.str().data();
		uint8_t size = (uint8_t)std::min(str.size(), (size_t)std::numeric_limits<uint8_t>::max());
		command_buf[40] = 0x02; //T = Domain
		command_buf[41] = size; //A.L
		memcpy(command_buf + 42, str.data(), size); //A
		command_size = 41 + 1 + size;
		break;
	}
	case address::V6:
	{
		command_buf[40] = 0x03; //T = IPv6
		memcpy(command_buf + 41, addr.v6().data(), address_v6::ADDR_SIZE); //A
		command_size = 41 + address_v6::ADDR_SIZE;
		break;
	}
	default:
		assert(false);
		command_size = 0;
	}

	//Rnd
	random_generator::random_bytes(command_buf + command_size, P);
	command_size += P;
	//F
	uint32_t f_be = boost::endian::native_to_big(FNV1a32(command_buf, command_size));
	memcpy(command_buf + command_size, &f_be, 4);
	command_size += 4;

	//Client Request

	buf.resize(16 + command_size);

	//Auth info

	static_assert(hmac_md5.DIGESTSIZE == 16, "Wrong hmac size");
	hmac_md5.SetKey(uid_, sizeof(uid_));
	hmac_md5.CalculateDigest((CryptoPP::byte *)buf.data(), (const CryptoPP::byte *)&timestamp_be, sizeof(timestamp_be));

	//Command (cipher)

	static_assert(hasher_md5.DIGESTSIZE == 16, "Wrong hash size");
	CryptoPP::byte command_key[hasher_md5.DIGESTSIZE], command_iv[hasher_md5.DIGESTSIZE];
	hasher_md5.Update(uid_, sizeof(uid_));
	hasher_md5.Update((const CryptoPP::byte *)command_salt, sizeof(command_salt) - 1); //Ignore the trailing \0
	hasher_md5.Final(command_key);
	hasher_md5.Update((const CryptoPP::byte *)&timestamp_be, sizeof(timestamp_be));
	hasher_md5.Update((const CryptoPP::byte *)&timestamp_be, sizeof(timestamp_be));
	hasher_md5.Update((const CryptoPP::byte *)&timestamp_be, sizeof(timestamp_be));
	hasher_md5.Update((const CryptoPP::byte *)&timestamp_be, sizeof(timestamp_be));
	hasher_md5.Final(command_iv);
	enc_aes_128_cfb.SetKeyWithIV(command_key, sizeof(command_key), command_iv);
	CryptoPP::ArraySource as(
		command_buf, command_size,
		true,
		new CryptoPP::StreamTransformationFilter(enc_aes_128_cfb, new CryptoPP::ArraySink((CryptoPP::byte *)buf.data() + 16, command_size))
	);

	//Save necessary protocol arguments

	memcpy(request_key_, command_buf + 17, 16);
	hasher_md5.CalculateDigest(response_key_, request_key_, 16);
	if (security_ == SEC_CHACHA20_POLY1305) //ChaCha20-Poly1305 need special body key
	{
		memcpy(request_body_key_, response_key_, 16);
		hasher_md5.CalculateDigest(request_body_key_ + 16, request_body_key_, 16);
		memcpy(response_body_key_, request_body_key_ + 16, 16);
		hasher_md5.CalculateDigest(response_body_key_ + 16, response_body_key_, 16);
	}
	else
	{
		memcpy(request_body_key_, request_key_, 16);
		memcpy(response_body_key_, response_key_, 16);
	}
	memcpy(request_iv_, command_buf + 1, 16);
	hasher_md5.CalculateDigest(response_iv_, request_iv_, 16);
	verify_byte_ = command_buf[33];
	request_mask_.Restart();
	request_mask_.Update(request_iv_, 16);
	request_mask_.ShakeStart();
	response_mask_.Restart();
	response_mask_.Update(response_iv_, 16);
	response_mask_.ShakeStart();
	request_count_ = 0;
	response_count_ = 0;
}

size_t vmess_tcp_socket::encode(const const_buffer &buffer)
{
	size_t transferring = (uint16_t)std::min(buffer.size(), MAX_BLOCK_SIZE - 64);

	uint16_t count_be = boost::endian::native_to_big(request_count_);
	++request_count_;
	memcpy(request_iv_, &count_be, sizeof(count_be));
	enc_->set_key_iv((const char *)request_body_key_, (const char *)request_iv_);
	send_buf_.resize(sizeof(uint16_t)); //L
	enc_->encrypt(send_buf_, buffer.data(), transferring);

	assert(send_buf_.size() - 2 <= MAX_BLOCK_SIZE);
	uint16_t size = (uint16_t)(send_buf_.size() - 2);
	uint16_t mask_be;
	request_mask_.ShakeContinue(&mask_be, sizeof(mask_be));
	uint16_t size_masked_be = boost::endian::native_to_big(size) ^ mask_be;
	memcpy(send_buf_.data(), &size_masked_be, sizeof(size_masked_be));

	return transferring;
}

void vmess_tcp_socket::encode(const_buffer_sequence &buffer)
{
	thread_local std::vector<char> enc_buf;
	size_t transferring = std::min(buffer.size_total(), MAX_BLOCK_SIZE - 64);
	enc_buf.resize(transferring);
	buffer.gather(enc_buf.data(), enc_buf.size());
	encode(const_buffer(enc_buf));
}

void vmess_tcp_socket::decode_header()
{
	thread_local CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption dec_aes_128_cfb;
	CryptoPP::byte dec_header[4];
	dec_aes_128_cfb.SetKeyWithIV(response_key_, sizeof(response_key_), response_iv_);
	CryptoPP::ArraySource as(
		(CryptoPP::byte *)recv_buf_.get(), 4,
		true,
		new CryptoPP::StreamTransformationFilter(dec_aes_128_cfb, new CryptoPP::ArraySink(dec_header, sizeof(dec_header)))
	);
	if (dec_header[0] != verify_byte_)
		throw std::invalid_argument("Invalid verify byte");
	if (dec_header[2] != 0x00)
		throw std::invalid_argument("Unsupported command");
	if (dec_header[3] != 0x00)
		throw std::invalid_argument("Command length should be 0");
}

size_t vmess_tcp_socket::decode_size()
{
	uint16_t size_masked_be;
	memcpy(&size_masked_be, recv_buf_.get(), sizeof(uint16_t));
	uint16_t mask_be;
	response_mask_.ShakeContinue(&mask_be, sizeof(mask_be));
	return boost::endian::big_to_native((uint16_t)(size_masked_be ^ mask_be));
}

void vmess_tcp_socket::decode(size_t size)
{
	uint16_t count_be = boost::endian::native_to_big(response_count_);
	++response_count_;
	memcpy(response_iv_, &count_be, sizeof(count_be));
	dec_->set_key_iv((const char *)response_body_key_, (const char *)response_iv_);
	dec_->decrypt(dec_buf_, recv_buf_.get(), size);
}
