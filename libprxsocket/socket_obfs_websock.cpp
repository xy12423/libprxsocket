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
#include "socket_obfs_websock.h"
#include "random_generator.h"

using namespace prxsocket;
using namespace prxsocket::http_helper;
using namespace CryptoPP;

namespace
{

	struct base64_helper
	{
		static constexpr char map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		static constexpr char pad = '=';
		uint8_t rev_map[256];

		constexpr base64_helper()
			:rev_map{}
		{
			for (uint8_t i = 0; i < 64; ++i)
				rev_map[(uint8_t)map[i]] = i;
		}
	};
	constexpr base64_helper b64;

	void base64(std::string &dst, const char *data, size_t size)
	{
		const char *data_end = data + size - 3;
		for (; data <= data_end; data += 3)
		{
			dst.push_back(b64.map[(uint8_t)(data[0]) >> 2]);
			dst.push_back(b64.map[(((uint8_t)(data[0]) << 4) | ((uint8_t)(data[1]) >> 4)) & 0x3F]);
			dst.push_back(b64.map[(((uint8_t)(data[1]) << 2) | ((uint8_t)(data[2]) >> 6)) & 0x3F]);
			dst.push_back(b64.map[(uint8_t)(data[2]) & 0x3F]);
		}

		if (data != data_end)
		{
			data_end += 3;
			switch (data_end - data)
			{
			case 1:
				dst.push_back(b64.map[(uint8_t)(data[0]) >> 2]);
				dst.push_back(b64.map[((uint8_t)(data[0]) << 4) & 0x3F]);
				dst.push_back(b64.pad);
				dst.push_back(b64.pad);
				break;
			case 2:
				dst.push_back(b64.map[(uint8_t)(data[0]) >> 2]);
				dst.push_back(b64.map[((uint8_t)(data[0]) << 4 | (uint8_t)(data[1]) >> 4) & 0x3F]);
				dst.push_back(b64.map[((uint8_t)(data[1]) << 2) & 0x3F]);
				dst.push_back(b64.pad);
				break;
			}
		}
	}

	void base64(std::string &dst, const std::string &src)
	{
		base64(dst, src.data(), src.size());
	}

	void base64(std::string &dst, const byte *src, size_t src_size)
	{
		base64(dst, (const char*)src, src_size);
	}

	void base64_rev(std::string &dst, const char *data, size_t size)
	{
		if (size % 4 != 0)
			throw(std::runtime_error("Invalid base64"));
		if (size == 0)
			return;
		dst.reserve(dst.size() + size / 4 * 3);

		const char *data_end = data + size;
		for (; data < data_end; data += 4)
		{
			dst.push_back((b64.rev_map[(uint8_t)data[0]] << 2) | (b64.rev_map[(uint8_t)data[1]] >> 4));
			dst.push_back((b64.rev_map[(uint8_t)data[1]] << 4) | (b64.rev_map[(uint8_t)data[2]] >> 2));
			dst.push_back((b64.rev_map[(uint8_t)data[2]] << 6) | b64.rev_map[(uint8_t)data[3]]);
		}
		if (data[-1] == b64.pad)
		{
			dst.pop_back();
			if (data[-2] == b64.pad)
				dst.pop_back();
		}
	}

	void gen_websocket_accept(std::string &dst, const std::string &src_b64)
	{
		static constexpr char uuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		static constexpr size_t uuid_size = sizeof(uuid) - 1;
		std::string buf;
		buf.reserve(src_b64.size() + uuid_size);
		buf.append(src_b64);
		buf.append(uuid, uuid_size);
		thread_local SHA1 hasher_sha1;
		char result[20];
		hasher_sha1.CalculateDigest((byte*)result, (const byte*)buf.data(), buf.size());
		base64(dst, result, 20);
	}

	void gen_websocket_accept(std::string &dst, const byte *src, size_t size)
	{
		std::string src_b64;
		base64(src_b64, src, size);
		gen_websocket_accept(dst, src_b64);
	}

}

void obfs_websock_tcp_socket::encode(std::string &dst, const char *src, size_t size)
{
	thread_local std::vector<char> buf;
	buf.clear();
	StringSource ss((const byte *)src, size, true, new StreamTransformationFilter(e_, new StringSinkTemplate<std::vector<char>>(buf)));

	char *dst_p;
	if (buf.size() <= 125)
	{
		dst.resize(6 + buf.size());
		dst_p = dst.data();
		*dst_p++ = '\x82';
		*dst_p++ = 0x80 | (uint8_t)(buf.size());
	}
	else if (buf.size() <= 0xFFFF)
	{
		dst.resize(8 + buf.size());
		dst_p = dst.data();
		*dst_p++ = '\x82';
		*dst_p++ = '\xFE';
		uint16_t buf_size_be = boost::endian::native_to_big((uint16_t)buf.size());
		memcpy(dst_p, &buf_size_be, sizeof(buf_size_be));
		dst_p += sizeof(buf_size_be);
	}
	else
	{
		dst.resize(14 + buf.size());
		dst_p = dst.data();
		*dst_p++ = '\x82';
		*dst_p++ = '\xFF';
		uint64_t buf_size_be = boost::endian::native_to_big((uint64_t)buf.size());
		memcpy(dst_p, &buf_size_be, sizeof(buf_size_be));
		dst_p += sizeof(buf_size_be);
	}

	if constexpr (sizeof(uint32_t) == 4 * sizeof(char))
	{
		union {
			uint32_t u32;
			uint8_t u8[4];
			char c8[4];
		} mask{};
		random_generator::random_bytes(mask.c8, 4);
		memcpy(dst_p, mask.c8, 4);
		dst_p += 4;

		const char *data = buf.data(), *data_end = buf.data() + buf.size();
		for (; data < data_end && (uintptr_t)data % 8 != 0; ++data, ++dst_p)
		{
			*dst_p = (const unsigned char)*data ^ mask.u8[0];
			uint32_t tmp1 = boost::endian::little_to_native(mask.u32);
			uint32_t tmp2 = (tmp1 >> 8) | (tmp1 << 24);
			mask.u32 = boost::endian::native_to_little(tmp2);
		}
		for (; data < data_end - 8; data += 4, dst_p += 4)
		{
			uint32_t tmp = *(const uint32_t *)(const void *)data ^ mask.u32;
			memcpy(dst_p, &tmp, 4);
		}
		for (; data < data_end; ++data, ++dst_p)
		{
			*dst_p = (const unsigned char)*data ^ mask.u8[0];
			uint32_t tmp1 = boost::endian::little_to_native(mask.u32);
			uint32_t tmp2 = (tmp1 >> 8) | (tmp1 << 24);
			mask.u32 = boost::endian::native_to_little(tmp2);
		}
	}
	else
	{
		byte mask[4];
		int maskp = 0;
		random_generator::random_bytes(mask, 4);
		memcpy(dst_p, mask, 4);
		dst_p += 4;
		for (const char *data = buf.data(), *data_end = buf.data() + buf.size(); data < data_end; ++data, ++dst_p)
		{
			*dst_p = (const unsigned char)*data ^ mask[maskp];
			maskp = (maskp + 1) % 4;
		}
	}
}

void obfs_websock_tcp_socket::decode(std::string &dst, const char *src, size_t size)
{
	thread_local std::vector<char> buf;
	buf.resize(size - 4);
	const char *src_end = src + size;

	if constexpr (sizeof(uint32_t) == 4 * sizeof(char))
	{
		union {
			uint32_t u32;
			uint8_t u8[4];
			char c8[4];
		} mask{};
		for (int i = 0; i < 4; ++i, ++src)
			mask.c8[i] = *src;

		char *buf_p = buf.data();
		for (; src < src_end && (uintptr_t)src % 8 != 0; ++src, ++buf_p)
		{
			*buf_p = (const unsigned char)*src ^ mask.u8[0];
			uint32_t tmp1 = boost::endian::little_to_native(mask.u32);
			uint32_t tmp2 = (tmp1 >> 8) | (tmp1 << 24);
			mask.u32 = boost::endian::native_to_little(tmp2);
		}
		for (; src < src_end - 8; src += 4, buf_p += 4)
		{
			uint32_t tmp = *(const uint32_t *)(const void *)src ^ mask.u32;
			memcpy(buf_p, &tmp, 4);
		}
		for (; src < src_end; ++src, ++buf_p)
		{
			*buf_p = (const unsigned char)*src ^ mask.u8[0];
			uint32_t tmp1 = boost::endian::little_to_native(mask.u32);
			uint32_t tmp2 = (tmp1 >> 8) | (tmp1 << 24);
			mask.u32 = boost::endian::native_to_little(tmp2);
		}
	}
	else
	{
		byte mask[4];
		int maskp = 0;
		for (int i = 0; i < 4; ++i, ++src)
			mask[i] = *src;

		char *buf_p = buf.data();
		for (; src < src_end; ++src, ++buf_p)
		{
			*buf_p = (const unsigned char)*src ^ mask[maskp];
			maskp = (maskp + 1) % 4;
		}
	}

	dst.clear();
	StringSource ss((const byte *)buf.data(), buf.size(), true, new StreamTransformationFilter(d_, new StringSink(dst)));
}

void obfs_websock_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	socket_->connect(ep, err);
	if (err)
		return;

	try
	{
		std::string iv_b64, http_req;
		random_generator::random_bytes(iv_, SYM_BLOCK_SIZE);
		e_.SetKeyWithIV(key_, SYM_BLOCK_SIZE, iv_);
		d_.SetKeyWithIV(key_, SYM_BLOCK_SIZE, iv_);
		iv_b64.reserve((SYM_BLOCK_SIZE / 3 + 1) * 4);
		base64(iv_b64, iv_.data(), SYM_BLOCK_SIZE);
		http_req.append("GET /ep HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
		http_req.append(iv_b64);
		http_req.append("\r\nSec-WebSocket-Protocol: str\r\nSec-WebSocket-Version: 13\r\n\r\n");

		socket_->write(const_buffer(http_req), err);
		if (err)
		{
			reset();
			return;
		}

		http_header header;
		size_t recv_buf_ptr = 0, recv_buf_ptr_end = 0, size_read, size_parsed;
		bool finished;
		while (finished = header.parse(recv_buf_.get() + recv_buf_ptr, recv_buf_ptr_end - recv_buf_ptr, size_parsed), recv_buf_ptr += size_parsed, !finished)
		{
			if (recv_buf_ptr_end >= RECV_BUF_SIZE)
				throw(std::runtime_error("HTTP header too long"));
			socket_->recv(mutable_buffer(recv_buf_.get() + recv_buf_ptr_end, RECV_BUF_SIZE - recv_buf_ptr_end), size_read, err);
			if (err)
			{
				reset();
				return;
			}
			recv_buf_ptr_end += size_read;
		}

		if (header.at(http_header::NAME_STATUS_CODE) != "101" || header.at("Connection") != "Upgrade" || header.at("Upgrade") != "websocket")
			throw(std::runtime_error("Bad HTTP header"));
		std::string sec_accept;
		gen_websocket_accept(sec_accept, iv_b64);
		if (header.at("Sec-WebSocket-Accept") != sec_accept)
			throw(std::runtime_error("Invalid Sec-WebSocket-Accept"));
	}
	catch (const std::exception &)
	{
		reset();
		err = ERR_OPERATION_FAILURE;
		return;
	}

	state_ = STATE_OK;
}

void obfs_websock_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket_->async_connect(ep,
		[this, callback](error_code err)
	{
		if (err)
		{
			(*callback)(err);
			return;
		}
		send_websocket_req(callback);
	});
}

void obfs_websock_tcp_socket::send_websocket_req(const std::shared_ptr<null_callback> &callback)
{
	std::shared_ptr<std::string> http_req = std::make_shared<std::string>();
	try
	{
		random_generator::random_bytes(iv_, SYM_BLOCK_SIZE);
		e_.SetKeyWithIV(key_, SYM_BLOCK_SIZE, iv_);
		d_.SetKeyWithIV(key_, SYM_BLOCK_SIZE, iv_);
		http_req->append("GET /ep HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
		base64(*http_req, iv_.data(), SYM_BLOCK_SIZE);
		http_req->append("\r\nSec-WebSocket-Protocol: str\r\nSec-WebSocket-Version: 13\r\n\r\n");
	}
	catch (const std::exception &)
	{
		reset();
		(*callback)(ERR_OPERATION_FAILURE);
		return;
	}

	socket_->async_write(const_buffer(*http_req),
		[this, http_req, callback](error_code err)
	{
		if (err)
		{
			reset();
			(*callback)(err);
			return;
		}
		recv_websocket_resp(callback, std::make_shared<http_header>());
	});
}

void obfs_websock_tcp_socket::recv_websocket_resp(const std::shared_ptr<null_callback> &callback, const std::shared_ptr<http_header> &header, size_t old_ptr, size_t old_ptr_end)
{
	socket_->async_recv(mutable_buffer(recv_buf_.get() + old_ptr_end, RECV_BUF_SIZE - old_ptr_end),
		[this, callback, header, old_ptr, old_ptr_end](error_code err, size_t transferred)
	{
		if (err)
		{
			reset();
			(*callback)(err);
			return;
		}

		try
		{
			size_t new_ptr_end = old_ptr_end + transferred;
			size_t size_parsed;
			bool finished = header->parse(recv_buf_.get() + old_ptr, new_ptr_end - old_ptr, size_parsed);
			size_t new_ptr = old_ptr + size_parsed;
			if (!finished)
			{
				if (new_ptr_end >= RECV_BUF_SIZE)
					throw(std::runtime_error("HTTP response too long"));
				recv_websocket_resp(callback, header, new_ptr, new_ptr_end);
				return;
			}

			if (header->at(http_header::NAME_STATUS_CODE) != "101" || header->at("Connection") != "Upgrade" || header->at("Upgrade") != "websocket")
				throw(std::runtime_error("Bad HTTP header"));
			std::string sec_accept;
			gen_websocket_accept(sec_accept, iv_.data(), SYM_BLOCK_SIZE);
			if (header->at("Sec-WebSocket-Accept") != sec_accept)
				throw(std::runtime_error("Invalid Sec-WebSocket-Accept"));
			state_ = STATE_OK;
			(*callback)(0);
		}
		catch (const std::exception &)
		{
			reset();
			(*callback)(ERR_OPERATION_FAILURE);
		}
	});
}

void obfs_websock_tcp_socket::send(const_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t transferring = transfer_size(buffer.size());
	try
	{
		encode(send_buf_, buffer.data(), transferring);
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

void obfs_websock_tcp_socket::async_send(const_buffer buffer, transfer_callback &&complete_handler)
{
	size_t transferring = transfer_size(buffer.size());

	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	try
	{
		encode(send_buf_, buffer.data(), transferring);
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

void obfs_websock_tcp_socket::recv(mutable_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;
	if (dec_buf_.empty())
	{
		err = recv_data();
		if (err)
			return;
	}
	transferred = read_data(buffer.data(), buffer.size());
}

void obfs_websock_tcp_socket::async_recv(mutable_buffer buffer, transfer_callback &&complete_handler)
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

void obfs_websock_tcp_socket::read(mutable_buffer_sequence &&buffer, error_code &err)
{
	err = 0;
	while (!buffer.empty())
	{
		if (dec_buf_.empty())
		{
			err = recv_data();
			if (err)
				return;
		}
		size_t transferred = read_data(buffer.front().data(), buffer.front().size());
		buffer.consume_front(transferred);
	}
}

void obfs_websock_tcp_socket::async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler)
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
		buffer.consume_front(transferred);
	}
	complete_handler(0);
}

void obfs_websock_tcp_socket::async_read(const std::shared_ptr<mutable_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback)
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
		buffer->consume_front(transferred);
	}
	(*callback)(0);
}

void obfs_websock_tcp_socket::write(const_buffer_sequence &&buffer, error_code &err)
{
	if (buffer.count() == 1)
		return prx_tcp_socket::write(buffer.front(), err);
	err = 0;
	if (buffer.empty())
		return;

	thread_local std::unique_ptr<char[]> buf = std::make_unique<char[]>(SEND_SIZE_MAX);
	size_t transferring = transfer_size(buffer.size_total());

	while (!buffer.empty())
	{
		size_t copied = buffer.gather(buf.get(), transferring);
		try
		{
			encode(send_buf_, buf.get(), copied);
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

void obfs_websock_tcp_socket::async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	if (buffer.count() == 1)
		return prx_tcp_socket::async_write(buffer.front(), std::move(complete_handler));
	if (buffer.empty())
		return complete_handler(0);

	async_write(std::make_shared<const_buffer_sequence>(std::move(buffer)), std::make_shared<null_callback>(std::move(complete_handler)));
}

void obfs_websock_tcp_socket::async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback)
{
	thread_local std::unique_ptr<char[]> buf = std::make_unique<char[]>(SEND_SIZE_MAX);
	size_t transferring = transfer_size(buffer->size_total());

	size_t copied = buffer->gather(buf.get(), transferring);
	try
	{
		encode(send_buf_, buf.get(), copied);
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

void obfs_websock_tcp_socket::shutdown(shutdown_type type, error_code &ec)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->shutdown(type, ec);
}

void obfs_websock_tcp_socket::async_shutdown(shutdown_type type, null_callback &&complete_handler)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->async_shutdown(type, std::move(complete_handler));
}

void obfs_websock_tcp_socket::close(error_code &ec)
{
	reset();
	return socket_->close(ec);
}

void obfs_websock_tcp_socket::async_close(null_callback &&complete_handler)
{
	reset();
	socket_->async_close(std::move(complete_handler));
}

error_code obfs_websock_tcp_socket::recv_data()
{
	error_code err;
	socket_->read(mutable_buffer(recv_buf_.get(), 2), err);
	if (err)
	{
		reset_recv();
		return err;
	}
	if (recv_buf_[0] != '\x82')
	{
		shutdown(shutdown_receive, err);
		return ERR_BAD_ARG_REMOTE;
	}
	if (((uint8_t)recv_buf_[1] & 0x80u) != 0x80u)
	{
		shutdown(shutdown_receive, err);
		return ERR_BAD_ARG_REMOTE;
	}

	size_t size;
	if (recv_buf_[1] == '\xFF')
	{
		socket_->read(mutable_buffer(recv_buf_.get(), 8), err);
		if (err)
		{
			reset_recv();
			return err;
		}

		uint64_t size64 = 0;
		for (char *data = recv_buf_.get(), *data_end = recv_buf_.get() + 8; data < data_end; ++data)
			size64 = (size64 << 8) | (uint8_t)*data;
		if (size64 > std::numeric_limits<size_t>::max() - 4)
		{
			shutdown(shutdown_receive, err);
			return ERR_BAD_ARG_REMOTE;
		}
		size = (size_t)(size64 + 4);
	}
	else if (recv_buf_[1] == '\xFE')
	{
		socket_->read(mutable_buffer(recv_buf_.get(), 2), err);
		if (err)
		{
			reset_recv();
			return err;
		}
		size = (((uint8_t)recv_buf_[0] << 8u) | (uint8_t)recv_buf_[1]) + 4;
	}
	else
	{
		size = ((uint8_t)recv_buf_[1] & 0x7Fu) + 4;
	}

	if (size > RECV_BUF_SIZE)
	{
		shutdown(shutdown_receive, err);
		return ERR_OPERATION_FAILURE;
	}

	socket_->read(mutable_buffer(recv_buf_.get(), size), err);
	if (err)
	{
		reset_recv();
		return err;
	}

	try
	{
		assert(dec_buf_.empty());
		decode(dec_buf_, recv_buf_.get(), size);
	}
	catch (const std::exception &)
	{
		shutdown(shutdown_receive, err);
		return ERR_OPERATION_FAILURE;
	}

	return 0;
}

void obfs_websock_tcp_socket::async_recv_data(null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket_->async_read(mutable_buffer(recv_buf_.get(), 2),
		[this, callback](error_code err)
	{
		if (err)
		{
			reset_recv();
			(*callback)(err);
			return;
		}
		if (recv_buf_[0] != '\x82')
		{
			async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
			return;
		}
		if (((uint8_t)recv_buf_[1] & 0x80u) != 0x80u)
		{
			async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
			return;
		}

		if (recv_buf_[1] == '\xFF')
			async_recv_data_size_64(callback);
		else if (recv_buf_[1] == '\xFE')
			async_recv_data_size_16(callback);
		else
			async_recv_data_body(callback, ((uint8_t)recv_buf_[1] & 0x7Fu) + 4);
	});
}

void obfs_websock_tcp_socket::async_recv_data_size_16(const std::shared_ptr<null_callback> &callback)
{
	socket_->async_read(mutable_buffer(recv_buf_.get(), 2),
		[this, callback](error_code err)
	{
		if (err)
		{
			reset_recv();
			(*callback)(err);
			return;
		}
		uint16_t size = ((uint8_t)recv_buf_[0] << 8u) | (uint8_t)recv_buf_[1];
		async_recv_data_body(callback, size + 4);
	});
}

void obfs_websock_tcp_socket::async_recv_data_size_64(const std::shared_ptr<null_callback> &callback)
{
	socket_->async_read(mutable_buffer(recv_buf_.get(), 8),
		[this, callback](error_code err)
	{
		if (err)
		{
			reset_recv();
			(*callback)(err);
			return;
		}
		uint64_t size = 0;
		for (char *data = recv_buf_.get(), *data_end = recv_buf_.get() + 8; data < data_end; ++data)
			size = (size << 8) | (uint8_t)*data;

		if (size > std::numeric_limits<size_t>::max() - 4)
		{
			async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
			return;
		}
		async_recv_data_body(callback, (size_t)(size + 4));
	});
}

void obfs_websock_tcp_socket::async_recv_data_body(const std::shared_ptr<null_callback> &callback, size_t size)
{
	if (size > RECV_BUF_SIZE)
	{
		async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
		return;
	}
	socket_->async_read(mutable_buffer(recv_buf_.get(), size),
		[this, size, callback](error_code err)
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
			decode(dec_buf_, recv_buf_.get(), size);
		}
		catch (const std::exception &)
		{
			async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}

		(*callback)(0);
	});
}

size_t obfs_websock_tcp_socket::read_data(char *buf, size_t size)
{
	assert(dec_ptr_ <= dec_buf_.size());
	size_t size_cpy = std::min(dec_buf_.size() - dec_ptr_, size);
	memcpy(buf, dec_buf_.data() + dec_ptr_, size_cpy);
	dec_ptr_ += size_cpy;
	assert(dec_ptr_ <= dec_buf_.size());
	if (dec_ptr_ == dec_buf_.size())
	{
		dec_buf_.clear();
		dec_ptr_ = 0;
	}

	return size_cpy;
}

void obfs_websock_listener::accept(std::unique_ptr<prx_tcp_socket> &soc, error_code &ec)
{
	soc = nullptr;
	ec = ERR_OPERATION_FAILURE;

	do
	{
		std::unique_ptr<prx_tcp_socket> socket;
		acceptor_->accept(socket, ec);
		if (ec)
			return;

		try
		{
			http_header header;
			size_t recv_buf_ptr = 0, recv_buf_ptr_end = 0, size_read, size_parsed;
			bool finished;
			while (finished = header.parse(recv_buf_.get() + recv_buf_ptr, recv_buf_ptr_end - recv_buf_ptr, size_parsed), recv_buf_ptr += size_parsed, !finished)
			{
				if (recv_buf_ptr_end >= RECV_BUF_SIZE)
					throw(std::runtime_error("HTTP header too long"));
				socket->recv(mutable_buffer(recv_buf_.get() + recv_buf_ptr_end, RECV_BUF_SIZE - recv_buf_ptr_end), size_read, ec);
				if (ec)
					throw(std::runtime_error("obfs_websock_listener::accept(): recv() error"));
				recv_buf_ptr_end += size_read;
			}

			if (header.at(http_header::NAME_REQUEST_METHOD) != "GET" || header.at("Connection") != "Upgrade" || header.at("Upgrade") != "websocket" || header.at("Sec-WebSocket-Version") != "13")
				throw(std::runtime_error("Bad HTTP header"));
			if (header.at(http_header::NAME_REQUEST_TARGET) != "/eq" || header.at("Sec-WebSocket-Protocol") != "str")
				throw(std::runtime_error("Bad HTTP header"));

			iv_.clear();
			sec_accept_.clear();
			std::string &iv_b64 = header.at("Sec-WebSocket-Key");
			base64_rev(iv_, iv_b64.data(), iv_b64.size());
			gen_websocket_accept(sec_accept_, iv_b64);

			static constexpr char resp_1[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
			static constexpr size_t resp_1_size = sizeof(resp_1) - 1;
			static constexpr char resp_2[] = "\r\n\r\n";
			static constexpr size_t resp_2_size = sizeof(resp_2) - 1;
			std::string http_resp;
			http_resp.reserve(resp_1_size + sec_accept_.size() + resp_2_size);
			http_resp.append(resp_1, resp_1_size);
			http_resp.append(sec_accept_);
			http_resp.append(resp_2, resp_2_size);

			socket->write(const_buffer(http_resp), ec);
			if (ec)
				throw(std::runtime_error("obfs_websock_listener::accept(): write() error"));
		}
		catch (const std::exception &)
		{
			error_code err;
			socket->close(err);
			if (!ec)
				ec = ERR_BAD_ARG_REMOTE;
			continue;
		}

		soc = std::make_unique<obfs_websock_tcp_socket>(std::move(socket), key_, iv_);
		assert(!ec);
	} while (ec);
}

void obfs_websock_listener::async_accept(accept_callback &&complete_handler)
{
	std::shared_ptr<accept_callback> callback = std::make_shared<accept_callback>(std::move(complete_handler));
	acceptor_->async_accept([this, callback](error_code err, std::unique_ptr<prx_tcp_socket> &&socket)
	{
		if (err)
		{
			(*callback)(err, nullptr);
			return;
		}
		std::shared_ptr<std::unique_ptr<prx_tcp_socket>> socket_accept = std::make_shared<std::unique_ptr<prx_tcp_socket>>(std::move(socket));
		recv_websocket_req(callback, socket_accept, std::make_shared<http_header>());
	});
}

void obfs_websock_listener::recv_websocket_req(
	const std::shared_ptr<accept_callback> &callback,
	const std::shared_ptr<std::unique_ptr<prx_tcp_socket>> &socket_accept,
	const std::shared_ptr<http_header> &header,
	size_t old_ptr, size_t old_ptr_end
)
{
	(*socket_accept)->async_recv(mutable_buffer(recv_buf_.get() + old_ptr_end, RECV_BUF_SIZE - old_ptr_end),
		[this, callback, socket_accept, header, old_ptr, old_ptr_end](error_code err, size_t transferred)
	{
		if (err)
		{
			(*socket_accept)->async_close([this, socket_accept, callback](error_code) { async_accept(std::move(*callback)); });
			return;
		}

		try
		{
			size_t new_ptr_end = old_ptr_end + transferred;
			size_t size_parsed;
			bool finished = header->parse(recv_buf_.get() + old_ptr, new_ptr_end - old_ptr, size_parsed);
			size_t new_ptr = old_ptr + size_parsed;
			if (!finished)
			{
				if (new_ptr_end >= RECV_BUF_SIZE)
					throw(std::runtime_error("HTTP header too long"));
				recv_websocket_req(callback, socket_accept, header, new_ptr, new_ptr_end);
				return;
			}

			if (header->at(http_header::NAME_REQUEST_METHOD) != "GET" || header->at("Connection") != "Upgrade" || header->at("Upgrade") != "websocket" || header->at("Sec-WebSocket-Version") != "13")
				throw(std::runtime_error("Bad HTTP header"));
			if (header->at(http_header::NAME_REQUEST_TARGET) != "/ep" || header->at("Sec-WebSocket-Protocol") != "str")
				throw(std::runtime_error("Bad HTTP header"));

			iv_.clear();
			sec_accept_.clear();
			std::string &iv_b64 = header->at("Sec-WebSocket-Key");
			base64_rev(iv_, iv_b64.data(), iv_b64.size());
			gen_websocket_accept(sec_accept_, iv_b64);
		}
		catch (const std::exception &)
		{
			(*socket_accept)->async_close([this, socket_accept, callback](error_code) { async_accept(std::move(*callback)); });
			return;
		}

		send_websocket_resp(callback, socket_accept);
	});
}

void obfs_websock_listener::send_websocket_resp(const std::shared_ptr<accept_callback> &callback, const std::shared_ptr<std::unique_ptr<prx_tcp_socket>> &socket_accept)
{
	std::shared_ptr<std::string> http_resp = std::make_shared<std::string>();
	try
	{
		static constexpr char resp_1[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
		static constexpr size_t resp_1_size = sizeof(resp_1) - 1;
		static constexpr char resp_2[] = "\r\n\r\n";
		static constexpr size_t resp_2_size = sizeof(resp_2) - 1;
		http_resp->reserve(resp_1_size + sec_accept_.size() + resp_2_size);
		http_resp->append(resp_1, resp_1_size);
		http_resp->append(sec_accept_);
		http_resp->append(resp_2, resp_2_size);
	}
	catch (const std::exception &)
	{
		(*socket_accept)->async_close([this, socket_accept, callback](error_code) { async_accept(std::move(*callback)); });
		return;
	}

	(*socket_accept)->async_write(const_buffer(*http_resp),
		[this, http_resp, socket_accept, callback](error_code err)
	{
		if (err)
		{
			(*socket_accept)->async_close([this, socket_accept, callback](error_code) { async_accept(std::move(*callback)); });
			return;
		}

		(*callback)(0, std::make_unique<obfs_websock_tcp_socket>(std::move(*socket_accept), key_, iv_));
	});
}
