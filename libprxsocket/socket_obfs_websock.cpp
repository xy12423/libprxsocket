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
#include "crypto_rng.h"

using namespace prxsocket;
using namespace prxsocket::http;

namespace
{
	struct base64_helper
	{
		static constexpr char map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		static constexpr char pad = '=';
		byte rev_map[256];

		constexpr base64_helper()
			:rev_map{}
		{
			for (uint8_t i = 0; i < 64; ++i)
				rev_map[(uint8_t)map[i]] = byte{ i };
		}
	};
	constexpr base64_helper b64;

	void base64(std::string &dst, const byte *data, size_t size)
	{
		const byte *data_end = data + size - 3;
		for (; data <= data_end; data += 3)
		{
			dst.push_back(b64.map[(uint8_t)(data[0]) >> 2]);
			dst.push_back(b64.map[(((uint8_t)(data[0]) << 4) | ((uint8_t)(data[1]) >> 4)) & 0x3Fu]);
			dst.push_back(b64.map[(((uint8_t)(data[1]) << 2) | ((uint8_t)(data[2]) >> 6)) & 0x3Fu]);
			dst.push_back(b64.map[(uint8_t)(data[2]) & 0x3Fu]);
		}

		if (data != data_end)
		{
			data_end += 3;
			switch (data_end - data)
			{
			case 1:
				dst.push_back(b64.map[(uint8_t)(data[0]) >> 2]);
				dst.push_back(b64.map[((uint8_t)(data[0]) << 4) & 0x3Fu]);
				dst.push_back(b64.pad);
				dst.push_back(b64.pad);
				break;
			case 2:
				dst.push_back(b64.map[(uint8_t)(data[0]) >> 2]);
				dst.push_back(b64.map[((uint8_t)(data[0]) << 4 | (uint8_t)(data[1]) >> 4) & 0x3Fu]);
				dst.push_back(b64.map[((uint8_t)(data[1]) << 2) & 0x3Fu]);
				dst.push_back(b64.pad);
				break;
			}
		}
	}

	void base64(std::string &dst, const std::vector<byte> &src)
	{
		base64(dst, src.data(), src.size());
	}

	void base64_rev(std::vector<byte> &dst, const char *data, size_t size)
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

	bool gen_websocket_accept(std::string &dst, const std::string &src_b64)
	{
		static constexpr char uuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		static constexpr size_t uuid_size = sizeof(uuid) - 1;
		std::string buf;
		buf.reserve(src_b64.size() + uuid_size);
		buf.append(src_b64);
		buf.append(uuid, uuid_size);
		byte result[20];
		size_t result_size = sizeof(result);
		evp::message_digest<evp::md_sha1> sha1_hasher;
		if (!sha1_hasher.calculate_digest(result, result_size, (const byte *)buf.data(), buf.size()))
			return false;
		base64(dst, result, result_size);
		return true;
	}

	void gen_websocket_accept(std::string &dst, const byte *src, size_t size)
	{
		std::string src_b64;
		base64(src_b64, src, size);
		gen_websocket_accept(dst, src_b64);
	}

	uint64_t ror64_8_in_little_endian(uint64_t u64)
	{
		if constexpr (boost::endian::order::native == boost::endian::order::little)
			return (u64 >> 8) | (u64 << 56);
		else if constexpr (boost::endian::order::native == boost::endian::order::big)
			return (u64 << 8) | (u64 >> 56);
		else
			static_assert(boost::endian::order::native == boost::endian::order::little || boost::endian::order::native == boost::endian::order::big);
		return 0;
	}

	uint32_t ror32_8_in_little_endian(uint32_t u32)
	{
		if constexpr (boost::endian::order::native == boost::endian::order::little)
			return (u32 >> 8) | (u32 << 24);
		else if constexpr (boost::endian::order::native == boost::endian::order::big)
			return (u32 << 8) | (u32 >> 24);
		else
			static_assert(boost::endian::order::native == boost::endian::order::little || boost::endian::order::native == boost::endian::order::big);
		return 0;
	}

	void mask_append(std::vector<byte> &dst, const byte *data, size_t size, std::array<byte, 4> &mask_raw)
	{
		if (dst.size() > std::numeric_limits<size_t>::max() - size)
			throw std::bad_array_new_length();
		size_t dst_size_old = dst.size();
		dst.resize(dst_size_old + size);
		byte *dst_p = dst.data() + dst_size_old;

		if (size > 16) // Only try to use optimization if src is big enough
		{
			if constexpr (sizeof(void *) == sizeof(uint64_t) && sizeof(uint64_t) == 8)
			{
				union
				{
					uint64_t u64;
					byte b[8];
				} mask{};
				memcpy(mask.b, mask_raw.data(), 4);
				memcpy(mask.b + 4, mask_raw.data(), 4);
				const byte *data_p = data, *data_end = data + size;
				for (; data_p < data_end && (uintptr_t)data_p % alignof(uint64_t) != 0; ++data_p, ++dst_p)
				{
					*dst_p = *data_p ^ mask.b[0];
					mask.u64 = ror64_8_in_little_endian(mask.u64);
				}
				for (; data_p < data_end - 8; data_p += 8, dst_p += 8)
				{
					uint64_t tmp = *(const uint64_t *)data_p ^ mask.u64;
					memcpy(dst_p, &tmp, 8);
				}
				for (; data_p < data_end; ++data_p, ++dst_p)
				{
					*dst_p = *data_p ^ mask.b[0];
					mask.u64 = ror64_8_in_little_endian(mask.u64);
				}
				if (dst_p != dst.data() + dst.size())
					throw std::out_of_range("masking output has different size from original data");
				memcpy(mask_raw.data(), mask.b, 4);
				return;
			}
			else if constexpr (sizeof(void *) == sizeof(uint32_t) && sizeof(uint32_t) == 4)
			{
				union
				{
					uint32_t u32;
					byte b[4];
				} mask{};
				memcpy(mask.b, mask_raw.data(), 4);
				const byte *data_p = data, *data_end = data + size;
				for (; data_p < data_end && (uintptr_t)data_p % alignof(uint32_t) != 0; ++data_p, ++dst_p)
				{
					*dst_p = *data_p ^ mask.b[0];
					mask.u32 = ror32_8_in_little_endian(mask.u32);
				}
				for (; data_p < data_end - 4; data_p += 4, dst_p += 4)
				{
					uint32_t tmp = *(const uint32_t *)data_p ^ mask.u32;
					memcpy(dst_p, &tmp, 4);
				}
				for (; data_p < data_end; ++data_p, ++dst_p)
				{
					*dst_p = *data_p ^ mask.b[0];
					mask.u32 = ror32_8_in_little_endian(mask.u32);
				}
				if (dst_p != dst.data() + dst.size())
					throw std::out_of_range("masking output has different size from original data");
				memcpy(mask_raw.data(), mask.b, 4);
				return;
			}
		}
		int maskp = 0;
		for (const byte *data_p = data, *data_end = data + size; data_p < data_end; ++data_p, ++dst_p)
		{
			*dst_p = *data_p ^ mask_raw[maskp];
			maskp = (maskp + 1) % 4;
		}
		if (dst_p != dst.data() + dst.size())
			throw std::out_of_range("masking output has different size from original data");
		if (maskp != 0)
		{
			byte mask[8];
			memcpy(mask, mask_raw.data(), 4);
			memcpy(mask + 4, mask_raw.data(), 4);
			memcpy(mask_raw.data(), mask + maskp, 4);
		}
	}

	void mask_inplace(byte *data, size_t size, std::array<byte, 4> &mask_raw)
	{
		if (size > 16) // Only try to use optimization if src is big enough
		{
			if constexpr (sizeof(void *) == sizeof(uint64_t) && sizeof(uint64_t) == 8)
			{
				union
				{
					uint64_t u64;
					byte b[8];
				} mask{};
				memcpy(mask.b, mask_raw.data(), 4);
				memcpy(mask.b + 4, mask_raw.data(), 4);
				byte *data_p = data, *data_end = data + size;
				for (; data_p < data_end && (uintptr_t)data_p % alignof(uint64_t) != 0; ++data_p)
				{
					*data_p ^= mask.b[0];
					mask.u64 = ror64_8_in_little_endian(mask.u64);
				}
				for (; data_p < data_end - 8; data_p += 8)
				{
					*(uint64_t *)data_p ^= mask.u64;
				}
				for (; data_p < data_end; ++data_p)
				{
					*data_p ^= mask.b[0];
					mask.u64 = ror64_8_in_little_endian(mask.u64);
				}
				memcpy(mask_raw.data(), mask.b, 4);
				return;
			}
			else if constexpr (sizeof(void *) == sizeof(uint32_t) && sizeof(uint32_t) == 4)
			{
				union
				{
					uint32_t u32;
					byte b[4];
				} mask{};
				memcpy(mask.b, mask_raw.data(), 4);
				byte *data_p = data, *data_end = data + size;
				for (; data_p < data_end && (uintptr_t)data_p % alignof(uint32_t) != 0; ++data_p)
				{
					*data_p ^= mask.b[0];
					mask.u32 = ror32_8_in_little_endian(mask.u32);
				}
				for (; data_p < data_end - 4; data_p += 4)
				{
					*(uint32_t *)data_p ^= mask.u32;
				}
				for (; data_p < data_end; ++data_p)
				{
					*data_p ^= mask.b[0];
					mask.u32 = ror32_8_in_little_endian(mask.u32);
				}
				memcpy(mask_raw.data(), mask.b, 4);
				return;
			}
		}
		int maskp = 0;
		for (byte *data_p = data, *data_end = data + size; data_p < data_end; ++data_p)
		{
			*data_p ^= mask_raw[maskp];
			maskp = (maskp + 1) % 4;
		}
		if (maskp != 0)
		{
			byte mask[8];
			memcpy(mask, mask_raw.data(), 4);
			memcpy(mask + 4, mask_raw.data(), 4);
			memcpy(mask_raw.data(), mask + maskp, 4);
		}
	}

	constexpr size_t pkcs7_padding_size(size_t plaintext_size, int block_size)
	{
		if (block_size <= 1)
			return 0;
		return block_size - plaintext_size % block_size;
	}

}

void prxsocket::obfs_websock_tcp_socket::connect(const endpoint &ep, error_code &ec)
{
	socket_->connect(ep, ec);
	if (ec)
		return;

	try
	{
		PRXSOCKET_MAKE_INPLACE_BUFFER(std::string, http_req, http_req_holder);

		std::string iv_b64;
		random_generator::random_bytes(iv_, sizeof(iv_));
		encryptor_.init(key_, sizeof(key_), iv_, sizeof(iv_));
		decryptor_.init(key_, sizeof(key_), iv_, sizeof(iv_));
		iv_b64.reserve((sizeof(iv_) / 3 + 1) * 4);
		base64(iv_b64, iv_, sizeof(iv_));

		static constexpr char req_1[] = "GET /ep HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ";
		static constexpr size_t req_1_size = sizeof(req_1) - 1;
		static constexpr char req_2[] = "\r\nSec-WebSocket-Protocol: str\r\nSec-WebSocket-Version: 13\r\n\r\n";
		static constexpr size_t req_2_size = sizeof(req_2) - 1;
		http_req.reserve(req_1_size + req_2_size + iv_b64.size());
		http_req.append(req_1);
		http_req.append(iv_b64);
		http_req.append(req_2);

		const_buffer http_req_buf((byte *)http_req.data(), http_req.size());
		socket_->send(http_req_buf, std::move(http_req_holder), ec);
		if (ec)
		{
			reset();
			return;
		}

		http_header header;
		while (true)
		{
			const_buffer resp_buf;
			buffer_data_store_holder resp_holder;
			socket_->recv(resp_buf, resp_holder, ec);
			if (ec)
			{
				reset();
				return;
			}
			size_t size_parsed;
			bool completed = header.parse((const char *)resp_buf.data(), resp_buf.size(), size_parsed);
			if (!completed)
			{
				assert(size_parsed == resp_buf.size());
				resp_holder.reset();
				continue;
			}
			assert(size_parsed <= resp_buf.size());
			if (size_parsed < resp_buf.size())
			{
				recv_buf_.buffer = resp_buf.after_consume(size_parsed);
				recv_buf_.holder = std::move(resp_holder);
			}
			break;
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
		ec = ERR_OPERATION_FAILURE;
		return;
	}

	state_ = STATE_OK;
}

void prxsocket::obfs_websock_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket_->async_connect(ep,
		[this, callback](error_code ec)
	{
		if (ec)
		{
			(*callback)(ec);
			return;
		}
		send_websocket_req(callback);
	});
}

void obfs_websock_tcp_socket::send_websocket_req(const std::shared_ptr<null_callback> &callback)
{
	PRXSOCKET_MAKE_INPLACE_BUFFER(std::string, http_req, http_req_holder);
	try
	{
		random_generator::random_bytes(iv_, sizeof(iv_));
		encryptor_.init(key_, sizeof(key_), iv_, sizeof(iv_));
		decryptor_.init(key_, sizeof(key_), iv_, sizeof(iv_));

		static constexpr char req_1[] = "GET /ep HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ";
		static constexpr size_t req_1_size = sizeof(req_1) - 1;
		static constexpr char req_2[] = "\r\nSec-WebSocket-Protocol: str\r\nSec-WebSocket-Version: 13\r\n\r\n";
		static constexpr size_t req_2_size = sizeof(req_2) - 1;
		http_req.reserve(req_1_size + req_2_size + (sizeof(iv_) / 3 + 1) * 4);
		http_req.append(req_1);
		base64(http_req, iv_, sizeof(iv_));
		http_req.append(req_2);
	}
	catch (const std::exception &)
	{
		reset();
		(*callback)(ERR_OPERATION_FAILURE);
		return;
	}

	socket_->async_send(const_buffer((byte *)http_req.data(), http_req.size()), std::move(http_req_holder),
		[this, http_req, callback](error_code ec)
	{
		if (ec)
		{
			reset();
			(*callback)(ec);
			return;
		}
		recv_websocket_resp(std::make_shared<http_header>(), callback);
	});
}

void obfs_websock_tcp_socket::recv_websocket_resp(const std::shared_ptr<http_header> &header, const std::shared_ptr<null_callback> &callback)
{
	socket_->async_recv([this, header, callback](error_code ec, const_buffer resp_buf, buffer_data_store_holder &&resp_holder)
	{
		if (ec)
		{
			reset();
			(*callback)(ec);
			return;
		}

		try
		{
			size_t size_parsed;
			bool completed = header->parse((const char *)resp_buf.data(), resp_buf.size(), size_parsed);
			if (!completed)
			{
				assert(size_parsed == resp_buf.size());
				resp_holder.reset();
				recv_websocket_resp(header, callback);
				return;
			}
			assert(size_parsed <= resp_buf.size());
			if (size_parsed < resp_buf.size())
			{
				recv_buf_.buffer = resp_buf.after_consume(size_parsed);
				recv_buf_.holder = std::move(resp_holder);
			}

			if (header->at(http_header::NAME_STATUS_CODE) != "101" || header->at("Connection") != "Upgrade" || header->at("Upgrade") != "websocket")
				throw(std::runtime_error("Bad HTTP header"));
			std::string sec_accept;
			gen_websocket_accept(sec_accept, iv_, sizeof(iv_));
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

size_t prxsocket::obfs_websock_tcp_socket::send_size_max()
{
	size_t send_size_max = socket_->send_size_max();
	if (send_size_max <= 8) // arbitrary picked 8 as a lower limit
		return 0;

	if (mask_send_)
		send_size_max -= 4;
	if (send_size_max <= 129)
		return std::min<std::common_type<size_t, decltype(125)>::type>(send_size_max - 2, 125);
	if (send_size_max <= 65545)
		return std::min<std::common_type<size_t, decltype(0xFFFF)>::type>(send_size_max - 4, 0xFFFF);
	return std::min<std::common_type<size_t, decltype(0xFFFFFFFF)>::type>(send_size_max - 10, 0xFFFFFFFF); // Actually 0x7FFFFFFFFFFFFFFF, but 0xFFFFFFFF should be big enough
}

std::vector<byte> prxsocket::obfs_websock_tcp_socket::pack_ws_frame_header(size_t payload_length, std::array<byte, 4> *mask)
{
	static constexpr size_t payload_extra_reserve = 64;
	std::vector<byte> ret;
	size_t mask_length = 0;
	if (mask)
		mask_length = mask->size();
	if (payload_length <= 125)
	{
		ret.reserve(2 + mask_length + payload_extra_reserve + payload_length);
		ret.resize(2 + mask_length);
		ret[0] = byte{ 0x82 };
		ret[1] = byte{ payload_length & 0xFFu };
		if (mask)
		{
			ret[1] |= byte{ 0x80 };
			memcpy(ret.data() + 2, mask->data(), mask->size());
		}
	}
	else if (payload_length <= 0xFFFF)
	{
		ret.reserve(4 + mask_length + payload_extra_reserve + payload_length);
		ret.resize(4 + mask_length);
		ret[0] = byte{ 0x82 };
		ret[1] = byte{ 0x7E };
		ret[2] = byte{ (payload_length >> 8) & 0xFFu };
		ret[3] = byte{ payload_length & 0xFFu };
		if (mask)
		{
			ret[1] |= byte{ 0x80 };
			memcpy(ret.data() + 4, mask->data(), mask->size());
		}
	}
	else if (payload_length < 0x7FFFFFFFFFFFFFFFu && payload_length <= std::numeric_limits<size_t>::max() - (10 + mask_length + payload_extra_reserve))
	{
		ret.reserve(10 + mask_length + payload_extra_reserve + payload_length);
		ret.resize(10 + mask_length);
		ret[0] = byte{ 0x82 };
		ret[1] = byte{ 0x7F };
		ret[2] = byte{ (payload_length >> 56) & 0xFFu };
		ret[3] = byte{ (payload_length >> 48) & 0xFFu };
		ret[4] = byte{ (payload_length >> 40) & 0xFFu };
		ret[5] = byte{ (payload_length >> 32) & 0xFFu };
		ret[6] = byte{ (payload_length >> 24) & 0xFFu };
		ret[7] = byte{ (payload_length >> 16) & 0xFFu };
		ret[8] = byte{ (payload_length >> 8) & 0xFFu };
		ret[9] = byte{ payload_length & 0xFFu };
		if (mask)
		{
			ret[1] |= byte{ 0x80 };
			memcpy(ret.data() + 10, mask->data(), mask->size());
		}
	}
	else
	{
		throw std::bad_array_new_length();
	}
	return ret;
}

std::vector<byte> prxsocket::obfs_websock_tcp_socket::pack_ws_frame(const_buffer payload_final)
{
	// Calculate total payload size, and padding size (for block cipher)
	size_t payload_size = payload_final.size();
	if (!send_buf_.empty())
		for (const auto &p : send_buf_)
			payload_size += p.buffer.size();
	size_t padding_size = pkcs7_padding_size(payload_size, encryptor_.block_size());
	if (padding_size < 0 || padding_size > std::numeric_limits<unsigned char>::max())
		throw std::runtime_error("Padding would be too long");

	// Build header
	static_assert(sizeof(uint32_t) == 4);
	std::array<byte, 4> mask{};
	if (mask_send_)
		random_generator::random_bytes(mask.data(), mask.size());
	std::vector<byte> ws_frame = pack_ws_frame_header(payload_size + padding_size, mask_send_ ? &mask : nullptr);

	// Process payload data
	size_t ws_frame_payload_start = ws_frame.size();
	if (!send_buf_.empty())
	{
		for (const auto &p : send_buf_)
			if (!encryptor_.update(ws_frame, p.buffer.data(), p.buffer.size()))
				throw std::runtime_error("Encryption failed");
		send_buf_.clear();
	}
	if (!encryptor_.update(ws_frame, payload_final.data(), payload_final.size()))
		throw std::runtime_error("Encryption failed");
	// Process payload padding
	byte padding[SYM_BLOCK_SIZE];
	memset(padding, padding_size, sizeof(padding));
	for (size_t padded = 0; padded < padding_size;)
	{
		size_t n = std::min(sizeof(padding), padding_size - padded);
		if (!encryptor_.update(ws_frame, padding, n))
			throw std::runtime_error("Encryption padding failed");
		padded += n;
	}
	// Verify length
	size_t ws_frame_payload_end = ws_frame.size();
	if (ws_frame_payload_end - ws_frame_payload_start != payload_size + padding_size)
		throw std::runtime_error("Cipher text length and plain text length does not match");

	// Mask
	if (mask_send_)
		mask_inplace(ws_frame.data() + ws_frame_payload_start, ws_frame_payload_end - ws_frame_payload_start, mask);

	return ws_frame;
}

void prxsocket::obfs_websock_tcp_socket::send(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, error_code &ec)
{
	ec = 0;

	PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, ws_frame, ws_frame_holder);
	try
	{
		ws_frame = pack_ws_frame(buffer);
	}
	catch (const std::exception &)
	{
		shutdown(shutdown_send, ec);
		ec = ERR_OPERATION_FAILURE;
		return;
	}
	socket_->send(const_buffer(ws_frame), std::move(ws_frame_holder), ec);
	if (ec)
	{
		reset_send();
		return;
	}
}

void prxsocket::obfs_websock_tcp_socket::async_send(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, ws_frame, ws_frame_holder);
	try
	{
		ws_frame = pack_ws_frame(buffer);
	}
	catch (const std::exception &)
	{
		async_shutdown(shutdown_send, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		return;
	}

	socket_->async_send(const_buffer(ws_frame), std::move(ws_frame_holder),
		[this, callback](error_code ec)
	{
		if (ec)
		{
			reset_send();
			(*callback)(ec);
			return;
		}
		(*callback)(0);
	});
}

void prxsocket::obfs_websock_tcp_socket::send_partial(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, error_code &ec)
{
	send_buf_.push_back(buffer_with_data_store{ buffer, std::move(buffer_data_holder) });
	ec = 0;
}

void prxsocket::obfs_websock_tcp_socket::async_send_partial(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, null_callback &&complete_handler)
{
	send_buf_.push_back(buffer_with_data_store{ buffer, std::move(buffer_data_holder) });
	complete_handler(0);
}

bool prxsocket::obfs_websock_tcp_socket::unpack_ws_frame_header(ws_unpack_state &state, const_buffer &payload)
{
	auto &header = state.header_temp;
	if (header.size_read < 2)
	{
		size_t size_read = std::min(2 - header.size_read, payload.size());
		memcpy(header.data + header.size_read, payload.data(), size_read);
		header.size_read += size_read;
		payload = payload.after_consume(size_read);

		if (header.size_read < 2)
			return false;
	}

	size_t size_needed;
	unsigned int payload_len = std::to_integer<unsigned int>(header.data[1]) & 0x7Fu;
	bool has_mask = (std::to_integer<unsigned int>(header.data[1]) & 0x80u) != 0;
	switch (payload_len)
	{
	case 127:
		size_needed = 10;
		break;
	case 126:
		size_needed = 4;
		break;
	default:
		size_needed = 2;
		break;
	}
	if (has_mask)
	{
		size_needed += 4;
	}
	if (header.size_read < size_needed)
	{
		size_t size_read = std::min(size_needed - header.size_read, payload.size());
		memcpy(header.data + header.size_read, payload.data(), size_read);
		header.size_read += size_read;
		payload = payload.after_consume(size_read);

		if (header.size_read < size_needed)
			return false;
	}

	if (header.size_read > size_needed)
		throw std::logic_error("Header parsing consumed payload");
	assert(header.size_read == size_needed);
	switch (payload_len)
	{
	case 127:
	{
		static_assert(sizeof(uint64_t) == 8);
		uint64_t payload_length;
		memcpy(&payload_length, header.data + 2, 8);
		boost::endian::big_to_native_inplace(payload_length);
		if (payload_length > WS_FRAME_PAYLOAD_LENGTH_MAX)
			throw std::overflow_error("payload_length too big");
		state.payload_length = payload_length;
		state.mask = has_mask;
		if (has_mask)
			memcpy(state.payload_temp.masking_key.data(), header.data + 10, 4);
		break;
	}
	case 126:
	{
		static_assert(sizeof(uint16_t) == 2);
		uint16_t payload_length;
		memcpy(&payload_length, header.data + 2, 2);
		boost::endian::big_to_native_inplace(payload_length);
		if (payload_length > WS_FRAME_PAYLOAD_LENGTH_MAX)
			throw std::overflow_error("payload_length too big");
		state.payload_length = payload_length;
		state.mask = has_mask;
		if (has_mask)
			memcpy(state.payload_temp.masking_key.data(), header.data + 4, 4);
		break;
	}
	default:
	{
		state.payload_length = payload_len;
		state.mask = has_mask;
		if (has_mask)
			memcpy(state.payload_temp.masking_key.data(), header.data + 2, 4);
		break;
	}
	}
	return true;
}

bool prxsocket::obfs_websock_tcp_socket::unpack_ws_frame_payload(ws_unpack_state &state, const_buffer &payload)
{
	auto &payload_temp = state.payload_temp;

	size_t size_process = std::min(payload_temp.size_left, payload.size());
	if (size_process > 0) [[likely]]
	{
		if (state.mask)
			mask_append(state.payload, payload.data(), size_process, payload_temp.masking_key);
		else
			state.payload.insert(state.payload.end(), payload.data(), payload.data() + size_process);
		payload_temp.size_left -= size_process;
		payload = payload.after_consume(size_process);
	}

	if (payload_temp.size_left == 0)
	{
		// payload_size validation
		if (state.payload.size() != state.payload_length)
			throw std::runtime_error("Payload has different size from payload_size");
		if (state.payload.size() % SYM_BLOCK_SIZE != 0)
			throw std::runtime_error("Payload contains incomplete block");

		// Decryption & validation
		static_assert(WS_FRAME_PAYLOAD_LENGTH_MAX + SYM_BLOCK_SIZE <= std::numeric_limits<size_t>::max());
		state.payload.resize(state.payload.size() + SYM_BLOCK_SIZE);
		size_t plaintext_size = state.payload.size();
		if (!decryptor_.update(state.payload.data(), plaintext_size, state.payload.data(), state.payload_length))
			throw std::runtime_error("Decryption failed");
		if (plaintext_size != state.payload_length)
			throw std::runtime_error("Decrypted payload has different size from payload_size");
		state.payload.resize(plaintext_size);

		// Remove padding
		size_t padding_length = std::to_integer<unsigned int>(state.payload.back());
		if (padding_length > state.payload.size())
			throw std::overflow_error("padding_length bigger than plaintext size");
		state.payload.resize(state.payload.size() - padding_length);
		return true;
	}
	return false;
}

void prxsocket::obfs_websock_tcp_socket::recv(const_buffer &buffer, buffer_data_store_holder &buffer_data_holder, error_code &ec)
{
	ws_unpack_state state;

	error_code_or_op_result ec_or_result{};
	socket_->recv_until(recv_buf_, [this, &state](const_buffer &buffer_recv)
	{
		try
		{
			bool header_parsed = unpack_ws_frame_header(state, buffer_recv);
			return error_code_or_op_result{ header_parsed ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
		}
		catch (const std::exception &)
		{
			return error_code_or_op_result{ OPRESULT_ERROR };
		}
	}, ec_or_result);
	if (ec_or_result.code == OPRESULT_ERROR) [[unlikely]]
	{
		shutdown(shutdown_receive, ec);
		ec = ERR_OPERATION_FAILURE;
		return;
	}
	if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
	{
		ec = ec_or_result.code;
		if (ec == 0)
			ec = ERR_OPERATION_FAILURE;
		reset_recv();
		return;
	}

	state.payload.reserve(state.payload_length + SYM_BLOCK_SIZE);
	if (state.payload_temp.size_left > 0) [[likely]]
	{
		socket_->recv_until(recv_buf_, [this, &state](const_buffer &buffer_recv)
		{
			try
			{
				unpack_ws_frame_payload(state, buffer_recv);
				return error_code_or_op_result{ state.payload_temp.size_left == 0 ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
			}
			catch (const std::exception &)
			{
				return error_code_or_op_result{ OPRESULT_ERROR };
			}
		}, ec_or_result);
		if (ec_or_result.code == OPRESULT_ERROR) [[unlikely]]
		{
			shutdown(shutdown_receive, ec);
			ec = ERR_OPERATION_FAILURE;
			return;
		}
		if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
		{
			ec = ec_or_result.code;
			if (ec == 0)
				ec = ERR_OPERATION_FAILURE;
			reset_recv();
			return;
		}
	}

	PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, data_unpacked, data_unpacked_holder, std::move(state.payload));
	buffer = const_buffer(data_unpacked);
	buffer_data_holder = std::move(data_unpacked_holder);
	ec = 0;
	return;
}

void prxsocket::obfs_websock_tcp_socket::async_recv(transfer_data_callback &&complete_handler)
{
	std::shared_ptr<transfer_data_callback> callback = std::make_shared<transfer_data_callback>(std::move(complete_handler));
	std::shared_ptr<ws_unpack_state> state = std::make_shared<ws_unpack_state>();
	socket_->async_recv_until(std::move(recv_buf_), [this, state](const_buffer &buffer_recv)
	{
		try
		{
			bool header_parsed = unpack_ws_frame_header(*state, buffer_recv);
			return error_code_or_op_result{ header_parsed ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
		}
		catch (const std::exception &)
		{
			return error_code_or_op_result{ OPRESULT_ERROR };
		}
	}, [this, state, callback](error_code_or_op_result ec_or_result, buffer_with_data_store &&leftover)
	{
		if (ec_or_result.code == OPRESULT_ERROR) [[unlikely]]
		{
			async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE, const_buffer(), buffer_data_store_holder()); });
			return;
		}
		if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
		{
			reset_recv();
			(*callback)(ec_or_result.code != 0 ? ec_or_result.code : ERR_OPERATION_FAILURE, leftover.buffer, std::move(leftover.holder));
			return;
		}
		async_recv_frame_payload(state, std::move(leftover), callback);
	});
}

void prxsocket::obfs_websock_tcp_socket::async_recv_frame_payload(const std::shared_ptr<ws_unpack_state> &state,
	buffer_with_data_store &&leftover,
	const std::shared_ptr<transfer_data_callback> &callback)
{
	if (state->payload_temp.size_left == 0) [[unlikely]]
	{
		recv_buf_ = std::move(leftover);
		(*callback)(0, const_buffer(), buffer_data_store_holder());
		return;
	}
	state->payload.reserve(state->payload_length + SYM_BLOCK_SIZE);
	socket_->async_recv_until(std::move(leftover), [this, state](const_buffer &buffer_recv)
	{
		try
		{
			unpack_ws_frame_payload(*state, buffer_recv);
			return error_code_or_op_result{ state->payload_temp.size_left == 0 ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
		}
		catch (const std::exception &)
		{
			return error_code_or_op_result{ OPRESULT_ERROR };
		}
	}, [this, state, callback](error_code_or_op_result ec_or_result, buffer_with_data_store &&leftover)
	{
		if (ec_or_result.code == OPRESULT_ERROR) [[unlikely]]
		{
			async_shutdown(shutdown_receive, [callback](error_code) { (*callback)(ERR_OPERATION_FAILURE, const_buffer(), buffer_data_store_holder()); });
			return;
		}
		if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
		{
			reset_recv();
			(*callback)(ec_or_result.code != 0 ? ec_or_result.code : ERR_OPERATION_FAILURE, leftover.buffer, std::move(leftover.holder));
			return;
		}

		recv_buf_ = std::move(leftover);

		PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, data_unpacked, data_unpacked_holder, std::move(state->payload));
		(*callback)(0, const_buffer(data_unpacked), std::move(data_unpacked_holder));
	});
}

void prxsocket::obfs_websock_tcp_socket::shutdown(shutdown_type type, error_code &ec)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->shutdown(type, ec);
}

void prxsocket::obfs_websock_tcp_socket::async_shutdown(shutdown_type type, null_callback &&complete_handler)
{
	if (type & shutdown_send)
		reset_send();
	if (type & shutdown_receive)
		reset_recv();
	socket_->async_shutdown(type, std::move(complete_handler));
}

void prxsocket::obfs_websock_tcp_socket::close(error_code &ec)
{
	reset();
	return socket_->close(ec);
}

void prxsocket::obfs_websock_tcp_socket::async_close(null_callback &&complete_handler)
{
	reset();
	socket_->async_close(std::move(complete_handler));
}

prxsocket::obfs_websock_listener::accept_session::accept_session(std::unique_ptr<prx_tcp_socket> &&socket)
	:socket_accept(std::move(socket))
{
}

void prxsocket::obfs_websock_listener::accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &ec)
{
	socket = nullptr;
	ec = ERR_OPERATION_FAILURE;

	do
	{
		std::unique_ptr<prx_tcp_socket> socket_accept_;
		acceptor_->accept(socket_accept_, ec);
		if (ec)
			return;

		try
		{
			http_header header;
			buffer_with_data_store recv_buf_left_over;
			while (true)
			{
				const_buffer resp_buf;
				buffer_data_store_holder resp_holder;
				socket_accept_->recv(resp_buf, resp_holder, ec);
				if (ec)
					throw(std::runtime_error("recv Failed"));
				size_t size_parsed;
				bool completed = header.parse((const char *)resp_buf.data(), resp_buf.size(), size_parsed);
				if (!completed)
				{
					assert(size_parsed == resp_buf.size());
					resp_holder.reset();
					continue;
				}
				assert(size_parsed <= resp_buf.size());
				if (size_parsed < resp_buf.size())
				{
					recv_buf_left_over.buffer = resp_buf.after_consume(size_parsed);
					recv_buf_left_over.holder = std::move(resp_holder);
				}
				break;
			}

			if (header.at(http_header::NAME_REQUEST_METHOD) != "GET" || header.at("Connection") != "Upgrade" || header.at("Upgrade") != "websocket" || header.at("Sec-WebSocket-Version") != "13")
				throw(std::runtime_error("Bad HTTP header"));
			if (header.at(http_header::NAME_REQUEST_TARGET) != "/ep" || header.at("Sec-WebSocket-Protocol") != "str")
				throw(std::runtime_error("Bad HTTP header"));

			std::string sec_accept;
			std::string &iv_b64 = header.at("Sec-WebSocket-Key");
			std::vector<byte> iv_vec;
			base64_rev(iv_vec, iv_b64.data(), iv_b64.size());
			gen_websocket_accept(sec_accept, iv_b64);

			PRXSOCKET_MAKE_INPLACE_BUFFER(std::string, http_resp, http_resp_holder);

			static constexpr char resp_1[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
			static constexpr size_t resp_1_size = sizeof(resp_1) - 1;
			static constexpr char resp_2[] = "\r\n\r\n";
			static constexpr size_t resp_2_size = sizeof(resp_2) - 1;
			http_resp.reserve(resp_1_size + resp_2_size + sec_accept.size());
			http_resp.append(resp_1, resp_1_size);
			http_resp.append(sec_accept);
			http_resp.append(resp_2, resp_2_size);

			const_buffer http_resp_buf((byte *)http_resp.data(), http_resp.size());
			socket_accept_->send(http_resp_buf, std::move(http_resp_holder), ec);
			if (ec)
				throw(std::runtime_error("send Failed"));

			socket = std::make_unique<obfs_websock_tcp_socket>(std::move(socket_accept_), key_vec_, iv_vec, std::move(recv_buf_left_over));
			assert(!ec);
		}
		catch (const std::exception &)
		{
			error_code err;
			socket_accept_->close(err);
			if (!ec)
				ec = ERR_OPERATION_FAILURE;
		}
	} while (ec || !socket);
}

void prxsocket::obfs_websock_listener::async_accept(accept_callback &&complete_handler)
{
	std::shared_ptr<accept_callback> callback = std::make_shared<accept_callback>(std::move(complete_handler));
	acceptor_->async_accept([this, callback](error_code ec, std::unique_ptr<prx_tcp_socket> &&socket)
	{
		if (ec)
		{
			(*callback)(ec, std::unique_ptr<prx_tcp_socket>());
			return;
		}
		recv_websocket_req(std::make_shared<accept_session>(std::move(socket)), callback);
	});
}

void prxsocket::obfs_websock_listener::recv_websocket_req(const std::shared_ptr<accept_session> &accept_session, const std::shared_ptr<accept_callback> &callback)
{
	accept_session->socket_accept->async_recv([this, accept_session, callback](error_code ec, const_buffer resp_buf, buffer_data_store_holder &&resp_holder)
	{
		if (ec)
		{
			accept_session->socket_accept->async_close([this, accept_session, callback](error_code) { async_accept(std::move(*callback)); });
			return;
		}

		try
		{
			http_header &header = accept_session->header;
			size_t size_parsed;
			bool completed = header.parse((const char *)resp_buf.data(), resp_buf.size(), size_parsed);
			if (!completed)
			{
				assert(size_parsed == resp_buf.size());
				resp_holder.reset();
				recv_websocket_req(accept_session, callback);
				return;
			}
			assert(size_parsed <= resp_buf.size());
			if (size_parsed < resp_buf.size())
			{
				accept_session->recv_buf_left_over.buffer = resp_buf.after_consume(size_parsed);
				accept_session->recv_buf_left_over.holder = std::move(resp_holder);
			}

			if (header.at(http_header::NAME_REQUEST_METHOD) != "GET" || header.at("Connection") != "Upgrade" || header.at("Upgrade") != "websocket" || header.at("Sec-WebSocket-Version") != "13")
				throw(std::runtime_error("Bad HTTP header"));
			if (header.at(http_header::NAME_REQUEST_TARGET) != "/ep" || header.at("Sec-WebSocket-Protocol") != "str")
				throw(std::runtime_error("Bad HTTP header"));

			std::string &iv_b64 = header.at("Sec-WebSocket-Key");
			base64_rev(accept_session->iv_vec, iv_b64.data(), iv_b64.size());
			gen_websocket_accept(accept_session->sec_accept, iv_b64);
		}
		catch (const std::exception &)
		{
			accept_session->socket_accept->async_close([this, accept_session, callback](error_code) { async_accept(std::move(*callback)); });
			return;
		}

		send_websocket_resp(accept_session, callback);
	});
}

void prxsocket::obfs_websock_listener::send_websocket_resp(const std::shared_ptr<accept_session> &accept_session, const std::shared_ptr<accept_callback> &callback)
{
	PRXSOCKET_MAKE_INPLACE_BUFFER(std::string, http_resp, http_resp_holder);
	try
	{
		static constexpr char resp_1[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
		static constexpr size_t resp_1_size = sizeof(resp_1) - 1;
		static constexpr char resp_2[] = "\r\n\r\n";
		static constexpr size_t resp_2_size = sizeof(resp_2) - 1;
		std::string &sec_accept = accept_session->sec_accept;
		http_resp.reserve(resp_1_size + resp_2_size + sec_accept.size());
		http_resp.append(resp_1, resp_1_size);
		http_resp.append(sec_accept);
		http_resp.append(resp_2, resp_2_size);
	}
	catch (const std::exception &)
	{
		accept_session->socket_accept->async_close([this, accept_session, callback](error_code) { async_accept(std::move(*callback)); });
		return;
	}

	accept_session->socket_accept->async_send(const_buffer((byte *)http_resp.data(), http_resp.size()), std::move(http_resp_holder),
		[this, accept_session, callback](error_code ec)
	{
		if (ec)
		{
			accept_session->socket_accept->async_close([this, accept_session, callback](error_code) { async_accept(std::move(*callback)); });
			return;
		}
		(*callback)(0, std::make_unique<obfs_websock_tcp_socket>(std::move(accept_session->socket_accept), key_vec_, accept_session->iv_vec, std::move(accept_session->recv_buf_left_over)));
	});
}
