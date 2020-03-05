#include "stdafx.h"
#include "socket_obfs_websock.h"

using namespace CryptoPP;

static void base64(std::string &dst, const char *data, size_t size)
{
	static constexpr char base64_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	static constexpr char base64_pad = '=';

	const char *data_end = data + size - 3;
	for (; data <= data_end; data += 3)
	{
		dst.push_back(base64_map[(uint8_t)(data[0]) >> 2]);
		dst.push_back(base64_map[(((uint8_t)(data[0]) << 4) | ((uint8_t)(data[1]) >> 4)) & 0x3F]);
		dst.push_back(base64_map[(((uint8_t)(data[1]) << 2) | ((uint8_t)(data[2]) >> 6)) & 0x3F]);
		dst.push_back(base64_map[(uint8_t)(data[2]) & 0x3F]);
	}

	if (data != data_end)
	{
		data_end += 3;
		switch (data_end - data)
		{
			case 1:
				dst.push_back(base64_map[(uint8_t)(data[0]) >> 2]);
				dst.push_back(base64_map[((uint8_t)(data[0]) << 4) & 0x3F]);
				dst.push_back(base64_pad);
				dst.push_back(base64_pad);
				break;
			case 2:
				dst.push_back(base64_map[(uint8_t)(data[0]) >> 2]);
				dst.push_back(base64_map[((uint8_t)(data[0]) << 4 | (uint8_t)(data[1]) >> 4) & 0x3F]);
				dst.push_back(base64_map[((uint8_t)(data[1]) << 2) & 0x3F]);
				dst.push_back(base64_pad);
				break;
		}
	}
}

static void base64(std::string &dst, const std::string &src)
{
	base64(dst, src.data(), src.size());
}

static void base64(std::string &dst, const byte *src, size_t src_size)
{
	base64(dst, (const char*)src, src_size);
}

static void base64_rev(std::string &dst, const char *data, size_t size)
{
	static constexpr uint8_t base64_rev_map[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //00-15
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //16-31
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62,0, 0, 0, 63,//32-47
		52,53,54,55,56,57,58,59,60,61,0, 0, 0, 0, 0, 0, //48-63
		0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,11,12,13,14,//64-79
		15,16,17,18,19,20,21,22,23,24,25,0, 0, 0, 0, 0, //80-95
		0, 26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,//96-111
		41,42,43,44,45,46,47,48,49,50,51,0, 0, 0, 0, 0  //112-127
	};
	static constexpr char base64_pad = '=';

	if (size % 4 != 0)
		throw(std::runtime_error("Invalid base64"));
	if (size == 0)
		return;
	dst.reserve(dst.size() + size / 4 * 3);

	const char *data_end = data + size;
	for (; data < data_end; data += 4)
	{
		dst.push_back((base64_rev_map[data[0]] << 2) | (base64_rev_map[data[1]] >> 4));
		dst.push_back((base64_rev_map[data[1]] << 4) | (base64_rev_map[data[2]] >> 2));
		dst.push_back((base64_rev_map[data[2]] << 6) | base64_rev_map[data[3]]);
	}
	if (data[-1] == base64_pad)
	{
		dst.pop_back();
		if (data[-2] == base64_pad)
			dst.pop_back();
	}
}

static void gen_websocket_accept(std::string &dst, const std::string &src_b64)
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

static void gen_websocket_accept(std::string &dst, const byte *src, size_t size)
{
	std::string src_b64;
	base64(src_b64, src, size);
	gen_websocket_accept(dst, src_b64);
}

void obfs_websock_tcp_socket::encode(std::string &dst, const char *src, size_t size)
{
	std::lock_guard<std::mutex> lock(enc_mutex);
	thread_local std::string buf;
	buf.clear();
	StringSource ss((const byte*)src, size, true, new StreamTransformationFilter(e, new StringSink(buf)));

	dst.clear();
	if (buf.size() <= 125)
	{
		dst.reserve(6 + buf.size());
		dst.push_back('\x82');
		dst.push_back(0x80 | (uint8_t)(buf.size()));
	}
	else if (buf.size() <= 0xFFFF)
	{
		dst.reserve(8 + buf.size());
		dst.push_back('\x82');
		dst.push_back('\xFE');
		dst.push_back((uint8_t)(buf.size() >> 8));
		dst.push_back((uint8_t)(buf.size()));
	}
	else
	{
		dst.reserve(14 + buf.size());
		dst.push_back('\x82');
		dst.push_back('\xFF');
		size_t buf_size = buf.size();
		for (int shift = 56; shift >= 0; shift -= 8)
			dst.push_back((uint8_t)(buf_size >> shift));
	}

	CryptoPP::byte mask[4];
	int maskp = 0;
	prng.GenerateBlock(mask, 4);
	dst.append((const char*)mask, 4);
	for (const char *data = buf.data(), *data_end = buf.data() + buf.size(); data < data_end; ++data)
	{
		dst.push_back((const unsigned char)*data ^ mask[maskp]);
		maskp = (maskp + 1) % 4;
	}
}

void obfs_websock_tcp_socket::decode(std::string &dst, const char *src, size_t size)
{
	std::lock_guard<std::mutex> lock(dec_mutex);
	thread_local std::string buf;
	buf.clear();
	buf.reserve(size - 4);
	const char *src_end = src + size;

	CryptoPP::byte mask[4];
	int maskp = 0;
	for (int i = 0; i < 4; ++i, ++src)
		mask[i] = *src;

	for (; src < src_end; ++src)
	{
		buf.push_back((const unsigned char)*src ^ mask[maskp]);
		maskp = (maskp + 1) % 4;
	}

	dst.clear();
	StringSource ss(buf, true, new StreamTransformationFilter(d, new StringSink(dst)));
}

void obfs_websock_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	socket->connect(ep, err);
	if (err)
		return;

	try
	{
		std::string iv_b64, http_req;
		prng.GenerateBlock(iv, sym_block_size);
		e.SetKeyWithIV(key, sym_block_size, iv);
		d.SetKeyWithIV(key, sym_block_size, iv);
		iv_b64.reserve((sym_block_size / 3 + 1) * 4);
		base64(iv_b64, iv.data(), sym_block_size);
		http_req.append("GET /ep HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
		http_req.append(iv_b64);
		http_req.append("\r\nSec-WebSocket-Protocol: str\r\nSec-WebSocket-Version: 13\r\n\r\n");

		socket->write(const_buffer(http_req), err);
		if (err)
		{
			close();
			return;
		}

		http_header header;
		size_t recv_buf_ptr = 0, recv_buf_ptr_end = 0, size_read, size_parsed;
		bool finished;
		while (finished = header.parse(recv_buf.get() + recv_buf_ptr, recv_buf_ptr_end - recv_buf_ptr, size_parsed), recv_buf_ptr += size_parsed, !finished)
		{
			if (recv_buf_ptr_end >= recv_buf_size)
				throw(std::runtime_error("HTTP header too long"));
			socket->recv(mutable_buffer(recv_buf.get() + recv_buf_ptr_end, recv_buf_size - recv_buf_ptr_end), size_read, err);
			if (err)
			{
				close();
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
	catch (std::exception &)
	{
		close();
		err = ERR_OPERATION_FAILURE;
		return;
	}

	state = STATE_OK;
}

void obfs_websock_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket->async_connect(ep,
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
		prng.GenerateBlock(iv, sym_block_size);
		e.SetKeyWithIV(key, sym_block_size, iv);
		d.SetKeyWithIV(key, sym_block_size, iv);
		http_req->append("GET /ep HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
		base64(*http_req, iv.data(), sym_block_size);
		http_req->append("\r\nSec-WebSocket-Protocol: str\r\nSec-WebSocket-Version: 13\r\n\r\n");
	}
	catch (std::exception &)
	{
		async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		return;
	}

	socket->async_write(const_buffer(*http_req),
		[this, http_req, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}
		recv_websocket_resp(callback, std::make_shared<http_header>());
	});
}

void obfs_websock_tcp_socket::recv_websocket_resp(const std::shared_ptr<null_callback> &callback, const std::shared_ptr<http_header> &header, size_t old_ptr, size_t old_ptr_end)
{
	socket->async_recv(mutable_buffer(recv_buf.get() + old_ptr_end, recv_buf_size - old_ptr_end),
		[this, callback, header, old_ptr, old_ptr_end](error_code err, size_t transferred)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}

		try
		{
			size_t new_ptr_end = old_ptr_end + transferred;
			size_t size_parsed;
			bool finished = header->parse(recv_buf.get() + old_ptr, new_ptr_end - old_ptr, size_parsed);
			size_t new_ptr = old_ptr + size_parsed;
			if (!finished)
			{
				if (new_ptr_end >= recv_buf_size)
					throw(std::runtime_error("HTTP response too long"));
				recv_websocket_resp(callback, header, new_ptr, new_ptr_end);
				return;
			}

			if (header->at(http_header::NAME_STATUS_CODE) != "101" || header->at("Connection") != "Upgrade" || header->at("Upgrade") != "websocket")
				throw(std::runtime_error("Bad HTTP header"));
			std::string sec_accept;
			gen_websocket_accept(sec_accept, iv.data(), sym_block_size);
			if (header->at("Sec-WebSocket-Accept") != sec_accept)
				throw(std::runtime_error("Invalid Sec-WebSocket-Accept"));
			state = STATE_OK;
			(*callback)(0);
		}
		catch (std::exception &)
		{
			async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		}
	});
}

void obfs_websock_tcp_socket::send(const const_buffer &buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;

	size_t size_trans = std::min(buffer.size(), recv_buf_size / 2);

	try
	{
		encode(send_buf, buffer.data(), size_trans);
	}
	catch (std::exception &)
	{
		close();
		err = ERR_OPERATION_FAILURE;
		return;
	}
	socket->write(const_buffer(send_buf), err);
	if (err)
	{
		close();
		return;
	}
	transferred = size_trans;
}

void obfs_websock_tcp_socket::async_send(const const_buffer &buffer, transfer_callback &&complete_handler)
{
	size_t size_trans = std::min(buffer.size(), recv_buf_size / 2);

	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	try
	{
		encode(send_buf, buffer.data(), size_trans);
	}
	catch (std::exception &)
	{
		async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE, 0); });
		return;
	}

	socket->async_write(const_buffer(send_buf),
		[this, size_trans, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err, 0); });
			return;
		}
		(*callback)(0, size_trans);
	});
}

error_code obfs_websock_tcp_socket::recv_data()
{
	error_code err;
	socket->read(mutable_buffer(recv_buf.get(), 2), err);
	if (err)
	{
		close();
		return err;
	}
	if (recv_buf[0] != '\x82')
	{
		close();
		return ERR_BAD_ARG_REMOTE;
	}
	if (((uint8_t)recv_buf[1] & 0x80u) != 0x80u)
	{
		close();
		return ERR_BAD_ARG_REMOTE;
	}

	size_t size;
	if (recv_buf[1] == '\xFF')
	{
		socket->read(mutable_buffer(recv_buf.get(), 8), err);
		if (err)
		{
			close();
			return err;
		}

		uint64_t size64 = 0;
		for (char *data = recv_buf.get(), *data_end = recv_buf.get() + 8; data < data_end; ++data)
			size64 = (size64 << 8) | (uint8_t)*data;
		if (size64 > std::numeric_limits<size_t>::max() - 4)
		{
			close();
			return ERR_BAD_ARG_REMOTE;
		}
		size = (size_t)(size64 + 4);
	}
	else if (recv_buf[1] == '\xFE')
	{
		socket->read(mutable_buffer(recv_buf.get(), 2), err);
		if (err)
		{
			close();
			return err;
		}
		size = (((uint8_t)recv_buf[0] << 8u) | (uint8_t)recv_buf[1]) + 4;
	}
	else
	{
		size = ((uint8_t)recv_buf[1] & 0x7Fu) + 4;
	}

	if (size > recv_buf_size)
	{
		close();
		return ERR_OPERATION_FAILURE;
	}

	socket->read(mutable_buffer(recv_buf.get(), size), err);
	if (err)
	{
		close();
		return err;
	}

	std::string buf;
	try
	{
		decode(buf, recv_buf.get(), size);
	}
	catch (std::exception &)
	{
		close();
		return ERR_OPERATION_FAILURE;
	}
	recv_que.push_back(std::move(buf));

	return 0;
}

void obfs_websock_tcp_socket::async_recv_data(null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket->async_read(mutable_buffer(recv_buf.get(), 2),
		[this, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}
		if (recv_buf[0] != '\x82')
		{
			async_close([callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
			return;
		}
		if (((uint8_t)recv_buf[1] & 0x80u) != 0x80u)
		{
			async_close([callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
			return;
		}

		if (recv_buf[1] == '\xFF')
			async_recv_data_size_64(callback);
		else if (recv_buf[1] == '\xFE')
			async_recv_data_size_16(callback);
		else
			async_recv_data_body(callback, ((uint8_t)recv_buf[1] & 0x7Fu) + 4);
	});
}

void obfs_websock_tcp_socket::async_recv_data_size_16(const std::shared_ptr<null_callback> &callback)
{
	socket->async_read(mutable_buffer(recv_buf.get(), 2),
		[this, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}
		uint16_t size = ((uint8_t)recv_buf[0] << 8u) | (uint8_t)recv_buf[1];
		async_recv_data_body(callback, size + 4);
	});
}

void obfs_websock_tcp_socket::async_recv_data_size_64(const std::shared_ptr<null_callback> &callback)
{
	socket->async_read(mutable_buffer(recv_buf.get(), 8),
		[this, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}
		uint64_t size = 0;
		for (char *data = recv_buf.get(), *data_end = recv_buf.get() + 8; data < data_end; ++data)
			size = (size << 8) | (uint8_t)*data;

		if (size > std::numeric_limits<size_t>::max() - 4)
		{
			async_close([callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
			return;
		}
		async_recv_data_body(callback, (size_t)(size + 4));
	});
}

void obfs_websock_tcp_socket::async_recv_data_body(const std::shared_ptr<null_callback> &callback, size_t size)
{
	if (size > recv_buf_size)
	{
		async_close([callback](error_code) { (*callback)(ERR_BAD_ARG_REMOTE); });
		return;
	}
	socket->async_read(mutable_buffer(recv_buf.get(), size),
		[this, size, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
			return;
		}

		std::string buf;
		try
		{
			decode(buf, recv_buf.get(), size);
		}
		catch (std::exception &)
		{
			async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
			return;
		}
		recv_que.push_back(std::move(buf));

		(*callback)(0);
	});
}

size_t obfs_websock_tcp_socket::read_data(char *buf, size_t size)
{
	size_t size_read = 0;
	while (!recv_que.empty())
	{
		std::string &cur = recv_que.front();
		size_t size_cpy = std::min(cur.size() - ptr_head, size);
		memcpy(buf, cur.data() + ptr_head, size_cpy);
		ptr_head += size_cpy;
		buf += size_cpy;
		size -= size_cpy;
		size_read += size_cpy;
		if (ptr_head == cur.size())
		{
			recv_que.pop_front();
			ptr_head = 0;
		}
		if (size == 0)
			break;
	}
	return size_read;
}

void obfs_websock_tcp_socket::recv(const mutable_buffer &buffer, size_t &transferred, error_code &err)
{
	err = 0;
	transferred = 0;
	if (recv_que.empty())
	{
		err = recv_data();
		if (err)
			return;
	}
	transferred = read_data(buffer.data(), buffer.size());
}

void obfs_websock_tcp_socket::async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler)
{
	if (recv_que.empty())
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
		if (recv_que.empty())
		{
			err = recv_data();
			if (err)
				return;
		}
		size_t transferred = read_data(buffer.front().data(), buffer.front().size());
		buffer.consume(transferred);
	}
}

void obfs_websock_tcp_socket::async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	while (!buffer.empty())
	{
		if (recv_que.empty())
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

void obfs_websock_tcp_socket::async_read(const std::shared_ptr<mutable_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback)
{
	while (!buffer->empty())
	{
		if (recv_que.empty())
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

void obfs_websock_tcp_socket::write(const_buffer_sequence &&buffer, error_code &err)
{
	if (buffer.count() == 1)
		return prx_tcp_socket::write(buffer.front(), err);
	err = 0;
	if (buffer.empty())
		return;

	static constexpr size_t buf_size = recv_buf_size / 2;
	thread_local std::unique_ptr<char[]> buf = std::make_unique<char[]>(buf_size);

	while (!buffer.empty())
	{
		size_t copied = 0;
		while (!buffer.empty() && copied < buf_size)
		{
			size_t copying = std::min(buffer.front().size(), buf_size - copied);
			memcpy(buf.get() + copied, buffer.front().data(), copying);
			copied += copying;
			buffer.consume(copying);
		}
		
		try
		{
			encode(send_buf, buf.get(), copied);
		}
		catch (std::exception &)
		{
			close();
			err = ERR_OPERATION_FAILURE;
			return;
		}
		socket->write(const_buffer(send_buf), err);
		if (err)
		{
			close();
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
	static constexpr size_t buf_size = recv_buf_size / 2;
	thread_local std::unique_ptr<char[]> buf = std::make_unique<char[]>(buf_size);

	size_t copied = 0;
	while (!buffer->empty() && copied < buf_size)
	{
		size_t copying = std::min(buffer->front().size(), buf_size - copied);
		memcpy(buf.get() + copied, buffer->front().data(), copying);
		copied += copying;
		buffer->consume(copying);
	}

	try
	{
		encode(send_buf, buf.get(), copied);
	}
	catch (std::exception &)
	{
		async_close([callback](error_code) { (*callback)(ERR_OPERATION_FAILURE); });
		return;
	}

	socket->async_write(const_buffer(send_buf),
		[this, buffer, callback](error_code err)
	{
		if (err)
		{
			async_close([callback, err](error_code) { (*callback)(err); });
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

void obfs_websock_listener::accept(std::unique_ptr<prx_tcp_socket> &soc, error_code &ec)
{
	soc = nullptr;
	ec = ERR_OPERATION_FAILURE;

	std::unique_ptr<prx_tcp_socket> socket;
	acceptor->accept(socket, ec);
	if (ec)
		return;

	try
	{
		http_header header;
		size_t recv_buf_ptr = 0, recv_buf_ptr_end = 0, size_read, size_parsed;
		bool finished;
		while (finished = header.parse(recv_buf.get() + recv_buf_ptr, recv_buf_ptr_end - recv_buf_ptr, size_parsed), recv_buf_ptr += size_parsed, !finished)
		{
			if (recv_buf_ptr_end >= recv_buf_size)
				throw(std::runtime_error("HTTP header too long"));
			socket->recv(mutable_buffer(recv_buf.get() + recv_buf_ptr_end, recv_buf_size - recv_buf_ptr_end), size_read, ec);
			if (ec)
				throw(std::runtime_error("obfs_websock_listener::accept(): recv() error"));
			recv_buf_ptr_end += size_read;
		}

		if (header.at(http_header::NAME_REQUEST_METHOD) != "GET" || header.at("Connection") != "Upgrade" || header.at("Upgrade") != "websocket" || header.at("Sec-WebSocket-Version") != "13")
			throw(std::runtime_error("Bad HTTP header"));
		if (header.at(http_header::NAME_REQUEST_TARGET) != "/eq" || header.at("Sec-WebSocket-Protocol") != "str")
			throw(std::runtime_error("Bad HTTP header"));

		iv.clear();
		sec_accept.clear();
		std::string &iv_b64 = header.at("Sec-WebSocket-Key");
		base64_rev(iv, iv_b64.data(), iv_b64.size());
		gen_websocket_accept(sec_accept, iv_b64);

		static constexpr char resp_1[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
		constexpr size_t resp_1_size = sizeof(resp_1) - 1;
		static constexpr char resp_2[] = "\r\n\r\n";
		constexpr size_t resp_2_size = sizeof(resp_2) - 1;
		std::string http_resp;
		http_resp.reserve(resp_1_size + sec_accept.size() + resp_2_size);
		http_resp.append(resp_1, resp_1_size);
		http_resp.append(sec_accept);
		http_resp.append(resp_2, resp_2_size);

		socket->write(const_buffer(http_resp), ec);
		if (ec)
			throw(std::runtime_error("obfs_websock_listener::accept(): write() error"));
	}
	catch (std::exception &)
	{
		error_code err;
		socket->close(err);
		if (!ec)
			ec= ERR_BAD_ARG_REMOTE;
		return;
	}

	soc = std::make_unique<obfs_websock_tcp_socket>(std::move(socket), key, iv);
}

void obfs_websock_listener::async_accept(accept_callback &&complete_handler)
{
	if (socket_accept)
	{
		complete_handler(WARN_ALREADY_IN_STATE, nullptr);
		return;
	}
	//TODO: support queue
	std::shared_ptr<accept_callback> callback = std::make_shared<accept_callback>(std::move(complete_handler));
	acceptor->async_accept([this, callback](error_code err, std::unique_ptr<prx_tcp_socket> &&socket)
	{
		if (err)
		{
			(*callback)(err, nullptr);
			return;
		}
		socket_accept = std::move(socket);
		recv_websocket_req(callback, std::make_shared<http_header>());
	});
}

void obfs_websock_listener::recv_websocket_req(const std::shared_ptr<accept_callback> &callback, const std::shared_ptr<http_header> &header, size_t old_ptr, size_t old_ptr_end)
{
	socket_accept->async_recv(mutable_buffer(recv_buf.get() + old_ptr_end, recv_buf_size - old_ptr_end),
		[this, callback, header, old_ptr, old_ptr_end](error_code err, size_t transferred)
	{
		if (err)
		{
			error_code ec;
			//TODO: check if close continues to use resources
			//TODO: check if async invalidates callback
			socket_accept->close(ec);
			socket_accept.reset();
			(*callback)(err, nullptr);
			return;
		}

		try
		{
			size_t new_ptr_end = old_ptr_end + transferred;
			size_t size_parsed;
			bool finished = header->parse(recv_buf.get() + old_ptr, new_ptr_end - old_ptr, size_parsed);
			size_t new_ptr = old_ptr + size_parsed;
			if (!finished)
			{
				if (new_ptr_end >= recv_buf_size)
					throw(std::runtime_error("HTTP header too long"));
				recv_websocket_req(callback, header, new_ptr, new_ptr_end);
				return;
			}

			if (header->at(http_header::NAME_REQUEST_METHOD) != "GET" || header->at("Connection") != "Upgrade" || header->at("Upgrade") != "websocket" || header->at("Sec-WebSocket-Version") != "13")
				throw(std::runtime_error("Bad HTTP header"));
			if (header->at(http_header::NAME_REQUEST_TARGET) != "/ep" || header->at("Sec-WebSocket-Protocol") != "str")
				throw(std::runtime_error("Bad HTTP header"));

			iv.clear();
			sec_accept.clear();
			std::string &iv_b64 = header->at("Sec-WebSocket-Key");
			base64_rev(iv, iv_b64.data(), iv_b64.size());
			gen_websocket_accept(sec_accept, iv_b64);
		}
		catch (std::exception &)
		{
			error_code ec;
			socket_accept->close(ec);
			socket_accept.reset();
			(*callback)(ERR_OPERATION_FAILURE, nullptr);
			return;
		}

		send_websocket_resp(callback);
	});
}

void obfs_websock_listener::send_websocket_resp(const std::shared_ptr<accept_callback> &callback)
{
	std::shared_ptr<std::string> http_resp = std::make_shared<std::string>();
	try
	{
		static constexpr char resp_1[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
		static constexpr size_t resp_1_size = sizeof(resp_1) - 1;
		static constexpr char resp_2[] = "\r\n\r\n";
		static constexpr size_t resp_2_size = sizeof(resp_2) - 1;
		http_resp->reserve(resp_1_size + sec_accept.size() + resp_2_size);
		http_resp->append(resp_1, resp_1_size);
		http_resp->append(sec_accept);
		http_resp->append(resp_2, resp_2_size);
	}
	catch (std::exception &)
	{
		error_code ec;
		socket_accept->close(ec);
		socket_accept.reset();
		(*callback)(ERR_OPERATION_FAILURE, nullptr);
		return;
	}

	socket_accept->async_write(const_buffer(*http_resp),
		[this, http_resp, callback](error_code err)
	{
		if (err)
		{
			error_code ec;
			socket_accept->close(ec);
			socket_accept.reset();
			(*callback)(err, nullptr);
			return;
		}

		(*callback)(0, std::make_unique<obfs_websock_tcp_socket>(std::move(socket_accept), key, iv));
	});
}
