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
#include "socket_raw.h"

using namespace prxsocket;

thread_local boost::system::error_code raw_tcp_socket::ec;
thread_local boost::system::error_code raw_udp_socket::ec;
thread_local boost::system::error_code raw_listener::ec;

namespace
{

	void raw_ep_to_ep(const asio::ip::tcp::endpoint &raw_ep, endpoint &ep)
	{
		asio::ip::address raw_addr = raw_ep.address();
		if (raw_addr.is_v4())
		{
			ep = endpoint(raw_addr.to_v4().to_ulong(), raw_ep.port());
		}
		else if (raw_addr.is_v6())
		{
			ep = endpoint(address_v6(raw_addr.to_v6().to_bytes().data()), raw_ep.port());
		}
		else
		{
			ep = endpoint(raw_addr.to_string(), raw_ep.port());
		}
	}

	void raw_ep_to_ep(const asio::ip::udp::endpoint &raw_ep, endpoint &ep)
	{
		asio::ip::address raw_addr = raw_ep.address();
		if (raw_addr.is_v4())
		{
			ep = endpoint(raw_addr.to_v4().to_ulong(), raw_ep.port());
		}
		else if (raw_addr.is_v6())
		{
			ep = endpoint(address_v6(raw_addr.to_v6().to_bytes().data()), raw_ep.port());
		}
		else
		{
			ep = endpoint(raw_addr.to_string(), raw_ep.port());
		}
	}

	const std::vector<asio::mutable_buffer> &to_raw_buffers(const mutable_buffer_sequence &buffers)
	{
		thread_local std::vector<asio::mutable_buffer> raw_buffers;
		raw_buffers.clear();
		raw_buffers.reserve(buffers.count());
		for (const auto &buffer : buffers)
			raw_buffers.push_back(asio::mutable_buffer(buffer.data(), buffer.size()));
		return raw_buffers;
	}

	const std::vector<asio::const_buffer> &to_raw_buffers(const const_buffer_sequence &buffers)
	{
		thread_local std::vector<asio::const_buffer> raw_buffers;
		raw_buffers.clear();
		raw_buffers.reserve(buffers.count());
		for (const auto &buffer : buffers)
			raw_buffers.push_back(asio::const_buffer(buffer.data(), buffer.size()));
		return raw_buffers;
	}

}

void raw_tcp_socket::set_keep_alive()
{
	asio::ip::tcp::socket::keep_alive option(true);
	socket_.set_option(option, ec);
	if (ec)
		return;

	// the timeout value
	constexpr size_t timeout_milli = 120000;

	// platform-specific switch
#if defined _WIN32 || defined WIN32 || defined OS_WIN64 || defined _WIN64 || defined WIN64 || defined WINNT
	// use windows-specific time
	int32_t timeout = timeout_milli;
	setsockopt(socket_.native_handle(), SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
	setsockopt(socket_.native_handle(), SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
#else
	// assume everything else is posix
	struct timeval tv;
	tv.tv_sec = timeout_milli / 1000;
	tv.tv_usec = timeout_milli % 1000;
	setsockopt(socket_.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(socket_.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

void raw_tcp_socket::local_endpoint(endpoint &ep, error_code &err)
{
	err = 0;
	try
	{
		asio::ip::tcp::endpoint raw_ep = socket_.local_endpoint();
		raw_ep_to_ep(raw_ep, ep);
	}
	catch (const std::exception &) { err = ERR_OPERATION_FAILURE; }
}

void raw_tcp_socket::remote_endpoint(endpoint &ep, error_code &err)
{
	err = 0;
	try
	{
		asio::ip::tcp::endpoint raw_ep = socket_.remote_endpoint();
		raw_ep_to_ep(raw_ep, ep);
	}
	catch (const std::exception &) { err = ERR_OPERATION_FAILURE; }
}

void raw_tcp_socket::open(error_code &err)
{
	err = 0;
	socket_.open(asio::ip::tcp::v4(), ec);
	if (ec)
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}
	set_keep_alive();
	binded_ = false;
	connected_ = false;
}

void raw_tcp_socket::async_open(null_callback &&complete_handler)
{
	error_code err;
	open(err);
	complete_handler(err);
}

void raw_tcp_socket::check_protocol(const asio::ip::tcp::endpoint::protocol_type &protocol)
{
	if (!socket_.is_open())
	{
		socket_.open(protocol, ec);
		set_keep_alive();
	}
	else
	{
		asio::ip::tcp::endpoint local_endpoint = socket_.local_endpoint(ec);
		if (ec || local_endpoint.protocol() != protocol)
		{
			socket_.close(ec);
			socket_.open(protocol, ec);
			set_keep_alive();
		}
	}
}

void raw_tcp_socket::bind(const endpoint &ep, error_code &err)
{
	err = 0;
	if (is_connected())
	{
		err = ERR_ALREADY_IN_STATE;
		return;
	}
	const address &addr = ep.addr();
	asio::ip::address native_addr;
	switch (addr.type())
	{
	case address::V4:
	{
		check_protocol(asio::ip::tcp::v4());
		native_addr = asio::ip::address_v4(addr.v4().to_ulong());
		break;
	}
	case address::V6:
	{
		check_protocol(asio::ip::tcp::v6());
		std::array<uint8_t, address_v6::ADDR_SIZE> addr_byte{};
		memcpy(addr_byte.data(), addr.v6().to_bytes(), address_v6::ADDR_SIZE);
		native_addr = asio::ip::address_v6(addr_byte);
		break;
	}
	default:
	{
		err = ERR_UNSUPPORTED;
		return;
	}
	}
	socket_.bind(asio::ip::tcp::endpoint(native_addr, ep.port()), ec);
	binded_ = !ec;
	if (!binded_)
		err = ERR_OPERATION_FAILURE;
}

void raw_tcp_socket::async_bind(const endpoint &ep, null_callback &&complete_handler)
{
	error_code err;
	bind(ep, err);
	complete_handler(err);
}

void raw_tcp_socket::connect(const endpoint &ep, error_code &err)
{
	err = 0;
	if (is_connected())
	{
		err = ERR_ALREADY_IN_STATE;
		return;
	}
	const address &addr = ep.addr();
	asio::ip::address native_addr;
	switch (addr.type())
	{
	case address::V4:
	{
		if (!binded_)
			check_protocol(asio::ip::tcp::v4());
		native_addr = asio::ip::address_v4(addr.v4().to_ulong());
		break;
	}
	case address::V6:
	{
		if (!binded_)
			check_protocol(asio::ip::tcp::v6());
		std::array<uint8_t, address_v6::ADDR_SIZE> addr_byte{};
		memcpy(addr_byte.data(), addr.v6().to_bytes(), address_v6::ADDR_SIZE);
		native_addr = asio::ip::address_v6(addr_byte);
		break;
	}
	case address::STR:
	{
		connect_addr_str(ep.addr().str().data(), ep.port(), err);
		return;
	}
	default:
	{
		err = ERR_UNSUPPORTED;
		return;
	}
	}
	socket_.connect(asio::ip::tcp::endpoint(native_addr, ep.port()), ec);
	if (ec)
	{
		err = ERR_CONNECTION_REFUSED;
		return;
	}
	connected_ = true;
}

void raw_tcp_socket::connect_addr_str(const std::string &addr, port_type port, error_code &err)
{
	auto itr = resolver_.resolve(asio::ip::tcp::resolver::query(addr, std::to_string(port)), ec);
	if (ec)
	{
		err = ERR_UNRESOLVED_HOST;
		return;
	}
	asio::connect(socket_, itr,
		[this](const boost::system::error_code &, asio::ip::tcp::resolver::iterator itr)->asio::ip::tcp::resolver::iterator
	{
		if (!binded_)
			check_protocol(itr->endpoint().protocol());
		return itr;
	}, ec);
	if (ec)
	{
		err = ERR_CONNECTION_REFUSED;
		return;
	}
	connected_ = true;
}

void raw_tcp_socket::async_connect(const endpoint &ep, null_callback &&complete_handler)
{
	if (is_connected())
	{
		complete_handler(ERR_ALREADY_IN_STATE);
		return;
	}
	const address &addr = ep.addr();
	asio::ip::address native_addr;
	switch (addr.type())
	{
	case address::V4:
	{
		if (!binded_)
			check_protocol(asio::ip::tcp::v4());
		native_addr = asio::ip::address_v4(addr.v4().to_ulong());
		break;
	}
	case address::V6:
	{
		if (!binded_)
			check_protocol(asio::ip::tcp::v6());
		std::array<uint8_t, address_v6::ADDR_SIZE> addr_byte{};
		memcpy(addr_byte.data(), addr.v6().to_bytes(), address_v6::ADDR_SIZE);
		native_addr = asio::ip::address_v6(addr_byte);
		break;
	}
	case address::STR:
	{
		async_connect_addr_str(ep.addr().str().data(), ep.port(), std::make_shared<null_callback>(std::move(complete_handler)));
		return;
	}
	default:
	{
		complete_handler(ERR_UNSUPPORTED);
		return;
	}
	}
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket_.async_connect(asio::ip::tcp::endpoint(native_addr, ep.port()),
		[this, callback](const boost::system::error_code &e)
	{
		if (e)
		{
			(*callback)(ERR_CONNECTION_REFUSED);
			return;
		}
		connected_ = true;
		(*callback)(0);
	});
}

void raw_tcp_socket::async_connect_addr_str(const std::string &addr, port_type port, const std::shared_ptr<null_callback> &callback)
{
	resolver_.async_resolve(asio::ip::tcp::resolver::query(addr, std::to_string(port)),
		[this, callback](const boost::system::error_code &e, asio::ip::tcp::resolver::iterator itr)
	{
		if (e)
		{
			(*callback)(ERR_UNRESOLVED_HOST);
			return;
		}
		asio::async_connect(socket_, itr, asio::ip::tcp::resolver::iterator(),
			[this](const boost::system::error_code &, asio::ip::tcp::resolver::iterator itr)->asio::ip::tcp::resolver::iterator
		{
			if (!binded_)
				check_protocol(itr->endpoint().protocol());
			return itr;
		},
			[this, callback](const boost::system::error_code &e, asio::ip::tcp::resolver::iterator)
		{
			if (e)
			{
				(*callback)(ERR_CONNECTION_REFUSED);
				return;
			}
			connected_ = true;
			(*callback)(0);
		});
	});
}

size_t prxsocket::raw_tcp_socket::send_size_max()
{
	return 1360;
}

void prxsocket::raw_tcp_socket::send(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, error_code &err)
{
	err = 0;
	asio::write(socket_, asio::buffer(buffer.data(), buffer.size()), ec);
	buffer_data_holder.reset();
	if (ec)
	{
		socket_.shutdown(socket_.shutdown_send, ec);
		err = ERR_OPERATION_FAILURE;
	}
}

void prxsocket::raw_tcp_socket::async_send(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, null_callback &&complete_handler)
{
	using argument_pair = std::pair<buffer_data_store_holder, null_callback>;
	std::shared_ptr<argument_pair> arguments_shared = std::make_shared<argument_pair>(std::make_pair(std::move(buffer_data_holder), std::move(complete_handler)));
	asio::async_write(socket_, asio::buffer(buffer.data(), buffer.size()),
		[this, arguments_shared](const boost::system::error_code &e, std::size_t)
	{
		arguments_shared->first.reset();
		if (e)
		{
			socket_.shutdown(socket_.shutdown_send, ec);
			(arguments_shared->second)(ERR_OPERATION_FAILURE);
		}
		else
		{
			(arguments_shared->second)(0);
		}
	});
}

void prxsocket::raw_tcp_socket::send_partial(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, error_code &err)
{
	return send(buffer, std::move(buffer_data_holder), err);
}

void prxsocket::raw_tcp_socket::async_send_partial(const_buffer buffer, buffer_data_store_holder &&buffer_data_holder, null_callback &&complete_handler)
{
	return async_send_partial(buffer, std::move(buffer_data_holder), std::move(complete_handler));
}

void prxsocket::raw_tcp_socket::recv(const_buffer &buffer, buffer_data_store_holder &buffer_data_holder, error_code &err)
{
	PRXSOCKET_MAKE_INPLACE_BUFFER(recv_buffer_type, data, data_holder);
	err = 0;
	size_t transferred = socket_.receive(asio::buffer(data.data(), data.size()), 0, ec);
	if (ec)
	{
		socket_.shutdown(socket_.shutdown_receive, ec);
		err = ERR_OPERATION_FAILURE;
		return;
	}
	buffer = const_buffer(data.data(), transferred);
	buffer_data_holder = std::move(data_holder);
}

void prxsocket::raw_tcp_socket::async_recv(transfer_data_callback &&complete_handler)
{
	using argument_pair = std::pair<buffer_data_store_holder, transfer_data_callback>;
	std::shared_ptr<argument_pair> arguments_shared = std::make_shared<argument_pair>(std::make_pair(
		buffer_data_store_holder(new prxsocket::buffer_data_store_inplace<recv_buffer_type>()),
		std::move(complete_handler)
	));
	recv_buffer_type &data = static_cast<prxsocket::buffer_data_store_inplace<recv_buffer_type> *>(arguments_shared->first.get())->get();
	socket_.async_receive(asio::buffer(data.data(), data.size()),
		[this, arguments_shared](const boost::system::error_code &e, std::size_t transferred)
	{
		if (e)
		{
			socket_.shutdown(socket_.shutdown_receive, ec);
			(arguments_shared->second)(ERR_OPERATION_FAILURE, const_buffer(), buffer_data_store_holder());
		}
		else
		{
			recv_buffer_type &data = static_cast<prxsocket::buffer_data_store_inplace<recv_buffer_type> *>(arguments_shared->first.get())->get();
			(arguments_shared->second)(0, const_buffer(data.data(), transferred), std::move(arguments_shared->first));
		}
	});
}

void raw_tcp_socket::shutdown(shutdown_type type, error_code &err)
{
	if (type & shutdown_both)
	{
		socket_.shutdown(socket_.shutdown_both, ec);
		err = ec ? ERR_OPERATION_FAILURE : 0;
	}
	else if (type & shutdown_send)
	{
		socket_.shutdown(socket_.shutdown_send, ec);
		err = ec ? ERR_OPERATION_FAILURE : 0;
	}
	else if (type & shutdown_receive)
	{
		socket_.shutdown(socket_.shutdown_receive, ec);
		err = ec ? ERR_OPERATION_FAILURE : 0;
	}
	else
	{
		err = 0;
	}
}

void raw_tcp_socket::async_shutdown(shutdown_type type, null_callback &&complete_handler)
{
	if (type & shutdown_both)
	{
		socket_.shutdown(socket_.shutdown_both, ec);
		complete_handler(ec ? ERR_OPERATION_FAILURE : 0);
	}
	else if (type & shutdown_send)
	{
		socket_.shutdown(socket_.shutdown_send, ec);
		complete_handler(ec ? ERR_OPERATION_FAILURE : 0);
	}
	else if (type & shutdown_receive)
	{
		socket_.shutdown(socket_.shutdown_receive, ec);
		complete_handler(ec ? ERR_OPERATION_FAILURE : 0);
	}
	else
	{
		complete_handler(0);
	}
}

void raw_tcp_socket::close(error_code &err)
{
	socket_.close(ec);
	binded_ = false;
	connected_ = false;
	err = 0;
}

void raw_tcp_socket::async_close(null_callback &&complete_handler)
{
	socket_.close(ec);
	binded_ = false;
	connected_ = false;
	complete_handler(0);
}

void raw_udp_socket::local_endpoint(endpoint &ep, error_code &err)
{
	err = 0;
	try
	{
		asio::ip::udp::endpoint raw_ep = socket_.local_endpoint();
		raw_ep_to_ep(raw_ep, ep);
	}
	catch (const std::exception &) { err = ERR_OPERATION_FAILURE; }
}

void raw_udp_socket::open(error_code &err)
{
	err = 0;
	if (is_open())
	{
		err = ERR_ALREADY_IN_STATE;
		return;
	}
	socket_.open(asio::ip::udp::v4(), ec);
	if (ec)
	{
		err = ERR_OPERATION_FAILURE;
		return;
	}
	socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), ec);
	if (ec)
	{
		socket_.close(ec);
		err = ERR_OPERATION_FAILURE;
		return;
	}
}

void raw_udp_socket::async_open(null_callback &&complete_handler)
{
	error_code err;
	open(err);
	complete_handler(err);
}

void raw_udp_socket::bind(const endpoint &ep, error_code &err)
{
	err = 0;
	const address &addr = ep.addr();
	asio::ip::address native_addr;
	switch (addr.type())
	{
	case address::V4:
	{
		socket_.close(ec);
		socket_.open(asio::ip::udp::v4(), ec);
		native_addr = asio::ip::address_v4(addr.v4().to_ulong());
		break;
	}
	case address::V6:
	{
		socket_.close(ec);
		socket_.open(asio::ip::udp::v6(), ec);
		std::array<uint8_t, address_v6::ADDR_SIZE> addr_byte{};
		memcpy(addr_byte.data(), addr.v6().to_bytes(), address_v6::ADDR_SIZE);
		native_addr = asio::ip::address_v6(addr_byte);
		break;
	}
	default:
	{
		err = ERR_UNSUPPORTED;
		return;
	}
	}
	socket_.bind(asio::ip::udp::endpoint(native_addr, ep.port()), ec);
	if (ec)
	{
		socket_.close(ec);
		err = ERR_OPERATION_FAILURE;
		return;
	}
}

void raw_udp_socket::async_bind(const endpoint &ep, null_callback &&complete_handler)
{
	error_code err;
	bind(ep, err);
	complete_handler(err);
}

void raw_udp_socket::send_to(const endpoint &ep, const_buffer buffer, error_code &err)
{
	err = 0;
	asio::ip::udp::endpoint native_ep;
	error_code e = to_udp_ep(ep, native_ep);
	if (e)
	{
		err = e;
		return;
	}
	socket_.send_to(asio::buffer(buffer.data(), buffer.size()), native_ep, 0, ec);
	if (ec)
		err = ERR_OPERATION_FAILURE;
}

void raw_udp_socket::async_send_to(const endpoint &ep, const_buffer buffer, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	async_to_udp_ep(ep, [this, buffer, callback](error_code err, const asio::ip::udp::endpoint &native_ep)
	{
		if (err)
		{
			(*callback)(err);
			return;
		}
		socket_.async_send_to(asio::buffer(buffer.data(), buffer.size()), native_ep,
			[callback](const boost::system::error_code &e, size_t)
		{
			if (e)
				(*callback)(ERR_OPERATION_FAILURE);
			else
				(*callback)(0);
		});
	});
}

void raw_udp_socket::recv_from(endpoint &ep, mutable_buffer buffer, size_t &transferred, error_code &err)
{
	err = 0;
	asio::ip::udp::endpoint native_ep;
	transferred = socket_.receive_from(asio::buffer(buffer.data(), buffer.size()), native_ep, 0, ec);
	if (ec)
	{
		err = (ERR_OPERATION_FAILURE);
		return;
	}
	raw_ep_to_ep(native_ep, ep);
}

void raw_udp_socket::async_recv_from(endpoint &ep, mutable_buffer buffer, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socket_.async_receive_from(asio::buffer(buffer.data(), buffer.size()), recv_ep_,
		[this, &ep, callback](const boost::system::error_code &e, size_t recved)
	{
		if (e)
		{
			(*callback)(ERR_OPERATION_FAILURE, recved);
			return;
		}
		raw_ep_to_ep(recv_ep_, ep);
		(*callback)(0, recved);
	});
}

void raw_udp_socket::send_to(const endpoint &ep, const_buffer_sequence &&buffers, error_code &err)
{
	err = 0;
	asio::ip::udp::endpoint native_ep;
	error_code e = to_udp_ep(ep, native_ep);
	if (e)
	{
		err = e;
		return;
	}
	socket_.send_to(to_raw_buffers(buffers), native_ep, 0, ec);
	if (ec)
		err = (ERR_OPERATION_FAILURE);
}

void raw_udp_socket::async_send_to(const endpoint &ep, const_buffer_sequence &&buffers, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	async_to_udp_ep(ep, [this, buffers = std::move(buffers), callback](error_code err, const asio::ip::udp::endpoint &native_ep)
	{
		if (err)
		{
			(*callback)(err);
			return;
		}
		socket_.async_send_to(to_raw_buffers(buffers), native_ep,
			[callback](const boost::system::error_code &e, size_t)
		{
			if (e)
				(*callback)(ERR_OPERATION_FAILURE);
			else
				(*callback)(0);
		});
	});
}

void raw_udp_socket::recv_from(endpoint &ep, mutable_buffer_sequence &&buffers, size_t &transferred, error_code &err)
{
	err = 0;
	asio::ip::udp::endpoint native_ep;
	transferred = socket_.receive_from(to_raw_buffers(buffers), native_ep, 0, ec);
	if (ec)
	{
		err = (ERR_OPERATION_FAILURE);
		return;
	}
	raw_ep_to_ep(native_ep, ep);
}

void raw_udp_socket::async_recv_from(endpoint &ep, mutable_buffer_sequence &&buffers, transfer_callback &&complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socket_.async_receive_from(to_raw_buffers(buffers), recv_ep_,
		[this, &ep, callback](const boost::system::error_code &e, size_t recved)
	{
		if (e)
		{
			(*callback)(ERR_OPERATION_FAILURE, recved);
			return;
		}
		raw_ep_to_ep(recv_ep_, ep);
		(*callback)(0, recved);
	});
}

void raw_udp_socket::close(error_code &err)
{
	err = 0;
	socket_.shutdown(socket_.shutdown_both, ec);
	socket_.close(ec);
}

void raw_udp_socket::async_close(null_callback &&complete_handler)
{
	socket_.shutdown(socket_.shutdown_both, ec);
	socket_.close(ec);
	complete_handler(0);
}

error_code raw_udp_socket::to_udp_ep(const endpoint &ep, asio::ip::udp::endpoint &result)
{
	const address &addr = ep.addr();
	switch (addr.type())
	{
	case address::V4:
	{
		result = asio::ip::udp::endpoint(asio::ip::address_v4(addr.v4().to_ulong()), ep.port());
		break;
	}
	case address::V6:
	{
		std::array<uint8_t, address_v6::ADDR_SIZE> addr_byte{};
		memcpy(addr_byte.data(), addr.v6().to_bytes(), address_v6::ADDR_SIZE);
		result = asio::ip::udp::endpoint(asio::ip::address_v6(addr_byte), ep.port());
		break;
	}
	case address::STR:
	{
		result = *resolver_.resolve(asio::ip::udp::resolver::query(addr.str().data(), std::to_string(ep.port())), ec);
		if (ec)
			return ERR_UNRESOLVED_HOST;
		break;
	}
	default:
		return ERR_UNSUPPORTED;
	}
	return 0;
}

void raw_udp_socket::async_to_udp_ep(const endpoint &ep, std::function<void(error_code, const asio::ip::udp::endpoint &)> &&complete_handler)
{
	const address &addr = ep.addr();
	switch (addr.type())
	{
	case address::V4:
	{
		complete_handler(0, asio::ip::udp::endpoint(asio::ip::address_v4(addr.v4().to_ulong()), ep.port()));
		break;
	}
	case address::V6:
	{
		std::array<uint8_t, address_v6::ADDR_SIZE> addr_byte{};
		memcpy(addr_byte.data(), addr.v6().to_bytes(), address_v6::ADDR_SIZE);
		complete_handler(0, asio::ip::udp::endpoint(asio::ip::address_v6(addr_byte), ep.port()));
		break;
	}
	case address::STR:
	{
		auto callback = std::make_shared<std::function<void(error_code, const asio::ip::udp::endpoint &)>>(std::move(complete_handler));
		resolver_.async_resolve(asio::ip::udp::resolver::query(addr.str().data(), std::to_string(ep.port())),
			[callback](const boost::system::error_code &e, asio::ip::udp::resolver::iterator itr)
		{
			if (e)
				(*callback)(ERR_UNRESOLVED_HOST, asio::ip::udp::endpoint());
			else
				(*callback)(0, *itr);
		});
		break;
	}
	default:
		complete_handler(ERR_UNSUPPORTED, asio::ip::udp::endpoint());
	}
}

void raw_listener::local_endpoint(endpoint &ep, error_code &err)
{
	err = 0;
	try
	{
		asio::ip::tcp::endpoint raw_ep = acceptor_.local_endpoint();
		raw_ep_to_ep(raw_ep, ep);
	}
	catch (const std::exception &) { err = ERR_OPERATION_FAILURE; }
}

void raw_listener::open(error_code &err)
{
	err = 0;
	acceptor_.open(asio::ip::tcp::v4(), ec);
	if (ec)
		err = ERR_OPERATION_FAILURE;
	else
		listening_ = false;
}

void raw_listener::async_open(null_callback &&complete_handler)
{
	acceptor_.open(asio::ip::tcp::v4(), ec);
	if (ec)
	{
		complete_handler(ERR_OPERATION_FAILURE);
	}
	else
	{
		listening_ = false;
		complete_handler(0);
	}
}

void raw_listener::bind(const endpoint &ep, error_code &err)
{
	err = 0;
	if (is_listening())
	{
		err = ERR_ALREADY_IN_STATE;
		return;
	}
	const address &addr = ep.addr();
	asio::ip::address native_addr;
	switch (addr.type())
	{
	case address::V4:
		acceptor_.close(ec);
		acceptor_.open(asio::ip::tcp::v4(), ec);
		native_addr = asio::ip::address_v4(addr.v4().to_ulong());
		break;
	case address::V6:
		acceptor_.close(ec);
		acceptor_.open(asio::ip::tcp::v6(), ec);
		std::array<uint8_t, address_v6::ADDR_SIZE> addr_byte{};
		memcpy(addr_byte.data(), addr.v6().to_bytes(), address_v6::ADDR_SIZE);
		native_addr = asio::ip::address_v6(addr_byte);
		break;
	default:
		err = ERR_UNSUPPORTED;
		return;
	}
	acceptor_.bind(asio::ip::tcp::endpoint(native_addr, ep.port()), ec);
	if (ec)
		err = ERR_OPERATION_FAILURE;
}

void raw_listener::async_bind(const endpoint &ep, null_callback &&complete_handler)
{
	error_code err;
	bind(ep, err);
	complete_handler(err);
}

void raw_listener::listen(error_code &err)
{
	err = 0;
	acceptor_.listen(asio::socket_base::max_connections, ec);
	if (ec)
		err = ERR_OPERATION_FAILURE;
	else
		listening_ = true;
}

void raw_listener::async_listen(null_callback &&complete_handler)
{
	error_code err;
	listen(err);
	complete_handler(err);
}

void raw_listener::accept(std::unique_ptr<prx_tcp_socket> &new_socket, error_code &err)
{
	asio::ip::tcp::socket socket(iosrv_);
	acceptor_.accept(socket, ec);
	if (ec)
	{
		err = ERR_OPERATION_FAILURE;
		new_socket = nullptr;
	}
	else
	{
		err = 0;
		new_socket = std::make_unique<raw_tcp_socket>(std::move(socket), true);
	}
}

void raw_listener::async_accept(accept_callback &&complete_handler)
{
	auto socket = std::make_shared<asio::ip::tcp::socket>(iosrv_);
	auto callback = std::make_shared<accept_callback>(std::move(complete_handler));
	acceptor_.async_accept(*socket, [socket, callback](const boost::system::error_code &e)
	{
		if (e)
			(*callback)(ERR_OPERATION_FAILURE, nullptr);
		else
			(*callback)(0, std::make_unique<raw_tcp_socket>(std::move(*socket), true));
	});
}

void raw_listener::close(error_code &err)
{
	acceptor_.close(ec);
	err = (ec ? ERR_OPERATION_FAILURE : 0);
}

void raw_listener::async_close(null_callback &&complete_handler)
{
	acceptor_.close(ec);
	complete_handler(ec ? ERR_OPERATION_FAILURE : 0);
}
