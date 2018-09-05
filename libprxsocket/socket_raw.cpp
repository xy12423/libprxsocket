#include "stdafx.h"
#include "socket_raw.h"

void raw_ep_to_ep(const asio::ip::tcp::endpoint& raw_ep, endpoint& ep)
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

void raw_ep_to_ep(const asio::ip::udp::endpoint& raw_ep, endpoint& ep)
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

void raw_tcp_socket::set_keep_alive()
{
	// the timeout value
	constexpr size_t timeout_milli = 120000;

	// platform-specific switch
#if defined _WIN32 || defined WIN32 || defined OS_WIN64 || defined _WIN64 || defined WIN64 || defined WINNT
	// use windows-specific time
	int32_t timeout = timeout_milli;
	setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
	setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
	// assume everything else is posix
	struct timeval tv;
	tv.tv_sec = timeout_milli / 1000;
	tv.tv_usec = timeout_milli % 1000;
	setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

err_type raw_tcp_socket::local_endpoint(endpoint& ep)
{
	try
	{
		asio::ip::tcp::endpoint raw_ep = socket.local_endpoint();
		raw_ep_to_ep(raw_ep, ep);
	}
	catch (std::exception &) { return ERR_OPERATION_FAILURE; }
	return 0;
}

err_type raw_tcp_socket::remote_endpoint(endpoint& ep)
{
	try
	{
		asio::ip::tcp::endpoint raw_ep = socket.remote_endpoint();
		raw_ep_to_ep(raw_ep, ep);
	}
	catch (std::exception &) { return ERR_OPERATION_FAILURE; }
	return 0;
}

err_type raw_tcp_socket::bind(const endpoint& ep)
{
	const address &addr = ep.get_addr();
	asio::ip::address native_addr;
	switch (addr.get_type())
	{
		case address::V4:
		{
			socket.close(ec);
			socket.open(asio::ip::tcp::v4(), ec);
			native_addr = asio::ip::address_v4(addr.v4().to_ulong());
			break;
		}
		case address::V6:
		{
			socket.close(ec);
			socket.open(asio::ip::tcp::v6(), ec);
			std::array<uint8_t, address_v6::addr_size> addr_byte;
			memmove(addr_byte.data(), addr.v6().to_bytes(), address_v6::addr_size);
			native_addr = asio::ip::address_v6(addr_byte);
			break;
		}
		default:
			return ERR_UNSUPPORTED;
	}
	socket.bind(asio::ip::tcp::endpoint(native_addr, ep.get_port()), ec);
	binded = !ec;
	return (ec ? ERR_OPERATION_FAILURE : 0);
}

void raw_tcp_socket::async_bind(const endpoint& ep, null_callback&& complete_handler)
{
	complete_handler(bind(ep));
}

void raw_tcp_socket::check_protocol(const asio::ip::tcp::endpoint::protocol_type& protocol)
{
	try
	{
		if (!socket.is_open())
		{
			socket.open(protocol, ec);
		}
		else if (socket.local_endpoint().protocol() != protocol)
		{
			socket.close(ec);
			socket.open(protocol, ec);
		}
	}
	catch (std::exception &)
	{
		socket.close(ec);
		socket.open(protocol, ec);
	}
}

err_type raw_tcp_socket::connect(const endpoint& ep)
{
	const address &addr = ep.get_addr();
	asio::ip::address native_addr;
	switch (addr.get_type())
	{
		case address::V4:
		{
			if (!binded)
				check_protocol(asio::ip::tcp::v4());
			native_addr = asio::ip::address_v4(addr.v4().to_ulong());
			break;
		}
		case address::V6:
		{
			if (!binded)
				check_protocol(asio::ip::tcp::v6());
			std::array<uint8_t, address_v6::addr_size> addr_byte;
			memmove(addr_byte.data(), addr.v6().to_bytes(), address_v6::addr_size);
			native_addr = asio::ip::address_v6(addr_byte);
			break;
		}
		case address::STR:
		{
			return connect_addr_str(ep.get_addr().str().data(), ep.get_port());
		}
		default:
			return ERR_UNSUPPORTED;
	}
	socket.connect(asio::ip::tcp::endpoint(native_addr, ep.get_port()), ec);
	if (ec)
	{
		socket.close(ec);
		return ERR_CONNECTION_REFUSED;
	}
	return 0;
}

err_type raw_tcp_socket::connect_addr_str(const std::string& addr, port_type port)
{
	auto itr = resolver.resolve(asio::ip::tcp::resolver::query(addr, std::to_string(port)), ec);
	if (ec)
		return ERR_UNRESOLVED_HOST;
	asio::connect(socket, itr,
		[this](const boost::system::error_code&, asio::ip::tcp::resolver::iterator itr)->asio::ip::tcp::resolver::iterator
	{
		if (!binded)
			check_protocol(itr->endpoint().protocol());
		return itr;
	}, ec);
	if (ec)
	{
		socket.close(ec);
		return ERR_CONNECTION_REFUSED;
	}
	return 0;
}

void raw_tcp_socket::async_connect(const endpoint& ep, null_callback&& complete_handler)
{
	const address &addr = ep.get_addr();
	asio::ip::address native_addr;
	switch (addr.get_type())
	{
		case address::V4:
		{
			if (!binded)
				check_protocol(asio::ip::tcp::v4());
			native_addr = asio::ip::address_v4(addr.v4().to_ulong());
			break;
		}
		case address::V6:
		{
			if (!binded)
				check_protocol(asio::ip::tcp::v6());
			std::array<uint8_t, address_v6::addr_size> addr_byte;
			memmove(addr_byte.data(), addr.v6().to_bytes(), address_v6::addr_size);
			native_addr = asio::ip::address_v6(addr_byte);
			break;
		}
		case address::STR:
		{
			async_connect_addr_str(ep.get_addr().str().data(), ep.get_port(), std::make_shared<null_callback>(std::move(complete_handler)));
			return;
		}
		default:
			complete_handler(ERR_UNSUPPORTED);
			return;
	}
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	socket.async_connect(asio::ip::tcp::endpoint(native_addr, ep.get_port()),
		[this, callback](const boost::system::error_code& e)
	{
		if (e)
		{
			socket.close(ec);
			(*callback)(ERR_CONNECTION_REFUSED);
			return;
		}
		(*callback)(0);
	});
}

void raw_tcp_socket::async_connect_addr_str(const std::string& addr, port_type port, const std::shared_ptr<null_callback>& callback)
{
	resolver.async_resolve(asio::ip::tcp::resolver::query(addr, std::to_string(port)),
		[this, callback](const boost::system::error_code& e, asio::ip::tcp::resolver::iterator itr)
	{
		if (e)
		{
			socket.close(ec);
			(*callback)(ERR_UNRESOLVED_HOST);
			return;
		}
		asio::async_connect(socket, itr, asio::ip::tcp::resolver::iterator(),
			[this](const boost::system::error_code&, asio::ip::tcp::resolver::iterator itr)->asio::ip::tcp::resolver::iterator
		{
			if (!binded)
				check_protocol(itr->endpoint().protocol());
			return itr;
		},
			[this, callback](const boost::system::error_code& e, asio::ip::tcp::resolver::iterator)
		{
			if (e)
			{
				socket.close(ec);
				(*callback)(ERR_CONNECTION_REFUSED);
				return;
			}
			(*callback)(0);
		});
	});
}

err_type raw_tcp_socket::send(const const_buffer& buffer, size_t& transferred)
{
	transferred = socket.send(asio::buffer(buffer.get_data(), buffer.get_size()), 0, ec);
	if (ec)
		return ERR_OPERATION_FAILURE;
	return 0;
}

void raw_tcp_socket::async_send(const const_buffer& buffer, transfer_callback&& complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socket.async_send(asio::buffer(buffer.get_data(), buffer.get_size()),
		[this, callback](const boost::system::error_code& ec, std::size_t transferred)
	{
		if (ec)
			(*callback)(ERR_OPERATION_FAILURE, transferred);
		else
			(*callback)(0, transferred);
	});
}

err_type raw_tcp_socket::recv(const mutable_buffer& buffer, size_t& transferred)
{
	transferred = socket.receive(asio::buffer(buffer.access_data(), buffer.get_size()), 0, ec);
	if (ec)
		return ERR_OPERATION_FAILURE;
	return 0;
}

void raw_tcp_socket::async_recv(const mutable_buffer& buffer, transfer_callback&& complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socket.async_receive(asio::buffer(buffer.access_data(), buffer.get_size()),
		[this, callback](const boost::system::error_code& ec, std::size_t transferred)
	{
		if (ec)
			(*callback)(ERR_OPERATION_FAILURE, transferred);
		else
			(*callback)(0, transferred);
	});
}

err_type raw_tcp_socket::close()
{
	socket.shutdown(socket.shutdown_both, ec);
	socket.close(ec);
	return 0;
}

void raw_tcp_socket::async_close(null_callback&& complete_handler)
{
	socket.shutdown(socket.shutdown_both, ec);
	socket.close(ec);
	complete_handler(0);
}

err_type raw_udp_socket::local_endpoint(endpoint& ep)
{
	try
	{
		asio::ip::udp::endpoint raw_ep = socket.local_endpoint();
		raw_ep_to_ep(raw_ep, ep);
	}
	catch (std::exception &) { return ERR_OPERATION_FAILURE; }
	return 0;
}

err_type raw_udp_socket::open()
{
	socket.open(asio::ip::udp::v4(), ec);
	if (ec)
	{
		return ERR_OPERATION_FAILURE;
	}
	socket.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), ec);
	return ec ? ERR_OPERATION_FAILURE : 0;
}

void raw_udp_socket::async_open(null_callback && complete_handler)
{
	socket.open(asio::ip::udp::v4(), ec);
	if (ec)
	{
		complete_handler(ERR_OPERATION_FAILURE);
		return;
	}
	socket.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), ec);
	complete_handler(ec ? ERR_OPERATION_FAILURE : 0);
}

err_type raw_udp_socket::bind(const endpoint& ep)
{
	const address &addr = ep.get_addr();
	asio::ip::address native_addr;
	switch (addr.get_type())
	{
		case address::V4:
		{
			socket.close(ec);
			socket.open(asio::ip::udp::v4(), ec);
			native_addr = asio::ip::address_v4(addr.v4().to_ulong());
			break;
		}
		case address::V6:
		{
			socket.close(ec);
			socket.open(asio::ip::udp::v4(), ec);
			std::array<uint8_t, address_v6::addr_size> addr_byte;
			memmove(addr_byte.data(), addr.v6().to_bytes(), address_v6::addr_size);
			native_addr = asio::ip::address_v6(addr_byte);
			break;
		}
		default:
			return ERR_UNSUPPORTED;
	}
	socket.bind(asio::ip::udp::endpoint(native_addr, ep.get_port()), ec);
	return (ec ? ERR_OPERATION_FAILURE : 0);
}

void raw_udp_socket::async_bind(const endpoint& ep, null_callback&& complete_handler)
{
	const address &addr = ep.get_addr();
	asio::ip::address native_addr;
	switch (addr.get_type())
	{
		case address::V4:
		{
			socket.close(ec);
			socket.open(asio::ip::udp::v4(), ec);
			native_addr = asio::ip::address_v4(addr.v4().to_ulong());
			break;
		}
		case address::V6:
		{
			socket.close(ec);
			socket.open(asio::ip::udp::v4(), ec);
			std::array<uint8_t, address_v6::addr_size> addr_byte;
			memmove(addr_byte.data(), addr.v6().to_bytes(), address_v6::addr_size);
			native_addr = asio::ip::address_v6(addr_byte);
			break;
		}
		default:
			complete_handler(ERR_UNSUPPORTED);
			return;
	}
	socket.bind(asio::ip::udp::endpoint(native_addr, ep.get_port()), ec);
	complete_handler(ec ? ERR_OPERATION_FAILURE : 0);
}

err_type raw_udp_socket::send_to(const endpoint& ep, const const_buffer& buffer)
{
	asio::ip::udp::endpoint native_ep;
	err_type err = to_udp_ep(ep, native_ep);
	if (err)
		return WARN_OPERATION_FAILURE;
	socket.send_to(asio::buffer(buffer.get_data(), buffer.get_size()), native_ep, 0, ec);
	return (ec ? (socket.is_open() ? WARN_OPERATION_FAILURE : ERR_OPERATION_FAILURE) : 0);
}

void raw_udp_socket::async_send_to(const endpoint& ep, const const_buffer& buffer, null_callback&& complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	async_to_udp_ep(ep, [this, buffer, callback](err_type err, const asio::ip::udp::endpoint& native_ep)
	{
		if (err)
		{
			(*callback)(-abs(err));
			return;
		}
		socket.async_send_to(asio::buffer(buffer.get_data(), buffer.get_size()),native_ep,
			[this, callback](const boost::system::error_code& ec, size_t)
		{
			if (ec)
				(*callback)(socket.is_open() ? WARN_OPERATION_FAILURE : ERR_OPERATION_FAILURE);
			else
				(*callback)(0);
		});
	});
}

err_type raw_udp_socket::recv_from(endpoint& ep, const mutable_buffer& buffer, size_t& transferred)
{
	asio::ip::udp::endpoint native_ep;
	transferred = socket.receive_from(asio::buffer(buffer.access_data(), buffer.get_size()), native_ep, 0, ec);
	if (ec)
		return (socket.is_open() ? WARN_OPERATION_FAILURE : ERR_OPERATION_FAILURE);
	raw_ep_to_ep(native_ep, ep);
	return 0;
}

void raw_udp_socket::async_recv_from(endpoint& ep, const mutable_buffer& buffer, transfer_callback&& complete_handler)
{
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	socket.async_receive_from(asio::buffer(buffer.access_data(), buffer.get_size()), recv_ep,
		[this, &ep, callback](const boost::system::error_code& ec, size_t recved)
	{
		if (ec)
		{
			(*callback)((socket.is_open() ? WARN_OPERATION_FAILURE : ERR_OPERATION_FAILURE), recved);
			return;
		}
		raw_ep_to_ep(recv_ep, ep);
		(*callback)(0, recved);
	});
}

err_type raw_udp_socket::close()
{
	socket.shutdown(socket.shutdown_both, ec);
	socket.close(ec);
	return 0;
}

void raw_udp_socket::async_close(null_callback && complete_handler)
{
	socket.shutdown(socket.shutdown_both, ec);
	socket.close(ec);
	complete_handler(0);
}

err_type raw_udp_socket::to_udp_ep(const endpoint& ep, asio::ip::udp::endpoint& result)
{
	const address &addr = ep.get_addr();
	switch (addr.get_type())
	{
		case address::V4:
		{
			result = asio::ip::udp::endpoint(asio::ip::address_v4(addr.v4().to_ulong()), ep.get_port());
			break;
		}
		case address::V6:
		{
			std::array<uint8_t, address_v6::addr_size> addr_byte;
			memmove(addr_byte.data(), addr.v6().to_bytes(), address_v6::addr_size);
			result = asio::ip::udp::endpoint(asio::ip::address_v6(addr_byte), ep.get_port());
			break;
		}
		case address::STR:
		{
			result = *resolver.resolve(asio::ip::udp::resolver::query(addr.str().data(), std::to_string(ep.get_port())), ec);
			if (ec)
				return ERR_UNRESOLVED_HOST;
			break;
		}
		default:
			return ERR_UNSUPPORTED;
	}
	return 0;
}

void raw_udp_socket::async_to_udp_ep(const endpoint& ep, std::function<void(err_type, const asio::ip::udp::endpoint&)>&& complete_handler)
{
	const address &addr = ep.get_addr();
	switch (addr.get_type())
	{
		case address::V4:
		{
			complete_handler(0, asio::ip::udp::endpoint(asio::ip::address_v4(addr.v4().to_ulong()), ep.get_port()));
			break;
		}
		case address::V6:
		{
			std::array<uint8_t, address_v6::addr_size> addr_byte;
			memmove(addr_byte.data(), addr.v6().to_bytes(), address_v6::addr_size);
			complete_handler(0, asio::ip::udp::endpoint(asio::ip::address_v6(addr_byte), ep.get_port()));
			break;
		}
		case address::STR:
		{
			auto callback = std::make_shared<std::function<void(err_type, const asio::ip::udp::endpoint&)>>(std::move(complete_handler));
			resolver.async_resolve(asio::ip::udp::resolver::query(addr.str().data(), std::to_string(ep.get_port())),
				[this, callback](const boost::system::error_code& ec, asio::ip::udp::resolver::iterator itr)
			{
				if (ec)
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

err_type raw_listener::local_endpoint(endpoint& ep)
{
	try
	{
		asio::ip::tcp::endpoint raw_ep = acceptor.local_endpoint();
		raw_ep_to_ep(raw_ep, ep);
	}
	catch (std::exception &) { return ERR_OPERATION_FAILURE; }
	return 0;
}

err_type raw_listener::bind(const endpoint& ep)
{
	const address &addr = ep.get_addr();
	asio::ip::address native_addr;
	switch (addr.get_type())
	{
		case address::V4:
			acceptor.close();
			acceptor.open(asio::ip::tcp::v4());
			native_addr = asio::ip::address_v4(addr.v4().to_ulong());
			break;
		case address::V6:
			acceptor.close();
			acceptor.open(asio::ip::tcp::v6());
			std::array<uint8_t, address_v6::addr_size> addr_byte;
			memmove(addr_byte.data(), addr.v6().to_bytes(), address_v6::addr_size);
			native_addr = asio::ip::address_v6(addr_byte);
			break;
		default:
			return ERR_UNSUPPORTED;
	}
	acceptor.bind(asio::ip::tcp::endpoint(native_addr, ep.get_port()), ec);
	return (ec ? ERR_OPERATION_FAILURE : 0);
}

void raw_listener::async_bind(const endpoint& ep, null_callback&& complete_handler)
{
	complete_handler(bind(ep));
}

err_type raw_listener::listen()
{
	acceptor.listen(asio::socket_base::max_connections, ec);
	return (ec ? ERR_OPERATION_FAILURE : 0);
}

void raw_listener::async_listen(null_callback&& complete_handler)
{
	acceptor.listen(asio::socket_base::max_connections, ec);
	complete_handler(ec ? ERR_OPERATION_FAILURE : 0);
}

prx_tcp_socket_base* raw_listener::accept()
{
	asio::ip::tcp::socket socket(iosrv);
	acceptor.accept(socket, ec);
	return (ec ? nullptr : new raw_tcp_socket(std::move(socket)));
}

void raw_listener::async_accept(accept_callback&& complete_handler)
{
	auto socket = std::make_shared<asio::ip::tcp::socket>(iosrv);
	auto callback = std::make_shared<accept_callback>(std::move(complete_handler));
	acceptor.async_accept(*socket, [this, socket, callback](const boost::system::error_code& ec) {
		if (ec)
			(*callback)(ERR_OPERATION_FAILURE, nullptr);
		else
			(*callback)(0, new raw_tcp_socket(std::move(*socket)));
	});
}

