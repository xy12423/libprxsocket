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

#ifndef LIBPRXSOCKET_H_ADDRESS
#define LIBPRXSOCKET_H_ADDRESS

#ifndef _LIBPRXSOCKET_BUILD
#include <cstdint>
#include <cstring>

#include <string>
#include <utility>

#include <boost/endian/conversion.hpp>
#endif

namespace prxsocket
{

	class address_v4
	{
	public:
		static constexpr size_t ADDR_SIZE = 4;
	private:
		union addr_v4_data
		{
			addr_v4_data() :u32(0) {}
			addr_v4_data(uint32_t _u32) :u32(_u32) {}

			char c8[ADDR_SIZE];
			uint8_t u8[ADDR_SIZE];
			uint32_t u32;
		} data_;
	public:
		address_v4() = default;
		address_v4(uint32_t host_u32) :data_(boost::endian::native_to_big(host_u32)) {}
		address_v4(const char *data) { memmove(data_.c8, data, ADDR_SIZE); }

		const char *data() const { return data_.c8; }
		const uint8_t *to_bytes() const { return data_.u8; }
		uint32_t to_ulong() const { return boost::endian::big_to_native(data_.u32); }

		bool is_any() const { return data_.u32 == 0ul; }

		std::string to_string() const;
		std::string to_uri_string() const { return to_string(); }

		bool operator==(const address_v4 &b) const { return data_.u32 == b.data_.u32; }
		bool operator!=(const address_v4 &b) const { return data_.u32 != b.data_.u32; }
	};

	class address_v6
	{
	public:
		static constexpr size_t ADDR_SIZE = 16;
	private:
		union addr_v6_data
		{
			addr_v6_data() :u8{} {}

			char c8[ADDR_SIZE];
			uint8_t u8[ADDR_SIZE];
		} data_;
	public:
		address_v6() = default;
		address_v6(const char *data) { memmove(data_.c8, data, ADDR_SIZE); }
		address_v6(uint8_t *data) { memmove(data_.u8, data, ADDR_SIZE); }

		const char *data() const { return data_.c8; }
		const uint8_t *to_bytes() const { return data_.u8; }

		bool is_any() const;

		std::string to_string() const;
		std::string to_uri_string() const;

		bool operator==(const address_v6 &b) const { return memcmp(data_.u8, b.data_.u8, sizeof(addr_v6_data)) == 0; }
		bool operator!=(const address_v6 &b) const { return memcmp(data_.u8, b.data_.u8, sizeof(addr_v6_data)) != 0; }
	};

	class address_str
	{
	public:
		template <typename... T> address_str(T &&...addr) :data_(std::forward<T>(addr)...) {}

		const std::string &data() const { return data_; }

		bool is_any() const { return false; }

		std::string to_string() const { return data_; }
		std::string to_uri_string() const;

		bool operator==(const address_str &b) const { return data_ == b.data_; }
		bool operator!=(const address_str &b) const { return data_ != b.data_; }
	private:
		std::string data_;
	};

	class address
	{
	public:
		enum addr_type { UNDEFINED = 0, V4 = 1, STR = 3, V6 = 4 };

		address() :type_(UNDEFINED) {}
		address(uint32_t addr) : type_(V4), v4_(addr) {}
		address(const std::string &addr) : type_(STR), str_(addr) {}
		address(std::string &&addr) : type_(STR), str_(std::move(addr)) {}
		address(const char *addr) : type_(STR), str_(addr) {}

		address(const address_v4 &addr) : type_(V4), v4_(addr) {}
		address(address_v4 &&addr) : type_(V4), v4_(std::move(addr)) {}
		address(const address_str &addr) : type_(STR), str_(addr) {}
		address(address_str &&addr) : type_(STR), str_(std::move(addr)) {}
		address(const address_v6 &addr) : type_(V6), v6_(addr) {}
		address(address_v6 &&addr) : type_(V6), v6_(std::move(addr)) {}

		addr_type type() const { return type_; }
		const address_v4 &v4() const { return v4_; }
		const address_v6 &v6() const { return v6_; }
		const address_str &str() const { return str_; }

		bool is_any() const;

		std::string to_string() const;
		std::string to_uri_string() const;

		bool operator==(const address &b) const;
		bool operator!=(const address &b) const;
	private:
		addr_type type_;

		address_v4 v4_;
		address_v6 v6_;
		address_str str_;
	};

}

#endif
