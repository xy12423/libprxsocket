#ifndef _H_ADDRESS
#define _H_ADDRESS

#ifndef _LIBPRXSOCKET_BUILD
#include <cstdint>
#include <cstring>

#include <string>
#include <utility>

#include <boost/endian/conversion.hpp>
#endif

class address_v4
{
public:
	static constexpr size_t addr_size = 4;
private:
	union addr_v4_data
	{
		addr_v4_data() :u32(0) {}
		addr_v4_data(uint32_t _u32) :u32(_u32) {}

		char c8[addr_size];
		uint8_t u8[addr_size];
		uint32_t u32;
	} m_data;
public:
	address_v4() = default;
	address_v4(uint32_t host_u32) :m_data(boost::endian::native_to_big(host_u32)) {}
	address_v4(const char* _data) { memmove(m_data.c8, _data, addr_size); }

	const char* data() const { return m_data.c8; }
	const uint8_t* to_bytes() const { return m_data.u8; }
	uint32_t to_ulong() const { return boost::endian::big_to_native(m_data.u32); }
	
	bool is_any() const { return m_data.u32 == 0ul; }

	std::string to_string() const;

	bool operator==(const address_v4& b) const { return m_data.u32 == b.m_data.u32; }
	bool operator!=(const address_v4& b) const { return m_data.u32 != b.m_data.u32; }
};

class address_v6
{
public:
	static constexpr size_t addr_size = 16;
private:
	union addr_v6_data
	{
		addr_v6_data() { memset(u8, 0, sizeof(u8)); }

		char c8[addr_size];
		uint8_t u8[addr_size];
	} m_data;
public:
	address_v6() = default;
	address_v6(const char* _data) { memmove(m_data.c8, _data, addr_size); }
	address_v6(uint8_t* _data) { memmove(m_data.u8, _data, addr_size); }

	const char* data() const { return m_data.c8; }
	const uint8_t* to_bytes() const { return m_data.u8; }

	bool is_any() const;

	std::string to_string() const;

	bool operator==(const address_v6& b) const { return memcmp(m_data.u8, b.m_data.u8, sizeof(addr_v6_data)) == 0; }
	bool operator!=(const address_v6& b) const { return memcmp(m_data.u8, b.m_data.u8, sizeof(addr_v6_data)) != 0; }
};

class address_str
{
public:
	template <typename... T> address_str(T&&... addr) :m_data(std::forward<T>(addr)...) {}

	const std::string& data() const { return m_data; }

	bool is_any() const { return false; }

	std::string to_string() const { return m_data; }

	bool operator==(const address_str& b) const { return m_data == b.m_data; }
	bool operator!=(const address_str& b) const { return m_data != b.m_data; }
private:
	std::string m_data;
};

class address
{
public:
	enum addr_type { UNDEFINED = 0, V4 = 1, STR = 3, V6 = 4 };

	address() :type(UNDEFINED) {}
	address(uint32_t addr) : type(V4), m_v4(addr) {}
	address(const std::string& addr) : type(STR), m_str(addr) {}
	address(std::string&& addr) : type(STR), m_str(std::move(addr)) {}
	address(const char* addr) : type(STR), m_str(addr) {}

	address(const address_v4& addr) : type(V4), m_v4(addr) {}
	address(address_v4&& addr) : type(V4), m_v4(std::move(addr)) {}
	address(const address_str& addr) : type(STR), m_str(addr) {}
	address(address_str&& addr) : type(STR), m_str(std::move(addr)) {}
	address(const address_v6& addr) : type(V6), m_v6(addr) {}
	address(address_v6&& addr) : type(V6), m_v6(std::move(addr)) {}

	addr_type get_type() const { return type; }
	const address_v4& v4() const { return m_v4; }
	const address_v6& v6() const { return m_v6; }
	const address_str& str() const { return m_str; }

	bool is_any() const;

	size_t from_socks5(const char* data);
	void to_socks5(std::string& ret) const;
	std::string to_string() const;

	bool operator==(const address& b) const;
	bool operator!=(const address& b) const;
private:
	addr_type type;

	address_v4 m_v4;
	address_v6 m_v6;
	address_str m_str;
};

#endif
