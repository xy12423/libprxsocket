#include "stdafx.h"
#include "address.h"

std::string address_v4::to_string() const
{
	std::string ret(std::to_string(m_data.u8[0]));
	for (int i = 1; i < 4; i++)
	{
		ret.push_back('.');
		ret.append(std::to_string(m_data.u8[i]));
	}
	return ret;
}

bool address_v6::is_any() const
{
	for (int i = 0; i < sizeof(m_data); ++i)
		if (m_data.u8[i] != 0)
			return false;
	return true;
}

std::string address_v6::to_string() const
{
	char buf[10];
	std::string ret;
	for (const uint8_t *p = m_data.u8; p < m_data.u8 + 16; p += 2)
	{
		unsigned int n = (*p << 8ul) | *(p + 1);
		sprintf(buf, "%04x", n);
		ret.append(buf);
		ret.push_back(':');
	}
	ret.pop_back();
	return ret;
}

bool address::is_any() const
{
	switch (type)
	{
	case V4:
		return m_v4.is_any();
	case STR:
		return m_str.is_any();
	case V6:
		return m_v6.is_any();
	default:
		return false;
	}
}

size_t address::from_socks5(const char* data)
{
	switch (*data)
	{
		case 1:
		case 3:
		case 4:
			type = (addr_type)(*data);
			break;
		default:
			type = UNDEFINED;
			return 0;
	}
	++data;

	size_t size = 0;
	switch (type)
	{
		case V4:
		{
			m_v4 = address_v4(data);
			size = 1 + address_v4::addr_size;
			break;
		}
		case STR:
		{
			size = (unsigned char)(*data);
			++data;
			m_str = address_str(data, size);
			size = 2 + size;
			break;
		}
		case V6:
		{
			m_v6 = address_v6(data);
			size = 1 + address_v6::addr_size;
			break;
		}
	}
	return size;
}


void address::to_socks5(std::string& ret) const
{
	if (type == UNDEFINED)
		return;
	ret.push_back(type);
	switch (type)
	{
		case V4:
		{
			ret.append(m_v4.data(), m_v4.addr_size);
			break;
		}
		case STR:
		{
			const std::string& addr = m_str.data();
			assert(addr.size() < std::numeric_limits<unsigned char>::max());
			uint8_t size = (uint8_t)std::min(addr.size(), (size_t)std::numeric_limits<uint8_t>::max());
			ret.push_back(size);
			ret.append(addr, 0, size);
			break;
		}
		case V6:
		{
			ret.append(m_v6.data(), m_v6.addr_size);
			break;
		}
	}
}

std::string address::to_string() const
{
	switch (type)
	{
		case V4:
			return m_v4.to_string();
		case STR:
			return m_str.to_string();
		case V6:
			return m_v6.to_string();
	}
	return std::string();
}

bool address::operator==(const address& b) const
{
	if (type != b.type)
		return false;
	switch (type)
	{
	case V4:
		return m_v4 == b.m_v4;
	case STR:
		return m_str == b.m_str;
	case V6:
		return m_v6 == b.m_v6;
	default:
		return false;
	}
}

bool address::operator!=(const address & b) const
{
	if (type != b.type)
		return true;
	switch (type)
	{
	case V4:
		return m_v4 != b.m_v4;
	case STR:
		return m_str != b.m_str;
	case V6:
		return m_v6 != b.m_v6;
	default:
		return true;
	}
}
