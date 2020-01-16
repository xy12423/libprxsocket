#include "stdafx.h"
#include "address.h"

std::string address_v4::to_string() const
{
	std::string ret(std::to_string(data_.u8[0]));
	for (int i = 1; i < 4; i++)
	{
		ret.push_back('.');
		ret.append(std::to_string(data_.u8[i]));
	}
	return ret;
}

bool address_v6::is_any() const
{
	for (int i = 0; i < sizeof(data_); ++i)
		if (data_.u8[i] != 0)
			return false;
	return true;
}

std::string address_v6::to_string() const
{
	char buf[10];
	std::string ret;
	for (const uint8_t *p = data_.u8; p < data_.u8 + 16; p += 2)
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
	switch (type_)
	{
	case V4:
		return v4_.is_any();
	case STR:
		return str_.is_any();
	case V6:
		return v6_.is_any();
	default:
		return false;
	}
}

size_t address::from_socks5(const char *data)
{
	switch (*data)
	{
		case 1:
		case 3:
		case 4:
			type_ = (addr_type)(*data);
			break;
		default:
			type_ = UNDEFINED;
			return 0;
	}
	++data;

	size_t size = 0;
	switch (type_)
	{
		case V4:
		{
			v4_ = address_v4(data);
			size = 1 + address_v4::addr_size;
			break;
		}
		case STR:
		{
			size = (uint8_t)(*data);
			++data;
			str_ = address_str(data, size);
			size = 2 + size;
			break;
		}
		case V6:
		{
			v6_ = address_v6(data);
			size = 1 + address_v6::addr_size;
			break;
		}
	}
	return size;
}

void address::to_socks5(std::string &ret) const
{
	if (type_ == UNDEFINED)
		return;
	ret.push_back(type_);
	switch (type_)
	{
		case V4:
		{
			ret.append(v4_.data(), v4_.addr_size);
			break;
		}
		case STR:
		{
			const std::string &addr = str_.data();
			assert(addr.size() < 0x100);
			uint8_t size = (uint8_t)std::min(addr.size(), (size_t)std::numeric_limits<uint8_t>::max());
			ret.push_back(size);
			ret.append(addr, 0, size);
			break;
		}
		case V6:
		{
			ret.append(v6_.data(), v6_.addr_size);
			break;
		}
	}
}

std::string address::to_string() const
{
	switch (type_)
	{
		case V4:
			return v4_.to_string();
		case STR:
			return str_.to_string();
		case V6:
			return v6_.to_string();
	}
	return std::string();
}

bool address::operator==(const address &b) const
{
	if (type_ != b.type_)
		return false;
	switch (type_)
	{
	case V4:
		return v4_ == b.v4_;
	case STR:
		return str_ == b.str_;
	case V6:
		return v6_ == b.v6_;
	default:
		return false;
	}
}

bool address::operator!=(const address &b) const
{
	if (type_ != b.type_)
		return true;
	switch (type_)
	{
	case V4:
		return v4_ != b.v4_;
	case STR:
		return str_ != b.str_;
	case V6:
		return v6_ != b.v6_;
	default:
		return true;
	}
}
