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
#include "address.h"

using namespace prxsocket;

namespace
{

	constexpr bool uri_char_is_unreserved(char ch)
	{
		switch (ch)
		{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':
		case '-':
		case '.':
		case '_':
		case '~':
			return true;
		}
		return false;
	}

	constexpr bool uri_char_is_sub_delims(char ch)
	{
		switch (ch)
		{
		case '!':
		case '$':
		case '&':
		case '\'':
		case '(':
		case ')':
		case '*':
		case '+':
		case ',':
		case ';':
		case '=':
			return true;
		}
		return false;
	}

	constexpr char hex_digits[] = "0123456789ABCDEF";

}

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
	for (size_t i = 0; i < sizeof(data_); ++i)
		if (data_.u8[i] != 0)
			return false;
	return true;
}

std::string address_v6::to_string() const
{
	char buf[10];
	std::string ret;

	int l = -1, r = -1;
	for (int i = 0; i < 8; ++i)
	{
		if (data_.u8[i * 2] == 0 && data_.u8[i * 2 + 1] == 0)
		{
			int l_new = i;
			for (++i; i < 8; ++i)
				if (data_.u8[i * 2] != 0 || data_.u8[i * 2 + 1] != 0)
					break;
			int r_new = i - 1;
			if (r_new - l_new > r - l)
			{
				l = l_new;
				r = r_new;
			}
		}
	}

	if (l == 0)
		ret.push_back(':');
	for (int i = 0; i < 8; ++i)
	{
		if (i == l)
		{
			while (i != r)
				++i;
		}
		else
		{
			unsigned int n = ((unsigned int)data_.u8[i * 2] << 8) | data_.u8[i * 2 + 1];
			sprintf(buf, "%x", n);
			ret.append(buf);
		}
		ret.push_back(':');
	}
	if (r != 7)
		ret.pop_back();
	return ret;
}

std::string address_v6::to_uri_string() const
{
	char buf[10];
	std::string ret;

	int l = -1, r = -1;
	for (int i = 0; i < 8; ++i)
	{
		if (data_.u8[i * 2] == 0 && data_.u8[i * 2 + 1] == 0)
		{
			int l_new = i;
			for (++i; i < 8; ++i)
				if (data_.u8[i * 2] != 0 || data_.u8[i * 2 + 1] != 0)
					break;
			int r_new = i - 1;
			if (r_new - l_new > r - l)
			{
				l = l_new;
				r = r_new;
			}
		}
	}

	ret.push_back('[');
	if (l == 0)
		ret.push_back(':');
	for (int i = 0; i < 8; ++i)
	{
		if (i == l)
		{
			while (i != r)
				++i;
		}
		else
		{
			unsigned int n = ((unsigned int)data_.u8[i * 2] << 8) | data_.u8[i * 2 + 1];
			sprintf(buf, "%x", n);
			ret.append(buf);
		}
		ret.push_back(':');
	}
	if (r != 7)
		ret.back() = ']';
	else
		ret.push_back(']');
	return ret;
}

std::string address_str::to_uri_string() const
{
	char buf[3] = { '%' };
	std::string ret;
	ret.reserve(data_.size());
	for (size_t i = 0; i < data_.size(); ++i)
	{
		if (uri_char_is_unreserved(data_[i]) || uri_char_is_sub_delims(data_[i]))
		{
			ret.push_back(data_[i]);
		}
		else
		{
			buf[1] = hex_digits[(uint8_t)data_[i] >> 4];
			buf[2] = hex_digits[(uint8_t)data_[i] & 0x0F];
			ret.append(buf, 3);
		}
	}
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
		default:
			return std::string();
	}
}

std::string address::to_uri_string() const
{
	switch (type_)
	{
	case V4:
		return v4_.to_uri_string();
	case STR:
		return str_.to_uri_string();
	case V6:
		return v6_.to_uri_string();
	default:
		return std::string();
	}
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
