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
#include "http_header.h"

using namespace prxsocket::http;

constexpr char http_header::SPECIAL_NAME_IDENTIFIER;
constexpr const char *http_header::NAME_START_LINE_TYPE, *http_header::START_LINE_TYPE_REQUEST, *http_header::START_LINE_TYPE_STATUS;
constexpr const char *http_header::NAME_REQUEST_METHOD, *http_header::NAME_REQUEST_TARGET;
constexpr const char *http_header::NAME_STATUS_CODE, *http_header::NAME_STATUS_REASON_PHRASE;

namespace
{

	void ltrim(std::string &str)
	{
		std::string::iterator itr = str.begin(), itr_end = str.end();
		for (; itr != itr_end; ++itr)
			if (!isspace((unsigned char)*itr))
				break;
		str.erase(str.begin(), itr);
	}

	void rtrim(std::string &str)
	{
		while (!str.empty() && isspace((unsigned char)str.back()))
			str.pop_back();
	}

	void trim(std::string &str)
	{
		ltrim(str);
		rtrim(str);
	}

	std::string ltrimv(const std::string &str)
	{
		std::string::const_iterator itr = str.begin(), itr_end = str.end();
		for (; itr != itr_end; ++itr)
			if (!isspace((unsigned char)*itr))
				break;
		return std::string(itr, itr_end);
	}

	std::string rtrimv(const std::string &str)
	{
		std::string::const_reverse_iterator ritr = str.rbegin(), ritr_end = str.rend();
		for (; ritr != ritr_end; ++ritr)
			if (!isspace((unsigned char)*ritr))
				break;
		return std::string(str.begin(), ritr.base());
	}

	std::string trimv(const std::string &str)
	{
		std::string::const_iterator itr = str.begin(), itr_end = str.end();
		for (; itr != itr_end; ++itr)
			if (!isspace((unsigned char)*itr))
				break;
		std::string::const_reverse_iterator ritr = str.rbegin(), ritr_end(itr);
		for (; ritr != ritr_end; ++ritr)
			if (!isspace((unsigned char)*ritr))
				break;
		return std::string(itr, ritr.base());
	}

}

std::string http_header::to_string() const
{
	std::string str;
	for (const auto &p : headers)
	{
		if (p.first.front() == SPECIAL_NAME_IDENTIFIER)
			continue;
		str.append(p.first);
		str.append(": ", 2);
		str.append(p.second);
		str.push_back('\r');
		str.push_back('\n');
	}
	return str;
}

bool http_header::parse_http_request(const std::string &line)
{
	size_t pos = line.find(' ');
	if (pos == std::string::npos)
		return false;
	size_t pos2 = line.find(' ', pos + 1);
	if (pos2 == std::string::npos)
		return false;
	if (line.compare(pos2 + 1, line.size() - (pos2 + 1), "HTTP/1.1") != 0)
		return false;

	append(NAME_REQUEST_METHOD, line.substr(0, pos));
	append(NAME_REQUEST_TARGET, line.substr(pos + 1, pos2 - pos - 1));
	return true;
}

bool http_header::parse_http_status(const std::string &line)
{
	constexpr char str[] = "HTTP/1.1";
	constexpr size_t str_size = sizeof(str) - 1;
	for (size_t i = 0; i < str_size; i++)
		if (line[i] != str[i])
			return false;

	append(NAME_STATUS_CODE, line.substr(str_size + 1, 3));
	append(NAME_STATUS_REASON_PHRASE, line.substr(str_size + 5));
	return true;
}

bool http_header::parse(const char *src, size_t src_size, size_t &size_read)
{
	size_read = 0;
	const char *itr = src, *itr_end = src + src_size;
	const char *itr_buf = itr;
	std::string &buf = parse_buffer, val;
	bool first_line_parsed = (count(NAME_START_LINE_TYPE) > 0);

	for (; itr != itr_end; ++itr)
	{
		if (*itr == '\n')
		{
			if (itr < itr_buf)
			{
				assert(false);
				throw std::out_of_range("Buffer overflow in http_header::parse");
			}
			buf.append(itr_buf, itr - itr_buf);
			itr_buf = itr + 1;
			trim(buf);
			if (buf.empty())
			{
				size_read = itr + 1 - src;
				return true;
			}

			if (!first_line_parsed)
			{
				if (parse_http_status(buf))
				{
					first_line_parsed = true;
					append(NAME_START_LINE_TYPE, START_LINE_TYPE_STATUS);
					buf.clear();
					continue;
				}
				else if (parse_http_request(buf))
				{
					first_line_parsed = true;
					append(NAME_START_LINE_TYPE, START_LINE_TYPE_REQUEST);
					buf.clear();
					continue;
				}
				else
					throw std::invalid_argument("Invalid first line of HTTP header");
			}

			if (buf.front() == SPECIAL_NAME_IDENTIFIER)
				throw std::invalid_argument("Invalid character in HTTP header");
			size_t pos = buf.find(':');
			if (pos == std::string::npos)
				throw std::invalid_argument("HTTP header field without value");
			val.assign(buf, pos + 1, std::string::npos);
			buf.erase(pos);
			rtrim(buf);
			ltrim(val);
			append(std::move(buf), std::move(val));
			buf.clear();
		}
	}
	size_read = itr - src;
	return false;
}
