#include "stdafx.h"
#include "http_helper.h"

static void ltrim(std::string &str)
{
	std::string::iterator itr = str.begin(), itr_end = str.end();
	for (; itr != itr_end; ++itr)
		if (!isspace((unsigned char)*itr))
			break;
	str.erase(str.begin(), itr);
}

static void rtrim(std::string &str)
{
	while (!str.empty() && isspace((unsigned char)str.back()))
		str.pop_back();
}

static void trim(std::string &str)
{
	ltrim(str);
	rtrim(str);
}

std::string http_header::to_string() const
{
	std::string str;
	for (const auto &p : headers)
	{
		str.append(p.first);
		str.append(": ", 2);
		str.append(p.second);
		str.push_back('\r');
		str.push_back('\n');
	}
	return str;
}

bool parse_http_request(http_header &dst, const std::string &data)
{
	size_t pos = data.find(' ');
	if (pos == std::string::npos)
		return false;
	dst.append("@ReqMethod", data.substr(0, pos));
	size_t pos2 = data.find(' ', pos + 1);
	if (pos2 == std::string::npos)
		return false;
	dst.append("@ReqTarget", data.substr(pos + 1, pos2 - pos - 1));
	if (data.substr(pos2 + 1) != "HTTP/1.1")
		return false;
	return true;
}

bool parse_http_status(http_header &dst, const std::string &data)
{
	constexpr char str[] = "HTTP/1.1";
	constexpr size_t str_size = sizeof(str) - 1;
	for (int i = 0; i < str_size; i++)
		if (data[i] != str[i])
			return false;
	dst.append("@Status", data.substr(str_size + 1, 3));
	return true;
}

bool parse_http_header(http_header &dst, size_t &size_read, const char *src, size_t src_size)
{
	size_read = 0;
	const char *itr = src, *itr_end = src + src_size;
	std::string buf, val;
	bool first_line_parsed = (dst.count("@Type") > 0);

	for (; itr != itr_end; ++itr)
	{
		if (*itr == '\n')
		{
			size_read += buf.size() + 1;
			trim(buf);
			if (buf.empty())
				return true;

			if (!first_line_parsed)
			{
				if (parse_http_status(dst, buf))
				{
					first_line_parsed = true;
					dst.append("@Type", "Status");
					buf.clear();
					continue;
				}
				else if (parse_http_request(dst, buf))
				{
					first_line_parsed = true;
					dst.append("@Type", "Request");
					buf.clear();
					continue;
				}
				else
					return true;
			}

			size_t pos = buf.find(':');
			if (pos == std::string::npos)
				return false;
			val.assign(buf, pos + 1, std::string::npos);
			buf.erase(pos);
			rtrim(buf);
			ltrim(val);
			dst.append(std::move(buf), std::move(val));
			buf.clear();
		}
		else
			buf.push_back(*itr);
	}
	return false;
}
