#ifndef _H_HTTP_HELPER
#define _H_HTTP_HELPER

#ifndef _LIBPRXSOCKET_BUILD
#include <string>
#include <vector>
#include <unordered_map>
#endif

class http_header
{
public:
	static constexpr char SPECIAL_NAME_IDENTIFIER = '@';
	static constexpr const char *NAME_START_LINE_TYPE = "@Type", *START_LINE_TYPE_REQUEST = "Request", *START_LINE_TYPE_STATUS = "Status";
	static constexpr const char *NAME_REQUEST_METHOD = "@RequestMethod", *NAME_REQUEST_TARGET = "@RequestTarget";
	static constexpr const char *NAME_STATUS_CODE = "@StatusCode", *NAME_STATUS_REASON_PHRASE = "@StatusReason";

	typedef std::vector<std::pair<std::string, std::string>> container_type;
	typedef std::unordered_map<std::string, size_t> hash_table_type;

	template <typename T1, typename T2> void append(T1 &&name, T2 &&value)
	{
		if (header_names.count(name) == 0)
		{
			header_names.emplace(name, headers.size());
		}
		else
		{
			size_t &item_index = header_names.at(name);
			assert(headers.at(item_index).first == name);
			for (auto &p : header_names)
				if (p.second > item_index)
					--p.second;
			headers.erase(headers.begin() + item_index);
			item_index = headers.size();
		}
		headers.emplace_back(std::forward<T1>(name), std::forward<T2>(value));
	}
	const std::string &at(const std::string &name) const { return headers.at(header_names.at(name)).second; }
	std::string &at(const std::string &name) { return headers.at(header_names.at(name)).second; }
	size_t count(const std::string &name) const { return header_names.count(name); }

	container_type::iterator begin() { return headers.begin(); }
	container_type::const_iterator begin() const { return headers.begin(); }
	container_type::const_iterator cbegin() const { return headers.cbegin(); }
	container_type::iterator end() { return headers.end(); }
	container_type::const_iterator end() const { return headers.end(); }
	container_type::const_iterator cend() const { return headers.cend(); }

	bool parse(size_t &size_read, const char *src, size_t src_size);
	std::string to_string() const;
private:
	bool parse_http_request(const std::string &line);
	bool parse_http_status(const std::string &line);

	container_type headers;
	hash_table_type header_names;
};

#endif
