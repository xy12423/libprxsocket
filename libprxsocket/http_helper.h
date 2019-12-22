#ifndef _H_HTTP_HELPER
#define _H_HTTP_HELPER

#ifndef _LIBPRXSOCKET_BUILD
#include <string>
#include <vector>
#include <unordered_map>
#endif

class http_header
{
	typedef std::vector<std::pair<std::string, std::string>> container_type;
	typedef std::unordered_map<std::string, size_t> hash_table_type;
public:
	template <typename T1, typename T2> void append(T1 &&name, T2 &&value)
	{
		header_names.emplace(name, headers.size());
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

	std::string to_string() const;
private:
	container_type headers;
	hash_table_type header_names;
};

bool parse_http_header(http_header &dst, size_t &size_read, const char *src, size_t src_size);

#endif
