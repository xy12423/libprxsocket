#ifndef _H_HTTP_HELPER
#define _H_HTTP_HELPER

#ifndef _LIBPRXSOCKET_BUILD
#include <string>
#include <vector>
#include <unordered_map>
#endif

class http_header
{
	typedef std::vector<std::pair<std::string, std::string>> Container;
	typedef std::unordered_map<std::string, size_t> HashTable;
public:
	template <typename T1, typename T2> void append(T1 &&name, T2 &&value)
	{
		header_names.emplace(name, headers.size());
		headers.emplace_back(std::forward<T1>(name), std::forward<T2>(value));
	}
	const std::string &at(const std::string &name) const { return headers.at(header_names.at(name)).second; }
	std::string &at(const std::string &name) { return headers.at(header_names.at(name)).second; }
	int count(const std::string &name) const { return header_names.count(name); }

	Container::iterator begin() { return headers.begin(); }
	Container::const_iterator begin() const { return headers.begin(); }
	Container::const_iterator cbegin() const { return headers.cbegin(); }
	Container::iterator end() { return headers.end(); }
	Container::const_iterator end() const { return headers.end(); }
	Container::const_iterator cend() const { return headers.cend(); }
private:
	Container headers;
	HashTable header_names;
};

void ltrim(std::string &str);
void rtrim(std::string &str);
void trim(std::string &str);
void make_http_header(std::string &dst, const http_header &src);
bool parse_http_header(http_header &dst, size_t &size_read, const char *src, size_t src_size);

#endif
