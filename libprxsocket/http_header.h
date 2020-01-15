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

	using container_type = std::vector<std::pair<std::string, std::string>>;
	using index_container_type = std::vector<size_t>;
	using hash_table_type = std::unordered_map<std::string, index_container_type>;

	class iterator
	{
	public:
		using value_type = typename container_type::iterator::value_type;
		using difference_type = typename container_type::iterator::difference_type;
		using pointer = typename container_type::iterator::pointer;
		using reference = value_type &;

		iterator(container_type &base_container, const index_container_type::iterator &base_iterator) :base_container_(&base_container), base_iterator_(base_iterator) {}

		reference operator*() { return base_container_->at(*base_iterator_); }
		pointer operator->() { return &base_container_->at(*base_iterator_); }

		iterator &operator++() { ++base_iterator_; return *this; }
		iterator operator++(int) { iterator ret = *this; ++ret; return ret; }
		iterator &operator--() { --base_iterator_; return *this; }
		iterator operator--(int) { iterator ret = *this; --ret; return ret; }

		bool operator==(const iterator &rhs) const { assert(base_container_ == rhs.base_container_); return base_iterator_ == rhs.base_iterator_; }
		bool operator!=(const iterator &rhs) const { return !(*this == rhs); }
	private:
		container_type *base_container_;
		index_container_type::iterator base_iterator_;
	};

	template <typename T1, typename T2> void append(T1 &&name, T2 &&value)
	{
		header_names[name].push_back(headers.size());
		headers.emplace_back(std::forward<T1>(name), std::forward<T2>(value));
	}
	std::pair<iterator, iterator> equal_range(const std::string &name)
	{
		return std::make_pair<iterator, iterator>(
			iterator(headers, header_names.at(name).begin()),
			iterator(headers, header_names.at(name).end())
			);
	}
	std::string &at(const std::string &name)
	{
		index_container_type &indexs = header_names.at(name);
		if (indexs.size() != 1)
			throw std::out_of_range("http_header::at only allows to be used with unique header name");
		return headers.at(indexs.front()).second;
	}
	size_t count(const std::string &name) const
	{
		return header_names.count(name) > 0 ? header_names.at(name).size() : 0;
	}

	container_type::iterator begin() { return headers.begin(); }
	container_type::const_iterator begin() const { return headers.begin(); }
	container_type::const_iterator cbegin() const { return headers.cbegin(); }
	container_type::iterator end() { return headers.end(); }
	container_type::const_iterator end() const { return headers.end(); }
	container_type::const_iterator cend() const { return headers.cend(); }

	bool parse(const char *src, size_t src_size, size_t &size_read);
	std::string to_string() const;
private:
	bool parse_http_request(const std::string &line);
	bool parse_http_status(const std::string &line);

	container_type headers;
	hash_table_type header_names;
};

#endif
