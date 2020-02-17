#ifndef LIBPRXSOCKET_H_BUFFER
#define LIBPRXSOCKET_H_BUFFER

#ifndef _LIBPRXSOCKET_BUILD
#include <string>
#endif

class const_buffer
{
public:
	const_buffer(const char *data, size_t size) :data_(data), size_(size) {}
	const_buffer(const std::string &data) :data_(data.data()), size_(data.size()) {}

	const char *data() const { return data_; }
	size_t size() const { return size_; }
protected:
	const char *data_;
	size_t size_;
};

class mutable_buffer
{
public:
	mutable_buffer(char *data, size_t size) :data_(data), size_(size) {}

	char *data() const { return data_; }
	size_t size() const { return size_; }
protected:
	char *data_;
	size_t size_;
};

template <typename T, typename Container = std::deque<T>>
class buffer_sequence
{
public:
	using value_type = T;
	using container_type = Container;
	using const_iterator = typename Container::const_iterator;

	size_t size_total() const { return size_total_; }

	const value_type &front() const { return list_.front(); }
	const value_type &back() const { return list_.back(); }
	const_iterator begin() const { return list_.begin(); }
	const_iterator end() const { return list_.end(); }

	void push_front(const value_type &item) { list_.push_front(item); size_total_ += item.size(); }
	void push_back(const value_type &item) { list_.push_back(item); size_total_ += item.size(); }
	void pop_front() { size_total_ -= list_.front().size(); list_.pop_front(); }
	void pop_back() { size_total_ -= list_.back().size(); list_.pop_back(); }
	void consume(size_t size)
	{
		if (size > size_total_)
			size = size_total_;
		while (size > 0)
		{
			value_type &next = list_.front();
			if (size >= next.size())
			{
				size -= next.size();
				list_.pop_front();
			}
			else
			{
				next = value_type(next.data() + size, next.size() - size);
				size = 0;
			}
		}
		size_total_ -= size;
	}
private:
	Container list_;
	size_t size_total_;
};
using const_buffer_sequence = buffer_sequence<const_buffer>;
using mutable_buffer_sequence = buffer_sequence<mutable_buffer>;

#endif
