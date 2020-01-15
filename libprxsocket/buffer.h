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

class mutable_buffer :public const_buffer
{
public:
	mutable_buffer(char *data, size_t size) :const_buffer(data, size) {}

	char *access_data() const { return const_cast<char*>(data_); }
};

#endif
