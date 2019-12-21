#ifndef _H_BUFFER
#define _H_BUFFER

#ifndef _LIBPRXSOCKET_BUILD
#include <string>
#endif

class const_buffer
{
public:
	const_buffer(const char *_data, size_t _size) :data(_data), size(_size) {}
	const_buffer(const std::string &_data) :data(_data.data()), size(_data.size()) {}

	const char *get_data() const { return data; }
	size_t get_size() const { return size; }
protected:
	const char *data;
	size_t size;
};

class mutable_buffer :public const_buffer
{
public:
	mutable_buffer(char *_data, size_t _size) :const_buffer(_data, _size) {}

	char *access_data() const { return const_cast<char*>(data); }
};

#endif
