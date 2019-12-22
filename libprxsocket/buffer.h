#ifndef _H_BUFFER
#define _H_BUFFER

#ifndef _LIBPRXSOCKET_BUILD
#include <string>
#endif

class const_buffer
{
public:
	const_buffer(const char *data, size_t size) :m_data(data), m_size(size) {}
	const_buffer(const std::string &data) :m_data(data.data()), m_size(data.size()) {}

	const char *data() const { return m_data; }
	size_t size() const { return m_size; }
protected:
	const char *m_data;
	size_t m_size;
};

class mutable_buffer :public const_buffer
{
public:
	mutable_buffer(char *data, size_t size) :const_buffer(data, size) {}

	char *access_data() const { return const_cast<char*>(m_data); }
};

#endif
