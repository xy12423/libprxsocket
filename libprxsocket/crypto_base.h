#ifndef LIBPRXSOCKET_H_CRYPTO_BASE
#define LIBPRXSOCKET_H_CRYPTO_BASE

#ifndef _LIBPRXSOCKET_BUILD
#include <vector>
#endif

class encryptor
{
public:
	virtual size_t key_size() const = 0;
	virtual size_t iv_size() const = 0;
	virtual const char *iv() const = 0;
	//Set or reset key, generate iv
	virtual void set_key(const char *key) = 0;
	//Set or reset key and iv
	virtual void set_key_iv(const char *key, const char *iv) = 0;

	virtual void encrypt(std::vector<char> &dst, const char *src, size_t src_size) = 0;
};

class decryptor
{
public:
	virtual size_t key_size() const = 0;
	virtual size_t iv_size() const = 0;
	virtual const char *iv() const = 0;
	//Set or reset key, generate iv
	virtual void set_key(const char *key) = 0;
	//Set or reset key and iv
	virtual void set_key_iv(const char *key, const char *iv) = 0;

	virtual void decrypt(std::vector<char> &dst, const char *src, size_t src_size) = 0;
};

#endif
