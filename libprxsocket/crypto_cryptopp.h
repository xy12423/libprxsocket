#ifndef LIBPRXSOCKET_H_CRYPTO_CRYPTOPP
#define LIBPRXSOCKET_H_CRYPTO_CRYPTOPP

#include "crypto_base.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#endif

template <typename CRYPTO, size_t KEY_LENGTH>
class encryptor_cryptopp : public encryptor
{
	using encryptor_type = typename CRYPTO::Encryption;
	static constexpr size_t KEY_SIZE = KEY_LENGTH / 8;
public:
	virtual size_t key_size() const override { return KEY_SIZE; }
	virtual size_t iv_size() const override { return KEY_SIZE; }
	virtual const char *iv() const override { return (const char *)iv_; }
	virtual void set_key(const char *key) override
	{
		thread_local CryptoPP::AutoSeededRandomPool prng;
		prng.GenerateBlock(iv_, sizeof(iv_));
		e_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
	}
	virtual void set_key_iv(const char *key, const char *iv) override
	{
		memcpy(iv_, iv, KEY_SIZE);
		e_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
	}

	virtual void encrypt(std::vector<char> &dst, const char *src, size_t src_size) override
	{
		CryptoPP::StringSource ss(
			(const CryptoPP::byte *)src, src_size,
			true,
			new CryptoPP::StreamTransformationFilter(e_, new CryptoPP::StringSinkTemplate<std::vector<char>>(dst))
		);
	}
private:
	encryptor_type e_;
	CryptoPP::byte iv_[KEY_SIZE];
};

template <typename CRYPTO, size_t KEY_LENGTH>
class decryptor_cryptopp : public decryptor
{
	using decryptor_type = typename CRYPTO::Decryption;
	static constexpr size_t KEY_SIZE = KEY_LENGTH / 8;
public:
	virtual size_t key_size() const override { return KEY_SIZE; }
	virtual size_t iv_size() const override { return KEY_SIZE; }
	virtual const char *iv() const override { return (const char *)iv_; }
	virtual void set_key(const char *key) override
	{
		thread_local CryptoPP::AutoSeededRandomPool prng;
		prng.GenerateBlock(iv_, sizeof(iv_));
		d_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
	}
	virtual void set_key_iv(const char *key, const char *iv) override
	{
		memcpy(iv_, iv, KEY_SIZE);
		d_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
	}

	virtual void decrypt(std::vector<char> &dst, const char *src, size_t src_size) override
	{
		CryptoPP::StringSource ss(
			(const CryptoPP::byte *)src, src_size,
			true,
			new CryptoPP::StreamTransformationFilter(d_, new CryptoPP::StringSinkTemplate<std::vector<char>>(dst))
		);
	}
private:
	decryptor_type d_;
	CryptoPP::byte iv_[KEY_SIZE];
};

#endif
