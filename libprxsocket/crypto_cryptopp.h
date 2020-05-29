/*
Copyright (c) 2020 xy12423

This file is part of libprxsocket.

libprxsocket is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

libprxsocket is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libprxsocket. If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef LIBPRXSOCKET_H_CRYPTO_CRYPTOPP
#define LIBPRXSOCKET_H_CRYPTO_CRYPTOPP

#include "crypto_base.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#endif

template <typename Crypto, size_t KEY_LENGTH, size_t IV_LENGTH>
class encryptor_cryptopp : public prxsocket::encryptor
{
	using encryptor_type = typename Crypto::Encryption;
	static constexpr size_t KEY_SIZE = KEY_LENGTH / 8;
	static constexpr size_t IV_SIZE = IV_LENGTH / 8;
public:
	virtual size_t key_size() const override { return KEY_SIZE; }
	virtual size_t iv_size() const override { return IV_SIZE; }
	virtual const char *iv() const override { return (const char *)iv_; }
	virtual void set_key(const char *key) override
	{
		thread_local CryptoPP::AutoSeededRandomPool prng;
		prng.GenerateBlock(iv_, sizeof(iv_));
		e_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
	}
	virtual void set_key_iv(const char *key, const char *iv) override
	{
		memcpy(iv_, iv, sizeof(iv_));
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
	CryptoPP::byte iv_[IV_SIZE];
};

template <typename Crypto, size_t KEY_LENGTH, size_t IV_LENGTH>
class decryptor_cryptopp : public prxsocket::decryptor
{
	using decryptor_type = typename Crypto::Decryption;
	static constexpr size_t KEY_SIZE = KEY_LENGTH / 8;
	static constexpr size_t IV_SIZE = IV_LENGTH / 8;
public:
	virtual size_t key_size() const override { return KEY_SIZE; }
	virtual size_t iv_size() const override { return IV_SIZE; }
	virtual const char *iv() const override { return (const char *)iv_; }
	virtual void set_key(const char *key) override
	{
		thread_local CryptoPP::AutoSeededRandomPool prng;
		prng.GenerateBlock(iv_, sizeof(iv_));
		d_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
	}
	virtual void set_key_iv(const char *key, const char *iv) override
	{
		memcpy(iv_, iv, sizeof(iv_));
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
	CryptoPP::byte iv_[IV_SIZE];
};

#endif
