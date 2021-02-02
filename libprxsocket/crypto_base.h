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

#ifndef LIBPRXSOCKET_H_CRYPTO_BASE
#define LIBPRXSOCKET_H_CRYPTO_BASE

#include "buffer.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <vector>
#endif

namespace prxsocket
{

	class encryptor
	{
	public:
		virtual ~encryptor() = default;

		virtual size_t key_size() const = 0;
		virtual size_t iv_size() const = 0;
		virtual const char *iv() const = 0;
		//Set or reset key, generate iv
		virtual void set_key(const char *key) = 0;
		//Set or reset key and iv
		virtual void set_key_iv(const char *key, const char *iv) = 0;

		virtual void encrypt(std::vector<char> &dst, const char *src, size_t src_size) = 0;
		virtual void encrypt(std::vector<char> &dst, const_buffer_sequence &src, size_t src_size) = 0;
	};

	class decryptor
	{
	public:
		virtual ~decryptor() = default;

		virtual size_t key_size() const = 0;
		virtual size_t iv_size() const = 0;
		virtual const char *iv() const = 0;
		//Set or reset key, generate iv
		virtual void set_key(const char *key) = 0;
		//Set or reset key and iv
		virtual void set_key_iv(const char *key, const char *iv) = 0;

		virtual void decrypt(std::vector<char> &dst, const char *src, size_t src_size) = 0;
		virtual size_t decrypt(mutable_buffer dst, std::vector<char> &dst_last, const char *src, size_t src_size) = 0;
		virtual void decrypt(mutable_buffer_sequence &dst, std::vector<char> &dst_last, const char *src, size_t src_size) = 0;
	};

}

#endif
