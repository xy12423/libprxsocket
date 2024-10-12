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

#ifndef LIBPRXSOCKET_H_CRYPTO_EVP
#define LIBPRXSOCKET_H_CRYPTO_EVP

#include "buffer.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <limits>

#include <openssl/evp.h>
#endif

namespace prxsocket
{

	namespace evp
	{

		template <class Child>
		struct md
		{
			md(const char *md) :evp_md_(EVP_MD_fetch(NULL, md, NULL)) {}
			md(const md<Child> &) = delete;
			md(md<Child> &&) = delete;
			~md() { EVP_MD_free(evp_md_); }

			static const EVP_MD *shared_md() { static Child shared; return shared.evp_md_; }
		private:
			EVP_MD *evp_md_ = nullptr;
		};

		struct md_sha1 : md<md_sha1>
		{
			md_sha1() :md("SHA-1") {}
		};

		struct md_context
		{
			md_context() :ctx_(EVP_MD_CTX_new()) {}
			md_context(const md_context &) = delete;
			md_context(md_context &&) = delete;
			~md_context() { EVP_MD_CTX_free(ctx_); }

			bool operator!() const { return !ctx_; }

			operator EVP_MD_CTX *() const { return ctx_; }
		private:
			EVP_MD_CTX *ctx_ = nullptr;
		};

		template <class MD>
		class message_digest
		{
		public:
			bool calculate_digest(byte *dst, size_t &dst_size, const byte *src, size_t src_size)
			{
				if (!ctx_)
					return false;
				const EVP_MD *md = MD::shared_md();
				if (!md)
					return false;
				if (dst_size < EVP_MD_get_size(md))
					return false;

				if (!EVP_DigestInit_ex(ctx_, md, NULL))
					return false;
				if (!EVP_DigestUpdate(ctx_, src, src_size))
					return false;
				unsigned int dst_len = 0;
				if (!EVP_DigestFinal_ex(ctx_, (unsigned char *)dst, &dst_len))
					return false;
				dst_size = dst_len;
				return true;
			}
		private:
			md_context ctx_;
		};

		template <class Child>
		struct cipher
		{
			cipher(const char *cipher) :evp_cipher_(EVP_CIPHER_fetch(NULL, cipher, NULL)) {}
			cipher(const cipher<Child> &) = delete;
			cipher(cipher<Child> &&) = delete;
			~cipher() { EVP_CIPHER_free(evp_cipher_); }

			static const EVP_CIPHER *shared_cipher() { static Child shared; return shared.evp_cipher_; }
		private:
			EVP_CIPHER *evp_cipher_ = nullptr;
		};

		struct cipher_aes_256_gcm : cipher<cipher_aes_256_gcm>
		{
			cipher_aes_256_gcm() :cipher("AES-256-GCM") {}
		};

		struct cipher_context
		{
			cipher_context() :ctx_(EVP_CIPHER_CTX_new()) {}
			cipher_context(const cipher_context &) = delete;
			cipher_context(cipher_context &&) = delete;
			~cipher_context() { EVP_CIPHER_CTX_free(ctx_); }

			bool operator!() const { return !ctx_; }

			operator const EVP_CIPHER_CTX *() const { return ctx_; }
			operator EVP_CIPHER_CTX *() { return ctx_; }
		private:
			EVP_CIPHER_CTX *ctx_ = nullptr;
		};

		template <class Cipher, class CipherOperations>
		class cipher_common_processor
		{
		public:
			int block_size() const { return EVP_CIPHER_get_block_size(Cipher::shared_cipher()); }

			bool init(const byte *key, size_t key_size, const byte *iv, size_t iv_size)
			{
				if (!ctx_)
					return false;
				const EVP_CIPHER *cipher = Cipher::shared_cipher();
				if (!cipher)
					return false;
				if (key_size < EVP_CIPHER_get_key_length(cipher))
					return false;
				if (iv_size < EVP_CIPHER_get_iv_length(cipher))
					return false;

				OSSL_PARAM params[1]{};
				params[0] = OSSL_PARAM_construct_end();
				if (!CipherOperations::Init(ctx_, cipher, (const unsigned char *)key, (const unsigned char *)iv, params))
					return false;
				return true;
			}

			bool update(byte *out, size_t &out_size, const byte *in, size_t in_size)
			{
				if (!ctx_)
					return false;

				static_assert(std::numeric_limits<int>::max() <= std::numeric_limits<size_t>::max());
				constexpr int int_max = std::numeric_limits<int>::max();
				int block_size = EVP_CIPHER_CTX_get_block_size(ctx_);
				if (block_size < 0)
					return false;
				// If reaches here: 0 <= block_size <= int_max, 0 <= int_max - block_size <= int_max <= size_t_max
				if (in_size < 0 || in_size > (size_t)(int_max - block_size))
					return false;
				// If reaches here: 0 <= in_size <= int_max - block_size, 0 <= in_size + block_size <= int_max <= size_t_max
				if (out_size < in_size + block_size)
					return false;
				// If reaches here: out_size >= in_size + block_size, which is the maximum possible size required by any kind of cipher
				int inl = in_size;
				int outl = out_size < int_max ? out_size : int_max;
				if (!CipherOperations::Update(ctx_, (unsigned char *)out, &outl, (unsigned char *)in, inl))
					return false;
				return true;
			}

			bool update(std::vector<byte> &out, const byte *in, size_t in_size)
			{
				if (!ctx_)
					return false;

				static_assert(std::numeric_limits<int>::max() <= std::numeric_limits<size_t>::max());
				constexpr int int_max = std::numeric_limits<int>::max();
				int block_size = EVP_CIPHER_CTX_get_block_size(ctx_);
				if (block_size < 0)
					return false;
				// If reaches here: 0 <= block_size <= int_max, 0 <= int_max - block_size <= int_max <= size_t_max
				if (in_size < 0 || in_size > (size_t)(int_max - block_size))
					return false;
				// If reaches here: 0 <= in_size <= int_max - block_size, 0 <= in_size + block_size <= int_max <= size_t_max
				int out_size = in_size + block_size; // maximum possible size required by any kind of cipher
				if (out.size() > std::numeric_limits<size_t>::max() - out_size)
					return false;
				// If reaches here: out.size() <= size_t_max - out_size, out.size() + out_size <= size_t_max
				size_t out_size_old = out.size();
				out.resize(out_size_old + out_size);
				byte *out_ptr = out.data() + out_size_old;
				int inl = in_size;
				int outl = out_size;
				if (!CipherOperations::Update(ctx_, (unsigned char *)out_ptr, &outl, (unsigned char *)in, inl))
				{
					out.resize(out_size_old); // Revert side-effects
					return false;
				}
				out.resize(out_size_old + outl); // Resize according to real output length
				return true;
			}

			bool final(byte *out, size_t &out_size)
			{
				if (!ctx_)
					return false;

				static_assert(std::numeric_limits<int>::max() <= std::numeric_limits<size_t>::max());
				constexpr int int_max = std::numeric_limits<int>::max();
				int block_size = EVP_CIPHER_CTX_get_block_size(ctx_);
				if (block_size < 0)
					return false;
				if (out_size < block_size)
					return false;
				int outl = out_size < int_max ? out_size : int_max;
				if (!CipherOperations::Final(ctx_, (unsigned char *)out, &outl))
					return false;
				return true;
			}

			bool final(std::vector<byte> &out)
			{
				if (!ctx_)
					return false;

				static_assert(std::numeric_limits<int>::max() <= std::numeric_limits<size_t>::max());
				constexpr int int_max = std::numeric_limits<int>::max();
				int block_size = EVP_CIPHER_CTX_get_block_size(ctx_);
				if (block_size < 0)
					return false;
				if (out.size() > std::numeric_limits<size_t>::max() - block_size)
					return false;
				size_t out_size_old = out.size();
				out.resize(out_size_old + block_size);
				byte *out_ptr = out.data() + out_size_old;
				int outl = block_size;
				if (!CipherOperations::Final(ctx_, (unsigned char *)out_ptr, &outl))
				{
					out.resize(out_size_old); // Revert side-effects
					return false;
				}
				out.resize(out_size_old + outl); // Resize according to real output length
				return true;
			}
		protected:
			cipher_context ctx_;
		};

		struct cipher_operations_encrypt
		{
			template <typename... TArgs> static int Init(TArgs &&...args) { return EVP_EncryptInit_ex2(std::forward<TArgs>(args)...); }
			template <typename... TArgs> static int Update(TArgs &&...args) { return EVP_EncryptUpdate(std::forward<TArgs>(args)...); }
			template <typename... TArgs> static int Final(TArgs &&...args) { return EVP_EncryptFinal_ex(std::forward<TArgs>(args)...); }
		};

		template <class Cipher>
		class encryptor : public cipher_common_processor<Cipher, cipher_operations_encrypt>
		{
		};

		struct cipher_operations_decrypt
		{
			template <typename... TArgs> static int Init(TArgs &&...args) { return EVP_DecryptInit_ex2(std::forward<TArgs>(args)...); }
			template <typename... TArgs> static int Update(TArgs &&...args) { return EVP_DecryptUpdate(std::forward<TArgs>(args)...); }
			template <typename... TArgs> static int Final(TArgs &&...args) { return EVP_DecryptFinal_ex(std::forward<TArgs>(args)...); }
		};

		template <class Cipher>
		class decryptor : public cipher_common_processor<Cipher, cipher_operations_decrypt>
		{
		};

	}

}

#endif
