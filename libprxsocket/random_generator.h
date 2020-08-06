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

#ifndef LIBPRXSOCKET_H_RANDOM_GENERATOR
#define LIBPRXSOCKET_H_RANDOM_GENERATOR

#ifndef _LIBPRXSOCKET_BUILD
#include <cstdint>
#include <vector>

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#endif

namespace prxsocket
{

	class random_generator
	{
	public:
		static void random_bytes(void *dst, size_t dst_size)
		{
			thread_local CryptoPP::AutoSeededRandomPool prng;
			prng.GenerateBlock((CryptoPP::byte *)dst, dst_size);
		}

		static void random_bytes(std::vector<char> &dst, size_t rnd_size)
		{
			size_t rnd_begin = dst.size();
			dst.resize(dst.size() + rnd_size);
			random_bytes(dst.data() + rnd_begin, rnd_size);
		}

		template <typename T>
		static T random_int()
		{
			T val;
			random_bytes(&val, sizeof(T));
			return val;
		}

		static double random_double()
		{
			return random_int<uint32_t>() / 4294967296.0;
		}
	};

}

#endif
