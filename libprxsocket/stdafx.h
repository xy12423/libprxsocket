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

#pragma once

#ifndef _H_STDAFX
#define _H_STDAFX

#define _LIBPRXSOCKET_BUILD

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <ctime>

#include <iostream>
#include <fstream>
#include <sstream>

#include <array>
#include <vector>
#include <list>
#include <set>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <string>

#include <algorithm>
#include <chrono>
#include <functional>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
namespace asio = boost::asio;

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/md5.h>
#include <cryptopp/modes.h>

#ifdef _MSC_VER
#pragma comment(lib, "cryptlib.lib")
#endif

#endif
