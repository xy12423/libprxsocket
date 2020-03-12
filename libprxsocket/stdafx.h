#ifndef _H_STDAFX
#define _H_STDAFX

#pragma once

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
