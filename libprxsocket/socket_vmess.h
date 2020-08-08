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

#ifndef LIBPRXSOCKET_H_SOCKET_VMESS
#define LIBPRXSOCKET_H_SOCKET_VMESS

#include "socket_base.h"
#include "crypto_base.h"

#ifndef _LIBPRXSOCKET_BUILD
#include <cryptopp/cryptlib.h>
#endif

namespace prxsocket
{
	namespace v2ray
	{

		template <size_t c>
		class kekkak_sha3
		{
			static inline constexpr uint64_t rol(uint64_t x, uint8_t shift = 1)
			{
				return (x << shift) | (x >> (-shift & 0x3F));
			}

			static inline constexpr uint64_t ror(uint64_t x, uint8_t shift = 1)
			{
				return (x >> shift) | (x << (-shift & 0x3F));
			}

			struct rho_helper
			{
				constexpr rho_helper()
					:shifts()
				{
					int x = 1, y = 0;
					int shifts_tmp[25] = { 0 };
					for (int t = 0; t < 24; ++t)
					{
						shifts_tmp[5 * y + x] += (t + 1) * (t + 2) / 2;
						int x_ = y;
						int y_ = (2 * x + 3 * y) % 5;
						x = x_;
						y = y_;
					}
					for (int i = 0; i < 25; ++i)
						shifts[i] = shifts_tmp[i] % 64;
				}

				uint8_t shifts[25];
			};

			struct pi_helper
			{
				constexpr pi_helper()
					:srcs()
				{
					for (int y = 0; y < 5; ++y)
						for (int x = 0; x < 5; ++x)
							srcs[5 * y + x] = 5 * x + (x + 3 * y) % 5;
				}

				int srcs[25];
			};

			struct rc_helper
			{
				constexpr rc_helper()
					:rc_value()
				{
					uint8_t R = 0x01;
					int pos = 0;
					uint64_t bit = 0x0000000000000001ull;
					rc_value[pos] |= bit;
					bit <<= 1;
					for (int i = 1; i <= 254; ++i)
					{
						if (R & 0x80)
							R = (R << 1) ^ 0x71;
						else
							R = R << 1;
						if (R & 0x01)
							rc_value[pos] |= bit;
						if (bit == 0x8000000000000000ull)
						{
							pos += 1;
							bit = 0x0000000000000001ull;
						}
						else
						{
							bit <<= 1;
						}
					}
				}

				constexpr bool rc(size_t t) const
				{
					t %= 255;
					return rc_value[t / 64] & ((uint64_t)1 << (t % 64));
				}

				uint64_t rc_value[4];
			};

			template <size_t N>
			struct iota_helper
			{
				constexpr iota_helper()
					:iota_values()
				{
					constexpr rc_helper rc;
					for (size_t i = 0; i < N; ++i)
					{
						uint64_t res = 0;
						for (int j = 0; j <= 6; ++j)
						{
							if (rc.rc(j + 7 * i))
								res |= (uint64_t)1 << ((1 << j) - 1);
						}
						iota_values[i] = res;
					}
				}

				uint64_t iota_values[N];
			};
		public:
			static constexpr size_t DIGEST_SIZE = c / 16;

			constexpr kekkak_sha3() :A(), ptr(0) {}

			void Update(const void *data, size_t size)
			{
				for (size_t i = 0; i < size; i++)
				{
					State()[ptr++] ^= ((const unsigned char *)data)[i];
					if (ptr >= r / 8)
					{
						KekkakF();
						ptr = 0;
					}
				}
			}

			void Final(uint8_t *digest)
			{
				State()[ptr] ^= 0x06;
				State()[r / 8 - 1] ^= 0x80;
				KekkakF();
				for (size_t i = 0; i < c / 16; i++)
					digest[i] = State()[i];
			}

			void ShakeStart()
			{
				State()[ptr] ^= 0x1F;
				State()[r / 8 - 1] ^= 0x80;
				KekkakF();
				ptr = 0;
			}
			void ShakeContinue(void *data, size_t size)
			{
				for (size_t i = 0; i < size; i++)
				{
					if (ptr >= r / 8)
					{
						KekkakF();
						ptr = 0;
					}
					((unsigned char *)data)[i] = State()[ptr++];
				}
			}

			void Restart()
			{
				ptr = 0;
				for (int i = 0; i < 24; ++i)
					A[i] = 0;
			}
		private:
			static constexpr size_t b = 1600;
			static constexpr size_t r = b - c;

			unsigned char *State()
			{
				return (unsigned char *)A;
			}

			void KekkakF()
			{
				static constexpr rho_helper shift_bits;
				static constexpr pi_helper rotate_srcs;
				static constexpr iota_helper<24> rc_values;

				static constexpr int x_1[] = { 1, 2, 3, 4, 0 };
				static constexpr int x_2[] = { 2, 3, 4, 0, 1 };
				static constexpr int x_4[] = { 4, 0, 1, 2, 3 };

				uint64_t A_[25];
				uint64_t C[5], D[5];

				int x, y;

				for (int i = 0; i < 25; ++i)
					A[i] = boost::endian::little_to_native(A[i]);
				for (int round = 0; round < 12 + 2 * 6; ++round)
				{
					for (x = 0; x < 5; ++x)
						C[x] = A[x + 0] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
					for (x = 0; x < 5; ++x)
						D[x] = C[x_4[x]] ^ rol(C[x_1[x]]);
					for (x = 0; x < 5; ++x)
						for (y = 0; y < 5; ++y)
							A[5 * y + x] = A[5 * y + x] ^ D[x];

					for (int i = 0; i < 25; ++i)
						A[i] = rol(A[i], shift_bits.shifts[i]);

					for (int i = 0; i < 25; ++i)
						A_[i] = A[rotate_srcs.srcs[i]];

					for (x = 0; x < 5; ++x)
						for (y = 0; y < 5; ++y)
							A[5 * y + x] = A_[5 * y + x] ^ (~A_[5 * y + x_1[x]] & A_[5 * y + x_2[x]]);

					A[0] = A[0] ^ rc_values.iota_values[round];
				}
				for (int i = 0; i < 25; ++i)
					A[i] = boost::endian::native_to_little(A[i]);
			}

			uint64_t A[25];
			size_t ptr;
		};
		using shake_128 = kekkak_sha3<256>;

		class vmess_tcp_socket final : public prx_tcp_socket
		{
			static constexpr size_t MAX_BLOCK_SIZE = 1 << 14;
		public:
			vmess_tcp_socket(
				std::unique_ptr<prx_tcp_socket> &&base_socket, const endpoint &server_endpoint,
				const uint8_t *uid, uint8_t security, std::unique_ptr<encryptor> &&enc, std::unique_ptr<decryptor> &&dec
			);
			virtual ~vmess_tcp_socket() override {}

			virtual bool is_open() override { return socket_->is_open(); }
			virtual bool is_connected() override { return socket_->is_connected() && header_sent_; }

			virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = ERR_UNSUPPORTED; }
			virtual void remote_endpoint(endpoint &ep, error_code &ec) override { ec = 0; if (!is_connected()) { ec = ERR_OPERATION_FAILURE; return; } ep = remote_ep_; }

			virtual void open(error_code &ec) override { return socket_->open(ec); }
			virtual void async_open(null_callback &&complete_handler) override { socket_->async_open(std::move(complete_handler)); }

			virtual void bind(const endpoint &endpoint, error_code &ec) override { ec = ERR_UNSUPPORTED; }
			virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { complete_handler(ERR_UNSUPPORTED); }

			virtual void connect(const endpoint &endpoint, error_code &ec) override;
			virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override;

			virtual void send(const const_buffer &buffer, size_t &transferred, error_code &ec) override;
			virtual void async_send(const const_buffer &buffer, transfer_callback &&complete_handler) override;
			virtual void recv(const mutable_buffer &buffer, size_t &transferred, error_code &ec) override;
			virtual void async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
			virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
			virtual void write(const_buffer_sequence &&buffer, error_code &ec) override;
			virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

			virtual void close(error_code &ec) override;
			virtual void async_close(null_callback &&complete_handler) override;
		private:
			void force_close() { error_code err; force_close(err); }
			void force_close(error_code &ec);
			void force_async_close(null_callback &&complete_handler);

			void async_read(const std::shared_ptr<mutable_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);
			void async_write(const std::shared_ptr<const_buffer_sequence> &buffer, const std::shared_ptr<null_callback> &callback);

			void wait_header(error_code &ec);
			void async_wait_header(null_callback &&complete_handler);
			void recv_data(error_code &ec);
			void async_recv_data(null_callback &&complete_handler);
			void async_recv_data_body(size_t size, const std::shared_ptr<null_callback> &callback);
			size_t read_data(char *dst, size_t dst_size);
			bool read_empty();

			void encode_header(std::vector<char> &buf);
			size_t encode(const const_buffer &buffer);
			void encode(const_buffer_sequence &buffer);
			void decode_header();
			size_t decode_size();
			void decode(size_t size);

			std::unique_ptr<prx_tcp_socket> socket_;

			endpoint server_ep_, remote_ep_;

			uint8_t uid_[16];
			uint8_t security_;
			std::unique_ptr<encryptor> enc_;
			std::unique_ptr<decryptor> dec_;

			CryptoPP::byte request_key_[16], response_key_[16];
			CryptoPP::byte request_body_key_[32], response_body_key_[32];
			CryptoPP::byte request_iv_[16], response_iv_[16];
			uint8_t verify_byte_;
			shake_128 request_mask_, response_mask_;
			uint16_t request_count_, response_count_;

			bool header_sent_ = false, header_received_ = false;
			std::vector<char> send_buf_;
			std::unique_ptr<char[]> recv_buf_;
			std::vector<char> dec_buf_;
			size_t dec_ptr_ = 0;
		};

	}
}

#endif
