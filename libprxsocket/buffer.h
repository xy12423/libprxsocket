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

#ifndef LIBPRXSOCKET_H_BUFFER
#define LIBPRXSOCKET_H_BUFFER

#ifndef _LIBPRXSOCKET_BUILD
#include <cassert>
#include <algorithm>
#include <deque>
#include <vector>
#include <limits>
#include <memory>
#include <utility>

#include <boost/compressed_pair.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#endif

namespace prxsocket
{
	using byte = std::byte;

	class buffer_data_store : public boost::intrusive_ref_counter<buffer_data_store, boost::thread_safe_counter>
	{
	public:
		buffer_data_store(const buffer_data_store &) = delete;
		buffer_data_store(buffer_data_store &&) = delete;
		buffer_data_store &operator=(const buffer_data_store &) = delete;
		buffer_data_store &operator=(buffer_data_store &&) = delete;
		virtual ~buffer_data_store() = default;
	};
	using buffer_data_store_holder = boost::intrusive_ptr<buffer_data_store>;

	template <class T, class Deleter = std::default_delete<T>>
	class buffer_data_store_pointer : public buffer_data_store
	{
	public:
		buffer_data_store_pointer(T *ptr) :pair_(ptr) {}
		buffer_data_store_pointer(Deleter deleter, T *ptr) :pair_(std::move(deleter), ptr) {}
	private:
		virtual ~buffer_data_store_pointer() override { pair_.first()(pair_.second()); }
		boost::compressed_pair<Deleter, T *> pair_;
	};
	template <class T>
	class buffer_data_store_inplace : public buffer_data_store
	{
	public:
		template <typename... TArgs> buffer_data_store_inplace(TArgs &&...args) :obj_(std::forward<TArgs>(args)...) {}
		T &get() { return obj_; }
		const T &get() const { return obj_; }
	private:
		virtual ~buffer_data_store_inplace() override {};
		T obj_;
	};
	using buffer_data_store_group = buffer_data_store_inplace<std::vector<buffer_data_store_holder>>;

	class const_buffer
	{
	public:
		static const byte empty_data[sizeof(void *)];

		const_buffer() :data_(empty_data), size_(0) {}
		const_buffer(const const_buffer &) = default;
		const_buffer(const byte *data, size_t size) :data_(data), size_(size) {}
		template <typename T> explicit const_buffer(const T &data) :data_(data.data()), size_(data.size()) {}

		const byte *data() const { return data_; }
		size_t size() const { return size_; }

		const_buffer after_consume(size_t size) const { if (size <= size_) return const_buffer(data_ + size, size_ - size); return const_buffer(); }
	protected:
		const byte *data_;
		size_t size_;
	};

	struct buffer_with_data_store
	{
		const_buffer buffer;
		buffer_data_store_holder holder;
	};

	class mutable_buffer
	{
	public:
		mutable_buffer() = default;
		mutable_buffer(const mutable_buffer &) = default;
		mutable_buffer(byte *data, size_t size) :data_(data), size_(size) {}
		template <typename T> explicit mutable_buffer(T &data) :data_(data.data()), size_(data.size()) {}

		byte *data() const { return data_; }
		size_t size() const { return size_; }
	protected:
		byte *data_;
		size_t size_;
	};
	
	template <typename T, typename Container = std::deque<T>>
	class buffer_sequence
	{
	public:
		using value_type = T;
		using container_type = Container;
		using const_iterator = typename Container::const_iterator;

		size_t count() const { return list_.size(); }
		size_t size_total() const { return size_total_; }
		bool empty() const { return list_.empty(); }

		const value_type &front() const { return list_.front(); }
		const value_type &back() const { return list_.back(); }
		const_iterator begin() const { return list_.begin(); }
		const_iterator end() const { return list_.end(); }

		void clear() { list_.clear(); size_total_ = 0; }
		void push_front(const value_type &item) { assert(item.size() > 0); list_.push_front(item); size_total_ += item.size(); }
		void push_front(value_type &&item) { assert(item.size() > 0); size_t size = item.size(); list_.push_front(std::move(item)); size_total_ += size; }
		void push_back(const value_type &item) { assert(item.size() > 0); list_.push_back(item); size_total_ += item.size(); }
		void push_back(value_type &&item) { assert(item.size() > 0); size_t size = item.size(); list_.push_back(std::move(item)); size_total_ += size; }
		void pop_front() { size_total_ -= list_.front().size(); list_.pop_front(); }
		void pop_back() { size_total_ -= list_.back().size(); list_.pop_back(); }

		void consume_front(size_t size)
		{
			assert(size <= list_.front().size());
			value_type &next = list_.front();
			if (next.size() <= size)
			{
				list_.pop_front();
			}
			else
			{
				next = value_type(next.data() + size, next.size() - size);
			}
			size_total_ -= size;
		}
		void consume(size_t size)
		{
			assert(size <= size_total_);
			size_t left = size;
			while (left > 0)
			{
				value_type &next = list_.front();
				if (next.size() <= left)
				{
					left -= next.size();
					list_.pop_front();
				}
				else
				{
					next = value_type(next.data() + left, next.size() - left);
					left = 0;
					break;
				}
			}
			size_total_ -= size;
		}
		template <typename ReturnType>
		ReturnType truncate(size_t size)
		{
			ReturnType truncated{};
			while (!list_.empty() && truncated.size_total() < size)
			{
				value_type &next = list_.front();
				if (truncated.size_total() + next.size() <= size)
				{
					truncated.push_back(std::move(next));
					list_.pop_front();
				}
				else
				{
					size_t extra_size = size - truncated.size_total();
					truncated.push_back(value_type(next.data(), extra_size));
					next = value_type(next.data() + extra_size, next.size() - extra_size);
					break;
				}
			}
			size_total_ -= truncated.size_total();
			return truncated;
		}
		template <typename ReturnType>
		void truncate(ReturnType &truncated, size_t size)
		{
			size_t truncated_size = 0;
			while (!list_.empty() && truncated_size < size)
			{
				value_type &next = list_.front();
				if (truncated_size + next.size() <= size)
				{
					truncated_size += next.size();
					truncated.push_back(std::move(next));
					list_.pop_front();
				}
				else
				{
					size_t extra_size = size - truncated_size;
					truncated_size = size;
					truncated.push_back(value_type(next.data(), extra_size));
					next = value_type(next.data() + extra_size, next.size() - extra_size);
					break;
				}
			}
			size_total_ -= truncated_size;
		}
	protected:
		Container list_;
		size_t size_total_ = 0;
	};

	class const_buffer_sequence final : public buffer_sequence<const_buffer>
	{
	public:
		const_buffer_sequence() = default;
		const_buffer_sequence(const const_buffer &buffer) { push_back(buffer); }
		const_buffer_sequence(const_buffer &&buffer) { push_back(std::move(buffer)); }

		const_buffer_sequence truncate(size_t size) { return buffer_sequence<const_buffer>::truncate<const_buffer_sequence>(size); }
		void truncate(const_buffer_sequence &truncated, size_t size) { return buffer_sequence<const_buffer>::truncate<const_buffer_sequence>(truncated, size); }

		size_t gather(byte *dst, size_t dst_size)
		{
			size_t copied = 0;
			while (!list_.empty() && copied < dst_size)
			{
				value_type &next = list_.front();
				if (next.size() <= dst_size - copied)
				{
					size_t copying = next.size();
					memcpy(dst + copied, next.data(), copying);
					copied += copying;
					list_.pop_front();
				}
				else
				{
					size_t copying = dst_size - copied;
					memcpy(dst + copied, next.data(), copying);
					next = value_type(next.data() + copying, next.size() - copying);
					copied = dst_size;
					break;
				}
			}
			size_total_ -= copied;
			return copied;
		}
	};

	class mutable_buffer_sequence final : public buffer_sequence<mutable_buffer>
	{
	public:
		mutable_buffer_sequence() = default;
		mutable_buffer_sequence(const mutable_buffer &buffer) { push_back(buffer); }
		mutable_buffer_sequence(mutable_buffer &&buffer) { push_back(std::move(buffer)); }

		mutable_buffer_sequence truncate(size_t size) { return buffer_sequence<mutable_buffer>::truncate<mutable_buffer_sequence>(size); }
		void truncate(mutable_buffer_sequence &truncated, size_t size) { return buffer_sequence<mutable_buffer>::truncate<mutable_buffer_sequence>(truncated, size); }

		size_t scatter(const byte *src, size_t src_size)
		{
			size_t copied = 0;
			while (!list_.empty() && copied < src_size)
			{
				value_type &next = list_.front();
				if (next.size() <= src_size - copied)
				{
					size_t copying = next.size();
					memcpy(next.data(), src + copied, copying);
					copied += copying;
					list_.pop_front();
				}
				else
				{
					size_t copying = src_size - copied;
					memcpy(next.data(), src + copied, copying);
					next = value_type(next.data() + copying, next.size() - copying);
					copied = src_size;
					break;
				}
			}
			size_total_ -= copied;
			return copied;
		}
	};

}

#define PRXSOCKET_MAKE_INPLACE_BUFFER(buffer_type, buffer_data_ref_name, buffer_holder_name, ...) buffer_data_store_holder buffer_holder_name(new prxsocket::buffer_data_store_inplace<buffer_type>(__VA_ARGS__)); \
	buffer_type &buffer_data_ref_name = static_cast<prxsocket::buffer_data_store_inplace<buffer_type> *>(buffer_holder_name.get())->get();

#endif
