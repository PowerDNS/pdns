/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once

#include <atomic>

#ifndef DISABLE_FALSE_SHARING_PADDING
#define CPU_LEVEL1_DCACHE_LINESIZE 64 // Until we know better via configure/getconf

namespace pdns {
  template <typename T>
  class stat_t_trait {
  public:
    using base_t = T;
    using atomic_t = std::atomic<base_t>;

    stat_t_trait() : stat_t_trait(base_t(0)) {
    }
    stat_t_trait(const base_t value)
    {
      new(&counter) atomic_t(value);
    }
    stat_t_trait& operator=(const base_t& value) {
      ref().store(value);
      return *this;
    }
    ~stat_t_trait() {
      ref().~atomic_t();
    }
    stat_t_trait(stat_t_trait&&) = delete;
    stat_t_trait& operator=(const stat_t_trait&) = delete;
    stat_t_trait& operator=(stat_t_trait&&) = delete;
    stat_t_trait(const stat_t_trait&) = delete;
    base_t operator++(int) {
      return ref()++;
    }
    base_t operator++() {
      return ++(ref());
    }
    base_t operator--(int) {
      return ref()--;
    }
    base_t operator--() {
      return --(ref());
    }
    base_t operator+=(base_t arg) {
      return ref() += arg;
    }
    base_t operator-=(base_t arg) {
      return ref() -= arg;
    }
    base_t load() const {
      return ref().load();
    }
    void store(base_t value) {
      ref().store(value);
    }
    operator base_t() const {
      return ref().load();
    }

  private:
    atomic_t& ref()  {
      return *reinterpret_cast<atomic_t *>(&counter); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }
    const atomic_t& ref() const {
      return *reinterpret_cast<const atomic_t *>(&counter); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }
    typename std::aligned_storage_t<sizeof(atomic_t), CPU_LEVEL1_DCACHE_LINESIZE> counter;
  };
}
#else
namespace pdns {
  template <class T>
  using stat_t_trait = std::atomic<T>;
}
#endif

namespace pdns {
  using stat_t = stat_t_trait<uint64_t>;
  using stat32_t = stat_t_trait<uint32_t>;
  using stat16_t = stat_t_trait<uint16_t>;
  using stat_double_t = stat_t_trait<double>;
}
