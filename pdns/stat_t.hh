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

#define CPU_LEVEL1_DCACHE_LINESIZE 64 // Until we know better via configure/getconf

namespace pdns {
  template <typename T>
  class stat_t_trait {
  public:
    typedef T base_t;
    typedef std::atomic<base_t> atomic_t;

    stat_t_trait() : stat_t_trait(base_t(0)) {
    }
    stat_t_trait(const base_t x) {
      new(&counter) atomic_t(x);
    }
    ~stat_t_trait() {
      reinterpret_cast<atomic_t *>(&counter)->~atomic_t();
    }
    stat_t_trait(const stat_t_trait&) = delete;
    base_t operator++(int) {
      return (*reinterpret_cast<atomic_t *>(&counter))++;
    }
    base_t operator++() {
      return ++(*reinterpret_cast<atomic_t *>(&counter));
    }
    base_t operator--(int) {
      return (*reinterpret_cast<atomic_t *>(&counter))--;
    }
    base_t operator--() {
      return --(*reinterpret_cast<atomic_t *>(&counter));
    }
    base_t operator+=(const stat_t_trait& v) {
      return *reinterpret_cast<atomic_t *>(&counter) += *reinterpret_cast<const atomic_t *>(&v.counter);
    }
    base_t operator-=(const stat_t_trait& v) {
      return *reinterpret_cast<atomic_t *>(&counter) -= *reinterpret_cast<const atomic_t *>(&v.counter);
    }
    base_t load() const {
      return reinterpret_cast<const atomic_t *>(&counter)->load();
    }
    void store(base_t v) {
      reinterpret_cast<atomic_t *>(&counter)->store(v);
    }
    operator base_t() const {
      return reinterpret_cast<const atomic_t *>(&counter)->load();
    }

  private:
    typename std::aligned_storage<sizeof(base_t), CPU_LEVEL1_DCACHE_LINESIZE>::type counter;
  };

  typedef stat_t_trait<uint64_t> stat_t;
  typedef stat_t_trait<uint32_t> stat32_t;
  typedef stat_t_trait<uint16_t> stat16_t;
}
