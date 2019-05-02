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
#ifndef LAZY_ALLOCATOR_HH
#define LAZY_ALLOCATOR_HH

#include <cstddef>
#include <utility>
#include <type_traits>
#include <new>
#include <sys/mman.h>

// On OpenBSD mem used as stack should be marked MAP_STACK
#if !defined(MAP_STACK)
#define MAP_STACK 0
#endif

template <typename T>
struct lazy_allocator {
    using value_type = T;
    using pointer = T*;
    using size_type = std::size_t;
    static_assert (std::is_trivial<T>::value,
                   "lazy_allocator must only be used with trivial types");

    pointer
    allocate (size_type const n) {
#ifdef __OpenBSD__
        void *p = mmap(nullptr, n * sizeof(value_type),
          PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_STACK, -1, 0);
        if (p == MAP_FAILED)
          throw std::bad_alloc();
        return static_cast<pointer>(p);
#else
        return static_cast<pointer>(::operator new (n * sizeof(value_type)));
#endif
    }

    void
    deallocate (pointer const ptr, size_type const n) noexcept {
#ifdef __OpenBSD__
        munmap(ptr, n * sizeof(value_type));
#else
#if defined(__cpp_sized_deallocation) &&  (__cpp_sized_deallocation >= 201309)
        ::operator delete (ptr, n * sizeof(value_type));
#else
        (void) n;
        ::operator delete (ptr);
#endif
#endif
    }

    void construct (T*) const noexcept {}

    template <typename X, typename... Args>
    void
    construct (X* place, Args&&... args) const noexcept {
        new (static_cast<void*>(place)) X (std::forward<Args>(args)...);
    }
};

template <typename T> inline
bool operator== (lazy_allocator<T> const&, lazy_allocator<T> const&) noexcept {
    return true;
}

template <typename T> inline
bool operator!= (lazy_allocator<T> const&, lazy_allocator<T> const&) noexcept {
    return false;
}

#endif // LAZY_ALLOCATOR_HH
