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
#include <cstddef>
#include <utility>
#include <type_traits>
#include <new>
#include <sys/mman.h>
#include <unistd.h>

// On OpenBSD and NetBSD mem used as stack should be marked MAP_STACK
#if defined(__OpenBSD__) || defined(__NetBSD__)
#define PDNS_MAP_STACK MAP_STACK
#else
#define PDNS_MAP_STACK 0
#endif

template <typename T>
struct lazy_allocator
{
  using value_type = T;
  using pointer = T*;
  using size_type = std::size_t;
  static_assert(std::is_trivial<T>::value,
                "lazy_allocator must only be used with trivial types");

#ifndef LAZY_ALLOCATOR_USES_NEW
  /* Pad the requested size to be a multiple of page size, so that we can
     properly restrict read and write access to our guard pages only */
  static size_type getAlignmentPadding(size_type requestedSize, size_type pageSize)
  {
    size_type remaining = requestedSize % pageSize;
    if (remaining == 0) {
      return 0;
    }
    return pageSize - remaining;
  }
#endif /* LAZY_ALLOCATOR_USES_NEW */

  pointer
  allocate(size_type const n)
  {
#ifdef LAZY_ALLOCATOR_USES_NEW
    return static_cast<pointer>(::operator new(n * sizeof(value_type)));
#else /* LAZY_ALLOCATOR_USES_NEW */
    /* This implements a very basic protection against stack overflow
       by placing two guard pages around the requested memory: one
       page right before the new stack and one right after.
       The guard pages cannot be read or written to, any attempt to
       do so will trigger an immediate access violation, terminating
       the program.
       This is much better than the default behaviour for two reasons:
       1/ the program is stopped right before corrupting memory, which
          prevents random corruption
       2/ it's easy to find the point where the stack overflow occurred
       The memory overhead is two pages (usually 4k on Linux) per stack,
       and the runtime CPU overhead is one call to mprotect() for every
       stack allocation.
    */
    static const size_type pageSize = sysconf(_SC_PAGESIZE);

    const size_type requestedSize = n * sizeof(value_type);
    const auto padding = getAlignmentPadding(requestedSize, pageSize);
    const size_type allocatedSize = requestedSize + padding + (pageSize * 2);

#if defined(__OpenBSD__) || defined(__NetBSD__)
    // OpenBSD and NetBSD don't like mmap MAP_STACK regions that have
    // PROT_NONE, so allocate r/w and mprotect the guard pages
    // explicitly.
    const int protection = PROT_READ | PROT_WRITE;
#else
    const int protection = PROT_NONE;
#endif
    void* p = mmap(nullptr, allocatedSize, protection, MAP_PRIVATE | MAP_ANON | PDNS_MAP_STACK, -1, 0);
    if (p == MAP_FAILED) {
      throw std::bad_alloc();
    }
    char* basePointer = static_cast<char*>(p);
    void* usablePointer = basePointer + pageSize;
#if defined(__OpenBSD__) || defined(__NetBSD__)
    int res = mprotect(basePointer, pageSize, PROT_NONE);
    if (res != 0) {
      munmap(p, allocatedSize);
      throw std::bad_alloc();
    }
    res = mprotect(basePointer + allocatedSize - pageSize, pageSize, PROT_NONE);
#else
    int res = mprotect(usablePointer, allocatedSize - (pageSize * 2), PROT_READ | PROT_WRITE);
#endif
    if (res != 0) {
      munmap(p, allocatedSize);
      throw std::bad_alloc();
    }
    return static_cast<pointer>(usablePointer);
#endif
  }

  void
  deallocate(pointer const ptr, size_type const n) noexcept
  {
#ifdef LAZY_ALLOCATOR_USES_NEW
#if defined(__cpp_sized_deallocation) && (__cpp_sized_deallocation >= 201309)
    ::operator delete(ptr, n * sizeof(value_type));
#else
    (void)n;
    ::operator delete(ptr);
#endif
#else /* LAZY_ALLOCATOR_USES_NEW */
    static const size_type pageSize = sysconf(_SC_PAGESIZE);

    const size_type requestedSize = n * sizeof(value_type);
    const auto padding = getAlignmentPadding(requestedSize, pageSize);
    const size_type allocatedSize = requestedSize + padding + (pageSize * 2);

    void* basePointer = static_cast<char*>(ptr) - pageSize;
    munmap(basePointer, allocatedSize);
#endif /* LAZY_ALLOCATOR_PROTECT */
  }

  void construct(T*) const noexcept {}

  template <typename X, typename... Args>
  void
  construct(X* place, Args&&... args) const noexcept
  {
    new (static_cast<void*>(place)) X(std::forward<Args>(args)...);
  }
};

template <typename T>
inline bool operator==(lazy_allocator<T> const&, lazy_allocator<T> const&) noexcept
{
  return true;
}

template <typename T>
inline bool operator!=(lazy_allocator<T> const&, lazy_allocator<T> const&) noexcept
{
  return false;
}
