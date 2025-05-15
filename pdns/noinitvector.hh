#pragma once

#include <cstdint>
#include <memory>
#include <new>
#include <utility>
#include <vector>

// based on boost::core::noinit_adaptor
// The goal is to avoid initialization of the content of a container,
// because setting several kB of uint8_t to 0 has a real cost if you
// do 100k times per second.
template<class Allocator>
struct noinit_adaptor: Allocator
{
  template<class U>
  struct rebind {
    typedef noinit_adaptor<typename std::allocator_traits<Allocator>::template
                           rebind_alloc<U> > other;
    };

  noinit_adaptor(): Allocator() { }

  template<class U>
  noinit_adaptor(U&& u) noexcept : Allocator(std::forward<U>(u)) { }

  template<class U>
  noinit_adaptor(const noinit_adaptor<U>& u) noexcept : Allocator(static_cast<const U&>(u)) { }

  template<class U>
  void construct(U* p) {
    ::new((void*)p) U;
  }

  template<class U, class V, class... Args>
  void construct(U* p, V&& v, Args&&... args) {
    ::new((void*)p) U(std::forward<V>(v), std::forward<Args>(args)...);
  }

  template<class U>
  void destroy(U* p) {
    p->~U();
  }
};

template<class T, class U>
inline bool operator==(const noinit_adaptor<T>& lhs,
                       const noinit_adaptor<U>& rhs) noexcept
{
  return static_cast<const T&>(lhs) == static_cast<const U&>(rhs);
}

template<class T, class U>
inline bool operator!=(const noinit_adaptor<T>& lhs,
                       const noinit_adaptor<U>& rhs) noexcept
{
  return !(lhs == rhs);
}

template<class Allocator>
inline noinit_adaptor<Allocator> noinit_adapt(const Allocator& a) noexcept
{
  return noinit_adaptor<Allocator>(a);
}

template<class T> using NoInitVector = std::vector<T, noinit_adaptor<std::allocator<T>>>;

using PacketBuffer = NoInitVector<uint8_t>;
