#ifndef LAZY_ALLOCATOR_HH
#define LAZY_ALLOCATOR_HH

#include <cstddef>
#include <utility>
#include <type_traits>

template <typename T>
struct lazy_allocator {
    using value_type = T;
    using pointer = T*;
    using size_type = std::size_t;
    static_assert (std::is_trivial<T>::value,
                   "lazy_allocator must only be used with trivial types");

    pointer
    allocate (size_type const n) {
        return static_cast<pointer>(::operator new (n * sizeof(value_type)));
    }

    void
    deallocate (pointer const ptr, size_type const n) noexcept {
#if defined(__cpp_sized_deallocation) &&  (__cpp_sized_deallocation >= 201309)
        ::operator delete (ptr, n * sizeof(value_type));
#else
        (void) n;
        ::operator delete (ptr);
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
