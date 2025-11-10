#ifndef PROTOZERO_CONFIG_HPP
#define PROTOZERO_CONFIG_HPP

/*****************************************************************************

protozero - Minimalistic protocol buffer decoder and encoder in C++.

This file is from https://github.com/mapbox/protozero where you can find more
documentation.

*****************************************************************************/

#include <cassert>

/**
 * @file config.hpp
 *
 * @brief Contains macro checks for different configurations.
 */

#if __has_include(<endian.h>)
#include <endian.h> // Recent posix
#elif __has_include(<machine/endian.h>)
#include <machine/endian.h> // Common place on older BSD derived systems
#else
#error no endian.h found
#endif

#define PROTOZERO_LITTLE_ENDIAN 1234
#define PROTOZERO_BIG_ENDIAN    4321

// Find out which byte order the machine has.
#if defined(__BYTE_ORDER)
# if (__BYTE_ORDER == __LITTLE_ENDIAN)
#  define PROTOZERO_BYTE_ORDER PROTOZERO_LITTLE_ENDIAN
# endif
# if (__BYTE_ORDER == __BIG_ENDIAN)
#  define PROTOZERO_BYTE_ORDER PROTOZERO_BIG_ENDIAN
# endif
#else
// This probably isn't a very good default, but might do until we figure
// out something better.
# define PROTOZERO_BYTE_ORDER PROTOZERO_LITTLE_ENDIAN
#endif

// Sanity check
static_assert(PROTOZERO_BYTE_ORDER == BYTE_ORDER);

// Check whether __builtin_bswap is available
#if defined(__GNUC__) || defined(__clang__)
# define PROTOZERO_USE_BUILTIN_BSWAP
#endif

// Wrapper for assert() used for testing
#ifndef protozero_assert
# define protozero_assert(x) assert(x)
#endif

#endif // PROTOZERO_CONFIG_HPP
