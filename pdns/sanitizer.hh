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
 * Foundation, Inc.
 */
#pragma once

/* g++ defines __SANITIZE_THREAD__
   clang++ supports the nice __has_feature(thread_sanitizer),
   let's merge them */
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __SANITIZE_THREAD__ 1
#endif
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif

#if __SANITIZE_THREAD__
#if defined(__has_include)
#if __has_include(<sanitizer/tsan_interface.h>)
#include <sanitizer/tsan_interface.h>
#else /* __has_include(<sanitizer/tsan_interface.h>) */
extern "C" void __tsan_acquire(void* addr);
extern "C" void __tsan_release(void* addr);
#endif /* __has_include(<sanitizer/tsan_interface.h>) */
#else /* defined(__has_include) */
extern "C" void __tsan_acquire(void* addr);
extern "C" void __tsan_release(void* addr);
#endif /* defined(__has_include) */
#else
#define __tsan_acquire(x)
#define __tsan_release(x)
#endif /* __SANITIZE_THREAD__ */
