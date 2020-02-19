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
#include "lazy_allocator.hh"
#include <boost/function.hpp>
#include <vector>
#include <exception>

struct pdns_ucontext_t
{
  pdns_ucontext_t();
  pdns_ucontext_t(pdns_ucontext_t const&) = delete;
  pdns_ucontext_t& operator=(pdns_ucontext_t const&) = delete;
  ~pdns_ucontext_t();

  void* uc_mcontext;
  pdns_ucontext_t* uc_link;
  std::vector<char, lazy_allocator<char>> uc_stack;
  std::exception_ptr exception;
#ifdef PDNS_USE_VALGRIND
  int valgrind_id;
#endif /* PDNS_USE_VALGRIND */
};

void pdns_swapcontext(pdns_ucontext_t& __restrict octx, pdns_ucontext_t const& __restrict ctx);

void pdns_makecontext(pdns_ucontext_t& ctx, boost::function<void(void)>& start);

#ifdef HAVE_FIBER_SANITIZER
#include <sanitizer/common_interface_defs.h>
#endif /* HAVE_FIBER_SANITIZER */

#ifdef HAVE_FIBER_SANITIZER
extern __thread void* t_mainStack;
extern __thread size_t t_mainStackSize;
#endif /* HAVE_FIBER_SANITIZER */

static inline void notifyStackSwitch(void* startOfStack, size_t stackSize)
{
#ifdef HAVE_FIBER_SANITIZER
  __sanitizer_start_switch_fiber(nullptr, startOfStack, stackSize);
#endif /* HAVE_FIBER_SANITIZER */
}

static inline void notifyStackSwitchToKernel()
{
#ifdef HAVE_FIBER_SANITIZER
  notifyStackSwitch(t_mainStack, t_mainStackSize);
#endif /* HAVE_FIBER_SANITIZER */
}

static inline void notifyStackSwitchDone()
{
#ifdef HAVE_FIBER_SANITIZER
#ifdef HAVE_SANITIZER_FINISH_SWITCH_FIBER_SINGLE_PTR
  __sanitizer_finish_switch_fiber(nullptr);
#else /* HAVE_SANITIZER_FINISH_SWITCH_FIBER_SINGLE_PTR */
#ifdef HAVE_SANITIZER_FINISH_SWITCH_FIBER_THREE_PTRS
  __sanitizer_finish_switch_fiber(nullptr, nullptr, nullptr);
#endif /* HAVE_SANITIZER_FINISH_SWITCH_FIBER_THREE_PTRS */
#endif /* HAVE_SANITIZER_FINISH_SWITCH_FIBER_SINGLE_PTR */
#endif /* HAVE_FIBER_SANITIZER */
}
