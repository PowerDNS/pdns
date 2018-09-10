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
#include "mtasker_context.hh"
#include <system_error>
#include <exception>
#include <cstring>
#include <cassert>
#include <signal.h>
#include <ucontext.h>

#ifdef PDNS_USE_VALGRIND
#include <valgrind/valgrind.h>
#endif /* PDNS_USE_VALGRIND */

#ifdef HAVE_FIBER_SANITIZER
__thread void* t_mainStack{nullptr};
__thread size_t t_mainStackSize{0};
#endif /* HAVE_FIBER_SANITIZER */

template <typename Message> static __attribute__((noinline, cold, noreturn))
void
throw_errno (Message&& msg) {
    throw std::system_error
            (errno, std::system_category(), std::forward<Message>(msg));
}

static inline
std::pair<int, int>
splitPointer (void* const ptr) noexcept {
    static_assert (sizeof(int) == 4, "splitPointer() requires an 4 byte 'int'");
// In theory, we need this assertion. In practice, it prevents compilation
// on EL6 i386. Without the assertion, everything works.
// If you ever run into trouble with this code, please heed the warnings at
// http://man7.org/linux/man-pages/man3/makecontext.3.html#NOTES
//    static_assert (sizeof(uintptr_t) == 8,
//                    "splitPointer() requires an 8 byte 'uintptr_t'");
    std::pair<int, int> words;
    auto rep = reinterpret_cast<uintptr_t>(ptr);
    uint32_t const hw = rep >> 32;
    auto const lw = static_cast<uint32_t>(rep);
    std::memcpy (&words.first, &hw, 4);
    std::memcpy (&words.second, &lw, 4);
    return words;
}

template <typename T> static inline
T*
joinPtr (int const first, int const second) noexcept {
    static_assert (sizeof(int) == 4, "joinPtr() requires an 4 byte 'int'");
// See above.
//    static_assert (sizeof(uintptr_t) == 8,
//                    "joinPtr() requires an 8 byte 'uintptr_t'");
    uint32_t hw;
    uint32_t lw;
    std::memcpy (&hw, &first, 4);
    std::memcpy (&lw, &second, 4);
    return reinterpret_cast<T*>((static_cast<uintptr_t>(hw) << 32) | lw);
}

extern "C" {
static
void
threadWrapper (int const ctx0, int const ctx1, int const fun0, int const fun1) {
    notifyStackSwitchDone();
    auto ctx = joinPtr<pdns_ucontext_t>(ctx0, ctx1);
    try {
        auto start = std::move(*joinPtr<boost::function<void()>>(fun0, fun1));
        start();
    } catch (...) {
        ctx->exception = std::current_exception();
    }
    notifyStackSwitchToKernel();
}
} // extern "C"

pdns_ucontext_t::pdns_ucontext_t() {
    uc_mcontext = new ::ucontext_t();
    uc_link = nullptr;
#ifdef PDNS_USE_VALGRIND
    valgrind_id = 0;
#endif /* PDNS_USE_VALGRIND */
}

pdns_ucontext_t::~pdns_ucontext_t() {
    delete static_cast<ucontext_t*>(uc_mcontext);
#ifdef PDNS_USE_VALGRIND
    if (valgrind_id != 0) {
      VALGRIND_STACK_DEREGISTER(valgrind_id);
    }
#endif /* PDNS_USE_VALGRIND */
}

void
pdns_swapcontext
(pdns_ucontext_t& __restrict octx, pdns_ucontext_t const& __restrict ctx) {
    if (::swapcontext (static_cast<ucontext_t*>(octx.uc_mcontext),
                       static_cast<ucontext_t*>(ctx.uc_mcontext))) {
        throw_errno ("swapcontext() failed");
    }
    if (ctx.exception) {
        std::rethrow_exception (ctx.exception);
    }
}

void
pdns_makecontext
(pdns_ucontext_t& ctx, boost::function<void(void)>& start) {
    assert (ctx.uc_link);
    assert (ctx.uc_stack.size());

    auto const mcp = static_cast<ucontext_t*>(ctx.uc_mcontext);
    auto const next = static_cast<ucontext_t*>(ctx.uc_link->uc_mcontext);
    if (::getcontext (mcp)) {
        throw_errno ("getcontext() failed");
    }
    mcp->uc_link = next;
    mcp->uc_stack.ss_sp = ctx.uc_stack.data();
    mcp->uc_stack.ss_size = ctx.uc_stack.size()-1;
    mcp->uc_stack.ss_flags = 0;

    auto ctxarg = splitPointer (&ctx);
    auto funarg = splitPointer (&start);
    return ::makecontext (mcp, reinterpret_cast<void(*)(void)>(&threadWrapper),
                          4, ctxarg.first, ctxarg.second,
                          funarg.first, funarg.second);
}
