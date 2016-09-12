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
#include <exception>
#include <cassert>
#include <type_traits>
#include <boost/context/fcontext.hpp>
#include <boost/version.hpp>

using boost::context::make_fcontext;

#if BOOST_VERSION < 105600
/* Note: This typedef means functions taking fcontext_t*, like jump_fcontext(),
 * now require a reinterpret_cast rather than a static_cast, since we're
 * casting from pdns_context_t->uc_mcontext, which is void**, to
 * some_opaque_struct**. In later versions fcontext_t is already void*. So if
 * you remove this, then fix the ugly.
 */
using fcontext_t = boost::context::fcontext_t*;

/* Emulate the >= 1.56 API for Boost 1.52 through 1.55 */
static inline intptr_t
jump_fcontext (fcontext_t* const ofc, fcontext_t const nfc, 
               intptr_t const arg) {
    /* If the fcontext_t is preallocated then use it, otherwise allocate one
     * on the stack ('self') and stash a pointer away in *ofc so the returning
     * MThread can access it. This is safe because we're suspended, so the
     * context object always outlives the jump.
     */
    if (*ofc) {
        return boost::context::jump_fcontext (*ofc, nfc, arg);
    } else {
        boost::context::fcontext_t self;
        *ofc = &self;
        auto ret = boost::context::jump_fcontext (*ofc, nfc, arg);
        *ofc = nullptr;
        return ret;
    }
}
#else
using boost::context::fcontext_t;
using boost::context::jump_fcontext;

static_assert (std::is_pointer<fcontext_t>::value,
               "Boost Context has changed the fcontext_t type again :-(");
#endif

/* Boost context only provides a means of passing a single argument across a
 * jump. args_t simply provides a way to pass more by reference.
 */
struct args_t {
    fcontext_t prev_ctx = nullptr;
    pdns_ucontext_t* self = nullptr;
    boost::function<void(void)>* work = nullptr;
};

extern "C" {
static
void
threadWrapper (intptr_t const xargs) {
    /* Access the args passed from pdns_makecontext, and copy them directly from
     * the calling stack on to ours (we're now using the MThreads stack).
     * This saves heap allocating an args object, at the cost of an extra
     * context switch to fashion this constructor-like init phase. The work
     * function object is still only moved after we're (re)started, so may
     * still be set or changed after a call to pdns_makecontext. This matches
     * the behaviour of the System V implementation, which can inherently only
     * be passed ints and pointers.
     */
    auto args = reinterpret_cast<args_t*>(xargs);
    auto ctx = args->self;
    auto work = args->work;
    jump_fcontext (reinterpret_cast<fcontext_t*>(&ctx->uc_mcontext),
                   static_cast<fcontext_t>(args->prev_ctx), 0);
    args = nullptr;

    try {
        auto start = std::move (*work);
        start();
    } catch (...) {
        ctx->exception = std::current_exception();
    }

    /* Emulate the System V uc_link feature. */
    auto const next_ctx = ctx->uc_link->uc_mcontext;
    jump_fcontext (reinterpret_cast<fcontext_t*>(&ctx->uc_mcontext),
                   static_cast<fcontext_t>(next_ctx),
                   static_cast<bool>(ctx->exception));
#ifdef NDEBUG
    __builtin_unreachable();
#endif
}
}

pdns_ucontext_t::pdns_ucontext_t
(): uc_mcontext(nullptr), uc_link(nullptr) {
}

pdns_ucontext_t::~pdns_ucontext_t
() {
    /* There's nothing to delete here since fcontext doesn't require anything
     * to be heap allocated.
     */
}

void
pdns_swapcontext
(pdns_ucontext_t& __restrict octx, pdns_ucontext_t const& __restrict ctx) {
    if (jump_fcontext (reinterpret_cast<fcontext_t*>(&octx.uc_mcontext),
                       static_cast<fcontext_t>(ctx.uc_mcontext), 0)) {
        std::rethrow_exception (ctx.exception);
    }
}

void
pdns_makecontext
(pdns_ucontext_t& ctx, boost::function<void(void)>& start) {
    assert (ctx.uc_link);
    assert (ctx.uc_stack.size() >= 8192);
    assert (!ctx.uc_mcontext);
    ctx.uc_mcontext = make_fcontext (&ctx.uc_stack[ctx.uc_stack.size()],
                                     ctx.uc_stack.size(), &threadWrapper);
    args_t args;
    args.self = &ctx;
    args.work = &start;
    jump_fcontext (reinterpret_cast<fcontext_t*>(&args.prev_ctx),
                   static_cast<fcontext_t>(ctx.uc_mcontext),
                   reinterpret_cast<intptr_t>(&args));
}
