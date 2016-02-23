#include "mtasker_context.hh"
#include <exception>
#include <cassert>
#include <type_traits>
#include <boost/context/fcontext.hpp>
#include <boost/version.hpp>

using boost::context::make_fcontext;

#if BOOST_VERSION < 105600
using fcontext_t = boost::context::fcontext_t*;

static inline intptr_t
jump_fcontext (fcontext_t* const ofc, fcontext_t const nfc, 
               intptr_t const arg) {
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

struct args_t {
    fcontext_t prev_ctx = nullptr;
    pdns_ucontext_t* self = nullptr;
    std::function<void(void)>* work = nullptr;
};

extern "C" {
static
void
threadWrapper (intptr_t const xargs) {
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
(pdns_ucontext_t& ctx, std::function<void(void)>& start) {
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
