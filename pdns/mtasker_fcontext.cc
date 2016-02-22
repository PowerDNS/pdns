#include "mtasker_context.hh"
#include <exception>
#include <cassert>
#include <boost/context/fcontext.hpp>

using boost::context::fcontext_t;
using boost::context::jump_fcontext;
using boost::context::make_fcontext;

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
    jump_fcontext (&ctx->uc_mcontext, args->prev_ctx, 0);
    args = nullptr;

    try {
        auto start = std::move (*work);
        start();
    } catch (...) {
        ctx->exception = std::current_exception();
    }

    auto const next_ctx = ctx->uc_link->uc_mcontext;
    jump_fcontext (&ctx->uc_mcontext, next_ctx,
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
    if (jump_fcontext (&octx.uc_mcontext, ctx.uc_mcontext, 0)) {
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
    jump_fcontext (&args.prev_ctx, ctx.uc_mcontext,
                   reinterpret_cast<intptr_t>(&args));
}
