#ifndef MTASKER_CONTEXT_HH
#define MTASKER_CONTEXT_HH

#include "lazy_allocator.hh"
#include <boost/function.hpp>
#include <vector>
#include <exception>

struct pdns_ucontext_t {
    pdns_ucontext_t ();
    pdns_ucontext_t (pdns_ucontext_t const&) = delete;
    pdns_ucontext_t& operator= (pdns_ucontext_t const&) = delete;
    ~pdns_ucontext_t ();

    void* uc_mcontext;
    pdns_ucontext_t* uc_link;
    std::vector<char, lazy_allocator<char>> uc_stack;
    std::exception_ptr exception;
};

void
pdns_swapcontext
(pdns_ucontext_t& __restrict octx, pdns_ucontext_t const& __restrict ctx);

void
pdns_makecontext
(pdns_ucontext_t& ctx, boost::function<void(void)>& start);

#endif // MTASKER_CONTEXT_HH
