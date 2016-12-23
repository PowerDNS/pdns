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
