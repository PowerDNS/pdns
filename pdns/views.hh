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

#ifdef __cpp_lib_string_view
using pdns_string_view = std::string_view;
#else
#include <boost/version.hpp>
#if BOOST_VERSION >= 106400
// string_view already exists in 1.61.0 but string_view::at() is not usable with modern compilers, see:
// https://github.com/boostorg/utility/pull/26
#include <boost/utility/string_view.hpp>
using pdns_string_view = boost::string_view;
#elif BOOST_VERSION >= 105300
#include <boost/utility/string_ref.hpp>
using pdns_string_view = boost::string_ref;
#else

/* this class implements a very restricted view, since nothing else is available
   and doing a full allocation + copy is just dumb */
class pdns_string_view
{
public:
  pdns_string_view() noexcept
  {
  }

  pdns_string_view(const std::string& str) noexcept: d_ptr{str.data()}, d_size(str.size())
  {
  }

  pdns_string_view(const char* str, size_t len) noexcept: d_ptr{str}, d_size(len)
  {
  }

  size_t size() const noexcept
  {
    return d_size;
  }

  const char& at(size_t pos) const
  {
    if (pos >= d_size) {
      throw std::out_of_range("pdns_string_view::at() " + std::to_string(pos) + " >= " + std::to_string(d_size));
    }
    return *(d_ptr + pos);
  }

  const char* data() const noexcept
  {
    return d_ptr;
  }

private:
  const char* d_ptr{nullptr};
  const size_t d_size{0};
};

#endif
#endif
