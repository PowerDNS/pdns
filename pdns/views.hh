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

#include <string_view>

namespace pdns::views
{

class UnsignedCharView
{
public:
  UnsignedCharView(const char* data_, size_t size_) :
    view(data_, size_)
  {
  }
  // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast): No unsigned char view in C++17
  UnsignedCharView(const unsigned char* data_, size_t size_) :
    view(reinterpret_cast<const char*>(data_), size_)
  {
  }
  using size_type = std::string_view::size_type;

  [[nodiscard]] const unsigned char& at(size_type pos) const
  {
    return reinterpret_cast<const unsigned char&>(view.at(pos));
  }

  [[nodiscard]] const unsigned char& operator[](size_type pos) const
  {
    return reinterpret_cast<const unsigned char&>(view[pos]);
  }

  [[nodiscard]] const unsigned char* data() const
  {
    return reinterpret_cast<const unsigned char*>(view.data());
  }
  // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast): No unsigned char view in C++17

  [[nodiscard]] size_t size() const
  {
    return view.size();
  }

  [[nodiscard]] size_t length() const
  {
    return view.length();
  }

private:
  std::string_view view;
};

}
