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
 * along with this program.
 */
#pragma once

#include <variant>

// A poor man's std::expected, which only becomes available for real with C++23

namespace pdns
{
template <class E>
class unexpected
{
public:
  unexpected(const E& arg) :
    err(arg) {}
  const E& error() const
  {
    return err;
  }

private:
  E err;
};

template <class T, class E>
class expected : private std::variant<T, E>
{
public:
  expected(const T& arg) :
    std::variant<T, E>(arg) {}

  expected(const unexpected<E>& arg) :
    std::variant<T, E>(arg.error()) {}

  [[nodiscard]] bool has_value() const
  {
    return std::holds_alternative<T>(*this);
  }

  const T& value() const
  {
    return std::get<T>(*this);
  }
  const E& error() const
  {
    return std::get<E>(*this);
  }
};
}
