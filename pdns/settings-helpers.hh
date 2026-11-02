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

#include <mutex>
#include <optional>
#include <stdexcept>

namespace pdns::settings::helpers
{
template <class T>
class SetOnlyOnce
{
public:
  SetOnlyOnce() = default;
  SetOnlyOnce(const SetOnlyOnce&) = delete;
  SetOnlyOnce& operator=(const SetOnlyOnce&) = delete;
  SetOnlyOnce(SetOnlyOnce&&) = delete;
  SetOnlyOnce& operator=(SetOnlyOnce&&) = delete;
  ~SetOnlyOnce() = default;

  void set(T&& data)
  {
    bool updated = false;
    std::call_once(d_flag, [this, &data, &updated]() {
      d_data = std::move(data);
      updated = true;
    });
    if (!updated) {
      throw std::runtime_error("Trying to set SetOnlyOnce data after it has been set");
    }
  }

  const T& get()
  {
    if (!d_data.has_value()) {
      throw std::runtime_error("Trying to access SetOnlyOnce data that has not been set yet");
    }
    return d_data.value();
  }

private:
  std::optional<T> d_data;
  std::once_flag d_flag;
};

};
