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

#include <cinttypes>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace dnsdist::metrics
{
  using Error = std::string;

  [[nodiscard]] std::optional<Error> declareCustomMetric(const std::string& name, const std::string& type, const std::string& description, std::optional<std::string> customName);
  [[nodiscard]] std::variant<uint64_t, Error> incrementCustomCounter(const std::string_view& name, uint64_t step);
  [[nodiscard]] std::variant<uint64_t, Error> decrementCustomCounter(const std::string_view& name, uint64_t step);
  [[nodiscard]] std::variant<double, Error> setCustomGauge(const std::string_view& name, const double value);
  [[nodiscard]] std::variant<double, Error> getCustomMetric(const std::string_view& name);
}
