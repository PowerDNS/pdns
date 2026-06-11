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

#include <boost/any.hpp>
#include <boost/variant/recursive_variant.hpp>
#include <boost/variant/recursive_wrapper.hpp>
#include <boost/variant/variant.hpp>
#include <boost/variant/variant_fwd.hpp>
#include <string>
#include <unordered_map>
#include <vector>

template <class T>
using LuaArray = std::vector<std::pair<int, T>>;
template <class T>
using LuaAssociativeTable = std::unordered_map<std::string, T>;
template <class T>
using LuaTypeOrArrayOf = boost::variant<T, LuaArray<T>>;
using LuaAny = boost::make_recursive_variant<std::string, int64_t, uint64_t, double, bool, LuaArray<boost::recursive_variant_>, LuaAssociativeTable<boost::recursive_variant_>>::type;
