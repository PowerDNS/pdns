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
#include <boost/tuple/tuple.hpp>
#include <boost/shared_array.hpp>
#include <boost/scoped_array.hpp>
#include <boost/optional.hpp>
#include <boost/any.hpp>
#include <boost/function.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include <memory>
#include <vector>
#include <map>
#include <set>
#include <deque>
#include <string>
#include <iostream>

using std::cerr;
using std::clog;
using std::cout;
using std::deque;
using std::endl;
using std::ifstream;
using std::make_pair;
using std::map;
using std::max;
using std::min; // these are a bit scary, everybody uses 'min'
using std::ofstream;
using std::ostream;
using std::ostringstream;
using std::pair;
using std::runtime_error;
using std::set;
using std::string;
using std::vector;

using boost::any;
using boost::any_cast;
using boost::ends_with;
using boost::equals;
using boost::format;
using boost::function;
using boost::iends_with;
using boost::is_any_of;
using boost::make_tuple;
using boost::optional;
using boost::scoped_array;
using boost::shared_array;
using boost::tie;
using boost::trim;
using boost::trim_copy;
using boost::trim_left;
using boost::trim_right;
using boost::trim_right_copy_if;
using boost::tuple;
using std::shared_ptr;
using std::unique_ptr;
