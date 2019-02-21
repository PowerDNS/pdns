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
#ifndef PDNS_NAMESPACES_HH
#define PDNS_NAMESPACES_HH
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

using std::vector;
using std::map;
using std::pair;
using std::make_pair;
using std::runtime_error;
using std::ostringstream;
using std::set;
using std::deque;
using std::cerr;
using std::cout;
using std::clog;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::ostream;
using std::min; // these are a bit scary, everybody uses 'min'
using std::max;
using std::string;

using boost::tie;
using std::shared_ptr;
using std::unique_ptr;
using boost::shared_array;
using boost::scoped_array;
using boost::tuple;
using boost::format;
using boost::make_tuple;
using boost::optional;
using boost::any_cast;
using boost::any;
using boost::function;
using boost::trim;
using boost::trim_copy;
using boost::trim_left;
using boost::trim_right;
using boost::is_any_of;
using boost::trim_right_copy_if;
using boost::equals;
using boost::ends_with;
using boost::iends_with;

#endif
