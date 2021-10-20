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
#include <boost/format.hpp>
#include <boost/optional.hpp>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

// We have a few paces where boost::tuple is used, and other places where an unscoped tuple is used
// prefer the boost one for now. We might want to switch to std::tuple one day. Same for tie.
using boost::make_tuple;
using boost::tuple;
using boost::tie;

using std::cerr;
using std::clog;
using std::cout;
using std::endl;
using std::ifstream;
using std::make_unique;
using std::map;
using std::max;
using std::min;
using std::ofstream;
using std::ostream;
using std::ostringstream;
using std::pair;
using std::runtime_error;
using std::set;
using std::shared_ptr;
using std::string;
using std::unique_ptr;
using std::vector;

using pdns_string_view = std::string_view;
