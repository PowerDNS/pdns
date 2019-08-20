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

// Disable the non-threadsafe debug code in boost::circular_buffer before 1.62
#define BOOST_CB_DISABLE_DEBUG 1

// Make sure it is also disabled when >= 1.62
#ifndef BOOST_CB_ENABLE_DEBUG
#define BOOST_CB_ENABLE_DEBUG 0
#endif

#if BOOST_CB_ENABLE_DEBUG
// https://github.com/boostorg/circular_buffer/pull/9
// https://svn.boost.org/trac10/ticket/6277
#error Building with BOOST_CB_ENABLE_DEBUG prevents accessing a boost::circular_buffer from more than one thread at once
#endif /* BOOST_CB_ENABLE_DEBUG */

#include <boost/circular_buffer.hpp>
