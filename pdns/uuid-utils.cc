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

#include "uuid-utils.hh"

// see https://github.com/boostorg/random/issues/49
#if BOOST_VERSION == 106900
#ifndef BOOST_PENDING_INTEGER_LOG2_HPP
#define BOOST_PENDING_INTEGER_LOG2_HPP
#include <boost/integer/integer_log2.hpp>
#endif /* BOOST_PENDING_INTEGER_LOG2_HPP */
#endif /* BOOST_VERSION */

#include <boost/uuid/uuid_generators.hpp>

thread_local boost::uuids::random_generator t_uuidGenerator;

boost::uuids::uuid getUniqueID()
{
  return t_uuidGenerator();
}

boost::uuids::uuid getUniqueID(const std::string& str)
{
  boost::uuids::string_generator gen;
  return gen(str);
}

