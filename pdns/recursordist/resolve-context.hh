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

#include "config.h"

#include <boost/uuid/uuid.hpp>
#include <boost/optional.hpp>
#include <functional>

#include "dnsname.hh"

struct ResolveContext
{
  ResolveContext(const boost::optional<const boost::uuids::uuid&>& uuid, DNSName name) :
    d_initialRequestId(uuid), d_nsName(std::move(name))
  {}
  ~ResolveContext() = default;

  ResolveContext(const ResolveContext&) = delete;
  ResolveContext& operator=(const ResolveContext&) = delete;
  ResolveContext(ResolveContext&&) = delete;
  ResolveContext& operator=(ResolveContext&&) = delete;

  boost::optional<const boost::uuids::uuid&> d_initialRequestId;
  DNSName d_nsName;
#ifdef HAVE_FSTRM
  boost::optional<const DNSName&> d_auth;
#endif
};
