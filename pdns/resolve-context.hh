#pragma once

#include "config.h"

#include <boost/uuid/uuid.hpp>
#include <boost/optional.hpp>

struct ResolveContext {
  ResolveContext()
  {
  }

  ResolveContext(const ResolveContext& ctx) = delete;
  ResolveContext & operator=(const ResolveContext&) = delete;
  
  boost::optional<const boost::uuids::uuid&> d_initialRequestId;
#ifdef HAVE_FSTRM
  boost::optional<const DNSName&> d_auth;
#endif
};
