#pragma once

#include "config.h"

#ifdef HAVE_PROTOBUF
#include <boost/uuid/uuid.hpp>
#endif

struct ResolveContext {
  ResolveContext()
  {
  }

  ResolveContext(const ResolveContext& ctx) = delete;
  ResolveContext & operator=(const ResolveContext&) = delete;
  
#ifdef HAVE_PROTOBUF
  boost::optional<const boost::uuids::uuid&> d_initialRequestId;
#endif
#ifdef HAVE_FSTRM
  boost::optional<const DNSName&> d_auth;
#endif
};
