#pragma once

#include "config.h"

#ifdef HAVE_PROTOBUF
#include <boost/uuid/uuid.hpp>
#endif

struct ResolveContext {
  ResolveContext()
  {
  }
  ResolveContext(const ResolveContext& ctx)
  {
#ifdef HAVE_PROTOBUF
    this->d_initialRequestId = ctx.d_initialRequestId;
#endif
  }
#ifdef HAVE_PROTOBUF
  boost::optional<const boost::uuids::uuid&> d_initialRequestId;
#endif
};
