#pragma once

#include <time.h>
//! This is a utility class used for platform independent abstraction.
class Utility
{
public:
  static time_t timegm(struct tm *const t);
};
