#pragma once

#include <cstddef>
#include <cinttypes>

extern "C"
{
  uint32_t arc4random(void);
  void arc4random_buf(void* buf, size_t nbytes);
  uint32_t arc4random_uniform(uint32_t upper_bound);
}
