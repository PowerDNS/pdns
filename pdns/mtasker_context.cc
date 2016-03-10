#include "config.h"

#if defined(HAVE_BOOST_CONTEXT)
#include "mtasker_fcontext.cc"
#else
#include "mtasker_ucontext.cc"
#endif
