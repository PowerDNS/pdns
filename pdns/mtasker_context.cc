#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_BOOST_CONTEXT)
#include "mtasker_fcontext.cc"
#else
#include "mtasker_ucontext.cc"
#endif
