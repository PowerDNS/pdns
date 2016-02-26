#include <boost/version.hpp>

/* Boost Context was introduced in 1.51 (Aug 2012), but it's probably not worth
 * supporting it because there was an immediate API break in 1.52 (Nov 2012)
 */
#if BOOST_VERSION <= 105100
#include "mtasker_ucontext.cc"
#else
#include "mtasker_fcontext.cc"
#endif
