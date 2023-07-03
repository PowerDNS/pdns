# Check for the tm_gmtoff field in struct tm
# Inputs: conf

prefix = '''
#include <sys/types.h>
#include <time.h>
'''

has = cxx.has_member('struct tm', 'tm_gmtoff', prefix: prefix)
conf.set10('HAVE_TM_GMTOFF', has, description: 'Whether tm_gmtoff is available')
summary('tm_gmtoff', has, bool_yn: true, section: 'System')
