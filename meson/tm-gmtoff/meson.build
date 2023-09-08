prefix = '''
#include <sys/types.h>
#include <time.h>
'''

has = cxx.has_member('struct tm', 'tm_gmtoff', prefix: prefix)
conf.set('HAVE_TM_GMTOFF', has, description: 'Whether tm_gmtoff is available')
summary('tm_gmtoff', has, bool_yn: true, section: 'System')
