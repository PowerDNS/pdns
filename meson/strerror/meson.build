# Strerror_r
# Inputs: conf

prog = '''
#include <string.h>
int main () {
    char error_string[256];
    char *ptr = strerror_r(-2, error_string, 256);
    char c = *strerror_r(-2, error_string, 256);
    return c != 0 && ptr != (void*) 0L;
}
'''

have_strerror_r_decl = cxx.has_header_symbol('string.h', 'strerror_r')
have_strerror_r = cxx.has_function('strerror_r', prefix: '#include <string.h>')
strerror_r_returns_charp = have_strerror_r and cxx.compiles(prog, name: 'strerror_r() returns char *')

conf.set10('HAVE_DECL_STRERROR_R', have_strerror_r_decl, description: 'Whether strerror_r is declared')
conf.set10('HAVE_STRERROR_R', have_strerror_r, description: 'Whether strerror_r is available')
conf.set10('STRERROR_R_CHAR_P', strerror_r_returns_charp, description: 'Whether strerror_r returns char *')

summary('strerror_r decl', have_strerror_r_decl, section: 'System')
summary('strerror_r', have_strerror_r, section: 'System')
summary('strerror_r returns char *', strerror_r_returns_charp, section: 'System')
