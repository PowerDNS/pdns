prog = fs.read('strerror_r.c')

have_strerror_r_decl = cxx.has_header_symbol('string.h', 'strerror_r')
have_strerror_r = cxx.has_function('strerror_r', prefix: '#include <string.h>')
strerror_r_returns_charp = have_strerror_r and cxx.compiles(prog, name: 'strerror_r() returns char *')

conf.set('HAVE_DECL_STRERROR_R', have_strerror_r_decl, description: 'Whether strerror_r is declared')
conf.set('HAVE_STRERROR_R', have_strerror_r, description: 'Whether strerror_r is available')
conf.set('STRERROR_R_CHAR_P', strerror_r_returns_charp, description: 'Whether strerror_r returns char *')

summary('Symbol', have_strerror_r_decl, bool_yn: true, section: 'Function strerror_r')
summary('Declaration', have_strerror_r, bool_yn: true, section: 'Function strerror_r')
summary('Returns char *', strerror_r_returns_charp, bool_yn: true, section: 'Function strerror_r')
