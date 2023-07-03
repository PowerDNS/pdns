# Pthread setname madness
# Inputs: conf

pthread_np_prefix = '''
#include <pthread.h>
#if HAVE_PTHREAD_NP_H
#  include <pthread_np.h>
#endif
'''

variants = [
  [
    '2-arg pthread_setname_np', 'HAVE_PTHREAD_SETNAME_NP_2', 'pthread_setname_np takes 2 arguments (Linux/glibc, QNX, IBM)',
    '''int main() { pthread_setname_np(pthread_self(), "foo"); return 0; }''',
  ],
  [
    '2-arg pthread_set_name_np', 'HAVE_PTHREAD_SET_NAME_NP_2', 'pthread_set_name_np takes 2 arguments and does not return void (FreeBSD, OpenBSD)',
    '''int main() { return pthread_set_name_np(pthread_self(), "foo"); }''',
  ],
  [
    '2-arg void pthread_set_name_np', 'HAVE_PTHREAD_SET_NAME_NP_2_VOID', 'pthread_set_name_np takes 2 arguments and returns void (FreeBSD, OpenBSD)',
    '''int main() { pthread_set_name_np(pthread_self(), "foo"); return 0; }''',
  ],
  [
    '1-arg pthread_setname_np', 'HAVE_PTHREAD_SETNAME_NP_1', 'pthread_setname_np takes 1 argument (Darwin, MacOS)',
    '''int main() { return pthread_setname_np("foo"); }''',
  ],
  [
    '3-arg pthread_setname_np', 'HAVE_PTHREAD_SETNAME_NP_3', 'pthread_setname_np takes 3 arguments (NetBSD)',
    '''int main() { return pthread_setname_np(pthread_self(), "foo", NULL); }''',
  ],
]

found = false
foreach variant: variants
  variant_name = variant[0]
  variant_define = variant[1]
  variant_description = variant[2]
  variant_program = variant[3]

  if cxx.links(pthread_np_prefix + variant_program, name: variant_name)
    found = true
    conf.set10(variant_define, true, description: variant_description)
    summary('pthread_setname', variant_define + ' - ' + variant_description, section: 'System')
    break
  endif
endforeach

if not found
  error('Could not find a suitable pthread_setname function')
endif
