timet_size = cxx.sizeof('time_t', prefix: '#include <sys/types.h>')

if timet_size < 8
  error('size of time_t is ' +
        timet_size.to_string() +
        ' which is not large enough to fix the y2k38 bug')
endif

summary('Size of time_t', timet_size, section: 'System')
