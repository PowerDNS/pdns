opt_redis = get_option('redis')
dep_redis = dependency('hiredis', required: opt_redis)

if opt_redis.allowed()
  if not dep_redis.found()
    if cxx.has_header('hiredis/hiredis.h', required: false)
      if cxx.has_function('redisConnect', args: ['-lhiredis'])
        dep_redis = declare_dependency(link_args: ['-lhiredis'])
      endif
    endif
  endif
endif

conf.set('HAVE_REDIS', dep_redis.found(), description: 'Whether we have Redis')
summary('Redis', dep_redis.found(), bool_yn: true, section: 'Key-Value')
if dep_redis.found()
  summary('Redis version', dep_redis.version(), bool_yn: true, section: 'Key-Value')
endif
