# Sanitizers

subdir('address-sanitizer')

sanitizers = {
  'memory': 'Memory',
  'thread': 'Thread',
  'leak': 'Leak',
  'undefined': 'Undefined Behavior',
}

foreach sanitizer, name: sanitizers
  opt_name = 'opt_' + sanitizer + '_sanitizer'
  set_variable(opt_name, get_option('sanitizer-' + sanitizer))

  if not get_variable(opt_name)
    continue
  endif

  compiler_opt = '-fsanitize=' + sanitizer
  if not cxx.has_argument(compiler_opt)
    error(name + ' Sanitizer requested but compiler does not support `' + compiler_opt + '`')
  endif
  add_global_arguments(compiler_opt)
  summary(name, get_variable(opt_name), bool_yn: true, section: 'Sanitizers')
endforeach

if opt_address_sanitizer and opt_thread_sanitizer
  error('Address Sanitizer is not compatible with Thread Sanitizer')
endif

if opt_memory_sanitizer and opt_address_sanitizer
  error('Memory Sanitizer is not compatible with Address Sanitizer')
endif

if opt_memory_sanitizer and opt_leak_sanitizer
  error('Memory Sanitizer is not compatible with Leak Sanitizer')
endif

if opt_memory_sanitizer and opt_thread_sanitizer
  error('Memory Sanitizer is not compatible with Thread Sanitizer')
endif

if opt_address_sanitizer or opt_thread_sanitizer or opt_leak_sanitizer or opt_undefined_behavior_sanitizer or opt_memory_sanitizer
  add_global_arguments('-fno-omit-frame-pointer')
endif
