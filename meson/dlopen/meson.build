# dlopen
# Inputs: cxx deps

# dep_dlopen = dependency('dl', required: true) # TODO Meson 0.62
# deps += dep_dlopen

if cxx.has_function('dlopen')
  subdir_done()
endif

dl = cxx.find_library('dl', required: true)
if not cxx.has_function('dlopen', dependencies: dl)
  error('Your system does not support dlopen')
endif

deps += dl
