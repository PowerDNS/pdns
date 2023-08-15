opt = get_option('experimental-pkcs11')

dep_pkcs11 = dependency('p11-kit-1', required: opt)
conf.set('HAVE_P11KIT1', dep_pkcs11.found(), description: 'Have p11-kit-1')

prog = fs.read('p11_kit_module_for_name.cc')
have = cxx.links(prog, dependencies: dep_pkcs11, name: 'we can link to p11kit1')
conf.set('HAVE_P11KIT1_V2', have, description: 'Have p11-kit-1 0.20 or newer')

if not have
  warning('Could not find p11-kit-1')
endif
