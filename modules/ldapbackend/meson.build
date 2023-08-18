sources = [
  'ldapauthenticator.cc',
  'ldapbackend.cc',
  'ldaputils.cc',
  'master.cc',
  'native.cc',
  'powerldap.cc',
]

extras = [
  'exceptions.hh',
  'ldapauthenticator.hh',
  'ldapauthenticator_p.hh',
  'ldapbackend.hh',
  'ldaputils.hh',
  'powerldap.hh',
  'utils.hh',

  'dnsdomain2.schema',
  'pdns-domaininfo.schema',
]

deps = [dep_pdns, dep_libcrypto, dep_ldap]

set_variable('dep_' + module_backend_name, dependency('', required: false))
if module_opt
  lib = static_library(module_backend_name, sources, dependencies: deps, extra_files: extras)
  set_variable('dep_' + module_backend_name, lib)
endif

if module_opt_dyn
  shared_module(module_backend_name, sources, dependencies: deps, extra_files: extras)
endif
