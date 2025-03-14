project(
  'dnsdist',
  ['c', 'cpp'],
  version: run_command('version.sh', 'get-vcs', check: true).stdout().strip(),
  license: 'GPLv2',
  license_files: 'NOTICE',
  meson_version: '>= 1.3.0',
  default_options: [
    'buildtype=debugoptimized',
    'warning_level=2',          # TODO Move this to 3 to enable -Wpedantic
    'cpp_std=c++17',
    'b_pie=true',
  ],
)
meson.add_dist_script('meson-dist-script.sh')

# When running meson dist, the command below produces multiple lines on stderr:
# Unable to evaluate subdir([]) in AstInterpreter --> Skipping
meson.add_dist_script('version.sh', 'set-dist', meson.project_version())

add_project_arguments('-DDNSDIST', language: 'cpp')


product_source_dir = meson.current_source_dir()
product_build_dir = meson.current_build_dir()
summary('Source Dir', product_source_dir, section: 'Build')
summary('Build Dir', product_build_dir, section: 'Build')

# Create the configuration object and dependencies list.
conf = configuration_data()
conf.set_quoted('PACKAGE_STRING', 'dnsdist ' + meson.project_version(), description: 'dnsdist version')
conf.set_quoted('PACKAGE_VERSION', meson.project_version(), description: 'version')

# Feature detection and system configuration
subdir('meson' / 'config')                  # Config
subdir('meson' / 'version')                 # Generate version define
subdir('meson' / 'compiler-setup')          # Common compiler setup
subdir('meson' / 'summary')                 # Print a system/project summary
subdir('meson' / 'sysconfdir')              # Sysconfdir
subdir('meson' / 'platform')                # Platform detection
subdir('meson' / 'atomics')                 # Check atomics support
subdir('meson' / 'pthread-headers')         # Check pthread headers
subdir('meson' / 'pthread-setname')         # Pthread setname madness
subdir('meson' / 'pthread-np')              # Pthread _np functions
subdir('meson' / 'strerror')                # Strerror_r
subdir('meson' / 'lua')                     # Lua
subdir('meson' / 'hardening')               # Hardening
subdir('meson' / 'net-libs')                # Network Libraries
subdir('meson' / 'tm-gmtoff')               # Check for tm_gmtoff field in struct tm
subdir('meson' / 'mmap')                    # Check for mmap
subdir('meson' / 'libcap')                  # Libcap to drop capabilities
subdir('meson' / 'libedit')                 # Libedit
subdir('meson' / 'libsodium')               # Libsodium
subdir('meson' / 'libcrypto')               # OpenSSL libcrypto
subdir('meson' / 'libssl')                  # OpenSSL libssl
subdir('meson' / 'libssl-providers')        # OpenSSL libssl providers
subdir('meson' / 'libsnmp')                 # SNMP
subdir('meson' / 'clock-gettime')           # Clock_gettime
subdir('meson' / 'boost')                   # Boost
subdir('meson' / 'boost-test')              # Boost Testing Library
subdir('meson' / 'reproducible')            # Reproducible Builds
subdir('meson' / 'libsystemd')              # Systemd notification
subdir('meson' / 'systemd')                 # Systemd and unit file handling
subdir('meson' / 'code-coverage')           # Code coverage
subdir('meson' / 'auto-var-init')           # Automatic Variable Initialization
subdir('meson' / 'sanitizers')              # Sanitizers
subdir('meson' / 'various-functions')       # Various Functions
subdir('meson' / 'various-headers')         # Various Headers
subdir('meson' / 'dnstap')                  # DNSTAP through libfstream
subdir('meson' / 'dnscrypt')                # DNSCrypt through libsodium
subdir('meson' / 'ipcipher')                # IPCipher (requires libcrypto)
subdir('meson' / 'cdb')                     # CDB
subdir('meson' / 'ebpf')                    # eBPF
subdir('meson' / 'gnutls')                  # GNUTLS
subdir('meson' / 'h2o')                     # H2O
subdir('meson' / 'lmdb')                    # LMDB
subdir('meson' / 'nghttp2')                 # NGHTTP2
subdir('meson' / 'quiche')                  # Quiche
subdir('meson' / 're2')                     # RE2
subdir('meson' / 'xsk')                     # BPF and XDP for XSK
subdir('meson' / 'dot')                     # DNS over TLS
subdir('meson' / 'doh2')                    # DNS over HTTP/2
subdir('meson' / 'doq')                     # DNS over QUIC
subdir('meson' / 'doh3')                    # DNS over HTTP/3
subdir('meson' / 'yaml-configuration')      # YAML configuration

common_sources = []

fs = import('fs')
src_dir = fs.is_dir('.') ? '.' : ''
docs_dir = 'docs'
# Toplevel includes
dep_pdns = declare_dependency(include_directories: include_directories('.', src_dir))

# Ext
subdir('ext' / 'arc4random')
subdir('ext' / 'ipcrypt')
subdir('ext' / 'json11')
subdir('ext' / 'luawrapper')
subdir('ext' / 'protozero')
subdir('ext' / 'yahttp')

if dep_lmdb.found()
  subdir('ext' / 'lmdb-safe')
else
  dep_lmdb_safe = declare_dependency()
endif

if get_option('yaml').allowed()
  subdir('dnsdist-rust-lib')
else
  dep_dnsdist_rust_lib = declare_dependency()
endif

common_sources += files(
  src_dir / 'bpf-filter.cc',
  src_dir / 'capabilities.cc',
  src_dir / 'channel.cc',
  src_dir / 'coverage.cc',
  src_dir / 'credentials.cc',
  src_dir / 'dns.cc',
  src_dir / 'dnscrypt.cc',
  src_dir / 'dnsdist-actions.cc',
  src_dir / 'dnsdist-actions-factory.cc',
  src_dir / 'dnsdist-async.cc',
  src_dir / 'dnsdist-backend.cc',
  src_dir / 'dnsdist-cache.cc',
  src_dir / 'dnsdist-carbon.cc',
  src_dir / 'dnsdist-configuration.cc',
  src_dir / 'dnsdist-configuration-yaml.cc',
  src_dir / 'dnsdist-console.cc',
  src_dir / 'dnsdist-crypto.cc',
  src_dir / 'dnsdist-discovery.cc',
  src_dir / 'dnsdist-dnscrypt.cc',
  src_dir / 'dnsdist-dnsparser.cc',
  src_dir / 'dnsdist-dnsquestion.cc',
  src_dir / 'dnsdist-doh-common.cc',
  src_dir / 'dnsdist-dynblocks.cc',
  src_dir / 'dnsdist-dynbpf.cc',
  src_dir / 'dnsdist-ecs.cc',
  src_dir / 'dnsdist-edns.cc',
  src_dir / 'dnsdist-frontend.cc',
  src_dir / 'dnsdist-healthchecks.cc',
  src_dir / 'dnsdist-idstate.cc',
  src_dir / 'dnsdist-internal-queries.cc',
  src_dir / 'dnsdist-kvs.cc',
  src_dir / 'dnsdist-lbpolicies.cc',
  src_dir / 'dnsdist-lua-actions.cc',
  src_dir / 'dnsdist-lua-bindings.cc',
  src_dir / 'dnsdist-lua-bindings-dnscrypt.cc',
  src_dir / 'dnsdist-lua-bindings-dnsparser.cc',
  src_dir / 'dnsdist-lua-bindings-dnsquestion.cc',
  src_dir / 'dnsdist-lua-bindings-kvs.cc',
  src_dir / 'dnsdist-lua-bindings-network.cc',
  src_dir / 'dnsdist-lua-bindings-packetcache.cc',
  src_dir / 'dnsdist-lua-bindings-protobuf.cc',
  src_dir / 'dnsdist-lua-bindings-rings.cc',
  src_dir / 'dnsdist-lua-configuration-items.cc',
  src_dir / 'dnsdist-lua.cc',
  src_dir / 'dnsdist-lua-hooks.cc',
  src_dir / 'dnsdist-lua-inspection.cc',
  src_dir / 'dnsdist-lua-network.cc',
  src_dir / 'dnsdist-lua-rules.cc',
  src_dir / 'dnsdist-lua-vars.cc',
  src_dir / 'dnsdist-lua-web.cc',
  src_dir / 'dnsdist-mac-address.cc',
  src_dir / 'dnsdist-metrics.cc',
  src_dir / 'dnsdist-nghttp2.cc',
  src_dir / 'dnsdist-nghttp2-in.cc',
  src_dir / 'dnsdist-protobuf.cc',
  src_dir / 'dnsdist-protocols.cc',
  src_dir / 'dnsdist-proxy-protocol.cc',
  src_dir / 'dnsdist-query-count.cc',
  src_dir / 'dnsdist-random.cc',
  src_dir / 'dnsdist-resolver.cc',
  src_dir / 'dnsdist-rings.cc',
  src_dir / 'dnsdist-rule-chains.cc',
  src_dir / 'dnsdist-rules.cc',
  src_dir / 'dnsdist-secpoll.cc',
  src_dir / 'dnsdist-session-cache.cc',
  src_dir / 'dnsdist-self-answers.cc',
  src_dir / 'dnsdist-snmp.cc',
  src_dir / 'dnsdist-svc.cc',
  src_dir / 'dnsdist-systemd.cc',
  src_dir / 'dnsdist-tcp.cc',
  src_dir / 'dnsdist-tcp-downstream.cc',
  src_dir / 'dnsdist-web.cc',
  src_dir / 'dnsdist-xsk.cc',
  src_dir / 'dnsname.cc',
  src_dir / 'dnsparser.cc',
  src_dir / 'dnswriter.cc',
  src_dir / 'dolog.cc',
  src_dir / 'doh3.cc',
  src_dir / 'ednscookies.cc',
  src_dir / 'ednsextendederror.cc',
  src_dir / 'ednsoptions.cc',
  src_dir / 'ednssubnet.cc',
  src_dir / 'gettime.cc',
  src_dir / 'iputils.cc',
  src_dir / 'libssl.cc',
  src_dir / 'misc.cc',
  src_dir / 'protozero.cc',
  src_dir / 'proxy-protocol.cc',
  src_dir / 'qtype.cc',
  src_dir / 'remote_logger.cc',
  src_dir / 'remote_logger_pool.cc',
  src_dir / 'snmp-agent.cc',
  src_dir / 'statnode.cc',
  src_dir / 'svc-records.cc',
  src_dir / 'tcpiohandler.cc',
  src_dir / 'threadname.cc',
  src_dir / 'uuid-utils.cc',
  src_dir / 'xsk.cc',
)

conditional_sources = {
  'cdb': {
    'sources': [
      src_dir / 'cdb.cc',
    ],
    'condition': dep_cdb.found(),
  },
  'doh': {
    'sources': [
      src_dir / 'doh.cc',
    ],
    'condition': dep_libh2o_evloop.found(),
   },
  'doq': {
    'sources': [
      src_dir / 'doq.cc',
    ],
    'condition': get_option('dns-over-quic'),
   },
  'ipcipher': {
    'sources': [
      src_dir / 'ipcipher.cc',
    ],
    'condition': dep_libcrypto.found(),
  },
  'quiche': {
    'sources': [
      src_dir / 'doq-common.cc',
    ],
    'condition': dep_libquiche.found(),
   },
   'yaml': {
     'sources': [
       src_dir / 'dnsdist-rust-lib/dnsdist-configuration-yaml-items-generated.cc',
     ],
     'condition': dep_dnsdist_rust_lib.found(),
   }
}

foreach name, info: conditional_sources
  if info['condition']
    common_sources += files(info['sources'])
  endif
endforeach

mplexer_sources = [src_dir / 'pollmplexer.cc']
if have_linux
  mplexer_sources += src_dir / 'epollmplexer.cc'
endif
if have_darwin
  mplexer_sources += src_dir / 'kqueuemplexer.cc'
endif
if have_openbsd
  mplexer_sources += src_dir / 'kqueuemplexer.cc'
endif
if have_freebsd
  mplexer_sources += src_dir / 'kqueuemplexer.cc'
endif
if have_sunos
  mplexer_sources += src_dir / 'devpollmplexer.cc'
  mplexer_sources += src_dir / 'portsmplexer.cc'
endif

# Generate config.h
config_h = configure_file(configuration: conf, output: 'config.h')

sh_program = find_program('sh')
dep_no_config_in_source_check = custom_target(
    input: [],
    output: ['check absense of config.h file in source directory'],
    command: [sh_program, '-c', 'test ! -e @SOURCE_ROOT@/config.h'],
    build_always_stale: true,
)
dep_no_config_in_source = declare_dependency(
  sources: dep_no_config_in_source_check
)

html_sources = [
  src_dir / 'html/index.html',
  src_dir / 'html/local.js',
  src_dir / 'html/js/moment.min.js',
  src_dir / 'html/js/rickshaw.min.js',
  src_dir / 'html/js/d3.min.js',
  src_dir / 'html/js/moment.min.js',
  src_dir / 'html/lines.css',
  src_dir / 'html/legend.css',
  src_dir / 'html/detail.css',
  src_dir / 'html/graph.css',
  src_dir / 'html/powerdns-logo-220px.png',
]

incfiles = find_program('incfiles')

htmlfiles = custom_target(
  command: [incfiles, '@SOURCE_ROOT@'],
  input: html_sources,
  output: 'htmlfiles.h',
  capture: true
)

dep_htmlfiles = declare_dependency(
  sources: [htmlfiles],
)

generate_ffi_interface = find_program('generate-ffi-interface.sh')
ffi_interface = custom_target(
  command: [generate_ffi_interface, '@INPUT@'],
  input: ['dnsdist-lua-ffi-interface.h', 'dnsdist-lua-inspection-ffi.h'],
  output: 'dnsdist-lua-ffi-interface.inc',
  capture: true
)

dep_ffi_interface = declare_dependency(
  sources: [ffi_interface],
)

deps = [
  dep_pdns,
  dep_no_config_in_source,
  dep_arc4random,
  dep_boost,
  dep_cdb,
  dep_dnstap,
  dep_htmlfiles,
  dep_ipcrypt,
  dep_libcap,
  dep_libcrypto,
  dep_gnutls,
  dep_libedit,
  dep_libh2o_evloop,
  dep_json11,
  dep_libnghttp2,
  dep_libquiche,
  dep_libsnmp,
  dep_libsodium,
  dep_libssl,
  dep_lmdb,
  dep_lmdb_safe,
  dep_lua,
  dep_protozero,
  dep_yahttp,
  dep_libre2,
  dep_threads,
  dep_libbpf,
  dep_libxdp,
  dep_dnsdist_rust_lib,
]

libdnsdist_dnslabeltext_source = src_dir / 'dnslabeltext.rl'
libdnsdist_dnslabeltext_gen    = src_dir / 'dnslabeltext.cc'
if not fs.is_file(libdnsdist_dnslabeltext_gen)
  ragel = find_program('ragel', required: true)

  summary('Ragel', ragel.found(), bool_yn: ragel.found(), section: 'DNS Labels')
  summary('Ragel Path', ragel.full_path(), section: 'DNS Labels')
  summary('Ragel Version', ragel.version(), section: 'DNS Labels')

  ragel_generator = generator(
    ragel,
    output: '@BASENAME@.cc',
    arguments: ['@INPUT@', '-o', '@OUTPUT@'],
  )

  libdnsdist_dnslabeltext_gen = ragel_generator.process(libdnsdist_dnslabeltext_source)
endif

libdnsdist_common = declare_dependency(
  link_with: static_library(
    'dnsdist-common',
    common_sources,
    config_h,
    libdnsdist_dnslabeltext_gen,
    dependencies: [
      deps,
    ],
  )
)

tools = {
  'dnsdist': {
    'main': src_dir / 'dnsdist.cc',
    'files-extra': [
      src_dir / 'dnstap.cc',
      src_dir / 'fstrm_logger.cc',
      # FFI files are directly added to the binary, because otherwise the visibility
      # is ignored and the functions that are not used in the binary are not exported
      src_dir / 'dnsdist-lua-ffi.cc',
      src_dir / 'dnsdist-lua-inspection-ffi.cc',
      mplexer_sources,
    ],
    'manpages': ['dnsdist.1'],
    'deps-extra': [
      dep_boost,
      dep_pdns,
      dep_ffi_interface,
      dep_lua,
      dep_protozero,
      dep_json11,
      dep_libsystemd,
      dep_yahttp,
    ],
    'install': true,
  },
}

if get_option('fuzz-targets')
  fuzz_extra_sources = []
  fuzzer_ldflags = []
  # https://github.com/harfbuzz/harfbuzz/pull/2549/files
  if get_option('fuzzer_ldflags') == ''
    fuzz_extra_sources += src_dir / 'standalone_fuzz_target_runner.cc'
  else
    fuzzer_ldflags += get_option('fuzzer_ldflags')
  endif
  tools += {
    'fuzz-target-dnsdistcache' : {
      'main': src_dir / 'fuzz_dnsdistcache.cc',
      'link-args': fuzzer_ldflags,
      'files-extra': fuzz_extra_sources
    },
  }
  if get_option('xsk').allowed() and dep_libbpf.found() and dep_libxdp.found()
    tools += {
      'fuzz-target-xsk' : {
         'main': src_dir / 'fuzz_xsk.cc',
         'link-args': fuzzer_ldflags,
         'files-extra': fuzz_extra_sources + [
           src_dir / 'dnsname.cc',
           src_dir / 'gettime.cc',
           src_dir / 'iputils.cc',
           src_dir / 'misc.cc',
           src_dir / 'xsk.cc'
           ]
       },
    }
  endif
endif

test_sources = []
test_sources += files(
  src_dir / 'test-base64_cc.cc',
  src_dir / 'test-channel.cc',
  src_dir / 'test-connectionmanagement_hh.cc',
  src_dir / 'test-credentials_cc.cc',
  src_dir / 'test-delaypipe_hh.cc',
  src_dir / 'test-dnscrypt_cc.cc',
  src_dir / 'test-dnsdistasync.cc',
  src_dir / 'test-dnsdistbackend_cc.cc',
  src_dir / 'test-dnsdistbackoff.cc',
  src_dir / 'test-dnsdist_cc.cc',
  src_dir / 'test-dnsdist-connections-cache.cc',
  src_dir / 'test-dnsdist-dnsparser.cc',
  src_dir / 'test-dnsdistdynblocks_hh.cc',
  src_dir / 'test-dnsdistedns.cc',
  src_dir / 'test-dnsdistkvs_cc.cc',
  src_dir / 'test-dnsdistlbpolicies_cc.cc',
  src_dir / 'test-dnsdist-lua-ffi.cc',
  src_dir / 'test-dnsdistluanetwork.cc',
  src_dir / 'test-dnsdistnghttp2_cc.cc',
  src_dir / 'test-dnsdistnghttp2-in_cc.cc',
  src_dir / 'test-dnsdistpacketcache_cc.cc',
  src_dir / 'test-dnsdistrings_cc.cc',
  src_dir / 'test-dnsdistrules_cc.cc',
  src_dir / 'test-dnsdistsvc_cc.cc',
  src_dir / 'test-dnsdisttcp_cc.cc',
  src_dir / 'test-dnsparser_cc.cc',
  src_dir / 'test-iputils_hh.cc',
  src_dir / 'test-luawrapper.cc',
  src_dir / 'test-mplexer.cc',
  src_dir / 'test-proxy_protocol_cc.cc',
  src_dir / 'test-sholder_hh.cc',
)

if get_option('unit-tests')
  libdnsdist_test = declare_dependency(
    link_whole: static_library(
      'dnsdist-test',
      config_h,
      test_sources,
      dependencies: [
          dep_boost,
          dep_boost_test,
          dep_lua,
      ],
    )
  )
  tools += {
    'testrunner': {
        'main': [
          src_dir / 'testrunner.cc',
          mplexer_sources,
        ],
        'files-extra': [
          # FFI files are directly added to the binary, because otherwise the visibility
          # is ignored and the functions that are not used in the binary are not exported
          src_dir / 'dnsdist-lua-ffi.cc',
        ],
        'deps-extra': [
          libdnsdist_test,
          dep_boost_test,
          dep_ffi_interface,
          dep_lua,
        ],
    }
  }
endif

man_pages = []
foreach tool, info: tools
  var_name = tool.underscorify()
  main = files(info['main'])

  export_dynamic = 'export-dynamic' in info ? info['export-dynamic'] : false
  files_extra = 'files-extra' in info ? info['files-extra'] : []
  deps_extra = 'deps-extra' in info ? info['deps-extra'] : []
  link_args = 'link-args' in info ? info['link-args'] : []
  install = 'install' in info ? info['install'] : false

  set_variable(
    var_name,
    executable(
      tool,
      main,
      config_h,
      files_extra,
      export_dynamic: export_dynamic,
      link_args: link_args,
      dependencies: [
        libdnsdist_common,
        deps_extra,
      ],
      install: install,
    )
  )

  if 'manpages' in info
    foreach man_page: info['manpages']
      man_pages += docs_dir / 'manpages' / (man_page + '.rst')
    endforeach
  endif
endforeach

if get_option('unit-tests')
  test('testrunner', testrunner)
endif

# Man-pages.
py = import('python')
python = py.find_installation('python3', modules: 'venv', required: false)

summary('Python', python.found(), bool_yn: true, section: 'Manual Pages')
summary('Path', python.full_path(), section: 'Manual Pages')
summary('Version', python.version(), section: 'Manual Pages')

if get_option('man-pages') and python.found()
  generated_man_pages = []
  foreach tool, info: tools
    if 'manpages' in info
      foreach man_page: info['manpages']
        if not fs.is_file(man_page)
          generated_man_pages += man_page
        else
          install_man(
            man_page,
            install_dir: join_paths(get_option('mandir'), 'man1'),
          )
        endif
      endforeach
    endif
  endforeach
  if generated_man_pages.length() != 0
    summary('Generating man pages', true, section: 'Manual Pages')
    custom_target(
       'man-pages',
       input: man_pages,
       output: generated_man_pages,
       install: true,
       install_dir: join_paths(get_option('mandir'), 'man1'),
       command: [
         python,
         product_source_dir / docs_dir / 'generate-man-pages.py',
         '--build-root', '@BUILD_ROOT@',
         '--source-root', '@SOURCE_ROOT@',
         '--venv-name', 'venv-dnsdist-man-pages',
         '--requirements-file', docs_dir / 'requirements.txt',
         '--source-directory', docs_dir,
         '--target-directory', '@BUILD_ROOT@',
       ] + man_pages,
    )
  else
    summary('Generating man pages', false, section: 'Manual Pages')
  endif
endif

if dep_systemd_prog.found()

  systemd_system_unit_dir = dep_systemd_prog.get_variable(
    'systemdsystemunitdir',
  )

  systemd_service_conf = configuration_data()
  systemd_service_conf.set('Description', 'DNS Loadbalancer')
  systemd_service_conf.set('BinDir', get_option('prefix') / get_option('bindir'))
  systemd_service_user = get_option('systemd-service-user')
  systemd_service_group = get_option('systemd-service-group')
  systemd_service_conf.set('ServiceUser', systemd_service_user)
  systemd_service_conf.set('ServiceGroup', systemd_service_group)
  summary('Service User', systemd_service_user, section: 'Systemd')
  summary('Service Group', systemd_service_group, section: 'Systemd')

  systemd_service_conf.set(
    'ProtectSystem', have_systemd_protect_system ? 'ProtectSystem=full' : '',
  )
  systemd_service_conf.set(
    'SystemCallArchitectures',
    have_systemd_system_call_architectures ? 'SystemCallArchitectures=native' : '',
  )
  systemd_system_call_filter = '~ @clock @debug @module @mount @raw-io @reboot @swap @cpu-emulation @obsolete'
  systemd_service_conf.set(
    'SystemCallFilter',
    have_systemd_system_call_filter ? 'SystemCallFilter=' + systemd_system_call_filter : '',
  )
  systemd_service_conf.set(
    'ProtectProc',
    have_systemd_protect_proc ? 'ProtectProc=invisible' : '',
  )

  systemd_features = {
    'LockPersonality': have_systemd_lock_personality,
    'PrivateDevices': have_systemd_private_devices,
    'PrivateTmp': have_systemd_private_tmp,
    'PrivateUsers': false, # Setting it to true prevents us from opening our sockets.
    'ProtectClock': have_systemd_protect_clock,
    'ProtectControlGroups': have_systemd_protect_control_groups,
    'ProtectHome': have_systemd_protect_home,
    'ProtectHostname': have_systemd_protect_hostname,
    'ProtectKernelLogs': have_systemd_protect_kernel_logs,
    'ProtectKernelModules': have_systemd_protect_kernel_modules,
    'ProtectKernelTunables': have_systemd_protect_kernel_tunables,
    'RestrictNamespaces': have_systemd_restrict_namespaces,
    'RestrictRealtime': have_systemd_restrict_realtime,
    'RestrictSUIDSGID': have_systemd_restrict_suidsgid,
    'PrivateIPC': have_systemd_private_ipc,
    'RemoveIPC': have_systemd_remove_ipc,
  }

  foreach feature, enable_it: systemd_features
    systemd_service_conf.set(feature, enable_it ? feature + '=true': '')
  endforeach

  # Disabled, it breaks LuaJIT.
  systemd_service_conf.set(
    'MemoryDenyWriteExecute',
    have_systemd_memory_deny_write_execute ? 'MemoryDenyWriteExecute=false' : '',
  )
  systemd_service_conf.set(
    'RestrictAddressFamilies',
    have_systemd_restrict_address_families ? 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' : '',
  )

  dnsdist_service_conf_general = configuration_data()
  dnsdist_service_conf_general.set('Description', 'DNS Loadbalancer')
  dnsdist_service_conf_general.merge_from(systemd_service_conf)
  dnsdist_service_conf_general.set('SyslogIdentifier', 'dnsdist')

  configure_file(
    input: 'dnsdist.service.meson.in',
    output: 'dnsdist.service',
    configuration: dnsdist_service_conf_general,
    install: true,
    install_dir: systemd_system_unit_dir,
  )

  dnsdist_service_conf_instance = configuration_data()
  dnsdist_service_conf_instance.merge_from(systemd_service_conf)
  dnsdist_service_conf_instance.set('Description', 'DNS Loadbalancer %i')
  dnsdist_service_conf_instance.set('SyslogIdentifier', 'dnsdist-%i')

  configure_file(
    input: 'dnsdist.service.meson.in',
    output: 'dnsdist@.service',
    configuration: dnsdist_service_conf_instance,
    install: true,
    install_dir: systemd_system_unit_dir,
  )
endif

install_data(
  'dnsdist.conf-dist',
  install_dir : get_option('sysconfdir'),
  follow_symlinks: true
)

if python.found()

  html_docs = custom_target(
    'html-docs',
    command: [
        python,
        product_source_dir / docs_dir / 'generate-docs.py',
        '--build-root', '@BUILD_ROOT@',
        '--source-root', '@SOURCE_ROOT@',
        '--venv-name', 'venv-docs',
        '--requirements-file', docs_dir / 'requirements.txt',
        '--source-directory', docs_dir,
        '--target-directory', '@BUILD_ROOT@' / 'html-docs',
    ],
    output: 'sphinx.stamp',
    console: true,
    depfile: 'sphinx.d',
  )

  docs_tarball = custom_target(
    'html-docs.tar.bz2',
    command: ['tar', 'cjf', 'html-docs.tar.bz2', html_docs],
    output: 'html-docs.tar.bz2',
  )

  pdf_docs = custom_target(
    command: [
        python,
        product_source_dir / docs_dir / 'generate-docs.py',
        '--build-root', '@BUILD_ROOT@',
        '--source-root', '@SOURCE_ROOT@',
        '--venv-name', 'venv-docs',
        '--requirements-file', docs_dir / 'requirements.txt',
        '--source-directory', docs_dir,
        '--target-directory', '@BUILD_ROOT@',
        '--pdf-name', 'dnsdist.pdf',
    ],
    output: 'dnsdist.pdf',
    console: true,
    depfile: 'sphinx.d',
  )

  run_target(
    'all-docs',
    # args mentioned in command line become auto-dependency
    command: ['echo', 'Generated', html_docs, docs_tarball, pdf_docs],
  )
endif
