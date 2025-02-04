project(
  'pdns-recursor',
  ['c', 'cpp'],
  version: run_command('version.sh', 'get-vcs', check: true).stdout().strip(),
  license: 'GPLv2',
  license_files: 'NOTICE',
  meson_version: '>= 1.2.1',
  default_options: [
    'buildtype=debugoptimized',
    'warning_level=2',          # TODO Move this to 3 to enable -Wpedantic
    'cpp_std=c++17',
  ],
)
meson.add_dist_script('meson-dist-script.sh')

# When runniog meson dist, the command below produces multiple lines on stderr:
# Unable to evaluate subdir([]) in AstInterpreter --> Skipping
meson.add_dist_script('version.sh', 'set-dist', meson.project_version())

add_project_arguments('-DRECURSOR', language: 'cpp')


product_source_dir = meson.current_source_dir()
product_build_dir = meson.current_build_dir()
summary('Source Dir', product_source_dir, section: 'Build')
summary('Build Dir', product_build_dir, section: 'Build')

# Create the configuration object and dependencies list.
conf = configuration_data()
conf.set_quoted('PACKAGE_STRING', meson.project_version(), description: 'version')
conf.set_quoted('NODCACHEDIRNOD', get_option('localstatedir') + '/nod', description: 'NOD data directory')
conf.set_quoted('NODCACHEDIRUDR', get_option('localstatedir') + '/udr', description: 'NDR data directory')

# Feature detection and system configuration
subdir('meson' / 'config')                  # Config
subdir('meson' / 'version')                 # Generate version define
subdir('meson' / 'compiler-setup')          # Common compiler setup
subdir('meson' / 'summary')                 # Print a system/project summary
subdir('meson' / 'sysconfdir')              # Sysconfdir
subdir('meson' / 'platform')                # Platform detection
subdir('meson' / 'timet-size')              # Check the size of time_t
subdir('meson' / 'timet-sign')              # Check the sign of time_t
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
subdir('meson' / 'libsodium')               # Libsodium-based signers
subdir('meson' / 'libcrypto')               # OpenSSL-based signers
subdir('meson' / 'libssl')                  # OpenSSL libssl
subdir('meson' / 'libsnmp')                 # SNMP
subdir('meson' / 'dot')                     # DNS over TLS
subdir('meson' / 'clock-gettime')           # Clock_gettime
subdir('meson' / 'boost')                   # Boost
subdir('meson' / 'boost-context')           # Boost Context Switching Library
subdir('meson' / 'boost-test')              # Boost Testing Library
subdir('meson' / 'boost-filesystem')        # Boost File System Library
subdir('meson' / 'reproducible')            # Reproducible Builds
subdir('meson' / 'libsystemd')              # Systemd notification
subdir('meson' / 'systemd')                 # Systemd and unit file handling
subdir('meson' / 'code-coverage')           # Code coverage
subdir('meson' / 'auto-var-init')           # Automatic Variable Initialization
subdir('meson' / 'sanitizers')              # Sanitizers
subdir('meson' / 'malloc-trace')            # Malloc-trace
subdir('meson' / 'socket-dir')              # Socket Dir
subdir('meson' / 'various-functions')       # Various Functions
subdir('meson' / 'various-headers')         # Various Headers
subdir('meson' / 'libresolv')               # res_query
subdir('meson' / 'dnstap')                  # DNSTAP through libfstream
subdir('meson' / 'libcurl')                 # Curl

subdir('settings')

common_sources = []

fs = import('fs')
src_dir = fs.is_dir('.') ? '.' : ''
docs_dir = 'docs'
# Toplevel includes
dep_pdns = declare_dependency(include_directories: include_directories('.', src_dir))

# Ext
subdir('ext' / 'arc4random')
subdir('ext' / 'json11')
subdir('ext' / 'luawrapper')
subdir('ext' / 'protozero')
subdir('ext' / 'probds')
subdir('ext' / 'yahttp')
subdir('meson' / 'nod')                     # Newly Observed Domains

common_sources += files(
  src_dir / 'aggressive_nsec.cc',
  src_dir / 'arguments.cc',
  src_dir / 'axfr-retriever.cc',
  src_dir / 'base32.cc',
  src_dir / 'base64.cc',
  src_dir / 'coverage.cc',
  src_dir / 'credentials.cc',
  src_dir / 'dns.cc',
  src_dir / 'dnsname.cc',
  src_dir / 'dnsparser.cc',
  src_dir / 'dnsrecords.cc',
  src_dir / 'dnssecinfra.cc',
  src_dir / 'dnswriter.cc',
  src_dir / 'ednsextendederror.cc',
  src_dir / 'ednsoptions.cc',
  src_dir / 'ednspadding.cc',
  src_dir / 'ednssubnet.cc',
  src_dir / 'filterpo.cc',
  src_dir / 'gettime.cc',
  src_dir / 'gss_context.cc',
  src_dir / 'iputils.cc',
  src_dir / 'ixfr.cc',
  src_dir / 'json.cc',
  src_dir / 'libssl.cc',
  src_dir / 'logger.cc',
  src_dir / 'logging.cc',
  src_dir / 'lua-base4.cc',
  src_dir / 'lua-recursor4.cc',
  src_dir / 'lwres.cc',
  src_dir / 'misc.cc',
  src_dir / 'mtasker_context.cc',
  src_dir / 'negcache.cc',
  src_dir / 'nsecrecords.cc',
  src_dir / 'protozero.cc',
  src_dir / 'proxy-protocol.cc',
  src_dir / 'pubsuffixloader.cc',
  src_dir / 'qtype.cc',
  src_dir / 'query-local-address.cc',
  src_dir / 'rcpgenerator.cc',
  src_dir / 'rec-carbon.cc',
  src_dir / 'rec-eventtrace.cc',
  src_dir / 'rec-lua-conf.cc',
  src_dir / 'rec-protozero.cc',
  src_dir / 'rec-responsestats.cc',
  src_dir / 'rec-system-resolve.cc',
  src_dir / 'rec-taskqueue.cc',
  src_dir / 'rec-tcounters.cc',
  src_dir / 'rec-zonetocache.cc',
  src_dir / 'rec_channel.cc',
  src_dir / 'rec_channel_rec.cc',
  src_dir / 'rec-xfr.cc',
  src_dir / 'rec-xfrtracker.cc',
  src_dir / 'recpacketcache.cc',
  src_dir / 'recursor_cache.cc',
  src_dir / 'reczones-helpers.cc',
  src_dir / 'reczones.cc',
  src_dir / 'remote_logger.cc',
  src_dir / 'resolver.cc',
  src_dir / 'rpzloader.cc',
  src_dir / 'secpoll-recursor.cc',
  src_dir / 'secpoll.cc',
  src_dir / 'shuffle.cc',
  src_dir / 'sillyrecords.cc',
  src_dir / 'snmp-agent.cc',
  src_dir / 'sortlist.cc',
  src_dir / 'svc-records.cc',
  src_dir / 'syncres.cc',
  src_dir / 'taskqueue.cc',
  src_dir / 'tcpiohandler.cc',
  src_dir / 'threadname.cc',
  src_dir / 'tsigverifier.cc',
  src_dir / 'unix_utility.cc',
  src_dir / 'uuid-utils.cc',
  src_dir / 'validate.cc',
  src_dir / 'validate-recursor.cc',
  src_dir / 'version.cc',
  src_dir / 'webserver.cc',
  src_dir / 'ws-api.cc',
  src_dir / 'ws-recursor.cc',
  src_dir / 'zonemd.cc',
  src_dir / 'zoneparser-tng.cc',
)

conditional_sources = {
  'minicurl': {
    'sources': [
      src_dir / 'minicurl.cc',
      src_dir / 'minicurl.hh',
    ],
    'condition': dep_libcurl.found(),
  },
  'dnstap': {
    'sources': [
      src_dir / 'dnstap.cc',
      src_dir / 'fstrm_logger.cc',
    ],
    'condition': dep_dnstap.found(),
  },
  'nod': {
    'sources': [
      src_dir / 'nod.cc',
    ],
    'condition': dep_nod.found(),
  },
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
  src_dir / 'html/local-2022.js',
  src_dir / 'html/js/rickshaw.min.js',
  src_dir / 'html/js/moment.js',
  src_dir / 'html/js/rickshaw.js',
  src_dir / 'html/js/d3.v3.js',
  src_dir / 'html/js/handlebars-v4.0.11.js',
  src_dir / 'html/js/handlebars-v4.0.11-min.js',
  src_dir / 'html/js/d3.v3-min.js',
  src_dir / 'html/js/moment.min.js',
  src_dir / 'html/lines.css',
  src_dir / 'html/legend.css',
  src_dir / 'html/styling.css',
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

metric_sources = [
  src_dir / 'metrics.py',
  src_dir / 'metrics_table.py',
  src_dir / 'RECURSOR-MIB.in',
]

py = import('python')
python = py.find_installation('python3', required: true)

metricfiles = custom_target(
  command: [python, '@INPUT0@', '@SOURCE_ROOT@', '@BUILD_ROOT@'],
  input: metric_sources,
  output: [
          'rec-metrics-gen.h',
          'rec-prometheus-gen.h',
          'rec-snmp-gen.h',
          'rec-oids-gen.h',
          'RECURSOR-MIB.txt',
  ],
  capture: false,
)

dep_metrics = declare_dependency(
  sources: [metricfiles],
)

deps = [
  dep_pdns,
  dep_no_config_in_source,
  dep_rust_settings,
  dep_boost,
  dep_boost_context,
  dep_threads,
  dep_arc4random,
  dep_json11,
  dep_libcrypto,
  dep_libresolv,
  dep_libsnmp,
  dep_libsodium,
  dep_libssl,
  dep_lua,
  dep_protozero,
  dep_yahttp,
  dep_htmlfiles,
  dep_dnstap,
  dep_libcurl,
  dep_metrics,
]

# Conditional sources that need to be separated into standalone libraries for special
# linking without implicitly getting rid of symbols.
librec_signers_sodium = dependency('', required: false)
if dep_libsodium.found()
  librec_signers_sodium = declare_dependency(
    link_whole: static_library(
      'rec-signers-sodium',
      sources: files(src_dir / 'sodiumsigners.cc'),
      dependencies: [dep_boost, dep_libsodium],
    )
  )
endif

librec_signers_openssl = declare_dependency(
  link_whole: static_library(
    'rec-signers-openssl',
    sources: files(src_dir / 'opensslsigners.cc'),
    dependencies: [dep_boost, dep_libssl],
  )
)

# If we have pubsuffix.cc in the source tree, use it. Otherwise download and build it.
pubsuffix_dl_source =  'effective_tld_names.dat'
pubsuffix_cc = src_dir / 'pubsuffix.cc'
if not fs.is_file(pubsuffix_cc)
  curl_command = find_program('curl', required: true)
  pubsuffix_dl_source = custom_target(
    'pubsuffix-dl',
    command: [curl_command, '-s', '-S', '-o', '@OUTPUT@', 'https://publicsuffix.org/list/public_suffix_list.dat'],
    output: pubsuffix_dl_source
  )

  mkpubsuffix_command = find_program('mkpubsuffixcc', required: true)
  pubsuffix_cc = custom_target(
    'pubsuffix-cc',
    command: [mkpubsuffix_command, '@INPUT@', '@OUTPUT@'],
    input: pubsuffix_dl_source,
    output: 'pubsuffix.cc',
  )
endif

dep_pubsuffix = declare_dependency(
  sources: pubsuffix_cc
)

librec_dnslabeltext_source = src_dir / 'dnslabeltext.rl'
librec_dnslabeltext_gen    = src_dir / 'dnslabeltext.cc'
if not fs.is_file(librec_dnslabeltext_gen)
  ragel = find_program('ragel', required: true)

  summary('Ragel', ragel.found(), bool_yn: ragel.found(), section: 'DNS Labels')
  summary('Ragel Path', ragel.full_path(), section: 'DNS Labels')
  summary('Ragel Version', ragel.version(), section: 'DNS Labels')

  ragel_generator = generator(
    ragel,
    output: '@BASENAME@.cc',
    arguments: ['@INPUT@', '-o', '@OUTPUT@'],
  )

  librec_dnslabeltext_gen = ragel_generator.process(librec_dnslabeltext_source)
endif

librec_dnslabeltext = declare_dependency(
  link_with: static_library(
    'rec-dnslabeltext',
    librec_dnslabeltext_gen,
    dependencies: deps,
  )
)

librec_common = declare_dependency(
  link_with: static_library(
    'rec-common',
    common_sources,
    config_h,
    dependencies: [
      deps,
      dep_settings_ch,
      librec_dnslabeltext,
    ],
  )
)

tools = {
  'pdns_recursor': {
    'main': src_dir / 'rec-main.cc',
    'files-extra': [
      src_dir / 'capabilities.cc',
      src_dir / 'channel.cc',
      src_dir / 'pdns_recursor.cc',
      src_dir / 'rec-tcp.cc',
      src_dir / 'rec-tcpout.cc',
      src_dir / 'rec-snmp.cc',
      src_dir / 'rec-tcp.cc',
      mplexer_sources,
    ],
    'manpages': ['pdns_recursor.1'],
    'deps-extra': [
      dep_boost,
      dep_nod,
      dep_lua,
      dep_protozero,
      dep_yahttp,
      dep_json11,
      dep_settings,
      dep_rust_settings,
      dep_systemd,
      librec_signers_openssl,
      librec_signers_sodium,
      dep_pubsuffix,
    ],
  },
  'rec_control': {
    'main': src_dir / 'rec_control.cc',
    'manpages': ['rec_control.1'],
    'deps-extra': [
      dep_boost,
      dep_settings,
      dep_rust_settings,
    ],
  },
}

test_sources = []
test_sources += files(
      src_dir / 'ednscookies.cc',
      src_dir / 'test-aggressive_nsec_cc.cc',
      src_dir / 'test-arguments_cc.cc',
      src_dir / 'test-base32_cc.cc',
      src_dir / 'test-base64_cc.cc',
      src_dir / 'test-common.hh',
      src_dir / 'test-credentials_cc.cc',
      src_dir / 'test-dns_random_hh.cc',
      src_dir / 'test-dnsname_cc.cc',
      src_dir / 'test-dnsparser_hh.cc',
      src_dir / 'test-dnsrecordcontent.cc',
      src_dir / 'test-dnsrecords_cc.cc',
      src_dir / 'test-ednsoptions_cc.cc',
      src_dir / 'test-filterpo_cc.cc',
      src_dir / 'test-histogram_hh.cc',
      src_dir / 'test-iputils_hh.cc',
      src_dir / 'test-ixfr_cc.cc',
      src_dir / 'test-luawrapper.cc',
      src_dir / 'test-misc_hh.cc',
      src_dir / 'test-mplexer.cc',
      src_dir / 'test-mtasker.cc',
      src_dir / 'test-negcache_cc.cc',
      src_dir / 'test-packetcache_hh.cc',
      src_dir / 'test-rcpgenerator_cc.cc',
      src_dir / 'test-rec-system-resolve.cc',
      src_dir / 'test-rec-taskqueue.cc',
      src_dir / 'test-rec-tcounters_cc.cc',
      src_dir / 'test-rec-zonetocache.cc',
      src_dir / 'test-recpacketcache_cc.cc',
      src_dir / 'test-recursorcache_cc.cc',
      src_dir / 'test-reczones-helpers.cc',
      src_dir / 'test-rpzloader_cc.cc',
      src_dir / 'test-secpoll_cc.cc',
      src_dir / 'test-settings.cc',
      src_dir / 'test-shuffle_cc.cc',
      src_dir / 'test-signers.cc',
      src_dir / 'test-syncres_cc.cc',
      src_dir / 'test-syncres_cc.hh',
      src_dir / 'test-syncres_cc1.cc',
      src_dir / 'test-syncres_cc10.cc',
      src_dir / 'test-syncres_cc2.cc',
      src_dir / 'test-syncres_cc3.cc',
      src_dir / 'test-syncres_cc4.cc',
      src_dir / 'test-syncres_cc5.cc',
      src_dir / 'test-syncres_cc6.cc',
      src_dir / 'test-syncres_cc7.cc',
      src_dir / 'test-syncres_cc8.cc',
      src_dir / 'test-syncres_cc9.cc',
      src_dir / 'test-tsig.cc',
)

if enable_nod
  test_sources += files(src_dir / 'test-nod_cc.cc')
endif

if get_option('unit-tests')
  librec_test = declare_dependency(
    link_whole: static_library(
      'rec-test',
      config_h,
      test_sources,
      dependencies: [
          dep_boost,
          dep_boost_test,
          dep_lua,
          dep_nod,
          dep_settings,
          dep_rust_settings,
          librec_signers_openssl,
          librec_signers_sodium,
      ],
    )
  )
  tools += {
    'testrunner': {
        'main': [
          src_dir / 'testrunner.cc',
          mplexer_sources,
        ],
        'deps-extra': [
          librec_test,
          dep_boost_test,
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

  set_variable(
    var_name,
    executable(
      tool,
      main,
      config_h,
      files_extra,
      export_dynamic: export_dynamic,
      dependencies: [
        librec_common,
        deps_extra,
      ],
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

if python.found()
  run_target(
    'man-pages',
    command: [
      python,
      product_source_dir / docs_dir / 'generate-man-pages.py',
      '--venv-name', 'venv-rec-man-pages',
      '--requirements-file', docs_dir / 'requirements.txt',
      '--source-directory', docs_dir,
      '--target-directory', 'rec-man-pages',
    ] + man_pages,
  )
endif
