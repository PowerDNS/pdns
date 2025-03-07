import os
import time
import json
import requests
from invoke import task
from invoke.exceptions import Failure, UnexpectedExit

auth_backend_ip_addr = os.getenv('AUTH_BACKEND_IP_ADDR', '127.0.0.1')

clang_version = os.getenv('CLANG_VERSION', '13')

all_build_deps = [
    'ccache',
    'libboost-all-dev',
    'libluajit-5.1-dev',
    'libsodium-dev',
    'libssl-dev', # This will install libssl 1.1 on Debian 11 and libssl3 on Debian 12
    'libsystemd-dev',
    'libtool',
    'make',
    'pkg-config',
    'python3-venv',
    'systemd',
]
git_build_deps = [
    'autoconf',
    'automake',
    'bison',
    'bzip2',
    'curl',
    'flex',
    'git',
    'ragel'
]
auth_build_deps = [    # FIXME: perhaps we should be stealing these from the debian (Ubuntu) control file
    'default-libmysqlclient-dev',
    'libcdb-dev',
    'libcurl4-openssl-dev',
    'libgeoip-dev',
    'libkrb5-dev',
    'libldap2-dev',
    'liblmdb-dev',
    'libmaxminddb-dev',
    'libp11-kit-dev',
    'libpq-dev',
    'libsqlite3-dev',
    'libyaml-cpp-dev',
    'libzmq3-dev',
    'ruby-bundler',
    'ruby-dev',
    'sqlite3',
    'unixodbc-dev',
    'cmake',
]
rec_build_deps = [
    'libcap-dev',
    'libfstrm-dev',
    'libsnmp-dev',
]
rec_bulk_deps = [
    'curl',
    'libboost-all-dev',
    'libcap2',
    'libfstrm0',
    'libluajit-5.1-2',
    '"libsnmp[1-9]+"',
    'libsodium23',
    'libsystemd0',
    'moreutils',
    'pdns-tools',
    'unzip',
]
dnsdist_build_deps = [
    'libcap-dev',
    'libcdb-dev',
    'libedit-dev',
    'libfstrm-dev',
    'libgnutls28-dev',
    'libh2o-evloop-dev',
    'liblmdb-dev',
    'libnghttp2-dev',
    'libre2-dev',
    'libsnmp-dev',
]
dnsdist_xdp_build_deps = [
    'libbpf-dev',
    'libxdp-dev',
]
auth_test_deps = [   # FIXME: we should be generating some of these from shlibdeps in build
    'authbind',
    'bc',
    'bind9utils',
    'curl',
    'default-jre-headless',
    'dnsutils',
    'faketime',
    'gawk',
    'krb5-user',
    'ldnsutils',
    '"libboost-serialization1.7[1-9]+"',
    'libcdb1',
    'libcurl4',
    'libgeoip1',
    'libkrb5-3',
    '"libldap-2.[1-9]+"',
    'liblmdb0',
    'libluajit-5.1-2',
    'libmaxminddb0',
    'libnet-dns-perl',
    'libp11-kit0',
    'libpq5',
    'libsodium23',
    'libsqlite3-dev',
    'libsystemd0',
    '"libyaml-cpp0.[1-9]+"',
    'libzmq3-dev',
    'lmdb-utils',
    'prometheus',
    'ruby-bundler',
    'ruby-dev',
    'socat',
    'softhsm2',
    'unbound-host',
    'unixodbc',
    'wget',
]
doc_deps = [
    'autoconf',
    'automake',
    'bison',
    'curl',
    'flex',
    'g++',
    'git',
    'latexmk',
    'libboost-all-dev',
    'libedit-dev',
    'libluajit-5.1-dev',
    'libssl-dev',
    'make',
    'pkg-config',
    'python3-venv',
    'ragel',
    'rsync',
]
doc_deps_pdf = [
    'texlive-binaries',
    'texlive-formats-extra',
    'texlive-latex-extra',
]

@task
def apt_fresh(c):
    c.sudo('apt-get update')
    c.sudo('apt-get -y --allow-downgrades dist-upgrade')

@task
def install_clang(c):
    """
    install clang and llvm
    """
    c.sudo(f'apt-get -y --no-install-recommends install clang-{clang_version} llvm-{clang_version}')

@task
def install_clang_tidy_tools(c):
    c.sudo(f'apt-get -y --no-install-recommends install clang-tidy-{clang_version} clang-tools-{clang_version} bear python3-yaml')

@task
def install_clang_runtime(c):
    # this gives us the symbolizer, for symbols in asan/ubsan traces
    c.sudo(f'apt-get -y --no-install-recommends install clang-{clang_version}')

@task
def ci_install_rust(c, repo):
    with c.cd(f'{repo}/builder-support/helpers/'):
        c.run('sudo sh install_rust.sh')

def install_libdecaf(c, product):
    c.run('git clone https://git.code.sf.net/p/ed448goldilocks/code /tmp/libdecaf')
    with c.cd('/tmp/libdecaf'):
        c.run('git checkout 41f349')
        c.run(f'CC={get_c_compiler()} CXX={get_cxx_compiler()} '
              'cmake -B build '
              '-DCMAKE_INSTALL_PREFIX=/usr/local '
              '-DCMAKE_INSTALL_LIBDIR=lib '
              '-DENABLE_STATIC=OFF '
              '-DENABLE_TESTS=OFF '
              '-DCMAKE_C_FLAGS="-Wno-sizeof-array-div -Wno-array-parameter" .')
        c.run('make -C build')
        c.run('sudo make -C build install')
    c.sudo(f'mkdir -p /opt/{product}/libdecaf')
    c.sudo(f'cp /usr/local/lib/libdecaf.so* /opt/{product}/libdecaf/.')

@task
def install_doc_deps(c):
    c.sudo('apt-get install -y ' + ' '.join(doc_deps))

@task
def install_doc_deps_pdf(c):
    c.sudo('apt-get install -y ' + ' '.join(doc_deps_pdf))

@task
def install_auth_build_deps(c):
    c.sudo('apt-get install -y --no-install-recommends ' + ' '.join(all_build_deps + git_build_deps + auth_build_deps))
    if os.getenv('DECAF_SUPPORT', 'no') == 'yes':
        install_libdecaf(c, 'pdns-auth')

def is_coverage_enabled():
    sanitizers = os.getenv('SANITIZERS')
    if sanitizers:
        sanitizers = sanitizers.split('+')
        if 'tsan' in sanitizers:
            return False
    return os.getenv('COVERAGE') == 'yes'

def get_coverage():
    return '--enable-coverage=clang' if is_coverage_enabled() else ''

@task
def install_coverage_deps(c):
    if is_coverage_enabled():
        c.sudo(f'apt-get install -y --no-install-recommends llvm-{clang_version}')

@task
def generate_coverage_info(c, binary, outputDir):
    if is_coverage_enabled():
        version = os.getenv('BUILDER_VERSION')
        c.run(f'llvm-profdata-{clang_version} merge -sparse -o {outputDir}/temp.profdata /tmp/code-*.profraw')
        c.run(f'llvm-cov-{clang_version} export --format=lcov --ignore-filename-regex=\'^/usr/\' -instr-profile={outputDir}/temp.profdata -object {binary} > {outputDir}/coverage.lcov')
        c.run(f'{outputDir}/.github/scripts/normalize_paths_in_coverage.py {outputDir} {version} {outputDir}/coverage.lcov {outputDir}/normalized_coverage.lcov')
        c.run(f'mv {outputDir}/normalized_coverage.lcov {outputDir}/coverage.lcov')

def setup_authbind(c):
    c.sudo('touch /etc/authbind/byport/53')
    c.sudo('chmod 755 /etc/authbind/byport/53')

auth_backend_test_deps = dict(
    gsqlite3=['sqlite3'],
    gmysql=['default-libmysqlclient-dev'],
    gpgsql=['libpq-dev'],
    lmdb=[],
    remote=[],
    bind=[],
    geoip=[],
    lua2=[],
    tinydns=[],
    authpy=[],
    godbc_sqlite3=['libsqliteodbc'],
    godbc_mssql=['freetds-bin','tdsodbc'],
    ldap=[],
    geoip_mmdb=[]
)

@task(help={'backend': 'Backend to install test deps for, e.g. gsqlite3; can be repeated'}, iterable=['backend'], optional=['backend'])
def install_auth_test_deps(c, backend): # FIXME: rename this, we do way more than apt-get
    extra=[]
    for b in backend:
        extra.extend(auth_backend_test_deps[b])
    c.sudo('DEBIAN_FRONTEND=noninteractive apt-get -y install ' + ' '.join(extra+auth_test_deps))

    c.run('chmod +x /opt/pdns-auth/bin/* /opt/pdns-auth/sbin/*')
    # c.run('''if [ ! -e $HOME/bin/jdnssec-verifyzone ]; then
    #               wget https://github.com/dblacka/jdnssec-tools/releases/download/0.14/jdnssec-tools-0.14.tar.gz
    #               tar xfz jdnssec-tools-0.14.tar.gz -C $HOME
    #               rm jdnssec-tools-0.14.tar.gz
    #          fi
    #          echo 'export PATH=$HOME/jdnssec-tools-0.14/bin:$PATH' >> $BASH_ENV''')  # FIXME: why did this fail with no error?
    c.run('touch regression-tests/tests/verify-dnssec-zone/allow-missing regression-tests.nobackend/rectify-axfr/allow-missing') # FIXME: can this go?
    # FIXME we may want to start a background recursor here to make ALIAS tests more robust
    setup_authbind(c)

    if os.getenv('DECAF_SUPPORT', 'no') == 'yes':
        # Copy libdecaf out
        c.sudo('mkdir -p /usr/local/lib')
        c.sudo('cp /opt/pdns-auth/libdecaf/libdecaf.so* /usr/local/lib/.')

@task
def install_rec_bulk_deps(c): # FIXME: rename this, we do way more than apt-get
    c.sudo('apt-get --no-install-recommends -y install ' + ' '.join(rec_bulk_deps))
    c.run('chmod +x /opt/pdns-recursor/bin/* /opt/pdns-recursor/sbin/*')

@task
def install_rec_test_deps(c): # FIXME: rename this, we do way more than apt-get
    c.sudo('apt-get --no-install-recommends install -y ' + ' '.join(rec_bulk_deps) + ' \
              pdns-server pdns-backend-bind daemontools \
              jq libfaketime lua-posix lua-socket bc authbind \
              python3-venv python3-dev default-libmysqlclient-dev libpq-dev \
              protobuf-compiler snmpd prometheus')

    c.run('chmod +x /opt/pdns-recursor/bin/* /opt/pdns-recursor/sbin/*')

    setup_authbind(c)

    c.run('sed "s/agentxperms 0700 0755 recursor/agentxperms 0777 0755/g" regression-tests.recursor-dnssec/snmpd.conf | sudo tee /etc/snmp/snmpd.conf')
    c.sudo('/etc/init.d/snmpd restart')
    time.sleep(5)
    c.sudo('chmod 755 /var/agentx')

@task(optional=['skipXDP'])
def install_dnsdist_test_deps(c, skipXDP=False): # FIXME: rename this, we do way more than apt-get
    deps = 'libluajit-5.1-2 \
            libboost-all-dev \
            libcap2 \
            libcdb1 \
            libcurl4-openssl-dev \
            libfstrm0 \
            libgnutls30 \
            libh2o-evloop0.13 \
            liblmdb0 \
            libnghttp2-14 \
            "libre2-[1-9]+" \
            libssl-dev \
            libsystemd0 \
            libsodium23 \
            lua-socket \
            patch \
            protobuf-compiler \
            python3-venv snmpd prometheus'
    if not skipXDP:
        deps = deps + '\
               libbpf1 \
               libxdp1'

    c.sudo(f'apt-get install -y {deps}')
    c.run('sed "s/agentxperms 0700 0755 dnsdist/agentxperms 0777 0755/g" regression-tests.dnsdist/snmpd.conf | sudo tee /etc/snmp/snmpd.conf')
    c.sudo('/etc/init.d/snmpd restart')
    time.sleep(5)
    c.sudo('chmod 755 /var/agentx')

@task
def install_rec_build_deps(c):
    c.sudo('apt-get install -y --no-install-recommends ' +  ' '.join(all_build_deps + git_build_deps + rec_build_deps))

@task(optional=['skipXDP'])
def install_dnsdist_build_deps(c, skipXDP=False):
    c.sudo('apt-get install -y --no-install-recommends ' +  ' '.join(all_build_deps + git_build_deps + dnsdist_build_deps + (dnsdist_xdp_build_deps if not skipXDP else [])))

@task
def ci_autoconf(c):
    c.run('autoreconf -vfi')

@task
def ci_docs_rec_generate(c):
    c.run('python3 generate.py')

@task
def ci_docs_build(c):
    c.run('make -f Makefile.sphinx -C docs html')

@task
def ci_docs_build_pdf(c):
    c.run('make -f Makefile.sphinx -C docs latexpdf')

@task
def ci_docs_upload_master(c, docs_host, pdf, username, product, directory=""):
    rsync_cmd = " ".join([
        "rsync",
        "--checksum",
        "--recursive",
        "--verbose",
        "--no-p",
        "--chmod=g=rwX",
        "--exclude '*~'",
    ])
    c.run(f"{rsync_cmd} --delete ./docs/_build/{product}-html-docs/ {username}@{docs_host}:{directory}")
    c.run(f"{rsync_cmd} ./docs/_build/{product}-html-docs.tar.bz2 {username}@{docs_host}:{directory}/html-docs.tar.bz2")
    c.run(f"{rsync_cmd} ./docs/_build/latex/{pdf} {username}@{docs_host}:{directory}")

@task
def ci_docs_add_ssh(c, ssh_key, host_key):
    c.run('mkdir -m 700 -p ~/.ssh')
    c.run(f'echo "{ssh_key}" > ~/.ssh/id_ed25519')
    c.run('chmod 600 ~/.ssh/id_ed25519')
    c.run(f'echo "{host_key}" > ~/.ssh/known_hosts')


def get_sanitizers():
    sanitizers = os.getenv('SANITIZERS', '')
    if sanitizers != '':
        sanitizers = sanitizers.split('+')
        sanitizers = ['--enable-' + sanitizer for sanitizer in sanitizers]
        sanitizers = ' '.join(sanitizers)
    return sanitizers

def get_unit_tests(auth=False):
    if os.getenv('UNIT_TESTS') != 'yes':
        return ''
    return '--enable-unit-tests --enable-backend-unit-tests' if auth else '--enable-unit-tests'

def get_build_concurrency(default=8):
    return os.getenv('CONCURRENCY', default)

def get_fuzzing_targets():
    return '--enable-fuzz-targets' if os.getenv('FUZZING_TARGETS') == 'yes' else ''

def is_compiler_clang():
    compiler = os.getenv('COMPILER', 'clang')
    return compiler == 'clang'

def get_c_compiler():
    return f'clang-{clang_version}' if is_compiler_clang() else 'gcc'

def get_cxx_compiler():
    return f'clang++-{clang_version}' if is_compiler_clang() else 'g++'

def get_optimizations():
    optimizations = os.getenv('OPTIMIZATIONS', 'yes')
    return '-O1' if optimizations == 'yes' else '-O0'

def get_cflags():
    return " ".join([
        get_optimizations(),
        "-Werror=vla",
        "-Werror=shadow",
        "-Wformat=2",
        "-Werror=format-security",
        "-fstack-clash-protection",
        "-fstack-protector-strong",
        "-fcf-protection=full",
        "-Werror=string-plus-int" if is_compiler_clang() else '',
    ])


def get_cxxflags():
    return " ".join([
        get_cflags(),
        "-Wp,-D_GLIBCXX_ASSERTIONS",
    ])


def get_base_configure_cmd(additional_c_flags='', additional_cxx_flags='', enable_systemd=True, enable_sodium=True):
    cflags = " ".join([get_cflags(), additional_c_flags])
    cxxflags = " ".join([get_cxxflags(), additional_cxx_flags])
    return " ".join([
        f'CFLAGS="{cflags}"',
        f'CXXFLAGS="{cxxflags}"',
        './configure',
        f"CC='{get_c_compiler()}'",
        f"CXX='{get_cxx_compiler()}'",
        "--enable-option-checking=fatal",
        "--enable-systemd" if enable_systemd else '',
        "--with-libsodium" if enable_sodium else '',
        "--enable-fortify-source=auto",
        "--enable-auto-var-init=pattern",
        get_coverage(),
        get_sanitizers()
    ])


@task
def ci_auth_configure(c):
    unittests = get_unit_tests(True)
    fuzz_targets = get_fuzzing_targets()
    modules = " ".join([
        "bind",
        "geoip",
        "gmysql",
        "godbc",
        "gpgsql",
        "gsqlite3",
        "ldap",
        "lmdb",
        "lua2",
        "pipe",
        "remote",
        "tinydns",
    ])
    configure_cmd = " ".join([
        get_base_configure_cmd(),
        "LDFLAGS='-L/usr/local/lib -Wl,-rpath,/usr/local/lib'",
        f"--with-modules='{modules}'",
        "--enable-tools",
        "--enable-dns-over-tls",
        "--enable-experimental-pkcs11",
        "--enable-experimental-gss-tsig",
        "--enable-remotebackend-zeromq",
        "--enable-verbose-logging",
        "--with-lmdb=/usr",
        "--with-libdecaf" if os.getenv('DECAF_SUPPORT', 'no') == 'yes' else '',
        "--prefix=/opt/pdns-auth",
        "--enable-ixfrdist",
        unittests,
        fuzz_targets
    ])
    res = c.run(configure_cmd, warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)


@task
def ci_rec_configure(c):
    unittests = get_unit_tests()

    configure_cmd = " ".join([
        get_base_configure_cmd(),
        "--enable-nod",
        "--prefix=/opt/pdns-recursor",
        "--with-lua=luajit",
        "--with-libcap",
        "--with-net-snmp",
        "--enable-dns-over-tls",
        "--enable-verbose-logging",
        unittests,
    ])
    res = c.run(configure_cmd, warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)


@task
def ci_dnsdist_configure(c, features):
    additional_flags = ''
    if features == 'full':
      features_set = '--enable-dnstap \
                      --enable-dnscrypt \
                      --enable-dns-over-tls \
                      --enable-dns-over-https \
                      --enable-dns-over-quic \
                      --enable-dns-over-http3 \
                      --enable-systemd \
                      --prefix=/opt/dnsdist \
                      --with-gnutls \
                      --with-h2o \
                      --with-libsodium \
                      --with-lua=luajit \
                      --with-libcap \
                      --with-net-snmp \
                      --with-nghttp2 \
                      --with-re2'
    else:
      features_set = '--disable-dnstap \
                      --disable-dnscrypt \
                      --disable-ipcipher \
                      --disable-systemd \
                      --without-cdb \
                      --without-ebpf \
                      --without-gnutls \
                      --without-h2o \
                      --without-libedit \
                      --without-libsodium \
                      --without-lmdb \
                      --without-net-snmp \
                      --without-nghttp2 \
                      --without-re2'
      additional_flags = '-DDISABLE_COMPLETION \
                          -DDISABLE_DELAY_PIPE \
                          -DDISABLE_DYNBLOCKS \
                          -DDISABLE_PROMETHEUS \
                          -DDISABLE_PROTOBUF \
                          -DDISABLE_BUILTIN_HTML \
                          -DDISABLE_CARBON \
                          -DDISABLE_SECPOLL \
                          -DDISABLE_DEPRECATED_DYNBLOCK \
                          -DDISABLE_LUA_WEB_HANDLERS \
                          -DDISABLE_NON_FFI_DQ_BINDINGS \
                          -DDISABLE_POLICIES_BINDINGS \
                          -DDISABLE_PACKETCACHE_BINDINGS \
                          -DDISABLE_DOWNSTREAM_BINDINGS \
                          -DDISABLE_COMBO_ADDR_BINDINGS \
                          -DDISABLE_CLIENT_STATE_BINDINGS \
                          -DDISABLE_QPS_LIMITER_BINDINGS \
                          -DDISABLE_SUFFIX_MATCH_BINDINGS \
                          -DDISABLE_NETMASK_BINDINGS \
                          -DDISABLE_DNSNAME_BINDINGS \
                          -DDISABLE_DNSHEADER_BINDINGS \
                          -DDISABLE_RECVMMSG \
                          -DDISABLE_WEB_CACHE_MANAGEMENT \
                          -DDISABLE_WEB_CONFIG \
                          -DDISABLE_RULES_ALTERING_QUERIES \
                          -DDISABLE_ECS_ACTIONS \
                          -DDISABLE_TOP_N_BINDINGS \
                          -DDISABLE_OCSP_STAPLING \
                          -DDISABLE_HASHED_CREDENTIALS \
                          -DDISABLE_FALSE_SHARING_PADDING \
                          -DDISABLE_NPN'
    unittests = get_unit_tests()
    fuzztargets = get_fuzzing_targets()
    tools = f'''AR=llvm-ar-{clang_version} RANLIB=llvm-ranlib-{clang_version}''' if is_compiler_clang() else ''
    configure_cmd = " ".join([
        tools,
        get_base_configure_cmd(additional_c_flags='', additional_cxx_flags=additional_flags, enable_systemd=False, enable_sodium=False),
        features_set,
        unittests,
        fuzztargets,
        '--enable-lto=thin',
        '--prefix=/opt/dnsdist'
    ])

    res = c.run(configure_cmd, warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)

@task
def ci_auth_make(c):
    c.run(f'make -j{get_build_concurrency()} -k V=1')

@task
def ci_auth_make_bear(c):
    c.run(f'bear --append -- make -j{get_build_concurrency()} -k V=1')

@task
def ci_rec_make(c):
    c.run(f'make -j{get_build_concurrency()} -k V=1')

@task
def ci_rec_make_bear(c):
    # Assumed to be running under ./pdns/recursordist/
    c.run(f'bear --append -- make -j{get_build_concurrency()} -k V=1')

@task
def ci_dnsdist_make(c):
    c.run(f'make -j{get_build_concurrency(4)} -k V=1')

@task
def ci_dnsdist_make_bear(c):
    # Assumed to be running under ./pdns/dnsdistdist/
    c.run(f'bear --append -- make -j{get_build_concurrency(4)} -k V=1')

@task
def ci_auth_install_remotebackend_test_deps(c):
    with c.cd('modules/remotebackend'):
      # c.run('bundle config set path vendor/bundle')
      c.run('sudo ruby -S bundle install')
    c.sudo('apt-get install -y socat')

@task
def ci_auth_run_unit_tests(c):
    res = c.run('make check', warn=True)
    if res.exited != 0:
      c.run('cat pdns/test-suite.log', warn=True)
      c.run('cat modules/remotebackend/test-suite.log', warn=True)
      raise UnexpectedExit(res)

@task
def ci_rec_run_unit_tests(c):
    res = c.run('make check', warn=True)
    if res.exited != 0:
      c.run('cat test-suite.log')
      raise UnexpectedExit(res)

@task
def ci_dnsdist_run_unit_tests(c):
    res = c.run('make check', warn=True)
    if res.exited != 0:
      c.run('cat test-suite.log')
      raise UnexpectedExit(res)

@task
def ci_make_distdir(c):
    res = c.run('make distdir')

@task
def ci_make_install(c):
    res = c.run('make install') # FIXME: this builds auth docs - again

@task
def add_auth_repo(c, dist_name, dist_release_name, pdns_repo_version):
    c.sudo('apt-get install -y curl gnupg2')
    if pdns_repo_version == 'master':
        c.sudo('curl -s -o /etc/apt/trusted.gpg.d/pdns-repo.asc https://repo.powerdns.com/CBC8B383-pub.asc')
    else:
        c.sudo('curl -s -o /etc/apt/trusted.gpg.d/pdns-repo.asc https://repo.powerdns.com/FD380FBB-pub.asc')
    c.run(f"echo 'deb [arch=amd64] http://repo.powerdns.com/{dist_name} {dist_release_name}-auth-{pdns_repo_version} main' | sudo tee /etc/apt/sources.list.d/pdns.list")
    c.run("echo 'Package: pdns-*' | sudo tee /etc/apt/preferences.d/pdns")
    c.run("echo 'Pin: origin repo.powerdns.com' | sudo tee -a /etc/apt/preferences.d/pdns")
    c.run("echo 'Pin-Priority: 600' | sudo tee -a /etc/apt/preferences.d/pdns")
    c.sudo('apt-get update')

@task
def test_api(c, product, backend=''):
    if product == 'recursor':
        with c.cd('regression-tests.api'):
            c.run(f'PDNSRECURSOR=/opt/pdns-recursor/sbin/pdns_recursor ./runtests recursor {backend}')
    elif product == 'auth':
        with c.cd('regression-tests.api'):
            c.run(f'PDNSSERVER=/opt/pdns-auth/sbin/pdns_server PDNSUTIL=/opt/pdns-auth/bin/pdnsutil SDIG=/opt/pdns-auth/bin/sdig MYSQL_HOST={auth_backend_ip_addr} PGHOST={auth_backend_ip_addr} PGPORT=5432 ./runtests authoritative {backend}')
    else:
        raise Failure('unknown product')

backend_regress_tests = dict(
    bind = [
        'bind-both',
        'bind-dnssec-both',
        'bind-dnssec-nsec3-both',
        'bind-dnssec-nsec3-optout-both',
        'bind-dnssec-nsec3-narrow',
        'bind-dnssec-pkcs11'
    ],
    geoip = [
        'geoip',
        'geoip-nsec3-narrow'
    ],
    lua2 = ['lua2', 'lua2-dnssec'],
    tinydns = ['tinydns'],
    remote = [
        'remotebackend-pipe',
        'remotebackend-unix',
        'remotebackend-http',
        'remotebackend-zeromq',
        'remotebackend-pipe-dnssec',
        'remotebackend-unix-dnssec',
        'remotebackend-http-dnssec',
        'remotebackend-zeromq-dnssec'
    ],
    lmdb = [
        'lmdb-nodnssec-both',
        'lmdb-both',
        'lmdb-nsec3-both',
        'lmdb-nsec3-optout-both',
        'lmdb-nsec3-narrow'
    ],
    gmysql = [
        'gmysql',
        'gmysql-nodnssec-both',
        'gmysql-nsec3-both',
        'gmysql-nsec3-optout-both',
        'gmysql-nsec3-narrow',
        'gmysql_sp-both'
    ],
    gpgsql = [
        'gpgsql',
        'gpgsql-nodnssec-both',
        'gpgsql-nsec3-both',
        'gpgsql-nsec3-optout-both',
        'gpgsql-nsec3-narrow',
        'gpgsql_sp-both'
    ],
    gsqlite3 = [
        'gsqlite3',
        'gsqlite3-nodnssec-both',
        'gsqlite3-nsec3-both',
        'gsqlite3-nsec3-optout-both',
        'gsqlite3-nsec3-narrow'
    ],
    godbc_sqlite3 = ['godbc_sqlite3-nodnssec'],
    godbc_mssql = [
        'godbc_mssql',
        'godbc_mssql-nodnssec',
        'godbc_mssql-nsec3',
        'godbc_mssql-nsec3-optout',
        'godbc_mssql-nsec3-narrow'
    ],
    ldap = [
        'ldap-tree',
        'ldap-simple',
        'ldap-strict'
    ],
    geoip_mmdb = ['geoip'],
)

godbc_mssql_credentials = {"username": "sa", "password": "SAsa12%%-not-a-secret-password"}

godbc_config = f'''
[pdns-mssql-docker]
Driver=FreeTDS
Trace=No
Server={auth_backend_ip_addr}
Port=1433
Database=pdns
TDS_Version=7.1

[pdns-mssql-docker-nodb]
Driver=FreeTDS
Trace=No
Server={auth_backend_ip_addr}
Port=1433
TDS_Version=7.1

[pdns-sqlite3-1]
Driver = SQLite3
Database = pdns.sqlite3

[pdns-sqlite3-2]
Driver = SQLite3
Database = pdns.sqlite32
'''

def setup_godbc_mssql(c):
    with open(os.path.expanduser("~/.odbc.ini"), "a") as f:
        f.write(godbc_config)
    c.sudo('sh -c \'echo "Threading=1" | cat /usr/share/tdsodbc/odbcinst.ini - | tee -a /etc/odbcinst.ini\'')
    c.sudo('sed -i "s/libtdsodbc.so/\/usr\/lib\/x86_64-linux-gnu\/odbc\/libtdsodbc.so/g" /etc/odbcinst.ini')
    c.run(f'echo "create database pdns" | isql -v pdns-mssql-docker-nodb {godbc_mssql_credentials["username"]} {godbc_mssql_credentials["password"]}')
    # FIXME: Skip 8bit-txt-unescaped test
    c.run('touch ${PWD}/regression-tests/tests/8bit-txt-unescaped/skip')

def setup_godbc_sqlite3(c):
    with open(os.path.expanduser("~/.odbc.ini"), "a") as f:
        f.write(godbc_config)
    c.sudo('sed -i "s/libsqlite3odbc.so/\/usr\/lib\/x86_64-linux-gnu\/odbc\/libsqlite3odbc.so/g" /etc/odbcinst.ini')

def setup_ldap_client(c):
    c.sudo('DEBIAN_FRONTEND=noninteractive apt-get install -y ldap-utils')
    c.sudo(f'sh -c \'echo "{auth_backend_ip_addr} ldapserver" | tee -a /etc/hosts\'')

def setup_softhsm(c):
    # Modify the location of the softhsm tokens and configuration directory.
    # Enables token generation by non-root users (runner)
    c.run('mkdir -p /opt/pdns-auth/softhsm/tokens')
    c.run('echo "directories.tokendir = /opt/pdns-auth/softhsm/tokens" > /opt/pdns-auth/softhsm/softhsm2.conf')

@task
def test_auth_backend(c, backend):
    pdns_auth_env_vars = f'PDNS=/opt/pdns-auth/sbin/pdns_server PDNS2=/opt/pdns-auth/sbin/pdns_server SDIG=/opt/pdns-auth/bin/sdig NOTIFY=/opt/pdns-auth/bin/pdns_notify NSEC3DIG=/opt/pdns-auth/bin/nsec3dig SAXFR=/opt/pdns-auth/bin/saxfr ZONE2SQL=/opt/pdns-auth/bin/zone2sql ZONE2LDAP=/opt/pdns-auth/bin/zone2ldap ZONE2JSON=/opt/pdns-auth/bin/zone2json PDNSUTIL=/opt/pdns-auth/bin/pdnsutil PDNSCONTROL=/opt/pdns-auth/bin/pdns_control PDNSSERVER=/opt/pdns-auth/sbin/pdns_server SDIG=/opt/pdns-auth/bin/sdig GMYSQLHOST={auth_backend_ip_addr} GMYSQL2HOST={auth_backend_ip_addr} MYSQL_HOST={auth_backend_ip_addr} PGHOST={auth_backend_ip_addr} PGPORT=5432'

    if backend == 'remote':
        ci_auth_install_remotebackend_test_deps(c)

    if backend == 'authpy':
        c.sudo(f'sh -c \'echo "{auth_backend_ip_addr} kerberos-server" | tee -a /etc/hosts\'')
        with c.cd('regression-tests.auth-py'):
            c.run(f'{pdns_auth_env_vars} WITHKERBEROS=YES ./runtests')
        return

    if backend == 'bind':
        setup_softhsm(c)
        with c.cd('regression-tests'):
            for variant in backend_regress_tests[backend]:
                c.run(f'{pdns_auth_env_vars} SOFTHSM2_CONF=/opt/pdns-auth/softhsm/softhsm2.conf ./start-test-stop 5300 {variant}')
        return

    if backend == 'godbc_sqlite3':
        setup_godbc_sqlite3(c)
        with c.cd('regression-tests'):
            for variant in backend_regress_tests[backend]:
                c.run(f'{pdns_auth_env_vars} GODBC_SQLITE3_DSN=pdns-sqlite3-1 ./start-test-stop 5300 {variant}')
        return

    if backend == 'godbc_mssql':
        setup_godbc_mssql(c)
        with c.cd('regression-tests'):
            for variant in backend_regress_tests[backend]:
                c.run(f'{pdns_auth_env_vars} GODBC_MSSQL_PASSWORD={godbc_mssql_credentials["password"]} GODBC_MSSQL_USERNAME={godbc_mssql_credentials["username"]} GODBC_MSSQL_DSN=pdns-mssql-docker GODBC_MSSQL2_PASSWORD={godbc_mssql_credentials["password"]} GODBC_MSSQL2_USERNAME={godbc_mssql_credentials["username"]} GODBC_MSSQL2_DSN=pdns-mssql-docker ./start-test-stop 5300 {variant}')
        return

    if backend == 'ldap':
        setup_ldap_client(c)

    if backend == 'geoip_mmdb':
        with c.cd('regression-tests'):
            for variant in backend_regress_tests[backend]:
                c.run(f'{pdns_auth_env_vars} geoipdatabase=../modules/geoipbackend/regression-tests/GeoLiteCity.mmdb ./start-test-stop 5300 {variant}')
        return

    with c.cd('regression-tests'):
        if backend == 'lua2':
            c.run('touch trustedkeys')  # avoid silly error during cleanup
        for variant in backend_regress_tests[backend]:
            c.run(f'{pdns_auth_env_vars} ./start-test-stop 5300 {variant}')

    if backend == 'gsqlite3':
        if os.getenv('SKIP_IPV6_TESTS'):
            pdns_auth_env_vars += ' context=noipv6'
        with c.cd('regression-tests.nobackend'):
            c.run(f'{pdns_auth_env_vars} ./runtests')
        c.run('/opt/pdns-auth/bin/pdnsutil test-algorithms')
        return

@task
def test_ixfrdist(c):
    with c.cd('regression-tests.ixfrdist'):
        c.run('IXFRDISTBIN=/opt/pdns-auth/bin/ixfrdist ./runtests')

@task
def test_dnsdist(c):
    c.run('chmod +x /opt/dnsdist/bin/*')
    c.run('ls -ald /var /var/agentx /var/agentx/master')
    c.run('ls -al /var/agentx/master')
    with c.cd('regression-tests.dnsdist'):
        c.run('DNSDISTBIN=/opt/dnsdist/bin/dnsdist LD_LIBRARY_PATH=/opt/dnsdist/lib/ ENABLE_SUDO_TESTS=1 ./runtests')

@task
def test_regression_recursor(c):
    c.run('/opt/pdns-recursor/sbin/pdns_recursor --version')
    c.run('PDNSRECURSOR=/opt/pdns-recursor/sbin/pdns_recursor RECCONTROL=/opt/pdns-recursor/bin/rec_control ./build-scripts/test-recursor')

@task
def test_bulk_recursor(c, threads, mthreads, shards):
    # We run an extremely small version of the bulk test, as GH does not seem to be able to handle the UDP load
    with c.cd('regression-tests'):
        c.run('curl -LO http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip')
        c.run('unzip top-1m.csv.zip -d .')
        c.run('chmod +x /opt/pdns-recursor/bin/* /opt/pdns-recursor/sbin/*')
        c.run(f'DNSBULKTEST=/usr/bin/dnsbulktest RECURSOR=/opt/pdns-recursor/sbin/pdns_recursor RECCONTROL=/opt/pdns-recursor/bin/rec_control THRESHOLD=95 TRACE=no ./recursor-test 5300 100 {threads} {mthreads} {shards}')

@task
def install_swagger_tools(c):
    c.run('npm install -g api-spec-converter')

@task
def swagger_syntax_check(c):
    c.run('api-spec-converter docs/http-api/swagger/authoritative-api-swagger.yaml -f swagger_2 -t openapi_3 -s json -c')

@task
def install_coverity_tools(c, project):
    token = os.getenv('COVERITY_TOKEN')
    c.run(f'curl -s https://scan.coverity.com/download/linux64 --data "token={token}&project={project}" | gunzip | sudo tar xvf /dev/stdin --strip-components=1 --no-same-owner -C /usr/local', hide=True)

@task
def coverity_clang_configure(c):
    c.sudo(f'/usr/local/bin/cov-configure --template --comptype clangcc --compiler clang++-{clang_version}')

@task
def coverity_make(c):
    c.run('/usr/local/bin/cov-build --dir cov-int make -j8 -k')

@task
def coverity_tarball(c, tarball):
    c.run(f'tar caf {tarball} cov-int')

@task
def coverity_upload(c, email, project, tarball):
    token = os.getenv('COVERITY_TOKEN')
    c.run(f'curl --form token={token} \
            --form email="{email}" \
            --form file=@{tarball} \
            --form version="$(./builder-support/gen-version)" \
            --form description="master build" \
            https://scan.coverity.com/builds?project={project}', hide=True)

@task
def ci_build_and_install_quiche(c, repo):
    with c.cd(f'{repo}/builder-support/helpers/'):
        c.run(f'sudo {repo}/builder-support/helpers/install_quiche.sh')

    # cannot use c.sudo() inside a cd() context, see https://github.com/pyinvoke/invoke/issues/687
    c.run('sudo mv /usr/lib/libdnsdist-quiche.so /usr/lib/libquiche.so')
    c.run("sudo sed -i 's,^Libs:.*,Libs: -lquiche,g' /usr/lib/pkgconfig/quiche.pc")
    c.run('mkdir -p /opt/dnsdist/lib')
    c.run('cp /usr/lib/libquiche.so /opt/dnsdist/lib/libquiche.so')

pulp_cmd_prefix = " ".join([
    "pulp",
    f"--base-url {os.getenv('PULP_URL', '')}",
    f"--username {os.getenv('PULP_CI_USERNAME', '')}",
    f"--password {os.getenv('PULP_CI_PASSWORD', '')}"
])

def run_pulp_cmd(c, cmd):
    res = c.run(f'{pulp_cmd_prefix} {cmd}')
    if res.exited != 0:
        raise UnexpectedExit(res)
    return res.stdout

@task
def validate_pulp_credentials(c):
    # Basic pulp command that require credentials to succeed
    repo_name = os.getenv("PULP_REPO_NAME", '')
    cmd = f'file repository show --repository {repo_name}'
    run_pulp_cmd(c, cmd)

@task
def pulp_upload_file_packages_by_folder(c, source):
    repo_name = os.getenv("PULP_REPO_NAME", '')
    for root, dirs, files in os.walk(source):
        for path in files:
            file = os.path.join(root, path).split('/',1)[1]
            # file repositories have been configured with autopublish set to true
            cmd = f'file content upload --repository {repo_name} --file {source}/{file} --relative-path {file}'
            run_pulp_cmd(c, cmd)

@task
def pulp_create_rpm_publication(c, product, list_os_rel, list_arch):
    rpm_distros = ["centos", "el"]
    for os_rel in json.loads(list_os_rel):
        if not "el-" in os_rel:
            break
        release = os_rel.split('-')[1]
        for arch in json.loads(list_arch):
            for distro in rpm_distros:
                repo_name = f"repo-{distro}-{release}-{arch}-{product}"
                cmd = f'rpm publication create --repository {repo_name} --checksum-type sha256'
                run_pulp_cmd(c, cmd)

@task
def pulp_create_deb_publication(c):
    deb_distros = ["debian", "ubuntu"]
    for distro in deb_distros:
        repo_name = f"repo-{distro}"
        cmd = f'deb publication create --repository {repo_name}'
        run_pulp_cmd(c, cmd)

@task
def pulp_upload_rpm_packages_by_folder(c, source, product):
    rpm_distros = ["centos", "el"]
    builds = os.listdir(source)

    for build_folder in builds:
        release = build_folder.split('.')[0].split('-')[1]
        arch = build_folder.split('.')[1]
        for distro in rpm_distros:
            repo_name = f"repo-{distro}-{release}-{arch}-{product}"
            for root, dirs, files in os.walk(f"{source}/{build_folder}"):
                for path in files:
                    file = os.path.join(root, path).split('/',1)[1]
                    # Set chunk size to 500MB to avoid creating an "upload" instead of a file. Required for signing RPMs.
                    cmd = f'rpm content -t package upload --file {source}/{file} --repository {repo_name} --no-publish --chunk-size 500MB'
                    run_pulp_cmd(c, cmd)

def get_pulp_repository_href(c, repo_name, repo_type):
    cmd = f"{repo_type} repository show --name {repo_name} | jq -r '.pulp_href' | tr -d '\n'"
    href = run_pulp_cmd(c, cmd)
    return href

def is_pulp_task_completed(c, task_href):
    elapsed_time = 0
    check_interval = 5
    max_wait_time = 60

    while elapsed_time < max_wait_time:
        cmd = f"task show --href {task_href} | jq -r .state | tr -d '\n'"
        task_state = run_pulp_cmd(c, cmd)
        if task_state == "completed":
            return True
        time.sleep(check_interval)
        elapsed_time += check_interval

    return False

@task
def pulp_upload_deb_packages_by_folder(c, source, product):
    builds = os.listdir(source)
    upload_url = os.getenv('PULP_URL', '') + "/pulp/api/v3/content/deb/packages/"
    headers = {"Content-Type": "application/json"}
    auth = requests.auth.HTTPBasicAuth(os.getenv("PULP_CI_USERNAME", ""), os.getenv("PULP_CI_PASSWORD", ""))

    for build_folder in builds:
        distro = build_folder.split('-')[0]
        distribution = f"{build_folder.split('-')[1]}-{product}"
        repo_name = f"repo-{distro}"
        repository_href = get_pulp_repository_href(c, repo_name, "deb")

        for root, dirs, files in os.walk(source):
            for path in files:
                file = os.path.join(root, path).split('/',1)[1]
                cmd = f"artifact upload --file {source}/{file} | jq -r '.pulp_href' | tr -d '\n'"
                artifact_href = run_pulp_cmd(c, cmd)

                package_data = {
                    "repository": repository_href,
                    "distribution": distribution,
                    "component": "main",
                    "artifact": artifact_href
                }

                try:
                    res = requests.post(upload_url, auth=auth, headers=headers, json=package_data)
                    res.raise_for_status()
                except requests.exceptions.HTTPError as e:
                    raise Failure(f'Error creating DEB upload: {e}')

                task_href = res.json().get('task')
                if not is_pulp_task_completed(c, task_href):
                    raise Failure('Error uploading DEB packages into Pulp')

@task
def test_install_package(c, product_name, distro_release, content_url, gpgkey_url, package_name, package_version):
    distro, release = distro_release.split('-')[:2]
    repo_domain = content_url.split('/')[2]
    is_rpm = True if distro == 'centos' or distro == 'el' else False

    if is_rpm:
        image_name = 'oraclelinux'
    else:
        image_name = distro
        # pdns package is called pdns-server for debian/ubuntu
        package_name = 'pdns-server' if package_name == 'pdns' else package_name

    # version of packages from master or not releases have a different order than the package name
    parts = package_version.split('.')
    if len(parts) > 4:
        if distro == 'el':
            if 'master' in package_version:
                package_version = f"{'.'.join(parts[:3])}.{parts[4]}.{parts[3]}.{'.'.join(parts[5:])}"
            else:
                package_version = f"{'.'.join(parts[:3])}-{parts[4]}.{parts[3]}.{'.'.join(parts[5:])}"
        else:
            package_version = f"{'.'.join(parts[:3])}+{parts[4]}.{parts[3]}.{'.'.join(parts[5:])}"

    # Add wildcards to work with and without releases
    parts = package_version.split('-')
    if len(parts) > 1:
        package_version = f"{parts[0]}*{parts[1]}" if is_rpm else f"{parts[0]}~{parts[1]}"

    dockerfile_rpm = f'''
FROM {image_name}:{release}
RUN curl -L {content_url}/repo-files/{distro}-{product_name}.repo -o /etc/yum.repos.d/{distro}-{product_name}.repo
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-{release}.noarch.rpm
RUN yum install -y {package_name}-{package_version}*
'''
    dockerfile_deb = f'''
FROM {image_name}:{release}
RUN apt update && apt install -y curl libluajit-5.1-dev adduser
RUN install -d /etc/apt/keyrings && curl -L {gpgkey_url} -o /etc/apt/keyrings/{product_name}-pub.asc
RUN echo "deb [signed-by=/etc/apt/keyrings/{product_name}-pub.asc] {content_url}/{distro} {release}-{product_name} main" | tee /etc/apt/sources.list.d/pdns.list
RUN bash -c 'echo -e "Package: auth*\\nPin: origin {repo_domain}\\nPin-Priority: 600" | tee /etc/apt/preferences.d/{product_name}'
RUN apt-get update && apt-get install -y {package_name}={package_version}*
'''
    dockerfile = dockerfile_rpm if is_rpm else dockerfile_deb
    with open('/tmp/Dockerfile', "w") as f:
        f.write(dockerfile)

    c.run(f'docker build . -t test-build-{product_name}-{distro_release}:latest -f /tmp/Dockerfile')

# this is run always
def setup():
    if '/usr/lib/ccache' not in os.environ['PATH']:
        os.environ['PATH']='/usr/lib/ccache:'+os.environ['PATH']

setup()
