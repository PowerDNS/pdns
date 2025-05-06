from invoke import task
from invoke.exceptions import Failure, UnexpectedExit

import os
import sys
import time

all_build_deps = [
    'ccache',
    'libboost-all-dev',
    'libluajit-5.1-dev',
    'libsodium-dev',
    'libssl-dev',
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
    'libsnmp35',
    'libsodium23',
    'libssl1.1',
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
    'libboost-serialization1.71.0',
    'libcdb1',
    'libcurl4',
    'libgeoip1',
    'libkrb5-3',
    'libldap-2.4-2',
    'liblmdb0',
    'libluajit-5.1-2',
    'libmaxminddb0',
    'libnet-dns-perl',
    'libp11-kit0',
    'libpq5',
    'libsodium23',
    'libsqlite3-dev',
    'libssl1.1',
    'libsystemd0',
    'libyaml-cpp0.6',
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
    install clang-12 and llvm-12
    """
    c.sudo('apt-get -y --no-install-recommends install clang-12 llvm-12')

@task
def install_clang_tidy_tools(c):
    c.sudo('apt-get -y --no-install-recommends install clang-tidy-12 clang-tools-12 bear python3-yaml')

@task
def install_clang_runtime(c):
    # this gives us the symbolizer, for symbols in asan/ubsan traces
    c.sudo('apt-get -y --no-install-recommends install clang-12')

def install_libdecaf(c, product):
    c.run('git clone https://git.code.sf.net/p/ed448goldilocks/code /tmp/libdecaf')
    with c.cd('/tmp/libdecaf'):
        c.run('git checkout 41f349')
        c.run('CC=clang-12 CXX=clang-12 '
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
    install_libdecaf(c, 'pdns-auth')

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
    c.sudo('apt-get -y install ' + ' '.join(extra+auth_test_deps))

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
    c.sudo('systemctl restart snmpd')
    time.sleep(5)
    c.sudo('chmod 755 /var/agentx')

@task
def install_dnsdist_test_deps(c): # FIXME: rename this, we do way more than apt-get
    c.sudo('apt-get install -y \
              libluajit-5.1-2 \
              libboost-all-dev \
              libcap2 \
              libcdb1 \
              libcurl4-openssl-dev \
              libfstrm0 \
              libgnutls30 \
              libh2o-evloop0.13 \
              liblmdb0 \
              libnghttp2-14 \
              libre2-5 \
              libssl-dev \
              libsystemd0 \
              libsodium23 \
              lua-socket \
              patch \
              protobuf-compiler \
              python3-venv snmpd prometheus')
    c.run('sed "s/agentxperms 0700 0755 dnsdist/agentxperms 0777 0755/g" regression-tests.dnsdist/snmpd.conf | sudo tee /etc/snmp/snmpd.conf')
    c.sudo('systemctl restart snmpd')
    time.sleep(5)
    c.sudo('chmod 755 /var/agentx')

@task
def install_rec_build_deps(c):
    c.sudo('apt-get install -y --no-install-recommends ' +  ' '.join(all_build_deps + git_build_deps + rec_build_deps))

@task
def install_dnsdist_build_deps(c):
    c.sudo('apt-get install -y --no-install-recommends ' +  ' '.join(all_build_deps + git_build_deps + dnsdist_build_deps))

@task
def ci_autoconf(c):
    c.run('BUILDER_VERSION=0.0.0-git1 autoreconf -vfi')

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
    sanitizers = os.getenv('SANITIZERS')
    if sanitizers != '':
        sanitizers = sanitizers.split('+')
        sanitizers = ['--enable-' + sanitizer for sanitizer in sanitizers]
        sanitizers = ' '.join(sanitizers)
    return sanitizers


def get_cflags():
    return " ".join([
        "-O1",
        "-Werror=vla",
        "-Werror=shadow",
        "-Wformat=2",
        "-Werror=format-security",
        "-Werror=string-plus-int",
    ])


def get_cxxflags():
    return " ".join([
        get_cflags(),
        "-Wp,-D_GLIBCXX_ASSERTIONS",
    ])


def get_base_configure_cmd():
    return " ".join([
        f'CFLAGS="{get_cflags()}"',
        f'CXXFLAGS="{get_cxxflags()}"',
        './configure',
        "CC='clang-12'",
        "CXX='clang++-12'",
        "--enable-option-checking=fatal",
        "--enable-systemd",
        "--with-libsodium",
        "--enable-fortify-source=auto",
        "--enable-auto-var-init=pattern",
    ])


@task
def ci_auth_configure(c):
    sanitizers = get_sanitizers()

    unittests = os.getenv('UNIT_TESTS')
    if unittests == 'yes':
        unittests = '--enable-unit-tests --enable-backend-unit-tests'
    else:
        unittests = ''

    fuzz_targets = os.getenv('FUZZING_TARGETS')
    fuzz_targets = '--enable-fuzz-targets' if fuzz_targets == 'yes' else ''

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
        "--enable-experimental-pkcs11",
        "--enable-experimental-gss-tsig",
        "--enable-remotebackend-zeromq",
        "--with-lmdb=/usr",
        "--with-libdecaf",
        "--prefix=/opt/pdns-auth",
        "--enable-ixfrdist",
        sanitizers,
        unittests,
        fuzz_targets,
    ])
    res = c.run(configure_cmd, warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)


@task
def ci_rec_configure(c):
    sanitizers = get_sanitizers()

    unittests = os.getenv('UNIT_TESTS')
    unittests = '--enable-unit-tests' if unittests == 'yes' else ''

    configure_cmd = " ".join([
        get_base_configure_cmd(),
        "--enable-nod",
        "--prefix=/opt/pdns-recursor",
        "--with-lua=luajit",
        "--with-libcap",
        "--with-net-snmp",
        "--enable-dns-over-tls",
        sanitizers,
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
                      --enable-systemd \
                      --prefix=/opt/dnsdist \
                      --with-gnutls \
                      --with-libsodium \
                      --with-lua=luajit \
                      --with-libcap \
                      --with-nghttp2 \
                      --with-re2 '
    else:
      features_set = '--disable-dnstap \
                      --disable-dnscrypt \
                      --disable-ipcipher \
                      --disable-systemd \
                      --without-cdb \
                      --without-ebpf \
                      --without-gnutls \
                      --without-libedit \
                      --without-libsodium \
                      --without-lmdb \
                      --without-net-snmp \
                      --without-nghttp2 \
                      --without-re2 '
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
    unittests = ' --enable-unit-tests' if os.getenv('UNIT_TESTS') == 'yes' else ''
    sanitizers = ' '.join('--enable-'+x for x in os.getenv('SANITIZERS').split('+')) if os.getenv('SANITIZERS') != '' else ''
    cflags = '-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int'
    cxxflags = cflags + ' -Wp,-D_GLIBCXX_ASSERTIONS ' + additional_flags
    res = c.run('''CFLAGS="%s" \
                   CXXFLAGS="%s" \
                   AR=llvm-ar-12 \
                   RANLIB=llvm-ranlib-12 \
                   ./configure \
                     CC='clang-12' \
                     CXX='clang++-12' \
                     --enable-option-checking=fatal \
                     --enable-fortify-source=auto \
                     --enable-auto-var-init=pattern \
                     --enable-lto=thin \
                     --prefix=/opt/dnsdist %s %s %s''' % (cflags, cxxflags, features_set, sanitizers, unittests), warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)

@task
def ci_auth_make(c):
    c.run('make -j8 -k V=1')

@task
def ci_auth_make_bear(c):
    # Needed for clang-tidy -line-filter vs project structure shenanigans
    with c.cd('pdns'):
        c.run('bear --append make -j8 -k V=1 -C ..')

@task
def ci_rec_make(c):
    c.run('make -j8 -k V=1')

@task
def ci_rec_make_bear(c):
    # Assumed to be running under ./pdns/recursordist/
    c.run('bear --append make -j8 -k V=1')

@task
def ci_dnsdist_make(c):
    c.run('make -j4 -k V=1')

@task
def ci_dnsdist_make_bear(c):
    # Assumed to be running under ./pdns/dnsdistdist/
    c.run('bear --append make -j4 -k V=1')

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
def ci_make_install(c):
    res = c.run('make install') # FIXME: this builds auth docs - again

@task
def add_auth_repo(c):
    dist = 'ubuntu' # FIXME take these from the caller?
    release = 'focal'
    version = '44'

    c.sudo('apt-get install -y curl gnupg2')
    if version == 'master':
        c.sudo('curl -s -o /etc/apt/trusted.gpg.d/pdns-repo.asc https://repo.powerdns.com/CBC8B383-pub.asc')
    else:
        c.sudo('curl -s -o /etc/apt/trusted.gpg.d/pdns-repo.asc https://repo.powerdns.com/FD380FBB-pub.asc')
    c.run(f"echo 'deb [arch=amd64] http://repo.powerdns.com/{dist} {release}-auth-{version} main' | sudo tee /etc/apt/sources.list.d/pdns.list")
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
            c.run(f'PDNSSERVER=/opt/pdns-auth/sbin/pdns_server PDNSUTIL=/opt/pdns-auth/bin/pdnsutil SDIG=/opt/pdns-auth/bin/sdig MYSQL_HOST="127.0.0.1" PGHOST="127.0.0.1" PGPORT="5432" ./runtests authoritative {backend}')
    else:
        raise Failure('unknown product')

backend_regress_tests = dict(
    bind = [
        'bind-both',
        'bind-dnssec-both',
        'bind-dnssec-nsec3-both',
        'bind-dnssec-nsec3-optout-both',
        'bind-dnssec-nsec3-narrow',
        # FIXME  'bind-dnssec-pkcs11'
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

godbc_mssql_credentials = {"username": "sa", "password": "SAsa12%%"}

godbc_config = '''
[pdns-mssql-docker]
Driver=FreeTDS
Trace=No
Server=127.0.0.1
Port=1433
Database=pdns
TDS_Version=7.1

[pdns-mssql-docker-nodb]
Driver=FreeTDS
Trace=No
Server=127.0.0.1
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
    c.sudo('sh -c \'echo "127.0.0.1 ldapserver" | tee -a /etc/hosts\'')

@task
def test_auth_backend(c, backend):
    pdns_auth_env_vars = 'PDNS=/opt/pdns-auth/sbin/pdns_server PDNS2=/opt/pdns-auth/sbin/pdns_server SDIG=/opt/pdns-auth/bin/sdig NOTIFY=/opt/pdns-auth/bin/pdns_notify NSEC3DIG=/opt/pdns-auth/bin/nsec3dig SAXFR=/opt/pdns-auth/bin/saxfr ZONE2SQL=/opt/pdns-auth/bin/zone2sql ZONE2LDAP=/opt/pdns-auth/bin/zone2ldap ZONE2JSON=/opt/pdns-auth/bin/zone2json PDNSUTIL=/opt/pdns-auth/bin/pdnsutil PDNSCONTROL=/opt/pdns-auth/bin/pdns_control PDNSSERVER=/opt/pdns-auth/sbin/pdns_server SDIG=/opt/pdns-auth/bin/sdig GMYSQLHOST=127.0.0.1 GMYSQL2HOST=127.0.0.1 MYSQL_HOST="127.0.0.1" PGHOST="127.0.0.1" PGPORT="5432"'

    if backend == 'remote':
        ci_auth_install_remotebackend_test_deps(c)

    if backend == 'authpy':
        with c.cd('regression-tests.auth-py'):
            c.run(f'{pdns_auth_env_vars} WITHKERBEROS=YES ./runtests')
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
        c.run('DNSDISTBIN=/opt/dnsdist/bin/dnsdist ./runtests')

@task
def test_regression_recursor(c):
    c.run('/opt/pdns-recursor/sbin/pdns_recursor --version')
    c.run('PDNSRECURSOR=/opt/pdns-recursor/sbin/pdns_recursor RECCONTROL=/opt/pdns-recursor/bin/rec_control SKIP_IPV6_TESTS=y ./build-scripts/test-recursor')

@task
def test_bulk_recursor(c, threads, mthreads, shards):
    # We run an extremely small version of the bulk test, as GH does not seem to be able to handle the UDP load
    with c.cd('regression-tests'):
        c.run('curl -LO http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip')
        c.run('unzip top-1m.csv.zip -d .')
        c.run('chmod +x /opt/pdns-recursor/bin/* /opt/pdns-recursor/sbin/*')
        c.run(f'DNSBULKTEST=/usr/bin/dnsbulktest RECURSOR=/opt/pdns-recursor/sbin/pdns_recursor RECCONTROL=/opt/pdns-recursor/bin/rec_control THRESHOLD=95 TRACE=no ./timestamp ./recursor-test 5300 100 {threads} {mthreads} {shards}')

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
    c.sudo('/usr/local/bin/cov-configure --template --comptype clangcc --compiler clang++-12')

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

# this is run always
def setup():
    if '/usr/lib/ccache' not in os.environ['PATH']:
        os.environ['PATH']='/usr/lib/ccache:'+os.environ['PATH']

setup()
