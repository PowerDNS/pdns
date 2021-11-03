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
]
rec_build_deps = [
    'libcap-dev',
    'libfstrm-dev',
    'libsnmp-dev',
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
    'ruby-bundler',
    'ruby-dev',
    'socat',
    'softhsm2',
    'unbound-host',
    'unixodbc',
    'wget'
]

@task
def apt_fresh(c):
    c.sudo('apt-get update')
    c.sudo('apt-get dist-upgrade')

@task
def install_clang(c):
    """
    install clang-12 and llvm-12
    """
    c.sudo('apt-get -qq -y --no-install-recommends install clang-12 llvm-12')

@task
def install_clang_runtime(c):
    # this gives us the symbolizer, for symbols in asan/ubsan traces
    c.sudo('apt-get -qq -y --no-install-recommends install clang-12')

@task
def install_auth_build_deps(c):
    c.sudo('apt-get install -qq -y --no-install-recommends ' + ' '.join(all_build_deps + git_build_deps + auth_build_deps))

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
    authpy=[]
)

@task(help={'backend': 'Backend to install test deps for, e.g. gsqlite3; can be repeated'}, iterable=['backend'], optional=['backend'])
def install_auth_test_deps(c, backend): # FIXME: rename this, we do way more than apt-get
    extra=[]
    for b in backend:
        extra.extend(auth_backend_test_deps[b])
    c.sudo('apt-get -y -qq install ' + ' '.join(extra+auth_test_deps))

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

@task
def install_rec_test_deps(c): # FIXME: rename this, we do way more than apt-get
    c.sudo('apt-get --no-install-recommends install -qq -y \
              pdns-server curl unzip pdns-backend-bind pdns-tools daemontools \
              jq libfaketime lua-posix lua-socket moreutils bc authbind \
              python3-venv python3-dev default-libmysqlclient-dev libpq-dev \
              libluajit-5.1-2 \
              libboost-all-dev \
              libcap2 \
              libssl1.1 \
              libsystemd0 \
              libsodium23 \
              libfstrm0 \
              libsnmp35 \
              protobuf-compiler \
              snmpd \
              prometheus')

    c.run('chmod +x /opt/pdns-recursor/bin/* /opt/pdns-recursor/sbin/*')

    setup_authbind(c)

    c.run('sed "s/agentxperms 0700 0755 recursor/agentxperms 0777 0755/g" regression-tests.recursor-dnssec/snmpd.conf | sudo tee /etc/snmp/snmpd.conf')
    c.sudo('systemctl restart snmpd')
    time.sleep(5)
    c.sudo('chmod 755 /var/agentx')

@task
def install_dnsdist_test_deps(c): # FIXME: rename this, we do way more than apt-get
    c.sudo('apt-get install -qq -y \
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
              patch \
              protobuf-compiler \
              python3-venv snmpd prometheus')
    c.run('sed "s/agentxperms 0700 0755 dnsdist/agentxperms 0777 0755/g" regression-tests.dnsdist/snmpd.conf | sudo tee /etc/snmp/snmpd.conf')
    c.sudo('systemctl restart snmpd')
    time.sleep(5)
    c.sudo('chmod 755 /var/agentx')

@task
def install_rec_build_deps(c):
    c.sudo('apt-get install -qq -y --no-install-recommends ' +  ' '.join(all_build_deps + git_build_deps + rec_build_deps))

@task
def install_dnsdist_build_deps(c):
    c.sudo('apt-get install -qq -y --no-install-recommends ' +  ' '.join(all_build_deps + git_build_deps + dnsdist_build_deps))

@task
def ci_autoconf(c):
    c.run('BUILDER_VERSION=0.0.0-git1 autoreconf -vfi')

@task
def ci_auth_configure(c):
    res = c.run('''CFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int" \
                   CXXFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int -Wp,-D_GLIBCXX_ASSERTIONS" \
                   ./configure \
                      CC='clang-12' \
                      CXX='clang++-12' \
                      --enable-option-checking=fatal \
                      --with-modules='bind geoip gmysql godbc gpgsql gsqlite3 ldap lmdb lua2 pipe remote tinydns' \
                      --enable-systemd \
                      --enable-tools \
                      --enable-unit-tests \
                      --enable-backend-unit-tests \
                      --enable-fuzz-targets \
                      --enable-experimental-pkcs11 \
                      --enable-remotebackend-zeromq \
                      --with-lmdb=/usr \
                      --with-libsodium \
                      --prefix=/opt/pdns-auth \
                      --enable-ixfrdist \
                      --enable-asan \
                      --enable-ubsan''', warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)
@task
def ci_rec_configure(c):
    res = c.run('''            CFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int" \
            CXXFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int -Wp,-D_GLIBCXX_ASSERTIONS" \
            ./configure \
              CC='clang-12' \
              CXX='clang++-12' \
              --enable-option-checking=fatal \
              --enable-unit-tests \
              --enable-nod \
              --enable-systemd \
              --prefix=/opt/pdns-recursor \
              --with-libsodium \
              --with-lua=luajit \
              --with-libcap \
              --with-net-snmp \
              --enable-dns-over-tls \
              --enable-asan \
              --enable-ubsan''', warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)

@task
def ci_dnsdist_configure(c):
    sanitizers = ' '.join('--enable-'+x for x in os.getenv('SANITIZERS').split('+'))
    res = c.run('''CFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int" \
                   CXXFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int -Wp,-D_GLIBCXX_ASSERTIONS" \
                   ./configure \
                     CC='clang-12' \
                     CXX='clang++-12' \
                     --enable-option-checking=fatal \
                     --enable-unit-tests \
                     --enable-dnstap \
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
                     --with-re2 ''' + sanitizers, warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)

@task
def ci_auth_make(c):
    c.run('make -j8 -k V=1')

@task
def ci_rec_make(c):
    c.run('make -j8 -k V=1')

@task
def ci_dnsdist_make(c):
    c.run('make -j4 -k V=1')

@task
def ci_auth_install_remotebackend_ruby_deps(c):
    with c.cd('modules/remotebackend'):
      # c.run('bundle config set path vendor/bundle')
      c.run('sudo ruby -S bundle install')

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

    c.sudo('apt-get install -qq -y curl gnupg2')
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
      # FIXME: also run this with the mmdb we ship
    ],
    lua2 = [
      'lua2',
      'lua2-dnssec'
    ],
    tinydns = [
      'tinydns'
    ],
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
    gmysql   = ['gmysql',     'gmysql-nodnssec-both',   'gmysql-nsec3-both',   'gmysql-nsec3-optout-both',   'gmysql-nsec3-narrow',   'gmysql_sp-both'],
    gpgsql   = ['gpgsql',     'gpgsql-nodnssec-both',   'gpgsql-nsec3-both',   'gpgsql-nsec3-optout-both',   'gpgsql-nsec3-narrow',   'gpgsql_sp-both'],
    gsqlite3 = ['gsqlite3', 'gsqlite3-nodnssec-both', 'gsqlite3-nsec3-both', 'gsqlite3-nsec3-optout-both', 'gsqlite3-nsec3-narrow'],
)

@task
def test_auth_backend(c, backend):
    if backend == 'remote':
        ci_auth_install_remotebackend_ruby_deps(c)

    if backend == 'authpy':
        with c.cd('regression-tests.auth-py'):
            c.run(f'PDNS=/opt/pdns-auth/sbin/pdns_server PDNS2=/opt/pdns-auth/sbin/pdns_server SDIG=/opt/pdns-auth/bin/sdig NOTIFY=/opt/pdns-auth/bin/pdns_notify NSEC3DIG=/opt/pdns-auth/bin/nsec3dig SAXFR=/opt/pdns-auth/bin/saxfr ZONE2SQL=/opt/pdns-auth/bin/zone2sql ZONE2LDAP=/opt/pdns-auth/bin/zone2ldap ZONE2JSON=/opt/pdns-auth/bin/zone2json PDNSUTIL=/opt/pdns-auth/bin/pdnsutil PDNSCONTROL=/opt/pdns-auth/bin/pdns_control PDNSSERVER=/opt/pdns-auth/sbin/pdns_server SDIG=/opt/pdns-auth/bin/sdig GMYSQLHOST=127.0.0.1 GMYSQL2HOST=127.0.0.1 MYSQL_HOST="127.0.0.1" PGHOST="127.0.0.1" PGPORT="5432" ./runtests')
        return

    with c.cd('regression-tests'):
        if backend == 'lua2':
            c.run('touch trustedkeys')  # avoid silly error during cleanup
        for variant in backend_regress_tests[backend]:
            # FIXME this long line is terrible
            c.run(f'PDNS=/opt/pdns-auth/sbin/pdns_server PDNS2=/opt/pdns-auth/sbin/pdns_server SDIG=/opt/pdns-auth/bin/sdig NOTIFY=/opt/pdns-auth/bin/pdns_notify NSEC3DIG=/opt/pdns-auth/bin/nsec3dig SAXFR=/opt/pdns-auth/bin/saxfr ZONE2SQL=/opt/pdns-auth/bin/zone2sql ZONE2LDAP=/opt/pdns-auth/bin/zone2ldap ZONE2JSON=/opt/pdns-auth/bin/zone2json PDNSUTIL=/opt/pdns-auth/bin/pdnsutil PDNSCONTROL=/opt/pdns-auth/bin/pdns_control PDNSSERVER=/opt/pdns-auth/sbin/pdns_server SDIG=/opt/pdns-auth/bin/sdig GMYSQLHOST=127.0.0.1 GMYSQL2HOST=127.0.0.1 MYSQL_HOST="127.0.0.1" PGHOST="127.0.0.1" PGPORT="5432" ./start-test-stop 5300 {variant}')

    if backend == 'gsqlite3':
        with c.cd('regression-tests.nobackend'):
            c.run(f'PDNS=/opt/pdns-auth/sbin/pdns_server PDNS2=/opt/pdns-auth/sbin/pdns_server SDIG=/opt/pdns-auth/bin/sdig NOTIFY=/opt/pdns-auth/bin/pdns_notify NSEC3DIG=/opt/pdns-auth/bin/nsec3dig SAXFR=/opt/pdns-auth/bin/saxfr ZONE2SQL=/opt/pdns-auth/bin/zone2sql ZONE2LDAP=/opt/pdns-auth/bin/zone2ldap ZONE2JSON=/opt/pdns-auth/bin/zone2json PDNSUTIL=/opt/pdns-auth/bin/pdnsutil PDNSCONTROL=/opt/pdns-auth/bin/pdns_control PDNSSERVER=/opt/pdns-auth/sbin/pdns_server SDIG=/opt/pdns-auth/bin/sdig GMYSQLHOST=127.0.0.1 GMYSQL2HOST=127.0.0.1 MYSQL_HOST="127.0.0.1" PGHOST="127.0.0.1" PGPORT="5432" ./runtests')
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
    c.run('PDNSRECURSOR=/opt/pdns-recursor/sbin/pdns_recursor RECCONTROL=/opt/pdns-recursor/bin/rec_control SKIP_IPV6_TESTS=y LIBFAKETIME=/bin/false ./build-scripts/test-recursor test_RecDnstap.py')
    c.run('PDNSRECURSOR=/opt/pdns-recursor/sbin/pdns_recursor RECCONTROL=/opt/pdns-recursor/bin/rec_control SKIP_IPV6_TESTS=y ./build-scripts/test-recursor -I test_RecDnstap.py')

@task
def test_bulk_recursor(c, threads, mthreads, shards):
    # We run an extremely small version of the bulk test, as GH does not seem to be able to handle the UDP load
    with c.cd('regression-tests'):
        c.run('curl -LO http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip')
        c.run('unzip top-1m.csv.zip -d .')
        c.run('chmod +x /opt/pdns-recursor/bin/* /opt/pdns-recursor/sbin/*')
        c.run(f'DNSBULKTEST=/usr/bin/dnsbulktest RECURSOR=/opt/pdns-recursor/sbin/pdns_recursor RECCONTROL=/opt/pdns-recursor/bin/rec_control THRESHOLD=95 TRACE=no ./timestamp ./recursor-test 5300 100 {threads} {mthreads} {shards}')

# this is run always
def setup():
    if '/usr/lib/ccache' not in os.environ['PATH']:
        os.environ['PATH']='/usr/lib/ccache:'+os.environ['PATH']

setup()
