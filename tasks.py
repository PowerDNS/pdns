import os
import time
from invoke import task
from invoke.exceptions import Failure, UnexpectedExit

auth_backend_ip_addr = os.getenv('AUTH_BACKEND_IP_ADDR', '127.0.0.1')

clang_version = os.getenv('CLANG_VERSION', '13')
repo_home = os.getenv('REPO_HOME', '.')

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
    'python3-venv',
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
    'bind9-dnsutils',
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
rec_bulk_ubicloud_deps = [
    'curl',
    'bind9-dnsutils',
    'libboost-context1.74.0',
    'libboost-system1.74.0',
    'libboost-filesystem1.74.0',
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
    'bind9-dnsutils',
    'datefudge',
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
    'python3-venv',
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
def install_lld_linker_if_needed(c):
    if is_compiler_clang():
        c.sudo(f'apt-get -y --no-install-recommends install lld-{clang_version}')

@task
def install_clang(c):
    """
    install clang and llvm
    """
    if int(clang_version) >= 14:
        c.sudo(f'apt-get -y --no-install-recommends install clang-{clang_version} llvm-{clang_version} llvm-{clang_version}-dev libclang-rt-{clang_version}-dev')
    else:
        c.sudo(f'apt-get -y --no-install-recommends install clang-{clang_version} llvm-{clang_version} llvm-{clang_version}-dev')

@task
def install_clang_tidy_tools(c):
    c.sudo(f'apt-get -y --no-install-recommends install clang-tidy-{clang_version} clang-tools-{clang_version} bear python3-yaml')

@task
def install_clang_runtime(c):
    # this gives us the symbolizer, for symbols in asan/ubsan traces
    # on Debian we need llvm-symbolizer-XX
    #c.sudo(f'apt-get -y --no-install-recommends install llvm-symbolizer-{clang_version}')
    # on Ubuntu we need llvm-XX instead
    c.sudo(f'apt-get -y --no-install-recommends install llvm-{clang_version}')

@task
def ci_install_rust(c, repo):
    with c.cd(f'{repo}/builder-support/helpers/'):
        c.run('sudo sh install_rust.sh')

@task
def install_doc_deps(c):
    c.sudo('apt-get install -y ' + ' '.join(doc_deps))

@task
def install_doc_deps_pdf(c):
    c.sudo('apt-get install -y ' + ' '.join(doc_deps_pdf))

@task
def install_auth_build_deps(c):
    c.sudo('apt-get install -y --no-install-recommends ' + ' '.join(all_build_deps + git_build_deps + auth_build_deps))

def is_coverage_enabled():
    sanitizers = os.getenv('SANITIZERS')
    if sanitizers:
        sanitizers = sanitizers.split('+')
        if 'tsan' in sanitizers:
            return False
    return os.getenv('COVERAGE') == 'yes'

def get_coverage(meson=False):
    if meson:
        return '-Dclang-coverage-format=true' if is_coverage_enabled() else ''
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
        c.run(f'{outputDir}/.github/scripts/normalize_paths_in_coverage.py {outputDir} {version} {outputDir}/coverage.lcov {outputDir}/normalized_coverage.lcov 0')
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
def install_auth_test_deps_only(c, backend):
    extra=[]
    for b in backend:
        extra.extend(auth_backend_test_deps[b])
    c.sudo('apt-get update')
    c.sudo('DEBIAN_FRONTEND=noninteractive apt-get -y install ' + ' '.join(extra+auth_test_deps))

@task(help={'backend': 'Backend to install test deps for, e.g. gsqlite3; can be repeated'}, iterable=['backend'], optional=['backend'])
def install_auth_test_deps(c, backend): # FIXME: rename this, we do way more than apt-get
    install_auth_test_deps_only(c, backend)

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
def install_rec_bulk_deps(c): # FIXME: rename this, we do way more than apt-get
    c.sudo('apt-get --no-install-recommends -y install ' + ' '.join(rec_bulk_deps))
    c.run('chmod +x /opt/pdns-recursor/bin/* /opt/pdns-recursor/sbin/*')

@task
def install_rec_bulk_ubicloud_deps(c): # FIXME: rename this, we do way more than apt-get
    c.sudo('apt-get --no-install-recommends -y install ' + ' '.join(rec_bulk_ubicloud_deps))
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
def ci_autoconf(c, meson=False):
    if not meson:
        c.run('autoreconf -vfi')

@task
def ci_docs_rec_generate(c):
    c.run('python3 generate.py')

@task
def ci_metrics_rec_generate(c):
    c.run('python3 metrics.py')

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

@task
def ci_docs_add_ssh(c, ssh_key, host_key):
    c.run('mkdir -m 700 -p ~/.ssh')
    c.run(f'echo "{ssh_key}" > ~/.ssh/id_ed25519')
    c.run('chmod 600 ~/.ssh/id_ed25519')
    c.run(f'echo "{host_key}" > ~/.ssh/known_hosts')


def get_sanitizers(meson=False):
    sanitizers = os.getenv('SANITIZERS', '')
    if meson:
        subst = {
            'tsan': 'thread',
            'asan': 'address',
            'ubsan': 'undefined'
        }
        meson_sanitizers = ''
        sanitizers = sanitizers.split('+')
        for sanitizer in sanitizers:
            if sanitizer in subst:
                if meson_sanitizers != '':
                    meson_sanitizers = meson_sanitizers + ','
                meson_sanitizers = meson_sanitizers + subst[sanitizer]
            else:
                meson_sanitizers = meson_sanitizers + sanitizer

        return f'-D b_sanitize={meson_sanitizers}' if meson_sanitizers != '' else ''
    if sanitizers != '':
        sanitizers = sanitizers.split('+')
        sanitizers = ['--enable-' + sanitizer for sanitizer in sanitizers]
        sanitizers = ' '.join(sanitizers)
    return sanitizers

def get_unit_tests(meson=False, auth=False):
    if os.getenv('UNIT_TESTS') != 'yes':
        return ''
    if meson:
        return '-D unit-tests=true -D unit-tests-backends=true' if auth else '-D unit-tests=true'
    return '--enable-unit-tests --enable-backend-unit-tests' if auth else '--enable-unit-tests'

def get_build_concurrency(default=8):
    return os.getenv('CONCURRENCY', default)

def get_fuzzing_targets(meson=False):
    if meson:
        return '-D fuzz-targets=true' if os.getenv('FUZZING_TARGETS') == 'yes' else ''
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


def get_base_configure_cmd(additional_c_flags='', additional_cxx_flags='', additional_ld_flags='', enable_systemd=True, enable_sodium=True):
    cflags = " ".join([get_cflags(), additional_c_flags])
    cxxflags = " ".join([get_cxxflags(), additional_cxx_flags])
    ldflags = additional_ld_flags
    return " ".join([
        f'CFLAGS="{cflags}"',
        f'CXXFLAGS="{cxxflags}"',
        f'LDFLAGS="{ldflags}"',
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

def get_base_configure_cmd_meson(build_dir, additional_c_flags='', additional_cxx_flags='', enable_systemd=True, enable_sodium=True):
    cflags = " ".join([get_cflags(), additional_c_flags])
    cxxflags = " ".join([get_cxxflags(), additional_cxx_flags])
    env = " ".join([
        f'CFLAGS="{cflags}"',
        f'CXXFLAGS="{cxxflags}"',
        f"CC='{get_c_compiler()}'",
        f"CXX='{get_cxx_compiler()}'"
    ])
    return " ".join([
        f'{env} meson setup {build_dir}',
        "-D systemd-service={}".format("enabled" if enable_systemd else "disabled"),
        "-D signers-libsodium={}".format("enabled" if enable_sodium else "disabled"),
        "-D hardening-fortify-source=auto",
        "-D auto-var-init=pattern",
        get_coverage(meson=True),
        get_sanitizers(meson=True)
    ])

def ci_auth_configure_autotools(c):
    unittests = get_unit_tests(auth=True)
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
        "--prefix=/opt/pdns-auth",
        "--enable-ixfrdist",
        unittests,
        fuzz_targets
    ])
    res = c.run(configure_cmd, warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)

def ci_auth_configure_meson(c, build_dir):
    unittests = get_unit_tests(meson=True, auth=True)
    fuzz_targets = get_fuzzing_targets(meson=True)
    configure_cmd = " ".join([
        "LDFLAGS='-L/usr/local/lib -Wl,-rpath,/usr/local/lib'",
        get_base_configure_cmd_meson(build_dir),
        "-D module-bind=static",
        "-D module-geoip=static",
        "-D module-gmysql=static",
        "-D module-godbc=static",
        "-D module-gpgsql=static",
        "-D module-gsqlite3=static",
        "-D module-ldap=static",
        "-D module-lmdb=static",
        "-D module-lua2=static",
        "-D module-pipe=static",
        "-D module-remote=static",
        "-D module-remote-zeromq=true",
        "-D module-tinydns=static",
        "-D tools=true",
        "-D dns-over-tls=enabled",
        "-D experimental-pkcs11=enabled",
        "-D experimental-gss-tsig=enabled",
        "-D prefix=/opt/pdns-auth",
        "-D tools-ixfrdist=true",
        unittests,
        fuzz_targets
    ])
    res = c.run(configure_cmd, warn=True)
    if res.exited != 0:
        c.run(f'cat {build_dir}/meson-logs/meson-log.txt')
        raise UnexpectedExit(res)

@task
def ci_auth_configure(c, build_dir=None, meson=False):
    if meson:
        ci_auth_configure_meson(c, build_dir)
    else:
        ci_auth_configure_autotools(c)
        if build_dir:
            ci_make_distdir(c)
            with c.cd(f'{build_dir}'):
                ci_auth_configure_autotools(c)

def ci_rec_configure_meson(c, features, build_dir):
    unittests = get_unit_tests(meson=True, auth=False)
    if features == "full":
        configure_cmd = " ".join([
            "LDFLAGS='-L/usr/local/lib -Wl,-rpath,/usr/local/lib'",
            get_base_configure_cmd_meson(build_dir),
            "-D prefix=/opt/pdns-recursor",
            "-D dns-over-tls=enabled",
            "-D nod=enabled",
            "-D libcap=enabled",
            "-D lua=luajit",
            "-D snmp=enabled",
            unittests,
        ])
    else:
        configure_cmd = " ".join([
            "LDFLAGS='-L/usr/local/lib -Wl,-rpath,/usr/local/lib'",
            get_base_configure_cmd_meson(build_dir),
            "-D prefix=/opt/pdns-recursor",
            "-D dns-over-tls=disabled",
            "-D dnstap=disabled",
            "-D nod=disabled",
            "-D systemd-service=disabled",
            "-D lua=luajit",
            "-D libcap=disabled",
            "-D libcurl=disabled",
            "-D signers-libsodium=disabled",
            "-D snmp=disabled",
            unittests,
        ])
    res = c.run(configure_cmd, warn=True)
    if res.exited != 0:
        c.run(f'cat {build_dir}/meson-logs/meson-log.txt')
        raise UnexpectedExit(res)

def ci_rec_configure_autotools(c, features):
    unittests = get_unit_tests()
    if features == 'full':
        configure_cmd = " ".join([
            get_base_configure_cmd(),
            "--prefix=/opt/pdns-recursor",
            "--enable-option-checking",
            "--enable-verbose-logging",
            "--enable-dns-over-tls",
            "--enable-nod",
            "--with-libcap",
            "--with-lua=luajit",
            "--with-net-snmp",
            unittests,
        ])
    else:
        configure_cmd = " ".join([
            get_base_configure_cmd(),
            "--prefix=/opt/pdns-recursor",
            "--enable-option-checking",
            "--enable-verbose-logging",
            "--disable-dns-over-tls",
            "--disable-dnstap",
            "--disable-nod",
            "--disable-systemd",
            "--with-lua=luajit",
            "--without-libcap",
            "--without-libcurl",
            "--without-libsodium",
            "--without-net-snmp",
            unittests,
        ])
    res = c.run(configure_cmd, warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)

@task
def ci_rec_configure(c, features, build_dir=None, meson=False):
    if meson:
        ci_rec_configure_meson(c, features, build_dir)
    else:
        ci_rec_configure_autotools(c, features)
        if build_dir:
            ci_make_distdir(c)
            with c.cd(f'{build_dir}'):
                ci_rec_configure_autotools(c, features)

@task
def ci_dnsdist_configure(c, features, builder, build_dir):
    additional_flags = ''
    additional_ld_flags = ''
    if is_compiler_clang():
        additional_ld_flags += '-fuse-ld=lld '

    if features == 'least':
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

    if builder == 'meson':
        cmd = ci_dnsdist_configure_meson(features, additional_flags, additional_ld_flags, build_dir)
        logfile = 'meson-logs/meson-log.txt'
    else:
        cmd = ci_dnsdist_configure_autotools(features, additional_flags, additional_ld_flags)
        logfile = 'config.log'

    res = c.run(cmd, warn=True)
    if res.exited != 0:
        c.run(f'cat {logfile}')
        raise UnexpectedExit(res)

def ci_dnsdist_configure_autotools(features, additional_flags, additional_ld_flags):
    if features == 'full':
      features_set = '--enable-dnstap \
                      --enable-dnscrypt \
                      --enable-dns-over-tls \
                      --enable-dns-over-https \
                      --enable-dns-over-quic \
                      --enable-dns-over-http3 \
                      --enable-systemd \
                      --enable-yaml \
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
    unittests = get_unit_tests()
    fuzztargets = get_fuzzing_targets()
    tools = f'''AR=llvm-ar-{clang_version} RANLIB=llvm-ranlib-{clang_version}''' if is_compiler_clang() else ''
    return " ".join([
        tools,
        get_base_configure_cmd(additional_c_flags='', additional_cxx_flags=additional_flags, additional_ld_flags=additional_ld_flags, enable_systemd=False, enable_sodium=False),
        features_set,
        unittests,
        fuzztargets,
        '--enable-lto=thin',
        '--prefix=/opt/dnsdist'
    ])

def ci_dnsdist_configure_meson(features, additional_flags, additional_ld_flags, build_dir):
    if features == 'full':
      features_set = '-D cdb=enabled \
                      -D dnscrypt=enabled \
                      -D dnstap=enabled \
                      -D ebpf=enabled \
                      -D h2o=enabled \
                      -D ipcipher=enabled \
                      -D libedit=enabled \
                      -D libsodium=enabled \
                      -D lmdb=enabled \
                      -D nghttp2=enabled \
                      -D re2=enabled \
                      -D systemd-service=enabled \
                      -D tls-gnutls=enabled \
                      -D dns-over-https=enabled \
                      -D dns-over-http3=enabled \
                      -D dns-over-quic=enabled \
                      -D dns-over-tls=enabled \
                      -D reproducible=true \
                      -D snmp=enabled \
                      -D yaml=enabled'
    else:
      features_set = '-D cdb=disabled \
                      -D dnscrypt=disabled \
                      -D dnstap=disabled \
                      -D ebpf=disabled \
                      -D h2o=disabled \
                      -D ipcipher=disabled \
                      -D libedit=disabled \
                      -D libsodium=disabled \
                      -D lmdb=disabled \
                      -D nghttp2=disabled \
                      -D re2=disabled \
                      -D systemd-service=disabled \
                      -D tls-gnutls=disabled \
                      -D dns-over-https=disabled \
                      -D dns-over-http3=disabled \
                      -D dns-over-quic=disabled \
                      -D dns-over-tls=disabled \
                      -D reproducible=false \
                      -D snmp=disabled \
                      -D yaml=disabled'
    unittests = get_unit_tests(meson=True)
    fuzztargets = get_fuzzing_targets(meson=True)
    tools = f'''AR=llvm-ar-{clang_version} RANLIB=llvm-ranlib-{clang_version}''' if is_compiler_clang() else ''
    cflags = " ".join([get_cflags()])
    cxxflags = " ".join([get_cxxflags(), additional_flags])
    env = " ".join([
        tools,
        f'CFLAGS="{cflags}"',
        f'LDFLAGS="{additional_ld_flags}"',
        f'CXXFLAGS="{cxxflags}"',
        f"CC='{get_c_compiler()}'",
        f"CXX='{get_cxx_compiler()}'",
    ])
    return " ".join([
        f'. {repo_home}/.venv/bin/activate && {env} meson setup {build_dir}',
        features_set,
        unittests,
        fuzztargets,
        "-D hardening-fortify-source=auto",
        "-D auto-var-init=pattern",
        get_coverage(meson=True),
        get_sanitizers(meson=True)
    ])

@task
def ci_auth_make(c):
    c.run(f'make -j{get_build_concurrency()} -k V=1')

@task
def ci_auth_make_bear(c):
    c.run(f'bear --append -- make -j{get_build_concurrency()} -k V=1')

def run_ninja(c):
    c.run(f'ninja -j{get_build_concurrency()} --verbose')

@task
def ci_auth_build(c, meson=False):
    if meson:
        run_ninja(c)
    else:
        ci_auth_make_bear(c)

@task
def ci_rec_make_bear(c):
    # Assumed to be running under ./pdns/recursordist/
    c.run(f'bear --append -- make -j{get_build_concurrency()} -k V=1')

@task
def ci_rec_build(c, meson=False):
    if meson:
        run_ninja(c)
    else:
        ci_rec_make_bear(c)

@task
def ci_dnsdist_make(c):
    c.run(f'make -j{get_build_concurrency(4)} -k V=1')

def ci_dnsdist_run_ninja(c):
    c.run(f'. {repo_home}/.venv/bin/activate && ninja -j{get_build_concurrency(4)} --verbose')

@task
def ci_dnsdist_make_bear(c, builder):
    if builder == 'meson':
        return ci_dnsdist_run_ninja(c)

    # Assumed to be running under ./pdns/dnsdistdist/
    c.run(f'bear --append -- make -j{get_build_concurrency(4)} -k V=1')

@task
def ci_auth_install_remotebackend_test_deps(c):
    c.sudo('apt-get install -y socat')

@task
def ci_auth_run_unit_tests(c, meson=False):
    if meson:
        suite_timeout_sec = 120
        logfile = 'meson-logs/testlog.txt'
        c.run(f'touch {repo_home}/regression-tests/tests/verify-dnssec-zone/allow-missing {repo_home}/regression-tests.nobackend/rectify-axfr/allow-missing') # FIXME: can this go?
        res = c.run(f'meson test --verbose -t {suite_timeout_sec}', warn=True)
    else:
        logfile = 'pdns/test-suite.log'
        res = c.run('make check', warn=True)
    if res.exited != 0:
        c.run(f'cat {logfile}', warn=True)
        c.run('cat ../modules/remotebackend/*.log', warn=True)
        raise UnexpectedExit(res)

@task
def ci_rec_run_unit_tests(c, meson=False):
    if meson:
        suite_timeout_sec = 120
        logfile = 'meson-logs/testlog.txt'
        res = c.run(f'meson test --verbose -t {suite_timeout_sec}', warn=True)
    else:
        res = c.run('make check', warn=True)
        if res.exited != 0:
          c.run('cat test-suite.log')
          raise UnexpectedExit(res)

@task
def ci_dnsdist_run_unit_tests(c, builder):
    if builder == 'meson':
        suite_timeout_sec = 120
        logfile = 'meson-logs/testlog.txt'
        res = c.run(f'. {repo_home}/.venv/bin/activate && meson test --verbose -t {suite_timeout_sec}', warn=True)
    else:
        logfile = 'test-suite.log'
        res = c.run('make check', warn=True)
    if res.exited != 0:
      c.run(f'cat {logfile}', warn=True)
      raise UnexpectedExit(res)

@task
def ci_make_distdir(c, meson=False):
    if not meson:
        c.run('make distdir')

@task
def ci_auth_install(c, meson=False):
    if not meson:
        c.run('make install') # FIXME: this builds auth docs - again

@task
def ci_rec_install(c, meson=False):
    if meson:
        c.sudo(f"bash -c 'source {repo_home}/.venv/bin/activate && meson install'")
    else:
        c.run('make install')

@task
def ci_dnsdist_install(c, meson=False):
    if meson:
        c.sudo(f"bash -c 'source {repo_home}/.venv/bin/activate && meson install'")
    else:
        c.run('make install')

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
            c.run(f'PDNSSERVER=/opt/pdns-auth/sbin/pdns-auth PDNSUTIL=/opt/pdns-auth/bin/pdns-auth-util SDIG=/opt/pdns-auth/bin/sdig MYSQL_HOST={auth_backend_ip_addr} PGHOST={auth_backend_ip_addr} PGPORT=5432 ./runtests authoritative {backend}')
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
        'lmdb-nsec3-narrow',
        'lmdb-nodnssec-variant',
        'lmdb-variant',
        'lmdb-nsec3-variant',
        'lmdb-nsec3-optout-variant',
        'lmdb-nsec3-narrow-variant'
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

backend_rootzone_tests = dict(
    geoip = False,
    geoip_mmdb = False,
    lua2 = False,
    ldap = False,
    tinydns = False,
    remote = False,
    bind = True,
    lmdb = True,
    gmysql = True,
    gpgsql = True,
    gsqlite3 = True,
    godbc_sqlite3 = True,
    godbc_mssql = True,
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
    pdns_auth_env_vars = f'PDNS=/opt/pdns-auth/sbin/pdns-auth PDNS2=/opt/pdns-auth/sbin/pdns-auth SDIG=/opt/pdns-auth/bin/sdig NOTIFY=/opt/pdns-auth/bin/pdns-auth-notify NSEC3DIG=/opt/pdns-auth/bin/nsec3dig SAXFR=/opt/pdns-auth/bin/saxfr ZONE2SQL=/opt/pdns-auth/bin/pdns-zone2sql ZONE2LDAP=/opt/pdns-auth/bin/pdns-zone2ldap ZONE2JSON=/opt/pdns-auth/bin/pdns-zone2json PDNSUTIL=/opt/pdns-auth/bin/pdns-auth-util PDNSCONTROL=/opt/pdns-auth/bin/pdns-auth-control PDNSSERVER=/opt/pdns-auth/sbin/pdns-auth SDIG=/opt/pdns-auth/bin/sdig GMYSQLHOST={auth_backend_ip_addr} GMYSQL2HOST={auth_backend_ip_addr} MYSQL_HOST={auth_backend_ip_addr} PGHOST={auth_backend_ip_addr} PGPORT=5432'
    backend_env_vars = ''

    if backend == 'remote':
        ci_auth_install_remotebackend_test_deps(c)

    if backend == 'authpy':
        c.sudo(f'sh -c \'echo "{auth_backend_ip_addr} kerberos-server" | tee -a /etc/hosts\'')
        for auth_backend in ('bind', 'lmdb'):
            with c.cd('regression-tests.auth-py'):
                c.run(f'{pdns_auth_env_vars} AUTH_BACKEND={auth_backend} WITHKERBEROS=YES ./runtests')
        return

    if backend == 'bind':
        setup_softhsm(c)
        backend_env_vars = 'SOFTHSM2_CONF=/opt/pdns-auth/softhsm/softhsm2.conf'

    if backend == 'godbc_sqlite3':
        setup_godbc_sqlite3(c)
        backend_env_vars = 'GODBC_SQLITE3_DSN=pdns-sqlite3-1'

    if backend == 'godbc_mssql':
        setup_godbc_mssql(c)
        backend_env_vars = f'GODBC_MSSQL_PASSWORD={godbc_mssql_credentials["password"]} GODBC_MSSQL_USERNAME={godbc_mssql_credentials["username"]} GODBC_MSSQL_DSN=pdns-mssql-docker GODBC_MSSQL2_PASSWORD={godbc_mssql_credentials["password"]} GODBC_MSSQL2_USERNAME={godbc_mssql_credentials["username"]} GODBC_MSSQL2_DSN=pdns-mssql-docker'

    if backend == 'ldap':
        setup_ldap_client(c)

    if backend == 'geoip_mmdb':
        backend_env_vars = 'geoipdatabase=../modules/geoipbackend/regression-tests/GeoLiteCity.mmdb'

    with c.cd('regression-tests'):
        if backend == 'lua2':
            c.run('touch trustedkeys')  # avoid silly error during cleanup
        for variant in backend_regress_tests[backend]:
            c.run(f'{pdns_auth_env_vars} {backend_env_vars} ./start-test-stop 5300 {variant}')

    if backend_rootzone_tests[backend]:
        with c.cd('regression-tests.rootzone'):
            for variant in backend_regress_tests[backend]:
                c.run(f'{pdns_auth_env_vars} {backend_env_vars} ./start-test-stop 5300 {variant}')

    if backend == 'gsqlite3':
        if os.getenv('SKIP_IPV6_TESTS'):
            pdns_auth_env_vars += ' context=noipv6'
        with c.cd('regression-tests.nobackend'):
            c.run(f'{pdns_auth_env_vars} ./runtests')
        c.run('/opt/pdns-auth/bin/pdns-auth-util test-algorithms')
        return

@task
def test_ixfrdist(c):
    with c.cd('regression-tests.ixfrdist'):
        c.run('IXFRDISTBIN=/opt/pdns-auth/bin/ixfrdist ./runtests')

@task(optional=['skipXDP'])
def test_dnsdist(c, skipXDP=False):
    test_env_vars = 'ENABLE_SUDO_TESTS=1' if not skipXDP else ''
    c.run('chmod +x /opt/dnsdist/bin/*')
    c.run('ls -ald /var /var/agentx /var/agentx/master')
    c.run('ls -al /var/agentx/master')
    with c.cd('regression-tests.dnsdist'):
        c.run(f'DNSDISTBIN=/opt/dnsdist/bin/dnsdist LD_LIBRARY_PATH=/opt/dnsdist/lib/ {test_env_vars} ./runtests')

@task
def test_regression_recursor(c):
    c.run('/opt/pdns-recursor/sbin/pdns_recursor --version')
    c.run('PDNSRECURSOR=/opt/pdns-recursor/sbin/pdns_recursor RECCONTROL=/opt/pdns-recursor/bin/rec_control ./build-scripts/test-recursor')

@task
def test_bulk_recursor(c, size, threads, mthreads, shards, ipv6):
    with c.cd('regression-tests'):
        c.run('curl --no-progress-meter -LO https://umbrella-static.s3.dualstack.us-west-1.amazonaws.com/top-1m.csv.zip')
        c.run('unzip top-1m.csv.zip -d .')
        c.run('chmod +x /opt/pdns-recursor/bin/* /opt/pdns-recursor/sbin/*')
        c.run(f'DNSBULKTEST=/usr/bin/dnsbulktest RECURSOR=/opt/pdns-recursor/sbin/pdns_recursor RECCONTROL=/opt/pdns-recursor/bin/rec_control IPv6={ipv6} THRESHOLD=95 TRACE=no ./recursor-test 5300 {size} {threads} {mthreads} {shards}')

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
        # be careful that rust needs to have been installed system-wide,
        # as the one installed in GitHub actions' Ubuntu images in /home/runner/.cargo/bin/cargo
        # is not in the path for the root user (and shouldn't be)
        c.run(f'sudo {repo}/builder-support/helpers/install_quiche.sh')

    # cannot use c.sudo() inside a cd() context, see https://github.com/pyinvoke/invoke/issues/687
    for tentative in ['lib/x86_64-linux-gnu', 'lib/aarch64-linux-gnu', 'lib64', 'lib']:
        tentative_libdir = f'/usr/{tentative}'
        quiche_lib = f'{tentative_libdir}/libdnsdist-quiche.so'
        if not os.path.isfile(quiche_lib):
            continue
        c.run(f'sudo mv {quiche_lib} /usr/lib/libquiche.so')
        c.run(f"sudo sed -i 's,^Libs:.*,Libs: -lquiche,g' {tentative_libdir}/pkgconfig/quiche.pc")
        c.run('mkdir -p /opt/dnsdist/lib')
        c.run('cp /usr/lib/libquiche.so /opt/dnsdist/lib/libquiche.so')
        break

# this is run always
def setup():
    if '/usr/lib/ccache' not in os.environ['PATH']:
        os.environ['PATH']='/usr/lib/ccache:'+os.environ['PATH']

setup()
