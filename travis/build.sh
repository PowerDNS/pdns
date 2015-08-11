#1/bin/sh

linux_configure() {
  #DNSName     --with-dynmodules='bind gmysql gpgsql gsqlite3 mydns tinydns remote random opendbx ldap lmdb lua'
  #Build without --enable-botan1.10 option, Botan/SoftHSM conflict #2496
  ./configure \
    --with-dynmodules='bind gmysql gpgsql gsqlite3 geoip mydns tinydns pipe remote random opendbx ldap lua' \
    --with-modules='' \
    --with-sqlite3 \
    --enable-unit-tests \
    --enable-remotebackend-zeromq \
    --enable-experimental-ed25519 \
    --enable-experimental-pkcs11 \
    --enable-tools \
    --disable-silent-rules \
    --disable-dependency-tracking
}

osx_configure(){
  ./configure \
    --with-dynmodules='bind gsqlite3 gmysql gpgsql pipe' \
    --with-modules='' \
    --enable-unit-tests \
    --enable-tools \
    --disable-silent-rules \
    --disable-dependency-tracking
}

dist_make_auth() {
  make -k dist
  make -j4 -k
}

make_docs(){
  make -C docs check-links
}

dist_make_recursor(){
  ./build-scripts/dist-recursor
  cd pdns/pdns-recursor-*/
  ./configure
  make -k -j 4
  cd ..
  ln -s pdns-recursor*/pdns_recursor .
  cd ..
}

dist_make_dnsdist(){
  ./build-scripts/dist-dnsdist
  cd pdns/dnsdistdist
  tar xf dnsdist*.tar.bz2
  cd dnsdist-*
  ./configure
  make -k -j 4
  cd ..
  rm -rf dnsdist-*/
  # back to the repo root
  cd ../..
}

./bootstrap
${TRAVIS_OS_NAME}_configure

# Create auth tarball and build auth
dist_make_auth

# Build documentation (needed for the manpages during make install)
make_docs

# Install
make -k install DESTDIR=/tmp/pdns-install-dir
find /tmp/pdns-install-dir -ls

# Run the checks
make -j 4 check
test -f pdns/test-suite.log && cat pdns/test-suite.log || true
test -f modules/remotebackend/test-suite.log && cat modules/remotebackend/test-suite.log || true

# Build the tools
# DNSName: make -k -C pdns $(grep '(EXEEXT):' pdns/Makefile | cut -f1 -d\$ | grep -E -v 'dnsdist|calidns')
make -k -C pdns $(grep '(EXEEXT):' pdns/Makefile | cut -f1 -d\$ | grep -E -v 'dnsdist|calidns|zone2lmdb|speedtest')

# Test if we can build the recursor from the repo root
make -C pdns -k -j 4 pdns_recursor
rm -f pdns/pdns_recursor

dist_make_recursor

dist_make_dnsdist

