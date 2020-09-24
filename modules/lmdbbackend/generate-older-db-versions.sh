#!/usr/bin/env bash
set -exu

working_directory=$(readlink -f $(dirname $0))

release_versions=$(cat $working_directory/old-schema-versions)

for version in $release_versions; do
  IFS=":" read -r -a parts <<< $version
  schemaversion="${parts[0]}"
  pdnsversion="${parts[1]}"
  echo "Running LMDB generation for LMDB version ${schemaversion} using pdns version ${pdnsversion}"
  tempDir=$(mktemp -d)
  cd $tempDir
  wget "https://github.com/PowerDNS/pdns/archive/auth-${pdnsversion}.tar.gz"
  tar xfvz "auth-${pdnsversion}.tar.gz"
  cd "pdns-auth-${pdnsversion}"
  autoreconf -vi
  ./configure --with-modules='lmdb' --disable-lua-records
  NPROC=$(nproc)
  make -j $NPROC -C ext && make -j $NPROC -C modules && make -j $NPROC -C pdns
  pdnsutilBinary="pdns-auth-${pdnsversion}/pdns/pdnsutil"
  cd ..
  cat << EOF > $tempDir/pdns-lmdb.conf
module-dir=${tempDir}/pdns-auth-${pdnsversion}/modules
launch=lmdb
lmdb-filename=${tempDir}/pdns.lmdb
lmdb-shards=2
EOF

  for zone in $(grep 'zone ' "${working_directory}/../../regression-tests/named.conf"  | cut -f2 -d\" | grep -v '^nztest.com$')
  do
    if [ "$zone" != "." ]; then
      $pdnsutilBinary --config-dir=. --config-name=lmdb load-zone $zone "${working_directory}/../../regression-tests/zones/${zone}"
      $pdnsutilBinary --config-dir=. --config-name=lmdb rectify-zone $zone
    fi
  done

  $pdnsutilBinary --config-dir=. --config-name=lmdb list-all-zones

  arch=$(uname -m)
  targetDir="lmdb-v${schemaversion}-${arch}"
  mkdir -p "${working_directory}/test-assets/${targetDir}"

  mv ${tempDir}/pdns.lmdb* "${working_directory}/test-assets/${targetDir}/"

  rm -r $tempDir
done

