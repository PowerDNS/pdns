startup() {
  export DEBFULLNAME="PowerDNS.COM BV AutoBuilder"
  export DEBEMAIL="noreply@powerdns.com"

  if [ -z "$VERSION" ]; then
    echo 'Please set $VERSION' >&2
    exit 1
  fi

  if [ -z "$RELEASE" ];then
    echo 'Please set $RELEASE' >&2
    exit 1
  fi

  TARBALLVERSION=${TARBALLVERSION:-$VERSION}

  TARBALLFILE=${TARBALLPREFIX}-${TARBALLVERSION}.tar.bz2

  if [ ! -f ${TARBALLFILE} ]; then
    echo "${TARBALLFILE} not found" >&2
    exit 1
  fi
}

cp_tarball_to_tmp() {
  DIR=$(mktemp -d)

  tar -xf ${TARBALLFILE} -C ${DIR}

  SRCDIR=${DIR}/${TARBALLPREFIX}-${TARBALLVERSION}
  if [ "${TARBALLPREFIX}" = "pdns" ]; then
    cp -r build-scripts/debian-authoritative ${SRCDIR}/debian
  elif [ "${TARBALLPREFIX}" = "pdns-recursor" ]; then
    cp -r build-scripts/debian-recursor ${SRCDIR}/debian
  else
    cp -r build-scripts/debian-${TARBALLPREFIX} ${SRCDIR}/debian
  fi
}

cp_tarball_to_rpm_sources() {
  rpmdev-setuptree
  cp ${TARBALLFILE} ${HOME}/rpmbuild/SOURCES
}

mv_debs_to_pwd() {
  mv ${DIR}/*.deb .
}
