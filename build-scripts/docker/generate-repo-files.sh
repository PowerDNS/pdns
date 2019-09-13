#!/bin/sh
#
# - `docker build --no-cache --pull --file Dockerfile.auth-41.ubuntu-bionic --tag auth-41.ubuntu-bionic .`
# - `docker run -it auth-41.ubuntu-bionic`
# - `docker run -it auth-41.ubuntu-bionic /bin/bash`
#     - `pdns_recursor`

if [ "$1" = "" -o "$1" = "-?" -o "$1" = "-h" -o "$1" = "--help" ]; then
    echo "Usage: generate-repo-files.sh RELEASE"
    echo
    echo "  • RELEASE: [ auth-40 | auth-41 | auth-42 | rec-40 | rec-41 | rec-42 ]"
    exit 1
fi

write_centos()
{
    OS=centos
    VERSION=$1
    PKG=$2
    CMD=$3
    cat <<EOF > Dockerfile.$RELEASE.$OS-$VERSION
FROM $OS:$VERSION

RUN yum install -y epel-release yum-plugin-priorities
RUN curl -o /etc/yum.repos.d/powerdns-$RELEASE.repo https://repo.powerdns.com/repo-files/$OS-$RELEASE.repo
RUN yum install -y $PKG

CMD $CMD --version
EOF
}

write_debian_or_ubuntu()
{
    OS=$1
    VERSION=$2
    PKG=$3
    CMD=$4
    cat <<EOF > pdns.list.$RELEASE.$OS-$VERSION
deb [arch=amd64] http://repo.powerdns.com/$OS $VERSION-$RELEASE main
EOF
    # if not exists
    cat <<EOF > pdns.debian-and-ubuntu
Package: pdns-*
Pin: origin repo.powerdns.com
Pin-Priority: 600
EOF
    cat <<EOF > Dockerfile.$RELEASE.$OS-$VERSION
FROM $OS:$VERSION

RUN apt-get update
RUN apt-get install -y curl gnupg

COPY pdns.debian-and-ubuntu /etc/apt/preferences.d/pdns
COPY pdns.list.$RELEASE.$OS-$VERSION /etc/apt/sources.list.d/pdns.list

RUN curl https://repo.powerdns.com/FD380FBB-pub.asc | apt-key add -
RUN apt-get update
RUN apt-get install -y $PKG

CMD $CMD --version
EOF
}

write_debian()
{
    write_debian_or_ubuntu debian $1 $2 $3
}

write_ubuntu()
{
    write_debian_or_ubuntu ubuntu $1 $2 $3
}

RELEASE=$1

if [ "$RELEASE" = "auth-40" ]; then
    write_centos 6 pdns pdns_server
    write_centos 7 pdns pdns_server
    write_debian jessie pdns-server pdns_server
    write_debian stretch pdns-server pdns_server
    write_ubuntu trusty pdns-server pdns_server
    write_ubuntu xenial pdns-server pdns_server
elif [ "$RELEASE" = "auth-41" ]; then
    write_centos 6 pdns pdns_server
    write_centos 7 pdns pdns_server
    write_debian jessie pdns-server pdns_server
    write_debian stretch pdns-server pdns_server
    write_ubuntu trusty pdns-server pdns_server
    write_ubuntu xenial pdns-server pdns_server
    write_ubuntu bionic pdns-server pdns_server
elif [ "$RELEASE" = "auth-42" ]; then
    write_centos 6 pdns pdns_server
    write_centos 7 pdns pdns_server
    write_debian jessie pdns-server pdns_server
    write_debian stretch pdns-server pdns_server
    write_ubuntu trusty pdns-server pdns_server
    write_ubuntu xenial pdns-server pdns_server
    write_ubuntu bionic pdns-server pdns_server
    write_ubuntu cosmic pdns-server pdns_server
elif [ "$RELEASE" = "rec-40" ]; then
    write_centos 6 pdns-recursor pdns_recursor
    write_centos 7 pdns-recursor pdns_recursor
    write_debian jessie pdns-recursor pdns_recursor
    write_debian stretch pdns-recursor pdns_recursor
    write_ubuntu trusty pdns-recursor pdns_recursor
    write_ubuntu xenial pdns-recursor pdns_recursor
elif [ "$RELEASE" = "rec-41" ]; then
    write_centos 6 pdns-recursor pdns_recursor
    write_centos 7 pdns-recursor pdns_recursor
    write_debian jessie pdns-recursor pdns_recursor
    write_debian stretch pdns-recursor pdns_recursor
    write_ubuntu trusty pdns-recursor pdns_recursor
    write_ubuntu xenial pdns-recursor pdns_recursor
    write_ubuntu bionic pdns-recursor pdns_recursor
elif [ "$RELEASE" = "rec-42" ]; then
    write_centos 6 pdns-recursor pdns_recursor
    write_centos 7 pdns-recursor pdns_recursor
    write_debian jessie pdns-recursor pdns_recursor
    write_debian stretch pdns-recursor pdns_recursor
    write_debian buster pdns-recursor pdns_recursor
    write_ubuntu trusty pdns-recursor pdns_recursor
    write_ubuntu xenial pdns-recursor pdns_recursor
    write_ubuntu bionic pdns-recursor pdns_recursor
    write_ubuntu cosmic pdns-recursor pdns_recursor
else
    echo "Invalid release: $RELEASE"
    exit 1
fi
