#!/bin/sh
#
# - `docker build --no-cache --pull --file Dockerfile.auth-41.ubuntu-bionic --tag auth-41.ubuntu-bionic .`
# - `docker run -it auth-41.ubuntu-bionic`
# - `docker run -it auth-41.ubuntu-bionic /bin/bash`
#     - `dnsdist --verbose 9.9.9.9`
#     - `pdns_recursor`
#     - `pdns_server`
#
# Remi contributed this snippet:
#
#     #!/bin/bash
#
#     readonly product=dnsdist-15
#
#     for version in centos-6 centos-7 centos-8 debian-buster debian-stretch ubuntu-bionic ubuntu-xenial; do
#       docker build --no-cache --pull --file Dockerfile.${product}.${version} --tag ${product}.${version} .
#     done
#
#     for version in centos-6 centos-7 centos-8 debian-buster debian-stretch ubuntu-bionic ubuntu-xenial; do
#       docker run -it ${product}.${version} dnsdist -v 9.9.9.9
#     done

if [ "$1" = "" -o "$1" = "-?" -o "$1" = "-h" -o "$1" = "--help" ]; then
    echo "Usage: generate-repo-files.sh RELEASE"
    echo
    echo "  • RELEASE: [ auth-40 | auth-41 | auth-42 | auth-43 |"
    echo "               rec-40 | rec-41 | rec-42 | rec-43 | rec-44 |"
    echo "               dnsdist-15 ]"
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

RUN yum install -y epel-release bind-utils
EOF

    if [ "$VERSION" = "6" -o "$VERSION" = "7" ]; then
        cat <<EOF >> Dockerfile.$RELEASE.$OS-$VERSION
RUN yum install -y yum-plugin-priorities
EOF
    elif [ "$RELEASE" = "dnsdist-15" -a "$VERSION" = "8" ]; then
        cat <<EOF >> Dockerfile.$RELEASE.$OS-$VERSION
RUN dnf install -y 'dnf-command(config-manager)'
RUN dnf config-manager --set-enabled PowerTools
EOF
    fi

    cat <<EOF >> Dockerfile.$RELEASE.$OS-$VERSION
RUN curl -o /etc/yum.repos.d/powerdns-$RELEASE.repo https://repo.powerdns.com/repo-files/$OS-$RELEASE.repo
RUN yum install -y $PKG
EOF

    if [ "$RELEASE" = "rec-43"  -o "$RELEASE" = "rec-44" ]; then
    cat <<EOF >> Dockerfile.$RELEASE.$OS-$VERSION

RUN mkdir /var/run/pdns-recursor
EOF
    fi

    cat <<EOF >> Dockerfile.$RELEASE.$OS-$VERSION

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

    # For the following two maybe only create depending on package, but
    # it's not really a big deal.

    # if not exists
    cat <<EOF > dnsdist.debian-and-ubuntu
Package: dnsdist*
Pin: origin repo.powerdns.com
Pin-Priority: 600
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
RUN apt-get install -y curl gnupg dnsutils

COPY dnsdist.debian-and-ubuntu /etc/apt/preferences.d/dnsdist
COPY pdns.debian-and-ubuntu /etc/apt/preferences.d/pdns
COPY pdns.list.$RELEASE.$OS-$VERSION /etc/apt/sources.list.d/pdns.list

RUN curl https://repo.powerdns.com/FD380FBB-pub.asc | apt-key add -
RUN apt-get update
RUN apt-get install -y $PKG
EOF

    if [ "$RELEASE" = "rec-43" -o "$RELEASE" = "rec-44" ]; then
        cat <<EOF >> Dockerfile.$RELEASE.$OS-$VERSION

RUN mkdir /var/run/pdns-recursor
EOF
    fi

    cat <<EOF >> Dockerfile.$RELEASE.$OS-$VERSION

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
elif [ "$RELEASE" = "auth-42" -o "$RELEASE" = "auth-43" ]; then
    write_centos 6 pdns pdns_server
    write_centos 7 pdns pdns_server
    write_centos 8 pdns pdns_server
    write_debian stretch pdns-server pdns_server
    write_debian buster pdns-server pdns_server
    write_ubuntu xenial pdns-server pdns_server
    write_ubuntu bionic pdns-server pdns_server
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
elif [ "$RELEASE" = "rec-42" -o "$RELEASE" = "rec-43" -o "$RELEASE" = "rec-44" ]; then
    write_centos 6 pdns-recursor pdns_recursor
    write_centos 7 pdns-recursor pdns_recursor
    write_centos 8 pdns-recursor pdns_recursor
    write_debian stretch pdns-recursor pdns_recursor
    write_debian buster pdns-recursor pdns_recursor
    write_ubuntu xenial pdns-recursor pdns_recursor
    write_ubuntu bionic pdns-recursor pdns_recursor
elif [ "$RELEASE" = "dnsdist-15" ]; then
    write_centos 6 dnsdist dnsdist
    write_centos 7 dnsdist dnsdist
    write_centos 8 dnsdist dnsdist
    write_debian stretch dnsdist dnsdist
    write_debian buster dnsdist dnsdist
    write_ubuntu xenial dnsdist dnsdist
    write_ubuntu bionic dnsdist dnsdist
else
    echo "Invalid release: $RELEASE"
    exit 1
fi
