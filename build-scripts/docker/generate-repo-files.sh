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
    echo "  • RELEASE: [ auth-41 | auth-42 | auth-43 | auth-44 | auth-master |"
    echo "               rec-41 | rec-42 | rec-43 | rec-44 | rec-master |"
    echo "               dnsdist-15 | dnsdist-master ]"
    exit 1
fi


write_centos()
{
    OS=centos
    VERSION=$1
    PKG=$2
    CMD=$3

    if [ "$VERSION" = "8" ]; then
        CENTOS8_FLAGS="--nobest"
    else
        CENTOS8_FLAGS=""
    fi

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
RUN yum install --assumeyes $CENTOS8_FLAGS $PKG
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
RUN apt-get install -y curl gnupg dnsutils apt-transport-https

COPY dnsdist.debian-and-ubuntu /etc/apt/preferences.d/dnsdist
COPY pdns.debian-and-ubuntu /etc/apt/preferences.d/pdns
COPY pdns.list.$RELEASE.$OS-$VERSION /etc/apt/sources.list.d/pdns.list

RUN curl https://repo.powerdns.com/FD380FBB-pub.asc | apt-key add -
RUN curl https://repo.powerdns.com/CBC8B383-pub.asc | apt-key add -
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
PRODUCT=$(echo $RELEASE | cut -d \- -f 1)

# For debugging:
#echo "rel=<${RELEASE}> prd=<${PRODUCT}>"
#exit

# CentOS 6
if [ "$RELEASE" = "auth-41" -o "$RELEASE" = "auth-42" -o     \
     "$RELEASE" = "auth-43" -o "$RELEASE" = "auth-master" -o \
     "$RELEASE" = "rec-41" -o "$RELEASE" = "rec-42" -o       \
     "$RELEASE" = "rec-43" -o                                \
     "$RELEASE" = "dnsdist-15" -o "$RELEASE" = "dnsdist-master" ]; then
    if [ "$PRODUCT" = "auth" ]; then
        write_centos 6 pdns pdns_server
    elif [ "$PRODUCT" = "rec" ]; then
        write_centos 6 pdns-recursor pdns_recursor
    elif [ "$PRODUCT" = "dnsdist" ]; then
        write_centos 6 dnsdist dnsdist
    fi
fi

# CentOS 7
if [ "$RELEASE" = "auth-41" -o "$RELEASE" = "auth-42" -o \
     "$RELEASE" = "auth-43" -o "$RELEASE" = "auth-44" -o \
     "$RELEASE" = "auth-master" -o                       \
     "$RELEASE" = "rec-41" -o "$RELEASE" = "rec-42" -o   \
     "$RELEASE" = "rec-43" -o "$RELEASE" = "rec-44" -o   \
     "$RELEASE" = "rec-master" -o                        \
     "$RELEASE" = "dnsdist-15" -o "$RELEASE" = "dnsdist-master" ]; then
    if [ "$PRODUCT" = "auth" ]; then
        write_centos 7 pdns pdns_server
    elif [ "$PRODUCT" = "rec" ]; then
        write_centos 7 pdns-recursor pdns_recursor
    elif [ "$PRODUCT" = "dnsdist" ]; then
        write_centos 7 dnsdist dnsdist
    fi
fi

# CentOS 8
if [ "$RELEASE" = "auth-42" -o "$RELEASE" = "auth-43" -o     \
     "$RELEASE" = "auth-44" -o "$RELEASE" = "auth-master" -o \
     "$RELEASE" = "rec-42" -o "$RELEASE" = "rec-43" -o       \
     "$RELEASE" = "rec-44" -o "$RELEASE" = "rec-master" -o   \
     "$RELEASE" = "dnsdist-15" -o "$RELEASE" = "dnsdist-master" ]; then
    if [ "$PRODUCT" = "auth" ]; then
        write_centos 8 pdns pdns_server
    elif [ "$PRODUCT" = "rec" ]; then
        write_centos 8 pdns-recursor pdns_recursor
    elif [ "$PRODUCT" = "dnsdist" ]; then
        write_centos 8 dnsdist dnsdist
    fi
fi

# Debian Stretch
if [ "$RELEASE" = "auth-41" -o "$RELEASE" = "auth-42" -o \
     "$RELEASE" = "auth-43" -o "$RELEASE" = "auth-44" -o \
     "$RELEASE" = "auth-master" -o                       \
     "$RELEASE" = "rec-41" -o "$RELEASE" = "rec-42" -o   \
     "$RELEASE" = "rec-43" -o "$RELEASE" = "rec-44" -o   \
     "$RELEASE" = "rec-master" -o                        \
     "$RELEASE" = "dnsdist-15" -o "$RELEASE" = "dnsdist-master" ]; then
    if [ "$PRODUCT" = "auth" ]; then
        write_debian stretch pdns-server pdns_server
    elif [ "$PRODUCT" = "rec" ]; then
        write_debian stretch pdns-recursor pdns_recursor
    elif [ "$PRODUCT" = "dnsdist" ]; then
        write_debian stretch dnsdist dnsdist
    fi
fi

# Debian Buster
if [ "$RELEASE" = "auth-42" -o "$RELEASE" = "auth-43" -o     \
     "$RELEASE" = "auth-44" -o "$RELEASE" = "auth-master" -o \
     "$RELEASE" = "rec-42" -o "$RELEASE" = "rec-43" -o       \
     "$RELEASE" = "rec-44" -o "$RELEASE" = "rec-master" -o   \
     "$RELEASE" = "dnsdist-15" -o "$RELEASE" = "dnsdist-master" ]; then
    if [ "$PRODUCT" = "auth" ]; then
        write_debian buster pdns-server pdns_server
    elif [ "$PRODUCT" = "rec" ]; then
        write_debian buster pdns-recursor pdns_recursor
    elif [ "$PRODUCT" = "dnsdist" ]; then
        write_debian buster dnsdist dnsdist
    fi
fi

# Ubuntu Xenial
if [ "$RELEASE" = "auth-41" -o "$RELEASE" = "auth-42" -o \
     "$RELEASE" = "auth-43" -o "$RELEASE" = "auth-44" -o \
     "$RELEASE" = "auth-master" -o                       \
     "$RELEASE" = "rec-41" -o "$RELEASE" = "rec-42" -o   \
     "$RELEASE" = "rec-43" -o "$RELEASE" = "rec-44" -o   \
     "$RELEASE" = "rec-master" -o                        \
     "$RELEASE" = "dnsdist-15" -o "$RELEASE" = "dnsdist-master" ]; then
    if [ "$PRODUCT" = "auth" ]; then
        write_ubuntu xenial pdns-server pdns_server
    elif [ "$PRODUCT" = "rec" ]; then
        write_ubuntu xenial pdns-recursor pdns_recursor
    elif [ "$PRODUCT" = "dnsdist" ]; then
        write_ubuntu xenial dnsdist dnsdist
    fi
fi

# Ubuntu Bionic
if [ "$RELEASE" = "auth-41" -o "$RELEASE" = "auth-42" -o \
     "$RELEASE" = "auth-43" -o "$RELEASE" = "auth-44" -o \
     "$RELEASE" = "auth-master" -o                       \
     "$RELEASE" = "rec-41" -o "$RELEASE" = "rec-42" -o   \
     "$RELEASE" = "rec-43" -o "$RELEASE" = "rec-44" -o   \
     "$RELEASE" = "rec-master" -o                        \
     "$RELEASE" = "dnsdist-15" -o "$RELEASE" = "dnsdist-master" ]; then
    if [ "$PRODUCT" = "auth" ]; then
        write_ubuntu bionic pdns-server pdns_server
    elif [ "$PRODUCT" = "rec" ]; then
        write_ubuntu bionic pdns-recursor pdns_recursor
    elif [ "$PRODUCT" = "dnsdist" ]; then
        write_ubuntu bionic dnsdist dnsdist
    fi
fi

# Ubuntu Focal
if [ "$RELEASE" = "auth-43" -o "$RELEASE" = "auth-44" -o \
     "$RELEASE" = "auth-master" -o                       \
     "$RELEASE" = "rec-43" -o "$RELEASE" = "rec-44" -o   \
     "$RELEASE" = "rec-master" -o                        \
     "$RELEASE" = "dnsdist-15" -o "$RELEASE" = "dnsdist-master" ]; then
    if [ "$PRODUCT" = "auth" ]; then
        write_ubuntu focal pdns-server pdns_server
    elif [ "$PRODUCT" = "rec" ]; then
        write_ubuntu focal pdns-recursor pdns_recursor
    elif [ "$PRODUCT" = "dnsdist" ]; then
        write_ubuntu focal dnsdist dnsdist
    fi
fi
