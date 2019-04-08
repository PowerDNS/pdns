#!/bin/sh
set -e

case $1 in
    debian-stretch-deps)
        apt-get update && apt-get -qq --no-install-recommends install \
            autoconf \
            automake \
            bc \
            bind9utils \
            bison \
            default-jre-headless \
            default-libmysqlclient-dev \
            dnsutils \
            flex \
            freetds-bin \
            g++ \
            git \
            ldnsutils \
            libboost-all-dev \
            libsqliteodbc \
            libssl-dev \
            libtool \
            make \
            pkg-config \
            ragel \
            sqlite3 \
            tdsodbc \
            unbound-host \
            unixodbc \
            unixodbc-dev \
            virtualenv \
            wget

        wget https://github.com/dblacka/jdnssec-tools/releases/download/0.14/jdnssec-tools-0.14.tar.gz
        tar xfz jdnssec-tools-0.14.tar.gz --strip-components=1 -C /
        rm jdnssec-tools-0.14.tar.gz

        ;;
    configure-odbc-sqlite)
        cat >> ~/.odbc.ini << __EOF__
[pdns-sqlite3-1]
Driver = SQLite3
Database = ${PWD}/regression-tests/pdns.sqlite3

[pdns-sqlite3-2]
Driver = SQLite3
Database = ${PWD}/regression-tests/pdns.sqlite32

__EOF__
        ;;
    configure-odbc-mssql)
        cat >> ~/.odbc.ini << __EOF__
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

__EOF__

        cat /usr/share/tdsodbc/odbcinst.ini >> /etc/odbcinst.ini
        ;;
    *)
        echo unknown command "$1"
        exit 1
        ;;
esac
