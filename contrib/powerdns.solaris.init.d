#!/bin/sh
################################################################################
# rc script for PowerDNS, Solaris-style  |  fernando@secret.org                #
################################################################################

prefix=/usr/local
exec_prefix=${prefix}
BINARYPATH=${exec_prefix}/bin
SBINARYPATH=${exec_prefix}/sbin
SOCKETPATH=/var/run

cd $SOCKETPATH

suffix=`/bin/basename $0 | /bin/awk -F- '{print $2}'`

if [ $suffix ]
then
	EXTRAOPTS=--config-name=$suffix
	PROGNAME=pdns-$suffix
else
	PROGNAME=$0
fi

pdns_server="$SBINARYPATH/pdns_server $EXTRAOPTS"

doPC()
{
	ret=`$BINARYPATH/pdns_control $EXTRAOPTS $1 $2 2> /dev/null`
}

doPC ping
NOTRUNNING=$?

case "$1" in
	status)
		/bin/echo "$PROGNAME: \c"

		if test "$NOTRUNNING" = "0"
		then
			doPC status
			/bin/echo $ret
		else
			/bin/echo "not running"
		fi
	;;

	stop)
		/bin/echo "$PROGNAME: \c"

		if test "$NOTRUNNING" = "0"
		then
			doPC quit
			/bin/echo $ret
		else
			/bin/echo "not running"
		fi
	;;

	force-stop)
		/bin/echo "$PROGNAME: \c"

		/bin/pkill -v -9 pdns_server

		/bin/echo "force-stopped"
	;;

	start)
		/bin/echo "$PROGNAME: \c"

		if test "$NOTRUNNING" = "0"
		then
			/bin/echo "already running"
		else
			$pdns_server --daemon --guardian=yes
			if test "$?" = "0"
			then
				/bin/echo "started"
			fi
		fi
	;;

	force-reload | restart)
		/bin/echo "$PROGNAME: \c"

		/bin/echo "stopping and waiting\c"
		doPC quit
		sleep 3
		/bin/echo
		$0 start
	;;

	reload)
		/bin/echo "$PROGNAME: \c"

		if test "$NOTRUNNING" = "0"
		then
			doPC cycle
			/bin/echo requested reload
		else
			/bin/echo not running yet
			$0 start
		fi
	;;
		
	monitor)
		/bin/echo "$PROGNAME: \c"

		if test "$NOTRUNNING" = "0"
		then
			/bin/echo "already running"
		else
			$pdns_server --daemon=no --guardian=no --control-console --loglevel=9
		fi
	;;

	dump)
		/bin/echo "$PROGNAME: \c"

		if test "$NOTRUNNING" = "0"
		then
			doPC list
			/bin/echo $ret
		else
			/bin/echo "not running"
		fi
	;;

	show)
		/bin/echo "$PROGNAME: \c"

		if [ $# -lt 2 ]
		then
			/bin/echo Insufficient parameters
			exit
		fi
		if test "$NOTRUNNING" = "0"
		then
			/bin/echo -n "$2="
			doPC show $2 ; /bin/echo $ret
		else
			/bin/echo "not running"
		fi
	;;

	mrtg)
		if [ $# -lt 2 ]
		then
			/bin/echo Insufficient parameters
			exit
		fi
		if test "$NOTRUNNING" = "0"
		then
			doPC show $2 ; /bin/echo $ret
			if [ "$3x" != "x" ]
			then
				doPC show $3 ; /bin/echo $ret
			else
				/bin/echo 0
			fi
			doPC uptime ; /bin/echo $ret
			/bin/echo PowerDNS daemon
		else
			/bin/echo "not running"
		fi
	
	;;

	cricket)
		if [ $# -lt 2 ]
		then
			/bin/echo Insufficient parameters
			exit
		fi
		if test "$NOTRUNNING" = "0"
		then
			doPC show $2 ; /bin/echo $ret
		else
			/bin/echo "not running"
		fi
	;;

	*)
		/bin/echo "Usage: $0 { start | stop | force-reload | restart | status | dump | show | mrtg | cricket | monitor }"
		exit 1
	;;
esac
exit 0
