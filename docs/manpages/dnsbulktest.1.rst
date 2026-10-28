dnsbulktest
===========

Synopsis
--------

:program:`dnsbulktest` [OPTION]... <IPADDRESS> <PORT> [LIMIT]

Description
-----------

:program:`dnsbulktest` sends a large amount of different queries (for up to
*LIMIT* different domains) to the nameserver at *IPADDRESS* on port
*PORT*. It reads the domain names from STDIN in the Alexa topX format
and outputs statistics on STDOUT.

Options
-------

.. option:: --help, -h

   Show a summary of options.

.. option:: --quiet, -q

   Don't show information on individual queries.

.. option:: --type, -t <TYPE>

   Query the nameserver for *TYPE*, A by default.

.. option:: --envoutput, -e

   Write results on STDOUT as shell environment variables

.. option:: --version

   Display the version of dnsbulktest
