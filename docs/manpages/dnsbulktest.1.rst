dnsbulktest
===========

Synopsis
--------

:program:`dnsbulktest` [*OPTION*]... *IPADDRESS* *PORT* [*LIMIT*]

Description
-----------

:program:`dnsbulktest` sends a large amount of different queries (for up to
*LIMIT* different domains) to the nameserver at *IPADDRESS* on port
*PORT*. It reads the domain names from STDIN in the alexa topX format
and outputs statistics on STDOUT.

Options
-------

--help, -h               Show a summary of options.
--quiet, -q              Don't show information on individual queries.
--type, -t <TYPE>        Query the nameserver for *TYPE*, A by default.
--envoutput, -e          Write results on STDOUT as shell environment variables
--version                Display the version of dnsbulktest
