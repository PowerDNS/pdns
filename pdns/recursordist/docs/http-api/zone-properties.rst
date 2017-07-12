The Zone object in the Recursor also supportes these elements:

:property [str] servers: For zones of type "Forwarded", addresses to send the queries to
:property bool recursion_desired: For zones of type "Forwarded", Whether or not the RD bit should be set in the query
