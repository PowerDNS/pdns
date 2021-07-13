Internal Design
===============

This part of the documentation is intended for developers interested in understanding how the actual code works, and might not be of much interest to regular users.

UDP design
----------

.. figure:: ../imgs/DNSDistUDP.png
   :align: center
   :alt: DNSDist UDP design

For UDP queries, dnsdist stores the initial ID in a per-backend table called *IDState*. That ID then replaced by one derived from a counter before forwarding the query to the backend, to prevent duplicated IDs sent clients from making it to the backend.
When the response is received, dnsdist uses the ID sent by the backend to find the corresponding *IDState* and restores the initial ID, as well as some flags if needed, before sending the response to the client.

That design means that there is a maximum of 65535 in-flight UDP queries per backend. It can actually be even less than that if :func:`setMaxUDPOutstanding` is set to a lower value, for example to reduce the overall memory usage.

Note that the source address and port used to contact a given backend is set at startup, for performance reasons, and then only changes on reconnect. There might be more than one socket, and thus several ports, if the ``sockets`` parameter was set to a higher value than 1 on the :func:`newServer` directive.

TCP / DoT design
----------------

.. figure:: ../imgs/DNSDistTCP.png
   :align: center
   :alt: DNSDist TCP and DoT design

For TCP and DoT, a single thread is created for each :func:`addLocal` and :func:`addTLSLocal` directive, listening to the incoming TCP sockets, accepting new connections and distributing them over a pipe to the TCP worker threads. These threads handle both the TCP connection with the client and the one with the backend.

DoH design
----------

.. figure:: ../imgs/DNSDistDoH.png
   :align: center
   :alt: DNSDist DoH design

For DoH, two threads are created for each :func:`addDOHLocal` directive, one handling the TLS and HTTP layers, then passing the queries to the second one over a pipe. The second thread does DNS processing, applying rules and forwarding the query to the backend if needed, over UDP.
Note that even if the query does not need to be passed to a backend (cache-hit, self-generated answer), the response will be passed back to the first thread via a pipe, since only that thread deals with the client.
If the response comes from a backend, it will be picked up by the regular UDP listener for that backend, the corresponding *IDState* object located, and the response sent to the first thread over a pipe.
