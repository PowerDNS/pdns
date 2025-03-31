Random Backend
==============

.. deprecated:: 4.6.0
  This backend was removed in 4.6.0

* Native: Yes
* Primary: No
* Secondary: No
* Producer: No
* Consumer: No
* Autosecondary: No
* DNS Update: No
* DNSSEC: No
* Disabled data: No
* Comments: No
* Search: No
* API: No
* Multiple instances: No
* Zone caching: No
* Module name: random
* Launch: ``random``

This used to be a very silly backend which is still discussed in the
:doc:`Backends writer's guide <../appendices/backend-writers-guide>`.  as a
demonstration on how to write a PowerDNS backend.

This backend knew about only one hostname, and only about its IP
address at that. With every query, a new random IP address was generated.

It only made sense to load the random backend in combination with a
regular backend. This can be done by prepending it to the
:ref:`setting-launch` instruction, such as
``launch=random,gmysql``.

Configuration Parameters
------------------------

.. _setting-random-hostname:

``random-hostname``
~~~~~~~~~~~~~~~~~~~

-  String

Hostname for which to supply a random IP address.
