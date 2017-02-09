Upgrade Guide
=============

1.1.0 to 1.2.0
--------------

In 1.2.0, several configuration options have been changed:

As the amount of possible settings for listen sockets is growing, all listen-related options must now be passed as a table as the second argument to both :func:`addLocal` and :func:`setLocal`.
See the function's reference for more information.

The ``BlockFilter`` function is removed, as :func:`addRule` combined with a :func:`DropAction` can do the same.
