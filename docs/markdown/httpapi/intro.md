Everything open for discussion.

TODO:

  * Everything marked as **TODO**
  * Finish data management (tsigkeys, …)
  * Incorporate applicable ideas from http://mailman.powerdns.com/pipermail/pdns-users/2013-February/009613.html

Big Picture
===========

* HTTP with SSL in-process in Auth & Recursor
* JSON API
  * make it really great for us and other consumers
  * “unified” API across Daemons and Console
* pdnsmgrd
  * cease to do SSL proxying
  * become completely optional component
  * only for “meta” features
* Console
  * get rid of all the API hacks
  * new features as detailed below
* CLI tool
  * should talk to daemons and Console (if there)
* “Pure” OOTB install
  * miniature single page js app for users not installing pdnscontrol

“Secondary” goals
=================

* keep everything lean
* minimal intrusions into existing code
