.. _views:

Views
=====

.. versionadded:: 5.0.0

Views are an experimental feature, which allows the scope of zones to be
narrowed, depending on the originating address of the query, by exposing
different `variants` of zones.

A simple use case for this feature is to separate internal (trusted) and
external (untrusted) views of a given domain, without having to rely upon a
GeoIP-like backend.

Requirements
------------

The `Views` features is currently only available in the :doc:`LMDB
<backends/lmdb>` backend, and requires the zone cache to be enabled (by setting
:ref:`setting-zone-cache-refresh-interval` to a non-zero value).

It must also be explicitly enabled using :ref:`setting-views` in the
configuration file.

Concepts
--------

The first piece of the Views puzzle is the `network`. A `network`, specified as
a base address and a prefix length, is associated to a `view name`. The `view
name` in turn, will select a set of `zone variants` to be used to answer queries
for these zones, originating from this network.

Queries originating from no configured network will be answered as in a
non-views setup, without any restriction.

Zone Variants
^^^^^^^^^^^^^

A Zone Variant is a zone on its own, written as ``<zone name with trailing dot>.<variant name>``.
Variant names are made of lowercase letters, digits, underscore and dashes only.

For example, the following variants are valid:

- ``example.org..variant01``
- ``example.org..1st_variant``
- ``example.org..othervariant``

and a variant of the root zone would be:

- ``..variant``

Zone variants can be used in any command or operation where a zone name is
expected, i.e. with :doc:`pdnsutil <manpages/pdnsutil.1>` or the
:doc:`HTTP API <http-api/index>`.

There is no mechanism to populate a freshly-created variant from the variantless
zone contents.

Networks
^^^^^^^^

Networks are set up either with :doc:`pdnsutil <manpages/pdnsutil.1>` or the
:doc:`HTTP API <http-api/index>`.

Every network is associated to a unique view name.

Note that in PowerDNS, unlike Bind, the order in which networks are configured
does not matter. When deciding which network to use to answer a DNS query, the
narrowest (smallest) network will always be chosen.

Views
^^^^^

Views are set up either with :doc:`pdnsutil <manpages/pdnsutil.1>` or the
:doc:`HTTP API <http-api/index>`.

Every view is associated to a list of zone variants. It can also include
regular (variantless) zones, but this is not needed as all zones which do not
appear in a view will operate as in a non-views setup.

In other words, zones not part of a view are always implicitly available in
that view, as their variantless contents.

Only one variant per zone may appear in a view; setting a new zone variant will
replace the previous one in the view.

View names are case-sensitive and may be composed of letters, digits, spaces,
as well as `-` (dash), `.` (dot) and `_` (underscore). They are not allowed to
start with a dot or a space.

Resolution Algorithm
--------------------

When views are enabled, the following operations take place when processing
a DNS query:

- the source address of the request (or the EDNS subnet option if present) is
  used to check whether it matches a configured *network*.
- if so, the *view* associated to that *network* is retrieved; otherwise,
  views will be bypassed.
- when searching for a given zone, if there is a specific *variant* for that
  zone in the *view*, then that zone variant will be used; otherwise,
  the regular variantless zone will be used.

Configuration tweaks
--------------------

When views are used, the :ref:`packet-cache` will cache result results for each
view independently. If your configuration benefits from the packet cache,
you might need to multiply its capacity
(:ref:`setting-max-packet-cache-entries`) by the number of views in use.

Examples
--------

Simple setup
^^^^^^^^^^^^

In such a setup, we want to provide three different flavours of a given zone:
one for internal (non-routable) queries, one for trusted origins, and one for
the rest of the Internet.

Let's start by defining the specific networks::

  pdnsutil network set 10.0.0.0/8 internal
  pdnsutil network set 172.16.0.0/12 internal
  pdnsutil network set 192.168.0.0/16 internal
  pdnsutil network set fc00::/7 internal

  pdnsutil network set 198.51.100.0/24 trusted
  pdnsutil network set 203.0.113.0/24 trusted
  pdnsutil network set 2001:db8::/32 trusted

Once these commands have been run, queries originating from these particular
networks will select either the "internal" or "trusted" view, while queries
originating from other addresses will default to the unbiased view, which you
may consider an always-existing default (nameless) view.

You can check the result of these commands with::

  $ pdnsutil network list
  10.0.0.0/8      internal
  172.16.0.0/12   internal
  192.168.0.0/16  internal
  198.51.100.0/24 trusted
  203.0.113.0/24  trusted
  2001:db8::/32   trusted
  fc00::/7        internal

Since these views have not been set up yet, they are empty, causing no change of
outcome when resolving domain queries.

Let's differentiate these views now::

  pdnsutil view add-zone internal example.com..internal
  pdnsutil view add-zone internal example2.com..secret

  pdnsutil view add-zone trusted example.com..trusted

Note that the `view add-zone` command does not create any zone! You will need
to create these zones, like you would do for any other "regular" zone::

  pdnsutil zone create example.com..internal
  pdnsutil zone create example2.com..secret
  pdnsutil zone create example.com..trusted

and then use `zone load`, `zone edit`, or `rrset add` to add contents to these
zones.

With these settings in place, queries for the `example.com.` zone will be
performed on the `example.com..internal` zone when originating from the internal
networks, on the `example.com..trusted` zone when originating from the trusted
network, and on the variantless, unmodified, `example.com.` zone when
originating from elsewhere; and queries for the `example2.com.` zone will be
performed on the `example2.com..secret` zone when originating from the internal
networks, and on the variantless `example2.com.` otherwise.

Queries for all other zones will be unaffected, since no other zone is
configured in the views.

As seen in this example, a given view may cause multiple zones to be resolved
differently. At any time, you can check which views are setup, and the details
of a given view::

  $ pdnsutil view list-all
  internal
  trusted
  $ pdnsutil view list internal
  example.com..internal
  example2.com..secret
  $ pdnsutil view list trusted
  example.com..trusted

Bind configuration adaptation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Consider the following Bind configuration, shamelessly adapted from
https://www.zytrax.com/books/dns/ch7/view.html::

  view "trusted" {
   match-clients { 192.168.23.0/24; }; // our network
    zone "example.com" {
     type primary;
     // private zone file including local hosts
     file "internal/primary.example.com";
    };
    // add required zones
   };
  view "badguys" {
   match-clients {"any"; }; // all other hosts
   zone "example.com" {
     type primary;
     // public only hosts
     file "external/primary.example.com";
    };
    // add required zones
   };

The equivalent PowerDNS setup would be::

  pdnsutil network set 192.168.23.0/24 trusted
  pdnsutil network set 0.0.0.0/0 badguys

  pdnsutil view add-zone trusted primary.example.com..internal
  pdnsutil view add-zone badguys primary.example.com..external

  pdnsutil zone load example.com..internal internal/primary.example.com
  pdnsutil zone load example.com..external external/primary.example.com

.. _views-catalog-zones:

Interaction with catalog zones
------------------------------

Catalog zones (both producer and consumer) can have variant names, and contain variant member zone names.
Producer zones are looked up via views like any other zone, but on the wire contain non-variant names.
Thus, it is important to make sure that the member zones of a catalog are visible to the same consumer in the same view.

On the consumer side, member zone names currently do not get a variant assigned to them, and thus are not automatically scoped to (a) certain view(s).
This is expected to improve in the future.
