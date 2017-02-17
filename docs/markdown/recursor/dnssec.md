# DNSSEC in the PowerDNS Recursor
As of 4.0.0, the PowerDNS Recursor has support for DNSSEC processing and
experimental support for DNSSEC validation.

# DNSSEC settings
The PowerDNS Recursor has 5 different levels of DNSSEC processing, which can be
set with the [`dnssec`](settings.md#dnssec) setting in the `recursor.conf`. In
order from least to most processing, these are:

## `off`
In this mode, **no** DNSSEC processing takes place. The PowerDNS Recursor will
not set the DNSSEC OK (DO) bit in the outgoing queries and will ignore the DO and
AD bits in queries. In this mode, the behaviour is equal to the PowerDNS Recursor
3.X.

## `process-no-validate`
The default mode. In this mode the Recursor acts as a "security aware, non-validating"
nameserver, meaning it will set the DO-bit on outgoing queries and will provide
DNSSEC related RRsets (NSEC, RRSIG) to clients that ask for them (by means of a
DO-bit in the query), except for zones provided through the `auth-zones` setting. 
It will not do any validation in this mode, not even when requested by the client.

## `process`
When `dnssec` is set to `process` the behaviour is similar to [`process-no-validate`](#process-no-validate).
However, the recursor will try to validate the data if at least one of the DO or AD bits is set in the query; in that case, it will set the AD-bit in the response when the data is validated successfully, or send SERVFAIL when the validation comes up bogus.

**Note:** in 4.0.0, only the AD-bit was considered when determining whether to validate.
This lead to interoperability issues with older client software.
From 4.0.1-onward, the DO-bit is also taken into account when determining whether to validate.

## `log-fail`
In this mode, the recursor will attempt to validate all data it retrieves from
authoritative servers, regardless of the client's DNSSEC desires, and will log the
validation result. This mode can be used to determine the extra load and amount
of possibly bogus answers before turning on full-blown validation. Responses to
client queries are the same as with `process`.

## `validate`
The highest mode of DNSSEC processing. In this mode, all queries will be be validated
and will be answered with a SERVFAIL in case of bogus data, regardless of the
client's request.

## What, when?
The descriptions above are a bit terse, here's a table describing different scenarios
with regards to the `dnssec` mode.

|    | `off` | `process-no-validate` | `process` | `log-fail` | `validate` |
|:------------|:-------|:-------------|:-------------|:-------------|:-------------|
|Perform validation| No | No | Only on +AD or +DO from client | Always (logs result) | Always |
|SERVFAIL on bogus| No | No | Only on +AD or +DO from client | Only on +AD or +DO from client | Always |
|AD in response on authenticated data| Never | Never | Only on +AD or +DO from client | Only on +AD or +DO from client | Only on +AD or +DO from client |
|RRSIGs/NSECs in answer on +DO from client| No | Yes | Yes | Yes | Yes |

**Note**: the `dig` tool sets the AD-bit in the query. This might lead to unexpected
query results when testing. Set `+noad` on the `dig` commandline when this is the
case.

# Trust Anchor Management
In the PowerDNS Recursor, both positive and negative trust anchors can be configured
during startup (from a persistent configuration file) and at runtime (which is
volatile).
However, all trust anchors are configurable.

## Trust Anchors
The PowerDNS Recursor ships with the DNSSEC Root key built-in. **Note**: is has
no support yet for [RFC 5011](https://tools.ietf.org/html/rfc5011) key rollover
and does not persist a changed root trust anchor to disk.

Configuring DNSSEC key material must be done in the [`lua-config-file`](settings.md#lua-config-file),
using `addDS`. This function takes 2 arguments, the node in the DNS-tree and the
data of the corresponding DS record. To e.g. add a trust anchor for the root and
powerdns.com, use the following config in the Lua file:

```lua
addDS('.', "63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a") -- This is not an ICANN root
addDS('powerdns.com', "44030 8 2 D4C3D5552B8679FAEEBC317E5F048B614B2E5F607DC57F1553182D49 AB2179F7")
```

Now (re)start the recursor to load these trust anchors.

### Runtime Configuration of Trust Anchors
To change or add trust anchors at runtime, use the [`rec_control`](running.md)
tool. These runtime settings are not saved to disk. To make them permanent, they
should be added to the `lua-config-file` as described above.

Adding a trust anchor is done with the `add-ta` command:

```
$ rec_control add-ta domain.example 63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a
Added Trust Anchor for domain.example. with data 63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a
```

To view the currently configured trust anchors, run `get-tas`:

```
$ rec_control get-tas
Configured Trust Anchors:
.       63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a
net.    2574 13 1 a5c5acb889a7ba9b5aa5bef2b0ac9fe1565ddaab
```

To remove a trust anchor, run `clear-ta`:

```
$ rec_control clear-ta domain.example
Removed Trust Anchor for subdomain.example
```

**Note**: The root trust anchor cannot be removed in this manner.

## Negative Trust Anchors
Negative trust anchors (defined in [RFC 7646](https://tools.ietf.org/html/rfc7646)
can be used to temporarily disable DNSSEC validation for a part of the DNS-tree.
This can be done when e.g. a TLD or high-traffic zone goes bogus. Note that it is
good practice to verify that this is indeed the case and not because of malicious
actions.

To configure a negative trust anchor, use the `addNTA()` function in the
[`lua-config-file`](settings.md#lua-config-file) and restart the recursor. This
function requires the name of the zone and an optional reason:

```lua
addNTA('example.', "Someone messed up the delegation")
addNTA('powerdns.com') -- No reason given
```

### Runtime Configuration of Negative Trust Anchors
The [`rec_control`](running.md) command can be used to manage the negative trust
anchors of a running instance. These runtime settings are lost when restarting
the recursor, more permanent NTAs should be added to the `lua-config-file` with
`addNTA()`.

Adding a negative trust anchor is done with the `add-nta` command (that optionally
accepts a reason):

```
$ rec_control add-nta domain.example botched keyroll
Added Negative Trust Anchor for domain.example. with reason 'botched keyroll'
```

To view the currently configured negative trust anchors, run `show-ntas`:

```
$ rec_control show-ntas
Configured Negative Trust Anchors:
subdomain.example.      Operator failed key-roll
otherdomain.example.    DS in parent, no DNSKEY in zone
```

To remove negative trust anchor(s), run `clear-nta`:

```
$ rec_control clear-nta subdomain.example
Removed Negative Trust Anchors for subdomain.example
```

`clear-nta` accepts multiple domain-names and accepts '*' (beware the shell quoting)
to remove all negative trust anchors.
