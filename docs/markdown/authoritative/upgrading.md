Before proceeding, it is advised to check the release notes for your PowerDNS version, as specified in the name of the distribution file.

Please upgrade to the PowerDNS Authoritative Server 4.0.0 from 3.4.2+. See the [3.X](https://doc.powerdns.com/3/authoritative/upgrading/) upgrade notes if your version is older than 3.4.2.

# 3.4.X to 4.0.0

## Database changes
No changes have been made to the database schema.
However, several superfluous queries have been dropped from the SQL backend.
If you use a non-standard SQL schema, please review the new defaults.

  - `insert-ent-query`, `insert-empty-non-terminal-query`, `insert-ent-order-query` have been replaced by one query named `insert-empty-non-terminal-order-query`
  - `insert-record-order-query` has been dropped, `insert-record-query` now sets the ordername (or NULL)
  - `insert-slave-query` has been dropped, `insert-zone-query` now sets the type of zone

## Changed options
Several options have been removed or renamed, for the full overview of all options, see [settings](settings.md).

### Renamed options
The following options have been renamed:

 * `experimental-json-interface` ==> [`api`](settings.md#api)
 * `experimental-api-readonly` ==> [`api-readonly`](settings.md#api-readonly)
 * `experimental-api-key` ==> [`api-key`](settings.md#api-key)
 * `experimental-dname-processing` ==> [`dname-processing`](settings.md#dname-processing)
 * `experimental-dnsupdate` ==> [`dnsupdate`](settings.md#dnsupdate)
 * `allow-dns-update-from` ==> [`allow-dnsupdate-from`](settings.md#allow-dnsupdate-from)
 * `forward-dnsupdates` ==> [`forward-dnsupdate`](settings.md#forward-dnsupdate)

### Changed defaults

 * [`default-ksk-algorithms`](settings.md#default-ksk-algorithms) changed from rsasha256 to ecdsa256
 * [`default-zsk-algorithms`](settings.md#default-zsk-algorithms) changed from rsasha256 to empty

### Removed options
The following options are removed:

 * `pipebackend-abi-version`, it now a setting per-pipe backend.
 * `strict-rfc-axfrs`
 * `send-root-referral`

## API
The API path has changed to `/api/v1`.

Incompatible change: `SOA-EDIT-API` now follows `SOA-EDIT-DNSUPDATE` instead of `SOA-EDIT` (incl. the fact that it now has a default value of `DEFAULT`).
You must update your existing `SOA-EDIT-API` metadata (set `SOA-EDIT` to your previous `SOA-EDIT-API` value, and `SOA-EDIT-API` to `SOA-EDIT` to keep the old behaviour).
