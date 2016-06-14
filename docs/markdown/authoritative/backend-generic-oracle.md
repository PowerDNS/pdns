# Generic Oracle backend
|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|Yes|
|Slave|Yes|
|Superslave|Yes|
|Autoserial|Yes (v3.1 and up)|
|Case|All lower|
|DNSSEC|Yes (set `goracle-dnssec`)|
|Disabled data|Yes (v3.4.0 and up)|
|Comments|Yes (v3.4.0 and up)|
|Module name | goracle|
|Launch name| goracle|

The Generic Oracle Backend is a [Generic SQL backend](backend-generic-sql.md).
The default setup conforms to the following schema, which you should add to an
Oracle database. You may need or want to add `namespace` statements.

```
!!include=../modules/goraclebackend/schema.goracle.sql
```

This schema contains all elements needed for master, slave and superslave operation.

Inserting records is a bit different compared to MySQL and PostgreSQL, you should use:

```
INSERT INTO domains (id,name,type) VALUES (domains_id_sequence.nextval, 'example.net', 'NATIVE');
```

# Settings
## `goracle-tnsname`
Which TNSNAME the Generic Oracle Backend should be connecting to. There are no
`goracle-dbname`, `goracle-host` or `goracle-port` settings, their equivalent is
in `/etc/tnsnames.ora`.

## `goracle-dnssec`
Enable DNSSEC processing for this backend. Default=no.

# Caveats
## Password Expiry
When your password is about to expire, and logging into oracle warns about this,
the Generic Oracle backend can no longer login, and will a OCILogin2 warning.

To work around this, either update the password in time or remove expiration
from the account used.
