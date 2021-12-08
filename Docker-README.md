# Intro

https://hub.docker.com/u/powerdns offers automatic builds of dnsdist, Auth and Recursor, from the pdns.git master branch.

The images are based on Debian Buster (slim).

The Dockerfiles:

* https://github.com/PowerDNS/pdns/blob/master/Dockerfile-auth
* https://github.com/PowerDNS/pdns/blob/master/Dockerfile-dnsdist
* https://github.com/PowerDNS/pdns/blob/master/Dockerfile-recursor

Other data involved in the Docker build process can be found at https://github.com/PowerDNS/pdns/tree/master/dockerdata

# Usage

The images are ready to run with limited functionality.
At container startup, the startup.py wrapper (from the dockerdata directory linked above) checks for `PDNS_RECURSOR_API_KEY` / `PDNS_AUTH_API_KEY` / `DNSDIST_API_KEY` environment variables for the product you are running.
If such a variable is found, `/etc/powerdns-api.conf` or `/etc/dnsdist-api.conf` is written, enabling the webserver in all products, and the dnsdist console.
For the dnsdist console, make sure that your API key is in a format suitable for the console (use `makeKey()`).

The default configs shipped in the image (see dockerdata above) parse all files in `/etc/powerdns/pdns.d` / `/etc/powerdns/recursor.d` / `/etc/dnsdist/conf.d`.
The image also ships a symlink to the API config file inside those `.d` dirs.
For Auth and Recursor, extra configuration can be passed or the command line, or via a volume mount into `/etc/powerdns` or the `.d` dir.
For dnsdist, only the volume mount is applicable.

If you want to volume mount a config, but also take the keys from the environment, please take care to include the same `X-api.conf` symlink in your `.d` directory.

# Auth and databases

The default auth config uses SQLite3 in `/var/lib/powerdns/pdns.sqlite3`.
We suggest providing that file via a volume.
For other databases, either pass config overrides on the command line, or mount a config file.

## LMDB

When using the LMDB backend with the auth image, please make sure that any containers that might access the database volume do not have overlapping PIDs - otherwise you will get locking problems and possibly resulting corruption.
In a plain Docker or Compose setup, this can be done by using the host PID namespace.

# Compose example

We have a Docker Compose example at https://github.com/PowerDNS/pdns/blob/master/docker-compose.yml .
It brings up all three services, and exposes them to eachother by name (using Docker's internal DNS).
In the dockerdata dir, you can find an example dnsdist Lua config (with Python helper to make DNS lookups non-blocking for dnsdist) for managing your auth/rec backends by name.

# Privileged ports

The default configurations included for dnsdist, Auth and Recursor attempt to bind to port 53, which may not be permitted by the platform on which you intend to use these images. Kubernetes clusters, for example, might have a restriction on binding to privileged ports unless the `NET_BIND_SERVICE` capability is explicitly added to the container's security context.

There are multiple ways of dealing with these restrictions if you encounter them:

* Grant the `NET_BIND_SERVICE` capability to the containers which utilize these images
* Use custom configuration files to bind to alternate ports outside of the privileged range. This can be done via the following configuration settings:
    * dnsdist: `setLocal()`
    * Auth & Recursor: `local-address` and/or `local-port`