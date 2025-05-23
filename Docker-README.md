# Intro

https://hub.docker.com/u/powerdns offers automatic builds of dnsdist, Auth and Recursor, from the pdns.git master branch.

The images are based on Debian Bullseye (slim).

The Dockerfiles:

* https://github.com/PowerDNS/pdns/blob/master/Dockerfile-auth
* https://github.com/PowerDNS/pdns/blob/master/Dockerfile-dnsdist
* https://github.com/PowerDNS/pdns/blob/master/Dockerfile-recursor

Other data involved in the Docker build process can be found at https://github.com/PowerDNS/pdns/tree/master/dockerdata

> **Note**
> If you are building the Dockerfiles directly from the git repo, make sure you run `git submodule init` followed by `git submodule update` first.

# Usage

The images are ready to run with limited functionality.
At container startup, the startup.py wrapper (from the dockerdata directory linked above) checks for `PDNS_RECURSOR_API_KEY` / `PDNS_AUTH_API_KEY` / `DNSDIST_API_KEY` environment variables for the product you are running.
If such a variable is found, `/etc/powerdns/recursor.d/_api.conf` / `/etc/powerdns/pdns.d/_api.conf` / `/etc/dnsdist/conf.d/_api.conf` is written, enabling the webserver in all products, and the dnsdist console.
For the dnsdist console, make sure that your API key is in a format suitable for the console (use `makeKey()`).

The default configs shipped in the image (see dockerdata above) parse all files in `/etc/powerdns/pdns.d` / `/etc/powerdns/recursor.d` / `/etc/dnsdist/conf.d`.
For Auth and Recursor, extra configuration can be passed on the command line, or via a volume mount into `/etc/powerdns` or the `.d` dir.
For dnsdist, only the volume mount is applicable.

If you want to volume mount a config, but also take the keys from the environment, please take care to include the same `_api.conf` file in your `.d` directory.

If you want to read the configuration for debugging purposes, you can run the containers with the `DEBUG_CONFIG` environment variable set to `'yes'`.
This will print the full config on startup. Please keep in mind that this also includes credentials, therefore this setting should never be used in production environments.

# Auth and databases

The default auth config uses SQLite3 in `/var/lib/powerdns/pdns.sqlite3`.
We suggest providing that file via a volume.
For other databases, either pass config overrides on the command line, or mount a config file.

## LMDB

When using the LMDB backend with the auth image, please make sure that any containers that might access the database volume do not have overlapping PIDs - otherwise you will get locking problems and possibly resulting corruption.
In a plain Docker or Compose setup, this can be done by using the host PID namespace.

# Compose example

We have a Docker Compose example at https://github.com/PowerDNS/pdns/blob/master/docker-compose.yml.
It brings up all three services, and exposes them to each other by name (using Docker's internal DNS).
In the dockerdata dir, you can find an example dnsdist Lua config (with Python helper to make DNS lookups non-blocking for dnsdist) for managing your auth/rec backends by name.

# Privileged ports

The default configurations included for dnsdist, Auth and Recursor attempt to bind to port 53, which may not be permitted by the platform on which you intend to use these images. Kubernetes clusters, for example, might have a restriction on binding to privileged ports unless the `NET_BIND_SERVICE` capability is explicitly added to the container's security context.

There are multiple ways of dealing with these restrictions if you encounter them:

* Grant the `NET_BIND_SERVICE` capability to the containers which utilize these images
* Use custom configuration files to bind to alternate ports outside of the privileged range. This can be done via the following configuration settings:
    * dnsdist: `setLocal()`
    * Auth & Recursor: `local-address` and/or `local-port`

Note: Docker Engine 20.10.0 (released december 2020) removed the need to set the `NET_BIND_SERVICE` capability when attempting to bind to a privileged port.

## Auth and Supervisord

The auth image uses `tini` as init process to run auth via the startup.py wrapper. However, it also has `supervisord` available for special use cases. Example scenarios for using `supervisord` include:

* Running multiple processes (ie: auth + ixfrdist) within the same container - Generally not advisable, but has benefits in some cases
* Allowing restarts of processes within a container without having the entire container restart - Primarily has benefits in Kubernetes where you could have a process (ixfrdist for example) restart when a script/agent detects changes in a mounted configmap containing the process' configuration.

To use `supervisord` within Kubernetes, you can configure the container with the following:

```yaml
command: ["supervisord"]
args:
  - "--configuration"
  - "/path/to/supervisord.conf"
```

In the above example `/path/to/supervisord.conf` is the path where a configmap containing your supervisord configuration is mounted.
Further details about `supervisord` and how to configure it can be found here: https://supervisord.org/configuration.html
