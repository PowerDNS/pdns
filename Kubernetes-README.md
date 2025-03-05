# Intro

Contribution by: OWNDOMAINHOME SAS (ODH) / https://github.com/owndomainhome

We give you a set of Kubernetes manifests (yaml) to deploy PowerDNS AS (Authoritative Server), RES (Resolver), Dist (DNSDist) roles using minimal configs.

Main requirements:

* Kubernetes Single Node (standalone) or Cluster.
* Storage Class (NFS) or any other.
* Bootstrap Sqlite Backend DB file (for AS component).
* MetalLB to expose DNS Dist component to the world. * You can use another LB solution, you only must change the specific annotations for them.
* Cert-Manager implementation u other option for TLS secrets on ingress resources.

Manifests can be found at https://github.com/PowerDNS/pdns/tree/master/kubernetes-manifests

# Usage

Adjust the manifests to suit your case and scenario. See last stable versions of images roles to adjust your docker TAGS. The <ENV_ROLE> is used on 'gitlab-ci pipeline' to associate the branch with specific environment, ex: 'development' or 'testing' or 'production'. The namespaces have an optional suffix 'clients', you can simply remove from your IAC or adjust to another term like: 'internal'.

# Auth and databases

We suggest use secrets for keys and another DB flavor if you want multiples AS or HA qualities.

# Privileged ports

We built the manifests to avoid the use of `NET_BIND_SERVICE` capability. We bind the roles to the 5353 port, because all comunication between roles is internal. Just the 'dist' role is exposed using LB solution over 53 (tcp/udp) port.

# About .gitlab-ci.yaml file

This a rustic and very basic pipeline file to just deploy the three roles (AS, RES, DIST) and get a working solution.