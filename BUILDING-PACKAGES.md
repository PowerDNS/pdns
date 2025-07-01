Building packages
=================

PowerDNS uses the pdns-builder tool to generate packages for its products. The actual workflow can be found in the [builder-support](https://github.com/PowerDNS/pdns/tree/master/builder-support) directory of the git repository.
The [build-tags.yml](https://github.com/PowerDNS/pdns/blob/master/.github/workflows/build-tags.yml) workflow automatically builds packages when a tag is pushed, so there is no need to trigger a manual build for releases, and actually doing so would be worse from a provenance point of view where full automation is always better.

Building packages on your own computer
--------------------------------------

This requires a working Docker installation.

1. Clone our git repo (`git clone https://github.com/PowerDNS/pdns.git`)
2. Check out the version you want, it can be a git tag like dnsdist-1.8.1, a git commit ID or branch
3. Update submodules (`git submodule update --init --recursive`)
4. Execute `builder/build.sh` to see what arguments it supports
5. Then run `builder/build.sh` with the arguments you want (for example, `builder/build.sh -m recursor debian-bookworm`)

Building packages from GitHub actions
-------------------------------------

You can build packages from your own fork of the PowerDNS repository. Go to the [PowerDNS/pdns](https://github.com/PowerDNS/pdns) repository and click on `Fork` at the top right of the screen. When asked if you would like to only copy the master branch, say no, as otherwise you will not be able to build packages from tagged releases. If you have already done so and have not done any modification to your fork, the easiest way is to delete and recreate it.

On your fork, go to the `Actions` tab. You will be greeted by a message stating `Workflows aren’t being run on this forked repository`. You can click `I understand my workflows, go ahead and enable them`.

Please be aware that by default some of the workflows are executed once every day, and enabling them will consume billing time our of your GitHub actions quota, although at the moment GitHub disables these by default: `This scheduled workflow is disabled because scheduled workflows are disabled by default in forks`. 

On the left side, click on `Trigger specific package build`.

Locate the `Run workflow` dropdown item on the top right side of the screen, inside the blue region stating `This workflow has a workflow_dispatch event trigger.` It will open a menu with several options:
- `Branch`: you can keep `master` here, unless you need to build for an operating system which is not in the list, in which case you will have to create a new branch and add the required file(s) for this OS. See `Adding a new OS` below.
- `Product to build`: select the product you want to build packages for, for example `dnsdist`
- `OSes to build for, space separated`: keep one or more OSes you want to build packages for, for example `ubuntu-focal`
- `git ref to checkout`: the exact version you want to build. It can be the name of branch, a git tag, or a git commit ID. Most likely you will be willing to build from a tagged release, like `dnsdist-1.8.1`.
- `is this a release build?`: Keep `NO`

Click `Run workflow` to start the build.

If you reload the page, you should now see your build in progress as a `Trigger specific package build` workflow run. It will take some time to finish, but you can look at the progress by clicking on it.

Once it's done, you can retrieve the generated package in the list of artifacts on the `Summary` page of the workflow run, by clicking on the `Summary` link on the top right of the screen.

Adding a new OS to the list
---------------------------

Adding a new OS is usually easy, provided that it does not differ too much from an existing one. For example, to add support for Debian Bookworm (already present in the current repository), one had to:

Copy the existing instructions for Debian bullseye:
```
cp builder-support/dockerfiles/Dockerfile.target.debian-bullseye builder-support/dockerfiles/Dockerfile.target.debian-bookworm
```

In the new `builder-support/dockerfiles/Dockerfile.target.debian-bookworm` file, replace every occurrence of `debian-bullseye` by `debian-bookworm`, and of `debian:bullseye` by `debian:bookworm`

Then add the new target to the list of OSes in the `.github/workflows/builder-dispatch.yml` workflow file:
```
default: >-
  el-8
  el-9
  debian-bullseye
  debian-bookworm
  ubuntu-focal
  ubuntu-jammy
```

If release packages should be automatically built for this new target, then `.github/workflows/build-packages.yml` has to be updated as well:
``
```
default: >-
  el-8
  el-9
  debian-bullseye
  debian-bookworm
  ubuntu-focal
  ubuntu-jammy
```

Not forgetting to update the list of hashes later in the same file:
```
pkghashes-el-8: ${{ steps.pkghashes.outputs.pkghashes-el-8 }}
pkghashes-el-9: ${{ steps.pkghashes.outputs.pkghashes-el-9 }}
pkghashes-debian-bullseye: ${{ steps.pkghashes.outputs.pkghashes-debian-bullseye }}
pkghashes-debian-bookworm: ${{ steps.pkghashes.outputs.pkghashes-debian-bookworm }}
pkghashes-ubuntu-focal: ${{ steps.pkghashes.outputs.pkghashes-ubuntu-focal }}
pkghashes-ubuntu-jammy: ${{ steps.pkghashes.outputs.pkghashes-ubuntu-jammy }}
```
