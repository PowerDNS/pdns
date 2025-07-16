#!/bin/sh

if [ "$1" = "get-vcs" ]; then
  builder-support/gen-version
elif [ "$1" = "set-dist" ]; then
  $MESONREWRITE -V --sourcedir="$MESON_PROJECT_DIST_ROOT" kwargs set project / version "$2"
else
  exit 1
fi
