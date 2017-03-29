# Dockerfile for building the markdown docs
#
# example usage:
# docs/$ docker build -t pdns-mkdocs .
# docs/$ docker run  -t -i -v $(pwd)/..:/pdns pdns-mkdocs bash
# root@07d38c7f88a5:/# useradd -u 1000 peter
# root@07d38c7f88a5:/# su - peter
# No directory, logging in with HOME=/
# $ bash
# peter@07d38c7f88a5:/$ cd /pdns/docs
# peter@07d38c7f88a5:/pdns/docs$ make html/index.html
# 

FROM ubuntu:14.04
RUN apt-get update
RUN apt-get -y install git build-essential vim-tiny pandoc python-pip
RUN pip install pandocfilters mkdocs
