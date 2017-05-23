FROM alpine:latest
MAINTAINER "Arno Uhlig <arno.uhlig@sap.com>"

ADD build/docker.tar /
ENTRYPOINT ["/usr/bin/maia"]