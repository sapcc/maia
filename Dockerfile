FROM alpine:latest
MAINTAINER "Arno Uhlig <arno.uhlig@sap.com>"

ADD build/docker.tar /usr/bin/
ENTRYPOINT ["/usr/bin/maia_linux_amd64"]
