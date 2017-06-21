FROM alpine:3.6

ADD build/docker.tar /usr/bin/
ENTRYPOINT ["/usr/bin/maia_linux_amd64"]
