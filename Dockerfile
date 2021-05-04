FROM keppel.eu-de-1.cloud.sap/ccloud-dockerhub-mirror/library/alpine:latest

LABEL "maintainer"="Joachim Barheine <joachim.barheine@sap.com>"
LABEL source_repository="https://github.com/sapcc/maia"

ADD build/docker.tar /usr/bin/
ENTRYPOINT ["/usr/bin/maia_linux_amd64"]
