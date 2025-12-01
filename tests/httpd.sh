#!/bin/bash -ex
PODMAN=@PODMAN@
${PODMAN} build -t fedora-httpd -f @srcdir@/tests/Containerfile \
          @srcdir@/tests/
CID=`${PODMAN} run -d -p 8080:80 fedora-httpd /usr/sbin/httpd -X`
sleep 5
./litmus $* http://localhost:8080/dav/
${PODMAN} kill ${CID}
