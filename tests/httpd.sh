#!/bin/bash
PODMAN=@PODMAN@

echo "-- Building container --"

if ! ${PODMAN} build -t fedora-httpd -f @srcdir@/tests/Containerfile \
     @srcdir@/tests/; then
    echo "-- Failed to build container, bailing."
    exit 1
fi

echo "-- Launching container --"
CID=`${PODMAN} run -d -p 8080:80 fedora-httpd /usr/sbin/httpd -X`
sleep 5

echo "-- Running tests --"
./litmus $* http://localhost:8080/dav/
RV=$?
${PODMAN} kill ${CID}
exit $RV
