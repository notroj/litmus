#!/bin/sh
set -e
echo -n "aclocal... "
${ACLOCAL:-aclocal} -I neon/macros -I m4
echo -n "autoheader... "
${AUTOHEADER:-autoheader} -Wall
echo -n "autoconf... "
${AUTOCONF:-autoconf} -Wall
echo okay.
rm -rf autom4te*.cache
