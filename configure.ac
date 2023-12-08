dnl autoconf script for litmus

AC_INIT([litmus],[0.14],[],[],[https://github.com/notroj/litmus])

AC_PREREQ([2.59])

AC_COPYRIGHT([Copyright (c) 2001-2022 Joe Orton and others
This configure script may be copied, distributed and modified under the 
terms of the GNU General Public license; see COPYING for more details])

AC_CONFIG_SRCDIR(litmus.in)
AC_CONFIG_HEADERS([config.h])

AC_DEFINE([_GNU_SOURCE], 1, [Define to enable GNU extensions])

AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL

dnl List of tests
AC_SUBST([TESTS], ["basic copymove props locks http"])

NE_REQUIRE_VERSIONS([0], [27 28 29 30 31 32 33])
NEON_WITHOUT_ZLIB
NEON_WITHOUT_ACL
NEON_TEST
NEON_TEST_WITHOUT_CHILD
NEON_VPATH_BUNDLED(['$(top_srcdir)/neon/src'], [neon/src], [
 NEON_NORMAL_BUILD
 NEON_XML_PARSER
])

dnl Check for getopt_long
AC_CHECK_FUNC(getopt_long,,[AC_LIBOBJ(lib/getopt)
AC_LIBOBJ(lib/getopt1)])

NEON_FORMAT(long long)
NEON_DEBUG
NEON_WARNINGS

CPPFLAGS="$CPPFLAGS -I\${top_builddir}"

AC_CONFIG_FILES([litmus], [chmod +x litmus])
AC_CONFIG_FILES([Makefile neon/src/Makefile])

AC_OUTPUT

AC_MSG_NOTICE([Configured to build AC_PACKAGE_STRING:

  Install prefix:  ${prefix}
  Compiler:        ${CC}
  neon library:    ${neon_library_message}
  XML parser:      ${neon_xml_parser_message}
  SSL library:     ${ne_SSL_message}
])

# For VPATH builds
for d in neon neon/src test-common src; do
    test -d $d || mkdir $d
done
