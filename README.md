
[![Build and test](https://github.com/notroj/litmus/actions/workflows/ci.yml/badge.svg)](https://github.com/notroj/litmus/actions/workflows/ci.yml)

# litmus

_litmus_ is a WebDAV server protocol compliance test suite.

GitHub: https://github.com/notroj/litmus | Web: https://notroj.github.io/litmus/

Tests include:

* OPTIONS for DAV: header
* PUT, GET with byte comparison
* MKCOL
* DELETE (collections, non-collections)
*   COPY, MOVE using combinations of:
    *   overwrite t/f
    *   destination exists/doesn't exist
    *   collection/non-collection
*   Property manipulation and querying:
    *   set, delete, replace properties
    *   persist dead props across COPY
    *   namespace handling
*   Locking
    *   attempts to modify locked resource (as lock owner, not owner)
    *   shared/exclusive locks
    *   lock discovery
    *   collection locking
    *   lock refresh

Bugs, feature requests and patches can be sent in via the GitHub
repository: https://github.com/notroj/litmus

## Usage

_litmus_ comprises of a set of test suites as separate executables: each
program takes a URL on the command-line, optionally followed by
username and password.  To run all the suites from a built _litmus_
tree, use

~~~
 $ make URL=http://dav.example.com/path/ check
~~~

Where http://dav.example.com/path/ is a DAV-enabled collection.  _litmus_
must be able to create a new collection called `litmus` at that
location.  The Makefile variable 'CREDS' can also be defined to be a
username/password separated by strings.  e.g. if you have a user 'jim'
defined with password '2518', use:

~~~
 $ make URL=http://dav.example.com/path/ CREDS="jim 2518" check
~~~

To aid debugging, _litmus_ adds a header `X-Litmus` to every request
made, which includes metadata about the test being run. Some tests
require a second session, for which requests will have a header named
`X-Litmus-Second` instead.

After running a test suite, the file `debug.log` includes a full neon
debugging trace (unless neon or _litmus_ was configured without
debugging enabled).

To use after installation is complete (`make install`), run the
`litmus` script, passing in a URL, optionally followed by the
username/password.  For instance:

~~~
 $ litmus http://dav.example.com/path/
~~~

or

~~~
 $ litmus http://dav.example.com/path/ jim 2518
~~~

## Test options

To use a more compact output format, use the `--quiet` option. By
default, _litmus_ uses colour in the output if the terminal is a
TTY. To override the default, use either the `--colour` or
`--no-colour` options to forcible enable or disable use of colour,
respectively.

To use an HTTP proxy server, pass the --proxy argument using an HTTP
URI for the proxy server, for example:

~~~
 $ litmus --proxy=http://proxy.example.com:3128 http://dav.example.com/path/ jim 2518
~~~

Alternatively, if `neon` is built to use the `libproxy` library
(https://github.com/libproxy/libproxy), then the system-defined proxy
environment can be used:

~~~
 $ litmus --system-proxy http://dav.example.com/path/ jim 2518
~~~

## SSL/TLS

Since version 0.17 _litmus_ trusts the default TLS CA certificates
configured in the SSL library. If you want to run against a server
with a self-signed or otherwise untrusted server certificate, use the
--insecure option, e.g.

~~~
 $ litmus --insecure https://dav.example.com/path/
~~~

`litmus` can use a TLS client certificate, which must be provided in
PKCS#12 format. e.g.:

~~~
 $ litmus --client-cert=client.p12 https://dav.example.com/path/
~~~

## Copyright and licensing

litmus is licensed under the GNU GPL; see COPYING for full details.

~~~
litmus is Copyright (C) 1999-2025 Joe Orton
~~~
