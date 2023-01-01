
# litmus

_litmus_ is a WebDAV server protocol compliance test suite.

GitHub: https://github.com/notroj/litmus | Web: https://notroj.github.io/litmus/

Tests include:

* OPTIONS for DAV: header
* PUT, GET with byte comparison
* MKCOL
* DELETE (collections, non-collections)
* COPY, MOVE using combinations of:
 - overwrite t/f
 - destination exists/doesn't exist
 - collection/non-collection
* Property manipulation and querying:
 - set, delete, replace properties
 - persist dead props across COPY
 - namespace handling
* Locking
 - attempts to modify locked resource (as lock owner, not owner)
 - shared/exclusive locks, lock discovery

Bugs, feature requests and patches can be sent in via the Github
repository: https://github.com/notroj/litmus

## Usage

litmus comprises of a set of test suites as separate executables: each
program takes a URL on the command-line, optionally followed by
username and password.  To run all the suites from a built litmus
tree, use

~~~
 $ make URL=http://dav.example.com/path/ check
~~~

Where http://dav.example.com/path/ is a DAV-enabled collection.  litmus
must be able to create a new collection called 'litmus' at that
location.  The Makefile variable 'CREDS' can also be defined to be a
username/password separated by strings.  e.g. if you have a user 'jim'
defined with password '2518', use:

~~~
 $ make URL=http://dav.example.com/path/ CREDS="jim 2518" check
~~~

To aid debugging, litmus adds a header `X-Litmus-One' to every request
made.  After running a test suite, the file 'debug.log' includes a
full neon debugging trace (unless neon or litmus was configured
without debugging enabled!).

To use after installation is complete ('make install'), run the
'litmus' script, passing in a URL, optionally followed by the
username/password.  For instance:

~~~
 $ litmus http://dav.example.com/path/
~~~

or

~~~
 $ litmus http://dav.example.com/path/ jim 2518
~~~

## Copyright and licensing

litmus is licensed under the GNU GPL; see COPYING for full details.

~~~
litmus is Copyright (C) 1999-2022 Joe Orton
~~~
