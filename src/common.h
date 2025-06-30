/* 
   litmus: WebDAV server test suite: common routines
   Copyright (C) 2001-2002, Joe Orton <joe@manyfish.co.uk>
                                                                     
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef INTEROP_H
#define INTEROP_H 1

#include <ne_session.h>
#include <ne_request.h>
#include <ne_basic.h>
#include <ne_socket.h> /* for ne_sock_addr */

#include "tests.h"

/* always use O_BINARY for cygwin/windows compatibility. */
#ifndef O_BINARY
#define O_BINARY (0)
#endif

/* prototype a test function. */
#define TF(x) int x(void)

/* Standard test functions.
 * init: parses and verifies cmd-line args (URL, username/password)
 * direct_connect: tests direct connection (optional, not recommended)
 * begin: opens session 'i_session' to server.
 * options: does an OPTIONS request on i_path, sets i_class2.
 * finish: closes i_session. */

TF(init); TF(begin); TF(direct_connect);
TF(options); TF(finish);

/* Standard initialisers for tests[] array: start everything up: */
#define INIT_TESTS T(begin)

/* And finish everything off */
#define FINISH_TESTS T(finish), T(NULL)

/* The session to use. */
extern ne_session *i_session, *i_session2;

/* server details. */
extern ne_uri i_origin;
#define i_path (i_origin.path)
#define i_port (i_origin.port)
#define i_hostname (i_origin.host)

/* If test_direct_connect() is invoked, this will be non-NULL. */
extern ne_sock_addr *i_address;

extern int i_class2; /* true if server is a class 2 DAV server. */

/* Upload htdocs/foo to i_path + path */
int upload_foo(const char *path);

/* Returns etag of resource at path within i_session */
char *get_etag(const char *path);

/* PUT request with body of "zero" to path. Returns NE_ERROR for
 * non-2xx responses. */
int dummy_put(ne_session *sess, const char *path);

/* PUT request to 'path' with request body NUL-terminated string
 * 'content'. */
int put_buffer(ne_session *sess, const char *path, const char *content);

/* for method 'method' on 'uri', do operation 'x'. */
#define ONMREQ(method, uri, x) do { int _ret = (x); if (_ret) { t_context("%s on `%s': %s", method, uri, ne_get_error(i_session)); return FAIL; } } while (0)

/* for method 'method' which 'uri1' to 'uri2', do operation 'x'. */
#define ONM2REQ(method, uri1, uri2, x) do { int _ret = (x); if (_ret) { t_context("%s `%s' to `%s': %s", method, uri1, uri2, ne_get_error(i_session)); return FAIL; } } while (0)

/* ONNREQ(msg, x): fails if (x) is non-zero, giving 'msg' followed by
 * neon session error. */
#define ONNREQ(msg, x) do { int _ret = (x); if (_ret) { t_context("%s:\n%s", msg, ne_get_error(i_session)); return FAIL; } } while (0)

/* similarly for second session. */
#define ONNREQ2(msg, x) do { int _ret = (x); if (_ret) { t_context("%s:\n%s", msg, ne_get_error(i_session2)); return FAIL; } } while (0)

#define GETSTATUS (atoi(ne_get_error(i_session)))

/* STATUS(404) returns non-zero if status code is not 404 */
#define STATUS(code) (GETSTATUS != (code))

#define GETSTATUS2 (atoi(ne_get_error((i_session2))))
#define STATUS2(code) (GETSTATUS2 != (code))

#endif /* INTEROP_H */
