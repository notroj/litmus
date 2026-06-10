/*
   litmus: WebDAV server test suite
   Copyright (C) 2026, Joe Orton <jorton@redhat.com>

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

#include "config.h"

#include <sys/types.h>

#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <fcntl.h>

#include <ne_request.h>
#include <ne_props.h>
#include <ne_locks.h>
#include <ne_string.h>

#include "common.h"

static const char *protected_name;
static char *prot_path, *prot_coll, *prot_within;
static char *src_uri;
static int prot_ok;

#define LEAF "protsrc.txt"

static int prot_init(void)
{
    protected_name = getenv("TEST_PROTECTED");
    if (!protected_name || *protected_name == '\0') {
        protected_name = ".DAV";
    }

    prot_within = ne_concat(protected_name, "/test.txt", NULL);
    prot_path = ne_concat(i_path, prot_within, NULL);
    prot_coll = ne_concat(i_path, protected_name, "/", NULL);
    src_uri = ne_concat(i_path, LEAF, NULL);

    CALL(upload_foo(LEAF));

    prot_ok = 1;
    return OK;
}

static int prepare(void)
{
    ne_propname pname = { "http://webdav.org/neon/litmus/", "forcecreate" };
    ne_proppatch_operation pops[] = {
        { &pname, ne_propset, "value" },
        { NULL }
    };

    PRECOND(prot_ok);

    CALL(upload_foo(LEAF));

    ONMREQ("PROPPATCH to trigger protected directory creation",
           src_uri, ne_proppatch(i_session, src_uri, pops));

    /* Try to upload within the protected directory as well, but
     * ignore failures (since it should fail). */
    (void) upload_foo(prot_within);

    return OK;
}

static int mkcol_protected(void)
{
    PRECOND(prot_ok);

    ONN("MKCOL of protected directory should be rejected",
        ne_mkcol(i_session, prot_coll) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 501,
        ("MKCOL of protected directory gave %d, expected error",
         GETSTATUS));

    return OK;
}

static int put(void)
{
    PRECOND(prot_ok);

    ONN("PUT into protected directory should be rejected",
        dummy_put(i_session, prot_path) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 409
        && GETSTATUS != 501 && GETSTATUS != 404,
        ("PUT into protected directory gave %d, expected 4xx error",
         GETSTATUS));

    return OK;
}

static int get(void)
{
    ne_request *req;
    int ret;

    PRECOND(prot_ok);

    req = ne_request_create(i_session, "GET", prot_path);
    ret = ne_request_dispatch(req);

    ONV(ret == NE_OK && ne_get_status(req)->klass == 2,
        ("GET of protected resource %s should be rejected, got %d",
         prot_path, ne_get_status(req)->code));

    ne_request_destroy(req);
    return OK;
}

static int mkcol(void)
{
    char *sub;

    PRECOND(prot_ok);

    sub = ne_concat(i_path, protected_name, "/subcoll/", NULL);

    ONN("MKCOL inside protected directory should be rejected",
        ne_mkcol(i_session, sub) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 409
        && GETSTATUS != 501 && GETSTATUS != 404,
        ("MKCOL inside protected directory gave %d, expected 4xx error",
         GETSTATUS));

    ne_free(sub);
    return OK;
}

static int move_into(void)
{
    char *dest;

    PRECOND(prot_ok);

    dest = ne_concat(i_path, protected_name, "/moved.txt", NULL);

    ONN("MOVE into protected directory should be rejected",
        ne_move(i_session, 0, src_uri, dest) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 409
        && GETSTATUS != 502 && GETSTATUS != 404,
        ("MOVE into protected directory gave %d, expected error",
         GETSTATUS));

    ne_free(dest);
    return OK;
}

static int copy_into(void)
{
    char *dest;

    PRECOND(prot_ok);

    dest = ne_concat(i_path, protected_name, "/copied.txt", NULL);

    ONN("COPY into protected directory should be rejected",
        ne_copy(i_session, 0, NE_DEPTH_INFINITE, src_uri, dest) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 409
        && GETSTATUS != 502 && GETSTATUS != 404,
        ("COPY into protected directory gave %d, expected error",
         GETSTATUS));

    ne_free(dest);
    return OK;
}

static int move_from(void)
{
    char *dest;

    PRECOND(prot_ok);

    dest = ne_concat(i_path, "extracted.txt", NULL);

    ONN("MOVE out of protected directory should be rejected",
        ne_move(i_session, 0, prot_path, dest) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 404
        && GETSTATUS != 502,
        ("MOVE from protected directory gave %d, expected error",
         GETSTATUS));

    ne_delete(i_session, dest);
    ne_free(dest);
    return OK;
}

static int copy_from(void)
{
    char *dest;

    PRECOND(prot_ok);

    dest = ne_concat(i_path, "extracted.txt", NULL);

    ONN("COPY out of protected directory should be rejected",
        ne_copy(i_session, 0, NE_DEPTH_INFINITE, prot_path, dest) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 502,
        ("COPY from protected directory gave %d, expected error",
         GETSTATUS));

    ne_delete(i_session, dest);
    ne_free(dest);
    return OK;
}

static int delete(void)
{
    PRECOND(prot_ok);

    ONN("DELETE inside protected directory should be rejected",
        ne_delete(i_session, prot_path) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 404
        && GETSTATUS != 501,
        ("DELETE inside protected directory gave %d, expected error",
         GETSTATUS));

    return OK;
}

static int delete_coll(void)
{
    PRECOND(prot_ok);

    ONN("DELETE of protected directory itself should be rejected",
        ne_delete(i_session, prot_coll) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 404
        && GETSTATUS != 501,
        ("DELETE of protected directory gave %d, expected error",
         GETSTATUS));

    return OK;
}

static int move_over(void)
{
    PRECOND(prot_ok);

    ONN("MOVE over protected directory should be rejected",
        ne_move(i_session, 1, src_uri, prot_coll) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 409
        && GETSTATUS != 502,
        ("MOVE over protected directory gave %d, expected error",
         GETSTATUS));

    return OK;
}

static int copy_over(void)
{
    PRECOND(prot_ok);

    ONN("COPY over protected directory should be rejected",
        ne_copy(i_session, 1, NE_DEPTH_INFINITE, src_uri, prot_coll)
        != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 409
        && GETSTATUS != 502,
        ("COPY over protected directory gave %d, expected error",
         GETSTATUS));

    return OK;
}

static int lock(void)
{
    struct ne_lock lk = {0};

    PRECOND(prot_ok);

    ne_fill_server_uri(i_session, &lk.uri);
    lk.uri.path = ne_strdup(prot_path);
    lk.depth = NE_DEPTH_ZERO;
    lk.scope = ne_lockscope_exclusive;
    lk.type = ne_locktype_write;
    lk.timeout = 3600;
    lk.owner = ne_strdup("litmus protected test");

    ONN("LOCK on protected resource should be rejected",
        ne_lock(i_session, &lk) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 404
        && GETSTATUS != 501,
        ("LOCK on protected resource gave %d, expected error",
         GETSTATUS));

    ne_free(lk.uri.path);
    ne_free(lk.owner);
    if (lk.token) ne_free(lk.token);
    return OK;
}

static int lock_coll(void)
{
    struct ne_lock lk = {0};

    PRECOND(prot_ok);

    ne_fill_server_uri(i_session, &lk.uri);
    lk.uri.path = ne_strdup(prot_coll);
    lk.depth = NE_DEPTH_INFINITE;
    lk.scope = ne_lockscope_exclusive;
    lk.type = ne_locktype_write;
    lk.timeout = 3600;
    lk.owner = ne_strdup("litmus protected test");

    ONN("LOCK on protected collection should be rejected",
        ne_lock(i_session, &lk) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 404
        && GETSTATUS != 501,
        ("LOCK on protected collection gave %d, expected error",
         GETSTATUS));

    ne_free(lk.uri.path);
    ne_free(lk.owner);
    if (lk.token) ne_free(lk.token);
    return OK;
}

static int proppatch(void)
{
    ne_propname pname = { "http://webdav.org/neon/litmus/", "protected-test" };
    ne_proppatch_operation pops[] = {
        { &pname, ne_propset, "value" },
        { NULL }
    };

    PRECOND(prot_ok);

    ONN("PROPPATCH on protected resource should be rejected",
        ne_proppatch(i_session, prot_path, pops) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 404
        && GETSTATUS != 501 && GETSTATUS != 207,
        ("PROPPATCH on protected resource gave %d, expected error",
         GETSTATUS));

    return OK;
}

static int proppatch_coll(void)
{
    ne_propname pname = { "http://webdav.org/neon/litmus/", "protected-test" };
    ne_proppatch_operation pops[] = {
        { &pname, ne_propset, "value" },
        { NULL }
    };

    PRECOND(prot_ok);

    ONN("PROPPATCH on protected collection should be rejected",
        ne_proppatch(i_session, prot_coll, pops) != NE_ERROR);

    ONV(GETSTATUS != 403 && GETSTATUS != 405 && GETSTATUS != 404
        && GETSTATUS != 501 && GETSTATUS != 207,
        ("PROPPATCH on protected collection gave %d, expected error",
         GETSTATUS));

    return OK;
}

static int prot_cleanup(void)
{
    ne_delete(i_session, src_uri);
    return OK;
}

ne_test tests[] = {
    INIT_TESTS,

    T(prot_init),
    T(prepare),
    T(mkcol_protected),
    T(put),
    T(get),
    T(mkcol),
    T(move_into),
    T(prepare),
    T(copy_into),
    T(prepare),
    T(move_from),
    T(prepare),
    T(copy_from),
    T(delete),
    T(delete_coll),
    T(move_over),
    T(prepare),
    T(copy_over),

    T(lock),
    T(lock_coll),
    T(proppatch),
    T(proppatch_coll),

    T(prot_cleanup),

    FINISH_TESTS
};
