/* 
   WebDAV locking stress test
   Copyright (C) 2024-6, Red Hat, Inc.

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
#include <sys/stat.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#if defined(HAVE_PTHREADS)
#include <pthread.h>
#endif

#include <ne_session.h>
#include <ne_basic.h>
#include <ne_uri.h>
#include <ne_locks.h>

#include "common.h"

#define ITERS 20000
#ifndef THREADS
#define THREADS (20)
#endif

struct thrarg {
#if defined(HAVE_PTHREADS) && (THREADS > 1)
    pthread_t thd;
#endif
    ne_uri uri;
};
    
static void *threadfn(void *varg)
{
    struct thrarg *arg = varg;
    ne_session *sess;
    unsigned int iter;
    int fd = open("/dev/zero", O_RDONLY);
    
    if (fd < 0) return "open(/dev/zero) failed";
    
    sess = ne_session_create(i_origin.scheme, i_origin.host, i_origin.port);

    if (ne_put(sess, arg->uri.path, fd) != NE_OK)
        return ne_concat("PUT: ", ne_get_error(sess), NULL);

    close(fd);
    
    for (iter = 0; iter < ITERS; iter++) {
        struct ne_lock *lock = ne_lock_create();
        int ret;
        
        memcpy(&lock->uri, &arg->uri, sizeof lock->uri);
        
        ret = ne_lock(sess, lock);
        if (ret != NE_OK) {
            return ne_concat("LOCK failure: ", ne_get_error(sess), NULL);
        }
        
        ret = ne_unlock(sess, lock);
        if (ret != NE_OK) {
            return ne_concat("UNLOCK failure: ", ne_get_error(sess), NULL);
        }

        memset(&lock->uri, 0, sizeof lock->uri);
        ne_lock_destroy(lock);
    }

    ne_session_destroy(sess);    
    
    return NULL;
}

#if THREADS > 1
#define T_name "lockbomb_threaded"
static int lockbomb(void)
{
    struct thrarg args[THREADS];
    unsigned n;
    int ret;

    for (n = 0; n < THREADS; n++) {
        char *path = ne_malloc(256);
        
        ne_snprintf(path, 256, "%s/lb-lock-%04u", i_origin.path, n);

        memcpy(&args[n].uri, &i_origin, sizeof i_origin);
        args[n].uri.path = path;

        ret = pthread_create(&args[n].thd, NULL, threadfn, &args[n]);
        ONV(ret, ("pthread_create failed: %s", strerror(ret)));
    }

    NE_DEBUG(NE_DBG_HTTP, "lockbomb: spawned %u threads, now waiting...\n",
             (unsigned int)THREADS);

    for (n = 0; n < THREADS; n++) {
        const char *retval;

        ret = pthread_join(args[n].thd, (void **)&retval);
        ONV(ret, ("pthread_join failed: %s", strerror(ret)));
        ONV(retval, ("thread failed: %s", retval));
   }
    
    return OK;
}

#else /* !HAVE_PTHREADS */

#define T_name "lockbomb_single"
static int lockbomb(void)
{
    struct thrarg args[THREADS];
    const char *retval;

    args[0].uri = i_origin;
    args[0].uri.path = ne_concat(i_origin.path, "lb-lock-single", NULL);
    
    retval = threadfn(&args[0]);
    ONV(retval, ("iteration failed: %s", retval));
    return OK;
}

#endif

ne_test tests[] = {
    INIT_TESTS,
    T_NAMED(lockbomb, T_name),
    FINISH_TESTS
};
