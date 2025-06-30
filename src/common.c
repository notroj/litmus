/* 
   litmus: WebDAV server test suite: common routines
   Copyright (C) 2001-2004, 2011, Joe Orton <joe@manyfish.co.uk>
                                                                     
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

#include <config.h>

#include <sys/stat.h> /* for struct stat */

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include <fcntl.h>
#include <stdlib.h>

#include <ne_uri.h>
#include <ne_auth.h>
#include <ne_ssl.h>
#include <ne_session.h>
#include <ne_locks.h>

#include "getopt.h"

#include "common.h"

int i_class2 = 0;

ne_session *i_session, *i_session2;

ne_uri i_origin;
ne_sock_addr *i_address;

static int use_tls, tls_trust_everything;

const char *i_username = NULL, *i_password;

static char *proxy_hostname = NULL;
static unsigned int proxy_port;
static int system_proxy;

static char *clicert_fn, *clicert_uri;

static const struct option longopts[] = {
    { "htdocs", required_argument, NULL, 'd' },
    { "help", no_argument, NULL, 'h' },
    { "quiet", no_argument, NULL, 'q' },
    { "no-colour", no_argument, NULL, 'n' },
    { "colour", no_argument, NULL, 'o' },
    { "proxy", required_argument, NULL, 'p' },
    { "system-proxy", no_argument, NULL, 's' },
    { "client-cert",  required_argument, NULL, 'c' },
    { "client-cert-uri",  required_argument, NULL, 'u' },
    { "insecure", no_argument, NULL, 'i' },
    { NULL }
};

#define HELPOPTS                                                        \
" -p, --proxy=URL            use given proxy server URL\n"              \
" -s, --system-proxy         use proxy server configuration from system\n" \
" -c, --client-cert=CERT     use given PKCS#12 client cert\n"           \
" -u, --client-cert-uri=URI  use given client cert URI\n"               \
" -i, --insecure             ignore TLS certificate verification failures\n" \
" -q, --quiet                use abbreviated output\n"                  \
" -n, --no-colour            enable colour in output\n"                 \
" -o, --colour               disable colour in output\n"

static void usage(FILE *output)
{
    fprintf(output, 
	    "\rUsage: %s [OPTIONS] URL [username password]\n"
	    "Options are:\n" HELPOPTS, test_argv[0]);
}

static int test_connect(void)
{
    const ne_inet_addr *ia;
    ne_socket *sock = ne_sock_create();
    unsigned int port = proxy_hostname ? proxy_port : i_port;
    int success = 0;

    if (!sock) {
        t_context("could not create socket");
        return FAILHARD;
    }

    for (ia = ne_addr_first(i_address); ia && !success; 
	 ia = ne_addr_next(i_address))
	success = ne_sock_connect(sock, ia, port) == 0;
    
    if (!success) {
	t_context("connection refused by `%s' port %d: %s",
		  i_hostname, port, ne_sock_error(sock));
	return FAILHARD;
    }

    ne_sock_close(sock);
    return OK;
}

static int test_resolve(const char *hostname, const char *name)
{
    i_address = ne_addr_resolve(hostname, 0);
    if (ne_addr_result(i_address)) {
       char buf[256];
       t_context("%s hostname `%s' lookup failed: %s", name, hostname,
                 ne_addr_error(i_address, buf, sizeof buf));
       return FAILHARD;
    }
    return OK;
}

int direct_connect(void)
{
    if (proxy_hostname)
        CALL(test_resolve(proxy_hostname, "proxy server"));
    else
        CALL(test_resolve(i_hostname, "server"));

    return test_connect();
}

int litmus_init(int argc, const char *const *argv, int *use_colour, int *quiet)
{
    ne_uri proxy = {0}, *server = &i_origin;
    int optc, n;
    char *proxy_url = NULL;

    while ((optc = getopt_long(argc, test_argv,
			       "c:d:hinop:qsu:", longopts, NULL)) != -1) {
	switch (optc) {
        case 'c':
            clicert_fn = optarg;
            break;
        case 'u':
            clicert_uri = optarg;
            break;
	case 'd':
            t_warning("the 'htdocs' argument is now ignored");
	    break;
	case 'h':
	    usage(stdout);
	    exit(1);
        case 'i':
            tls_trust_everything = 1;
            break;
        case 'n':
            *use_colour = 0;
            break;
        case 'o':
            *use_colour = 1;
            break;
	case 'p':
	    proxy_url = optarg;
	    break;
        case 'q':
            *quiet = 1;
            break;
	case 's':
	    system_proxy = 1;
	    break;
	default:
	    usage(stderr);
	    exit(1);
	}
    }

    n = argc - optind;

    if (n == 0 || n > 3 || n == 2) {
	usage(stderr);
	exit(1);
    }

    NE_DEBUG(NE_DBG_HTTP, "litmus: Parsing URI %s...\n", argv[optind]);

    if (ne_uri_parse(argv[optind], server) || !server->host
        || !server->path || !server->scheme) {
	t_context("couldn't parse server URL `%s'",
		  test_argv[optind]);
	return FAILHARD;
    }       

    if (proxy_url) {
	if (ne_uri_parse(proxy_url, &proxy) || !proxy.host) {
	    t_context("couldn't parse proxy URL `%s'", proxy_url);
	    return FAILHARD;
	}
	if (proxy.scheme && strcmp(proxy.scheme, "http") != 0) {
	    t_context("cannot use scheme `%s' for proxy", proxy.scheme);
	    return FAILHARD;
	}
	if (proxy.port > 0) {
	    proxy_port = proxy.port;
	} else {
	    proxy_port = 8080;
	}
	proxy_hostname = proxy.host;
    }

#ifdef NE_FEATURE_LIBPXY
    if (system_proxy && !ne_has_support(NE_FEATURE_LIBPXY)) {
        t_context("No system proxy support in neon");
        return FAILHARD;
    }
#endif

    use_tls = strcmp(server->scheme, "https") == 0;
    if (use_tls && !ne_has_support(NE_FEATURE_SSL)) {
        t_context("No SSL support, reconfigure using --with-ssl");
        return FAILHARD;
    }

    if (server->port == 0) {
        server->port = use_tls ? 443 : 80;
    }
    if (!ne_path_has_trailing_slash(server->path)) {
        char *newp = ne_concat(server->path, "/", NULL);
        ne_free(server->path);
        server->path = newp;
    }

    if (n > 2) {
	i_username = test_argv[optind+1];
	i_password = test_argv[optind+2];
	
	if (strlen(i_username) >= NE_ABUFSIZ) {
	    t_context("username must be <%d chars", NE_ABUFSIZ);
	    return FAILHARD;
	}

	if (strlen(i_password) >= NE_ABUFSIZ) {
	    t_context("password must be <%d chars", NE_ABUFSIZ);
	    return FAILHARD;
	}
    }
    
    return OK;
}

static int auth(void *ud, const char *realm, int attempt,
		char *username, char *password)
{
    strcpy(username, i_username);
    strcpy(password, i_password);
    return attempt;
}

static void i_pre_send(ne_request *req, void *userdata, ne_buffer *hdr)
{
    const char *name = userdata;
    
    ne_buffer_snprintf(hdr, BUFSIZ, "%s: %s: %d (%s)\r\n",
                       name, test_suite, test_num, tests[test_num].name);
}

/* Allow all certificates. */
static int ignore_verify(void *ud, int fs, const ne_ssl_certificate *cert)
{
    return 0;
}

static int init_ssl(ne_session *sess)
{
    int got_clicert = clicert_fn || clicert_uri;
    ne_ssl_client_cert *cc = NULL;

    ne_ssl_trust_default_ca(sess);

    if (tls_trust_everything) ne_ssl_set_verify(sess, ignore_verify, NULL);

    if (!got_clicert) return OK;

    if (clicert_fn)
        cc = ne_ssl_clicert_read(clicert_fn);
    else
#if NE_MINIMUM_VERSION(0, 35)
        cc = ne_ssl_clicert_fromuri(clicert_uri, 0);
#else
        t_warning("No client certificate URI support");
#endif

    if (!cc) {
        t_context("Can not read the client certificate '%s'",
                  clicert_fn ? clicert_fn : clicert_uri);
        return FAILHARD;
    }

    if (ne_ssl_clicert_encrypted(cc)) {
        t_context("Can not use encrypted the client certificate '%s'",
                  clicert_fn ? clicert_fn : clicert_uri);
        return FAILHARD;
    }

    ne_ssl_set_clicert(sess, cc);
    ne_ssl_clicert_free(cc);

    return OK;
}

static int init_session(ne_session *sess)
{
    if (proxy_hostname) {
	ne_session_proxy(sess, proxy_hostname, proxy_port);
    }
    else if (system_proxy) {
        ne_session_system_proxy(sess, 0);
    }

    ne_set_useragent(sess, "litmus/" PACKAGE_VERSION);

    if (i_username) {
	ne_set_server_auth(sess, auth, NULL);
    }

    if (use_tls) {
        CALL(init_ssl(sess));
    }
    
    return OK;
}    

static int make_space(void)
{
    char *space = ne_concat(i_path, "litmus/", NULL);
    
    ne_delete(i_session, space);

    if (ne_mkcol(i_session, space)) {
	t_context("Could not create new collection `%s' for tests: %s\n"
		  "Server must allow `MKCOL %s' for tests to proceed", 
		  space, ne_get_error(i_session), space);
	return FAILHARD;
    }
    
    free(i_path);
    i_path = space;    

    return OK;
}

int begin(void)
{
    const ne_uri *u = &i_origin;

    i_session = ne_session_create(u->scheme, u->host, u->port);
    i_session2 = ne_session_create(u->scheme, u->host, u->port);

    CALL(init_session(i_session));
    CALL(init_session(i_session2));

    /* Send header with every request associating the request with the
     * test number and session. */
    ne_hook_pre_send(i_session, i_pre_send, "X-Litmus");
    ne_hook_pre_send(i_session2, i_pre_send, "X-Litmus-Second");
    
    CALL(make_space());
    
    return OK;
}

int finish(void)
{
    ne_session_destroy(i_session);
    return OK;
}

int put_buffer(ne_session *sess, const char *path, const char *content)
{
#if NE_VERSION_MAJOR > 0 || NE_VERSION_MINOR > 32
    return ne_putbuf(sess, path, content, strlen(content));
#else
    ne_request *req;
    int ret;

    req = ne_request_create(sess, "PUT", path);
    ne_lock_using_resource(req, path, 0);
    ne_lock_using_parent(req, path);
    ne_set_request_body_buffer(req, content, strlen(content));
    ret = ne_request_dispatch(req);

    if (ret == NE_OK && ne_get_status(req)->klass != 2)
	ret = NE_ERROR;

    ne_request_destroy(req);

    return ret;
#endif
}

int dummy_put(ne_session *sess, const char *path)
{
    return put_buffer(sess, path, "zero");
}

static const char foo_content[] =
    "This\nis\na\ntest\nfile\ncalled\nfoo\n";

int upload_foo(const char *path)
{
    char *uri = ne_concat(i_path, path, NULL);
    int ret;

    ret = put_buffer(i_session, uri, foo_content);

    ne_free(uri);
    return ret;
}

int options(void)
{
    ne_server_capabilities caps = {0};
    
    ONV(ne_options(i_session, i_path, &caps),
	("OPTIONS on base collection `%s': %s", i_path, 
	 ne_get_error(i_session)));

    ONN("server does not claim WebDAV compliance", caps.dav_class1 == 0);
    if (caps.dav_class2 == 0) {
	t_warning("server does not claim Class 2 compliance");
    }
    i_class2 = caps.dav_class2;

    return OK;
}

char *get_etag(const char *path)
{
    ne_request *req = ne_request_create(i_session, "HEAD", path);
    char *etag = NULL;

    if (ne_request_dispatch(req) == NE_OK && ne_get_status(req)->code == 200) {
        const char *value = ne_get_response_header(req, "Etag");
        if (value) etag = ne_strdup(value);
    }

    ne_request_destroy(req);
    return etag;
}
