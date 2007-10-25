/* $Id$
 *
 * Copyright (c) 2007, Lorenz Schori <lo@znerol.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND THE CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include <netinet/tcp.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#define SYSLOG_NAMES
#include <syslog.h>

/* xassl includes */
#include <xyssl/havege.h>
#include <xyssl/certs.h>
#include <xyssl/x509.h>
#include <xyssl/ssl.h>
#include <xyssl/net.h>

// FIXME. implement some sort of DDOS prevention
#define MAXCONNCOUNT 16

// FIXME. configurable?
#define RUNNING_DIR "/"

#define DEFAULT_CERT_SUBJECT "CN='localhost'"
#define DEFAULT_CERT_TIMESPAN 31536000

void dolog(int prio, const char *fmt, ...);

#ifdef NDEBUG
#define CLOG(_level, _format, _args...) dolog(_level,_format, ## _args);
#else
#define CLOG(_level, _format, _args...) dolog(_level,"%s:%d " _format, __FILE__, __LINE__, ## _args);
#endif

#define ELOG(_format, _args...) CLOG(LOG_ERR, _format, ## _args)
#define WLOG(_format, _args...) CLOG(LOG_WARNING, _format, ## _args)
#define NLOG(_format, _args...) CLOG(LOG_NOTICE, _format, ## _args)
#define ILOG(_format, _args...) CLOG(LOG_INFO, _format, ## _args)
#define DLOG(_format, _args...) CLOG(LOG_DEBUG, _format, ## _args)

/*
 * sorted by order of preference
 */
int xrly_ciphers[] =
{
#if !defined(NO_AES)
    SSL_RSA_AES_256_SHA,
#endif
#if !defined(NO_DES)
    SSL_RSA_DES_168_SHA,
#endif
#if !defined(NO_ARC4)
    SSL_RSA_RC4_128_SHA,
    SSL_RSA_RC4_128_MD5,
#endif
    0
};

/* key generation */
#define EXPONENT 65537

int             servermode = 1;
char            *dst_host = "localhost";
int             dst_port    = 0;
int             nosysl=0;
int             nofork=0;
int             quit=0;
char*           pidfile=NULL;
int loglevel = LOG_NOTICE;

void sigchld_handler(int s)
{
        while(waitpid(-1, NULL, WNOHANG) > 0);
}

void kill_handler(int s)
{
    char* signame="unknown";
    switch(s) {
        case SIGQUIT    : signame="QUIT"; break;
        case SIGHUP     : signame="HUP"; break;
        case SIGTERM    : signame="TERM"; break;
    }
    NLOG("Caugth %s signal. Terminate",signame);
    quit=1;
}

void usage(int status)
{
    fprintf(stderr, "usage: [-c] [-v] [-d localip:port] [-r remoteip:port]\n\n"
                    "    -A      Certificate Authority file \n"
                    "    -p      private key and certificate chain PEM file name\n"
                    "    -c      client mode. remote is ssl, local plain\n"
                    "    -v      validate certificate\n"
                    "    -d      listen locally on this [host:]port\n"
                    "    -r      connect to remote machine on [host:]port\n"
                    "    -P      pidfile\n"
                    "    -f      foreground mode\n"
                    "    -D      syslog level (0...7)\n"
                    "\n"
                    "  Options for private key and x509 certificate generation\n"
                    "    -K      generate private key and certificate. arg=keylen\n"
                    "    -U      subjectline for certificate. specify at least CN\n"
                    "    -Y      number of days before this cert becomes invalid\n"
                    "\n");
    exit(status);
}

void
getprio(int pri, char *res, int reslen)
{
    CODE *c_pri;
    
    c_pri = prioritynames;
    while (c_pri->c_name && !(c_pri->c_val == LOG_PRI(pri)))
        c_pri++;
    if(c_pri->c_name == NULL)
        snprintf(res, reslen, "<%d>", pri);
    else
        snprintf(res, reslen, "%s", c_pri->c_name);
}

void dolog(int prio, const char *fmt, ...)
{
    va_list ap;
    char    logprio[20];

    if(nosysl && prio <= loglevel) {
        time_t  ct=time(NULL);
        char*   cs=ctime(&ct);
        
        getprio(prio,logprio,sizeof(logprio));
        fprintf(stderr,"[%-6s] ",logprio);
        fprintf(stderr,"%.15s xrelayd[%.4d] ",&cs[4],getpid());
        va_start(ap, fmt);
        (void) vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr,"\n");
    }
    else {
        va_start(ap, fmt);
        vsyslog(prio, fmt, ap);
        va_end(ap);
    }
}

void daemonize()
{
    int i,lfp;
    char str[10];
    
    if(getppid()==1) return; /* already a daemon */
    
    i=fork();
    if (i<0) exit(1); /* fork error */
    if (i>0) exit(0); /* parent exits */
    
    /* child (daemon) continues */
    setsid(); /* obtain a new process group */
    close(0);
    close(1);
    close(2);
    i=open("/dev/null",O_RDWR); dup(i); dup(i); /* handle standart I/O */
    umask(027); /* set newly created file permissions */
    chdir(RUNNING_DIR); /* change running directory */

    if(pidfile) {
        lfp=open(pidfile,O_RDWR|O_CREAT,0640);

        if (lfp<0) exit(1); /* can not open */

        if (lockf(lfp,F_TLOCK,0)<0) exit(0); /* can not lock */

        /* first instance continues */
        sprintf(str,"%d\n",getpid());

        write(lfp,str,strlen(str)); /* record pid to lockfile */
    }

    signal(SIGCHLD,sigchld_handler); /* ignore child */
    signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGQUIT,kill_handler); /* catch hangup signal */
    signal(SIGHUP,kill_handler); /* catch hangup signal */
    signal(SIGTERM,kill_handler); /* catch kill signal */
}

int handle_sockres(char* op, char* conn,int res)
{
    if(res>0) return 0;
    
    switch( res ) {
        case XYSSL_ERR_NET_TRY_AGAIN:
            DLOG( "%s operation on %s connection would block",op,conn);
        case 0:
            return 0;
            
        case XYSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
            ILOG( "%s connection closed by peer during %s operation",conn,op);
            break;

        case XYSSL_ERR_NET_CONN_RESET:
            ILOG( "%s connection was reset by peer during %s operation",conn,op);
            break;
            
        default:
            ELOG( "%s operation on %s connection returned %08x",op,conn,res );
            break;
    }
    return res;
}

/*
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 */
ssl_session *s_list_1st = NULL;
ssl_session *cur, *prv;

static int my_get_session( ssl_context *ssl )
{
    time_t t = time( NULL );

    if( ssl->resume == 0 )
        return( 1 );

    cur = s_list_1st;
    prv = NULL;

    while( cur != NULL )
    {
        prv = cur;
        cur = cur->next;

        if( ssl->timeout != 0 && t - prv->start > ssl->timeout )
            continue;

        if( ssl->session->cipher != prv->cipher ||
            ssl->session->length != prv->length )
            continue;

        if( memcmp( ssl->session->id, prv->id, prv->length ) != 0 )
            continue;

        memcpy( ssl->session->master, prv->master, 48 );
        return( 0 );
    }

    return( 1 );
}

static int my_set_session( ssl_context *ssl )
{
    time_t t = time( NULL );

    cur = s_list_1st;
    prv = NULL;

    while( cur != NULL )
    {
        if( ssl->timeout != 0 && t - cur->start > ssl->timeout )
            break; /* expired, reuse this slot */

        if( memcmp( ssl->session->id, cur->id, cur->length ) == 0 )
            break; /* client reconnected */

        prv = cur;
        cur = cur->next;
    }

    if( cur == NULL )
    {
        cur = (ssl_session *) malloc( sizeof( ssl_session ) );
        if( cur == NULL )
            return( 1 );

        if( prv == NULL )
              s_list_1st = cur;
        else  prv->next  = cur;
    }

    memcpy( cur, ssl->session, sizeof( ssl_session ) );

    return( 0 );
}

inline int proxy_send_all( int (*f_send)(void *, unsigned char *, int),
                           void *ctx, unsigned char *buf, int len, int *eof)
{
    int     ret=0;
    while(len) {
        if ((ret = f_send(ctx,buf,len)) <= 0) {
            if( ret == XYSSL_ERR_NET_TRY_AGAIN ) continue;
            break;
        }
        len-=ret;
        buf+=ret;
    }
    *eof |= (ret == XYSSL_ERR_NET_CONN_RESET);
    return ret;
}

inline int proxy_recv_available( int (*f_recv)(void *, unsigned char *, int),
                                 void *ctx, unsigned char *buf, int len, int *eof)
{
    int     ret=0;
    ret = f_recv(ctx,buf,len);
    *eof |= (ret == XYSSL_ERR_NET_CONN_RESET);
    return ret;
}

void proxy_connection(
    int client_fd, unsigned char client_ip[4], char* srv_host, int srv_port,
    x509_cert *cert, rsa_context *key, int sslserver
) {
    int     ret;
    
    /*
     *  Connect to other party
     */
    int     server_fd;
    ILOG("Attempting to connect to %s:%d", srv_host, srv_port);
    if( ( ret = net_connect( &server_fd, srv_host, srv_port ) ) != 0 ) {
        ELOG("Failed to connect to %s:%d: %08x, %s", srv_host, srv_port, ret, strerror(errno));
        return;
    }
    ILOG("Connected to %s:%d", srv_host, srv_port);
    
    /*
     *  Setup ssl
     */
    ssl_context     ssl;
    if( ( ret = ssl_init( &ssl ) ) != 0 ) {
        ELOG("Failed to initialize ssl: %08x", ret);
        return;
    }
    
    /* setup endpoint */
    ssl_set_endpoint( &ssl, sslserver );
    
    /* FIXME: verify hook for client connections. */
    ssl_set_authmode( &ssl, SSL_VERIFY_NONE );

    /* random number generation */
    havege_state hs;
    havege_init( &hs );
    ssl_set_rng( &ssl, havege_rand, &hs );
    
    /* io */
    int     *ssl_fd = sslserver ? &client_fd : &server_fd;
    int     *plain_fd = sslserver ? &server_fd : &client_fd;
    ssl_set_bio( &ssl, net_recv, ssl_fd,
                       net_send, ssl_fd );
    
    /* ciphers */
    ssl_set_ciphers( &ssl, xrly_ciphers );
    
    if(cert && key) {
        ssl_set_ca_chain( &ssl, cert->next, NULL );
        ssl_set_own_cert( &ssl, cert, key );
    }
    
    /* session caching */
    ssl_session ssn;
    ssl_set_scb( &ssl, my_get_session, my_set_session );
    ssl_set_session( &ssl, 1, 0, &ssn );
    
    ILOG("Initialized SSL for %s mode",sslserver ? "server" : "client");
    
    /*
     *  disable nagle algorithm
     */ 
    int flag;
    flag = 1;
    ret = setsockopt(server_fd,IPPROTO_TCP,TCP_NODELAY,(char *) &flag,sizeof(int));
    flag = 1;
    ret = setsockopt(client_fd,IPPROTO_TCP,TCP_NODELAY,(char *) &flag,sizeof(int));
    
    /*
     *  Handshake & Co
     */
    if(sslserver) {
        ILOG("Performing ssl handshake");
        while( ( ret = ssl_handshake( &ssl ) ) != 0 ) {
            if( ret != XYSSL_ERR_NET_TRY_AGAIN ) {
                ELOG("SSL handshake failed: %08x", ret);
                return;
            }
        }
        ILOG("Handshake succeded");
    }
    
    NLOG("Connected %s client %d.%d.%d.%d to %s server %s:%d",
        sslserver ? "ssl" : "plain", client_ip[0],client_ip[1],client_ip[2],client_ip[3],
        sslserver ? "plain" : "ssl", srv_host, srv_port);
    
    /*
     *  Proxy stuff
     *  Its perfectly okay to only select on readsets because we don't want to
     *  buffer the data and thus block the process as long as we are not able
     *  to forward...
     */
    
    fd_set rs;
    int fdmax = 1 + (server_fd > client_fd ? server_fd : client_fd);
    
    unsigned char buf[2048];
    
    net_set_nonblock(*plain_fd);
    net_set_nonblock(*ssl_fd);
    
    int done=0,rret,wret;
    
    while(!done) {
        FD_ZERO(&rs);
        FD_SET(server_fd, &rs);
        FD_SET(client_fd, &rs);
        
        DLOG("enter select. fdmax %d",fdmax);
        
        if((ret = select(fdmax,&rs,NULL,NULL,NULL))<0) {
            return;
        }
        if(ret == 0) {
            // timeout
            break;
        }
        
        DLOG("select returned %d",ret);
        
        /*
         *  read from ssl and write to plain socket
         */
        if(FD_ISSET(*ssl_fd,&rs)) {
            DLOG("ssl fd is set");
            do {
                DLOG("trying to read from ssl fd %d",*ssl_fd);
                if((rret = proxy_recv_available(ssl_read, &ssl, buf, sizeof(buf), &done)) < 0) break;
                DLOG("read: %d bytes",rret);
                
                DLOG("trying to write on plain fd %d",*plain_fd);
                if((wret = proxy_send_all(net_send, (void*)plain_fd, buf, rret, &done)) < 0) break;
                DLOG("write: plain complete");
            } while(0);
            
            if(handle_sockres("read","ssl",rret)) break;
            if(handle_sockres("write","plain",wret)) break;
        }
        
        /*
         *  read from plain and write to ssl socket
         */
        if(FD_ISSET(*plain_fd,&rs)) {
            DLOG("plain fd is set");
            do {
                DLOG("trying to read from plain fd %d",*plain_fd);
                if((rret = proxy_recv_available(net_recv, plain_fd, buf, sizeof(buf), &done)) < 0) break;
                DLOG("read: %d bytes",rret);
                
                DLOG("trying to write on ssl fd %d",*ssl_fd);
                if((wret = proxy_send_all(ssl_write, (void*)&ssl, buf, rret, &done)) < 0) break;
                DLOG("write: ssl complete");
            } while(0);
            
            if(handle_sockres("read","plain",rret)) break;
            if(handle_sockres("write","ssl",wret)) break;
            ssl_flush_output(&ssl);
        }
    }
    
    /*
     *  Cleanup
     */
    ssl_free( &ssl );
    memset( &ssl, 0, sizeof( ssl ) );
    
    net_close(client_fd);
    ILOG("Closed %s connection from %d.%d.%d.%d",client_fd==*ssl_fd ? "ssl" : "plain",
        client_ip[0],client_ip[1],client_ip[2],client_ip[3]);
    net_close(server_fd);
    ILOG("Closed %s connection to %s:%d",server_fd==*ssl_fd ? "ssl" : "plain",srv_host,srv_port);
    
    NLOG("Closed connection between %s client %d.%d.%d.%d and %s server %s:%d",
        sslserver ? "ssl" : "plain", client_ip[0],client_ip[1],client_ip[2],client_ip[3],
        sslserver ? "plain" : "ssl", srv_host, srv_port);
}

int main(int argc, char** argv)
{
    // options
    char            *srv_host = NULL;
    int             srv_port = 0;
    char            *keyfile = NULL; //"privkeySrv.pem";
    char            *certfile = NULL; //"certSrv.pem";
    // int             vlevel = 0;
    char            *cpos;
    int             c,intarg,tmpport,genstuff=0,exitaftergen=0,keysize=1024;
    char            *cert_subject=DEFAULT_CERT_SUBJECT;
    time_t          cert_notbefore=time(NULL);
    time_t          cert_notafter=0;
    int             cert_timespan=DEFAULT_CERT_TIMESPAN;

    // return code
    int             status=1;
    
    for (;;) {
        c = getopt (argc, argv, "VD:P:fo:cd:r:p:A:K::U:Y:v:h");
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'c':
                // client mode
                servermode=0;
                break;
            
            case 'd':
                // daemon mode [host:]port
                cpos = NULL;
                tmpport = 0;
                if((cpos = strchr(optarg,':'))) {               
                    *cpos = '\0';
                    if(optarg && optarg[0])
                        srv_host = optarg;
                    optarg = ++cpos;
                }
                if(optarg && optarg[0]) {
                    tmpport = (int)strtol(optarg, (char **)NULL, 0);
                    if(tmpport) srv_port = tmpport;
                }
                break;
            
            case 'r':
                // remote [host:]port
                cpos = NULL;
                tmpport = 0;
                if((cpos = strchr(optarg,':'))) {               
                    *cpos = '\0';
                    if(optarg && optarg[0])
                        dst_host = optarg;
                    optarg = ++cpos;
                }
                if(optarg && optarg[0]) {
                    tmpport = (int)strtol(optarg, (char **)NULL, 0);
                    if(tmpport) dst_port = tmpport;
                }
                break;
                
            case 'p':
                // pemfile (requred in servermode)
                keyfile = optarg;
                break;
            
            case 'A':
                // CA file
                certfile = optarg;
                break;
            
            case 'v':
                // veryfication level
                if(optarg && optarg[0]) {
/*
                    vlevel = (int)strtol(optarg, (char **)NULL, 0);
                    if(vlevel == 1 ) {
                        cervalidator = certChecker;
                    }
                    else if(vlevel > 3 || vlevel < 0) {
                        fprintf(stderr,"-v takes whole numbers between 0 and 3");
                        exit(2);
                    }
*/
                }
                break;
            
            case 'P':
                // create a pidfile
                pidfile=optarg;
                break;
                
            case 'f':
                // run in foreground.
                nofork=1;
                nosysl=1;
                break;
                
            case 'o':
                // append logmessages to a file instead of stdout/syslog
                break;
                
            case 'O':
                // socket options. TODO
                break;
            
            case 'D':
                // debug level 0...7
                intarg=strtol(optarg,NULL,0);
                if(intarg<0 || intarg>7) {
                    usage(1);
                }
                loglevel=intarg;
                break;
                
            case 'V':
                // version
                break;

            case 'K':
                // generate keys + certificate
                genstuff=1;
                if(optarg) {
                    keysize=strtol(optarg,NULL,0);
                    if(keysize>2048 || keysize<128) {
                        usage(1);
                    }
                }
                break;
            
            case 'U':
                cert_subject=optarg;
                break;

            case 'Y':
                cert_timespan = 86400 * strtol(optarg,NULL,0);
                if(cert_timespan<=0) {
                    usage(1);
                }
                break;
            
            case '?':
            case 'h':
                usage(0);
                break;
            
            default:
                usage(1);
                break;
        }
    }
    
    if(!srv_port || !dst_port) {
        if(genstuff) {
            exitaftergen=1;
        }
        else {
            usage(1);
        }
    }

/* install handlers */
    signal(SIGCHLD,sigchld_handler); /* ignore child */
    signal(SIGQUIT,kill_handler); /* catch hangup signal */
    signal(SIGHUP,kill_handler); /* catch hangup signal */
    signal(SIGTERM,kill_handler); /* catch kill signal */
    
    if(!nosysl) {
        openlog("xrelayd", LOG_PID, LOG_DAEMON);
        setlogmask(LOG_UPTO(loglevel));
    }
    
    x509_cert       cert;
    rsa_context     key;
    havege_state    hs;
    int             ret;
    
    // key
    if(genstuff && servermode) {
        // generate key if desired
        ILOG("Generating private key");
        havege_init( &hs );
        rsa_init( &key, RSA_PKCS_V15, 0, havege_rand, &hs );
        ret = rsa_gen_key( &key, keysize, EXPONENT);
        if(ret) {
            ELOG("Failed to generate private key: %08x",ret);
            goto fail;
        }
        if(keyfile) {
            // write out PEM-keyfile here
            x509_write_keyfile(&key, keyfile, X509_OUTPUT_PEM); 
        }
    }
    else if(keyfile) {
        ILOG("Loading the private key");
        ret = x509parse_keyfile(&key, keyfile, NULL);
        if(ret) {
            ELOG("Failed to load private key: %08x, %s",ret,strerror(errno));
            goto fail;
        }
    }
    else if(servermode){
        ELOG("A private key is required in server mode");
        usage(1);
    }
    
    // cert
    memset(&cert, 0, sizeof(x509_cert));
    x509_raw raw_cert;
    char    notbefore[24],notafter[24];

    if(genstuff && servermode) {
        // generate self signed certificate
        ILOG("Generating x509 certificate");
        x509_init_raw(&raw_cert);

        x509_add_pubkey(&raw_cert,&key);
        x509_create_subject(&raw_cert,cert_subject);
        
        struct tm *tm;
        tm=gmtime(&cert_notbefore);
        strftime(notbefore,sizeof(notbefore),"%Y-%m-%d %H:%M:%S %Z",tm);

        if(!cert_notafter) {
            cert_notafter=cert_notbefore + cert_timespan;
        }
        tm=gmtime(&cert_notafter);
        strftime(notafter,sizeof(notafter),"%Y-%m-%d %H:%M:%S %Z",tm);
        
        x509_create_validity(&raw_cert,notbefore,notafter); 
        x509_create_selfsign(&raw_cert,&key);
        
        if(certfile) {
            // write cert in PEM format
            x509_write_crtfile(&raw_cert, certfile, X509_OUTPUT_PEM);       
        }
        
        // convert raw to cert.
        x509parse_crt(&cert, raw_cert.raw.data, raw_cert.raw.len);
        
        x509_free_raw(&raw_cert);
    }
    else if(certfile) {
        ILOG("Loading the server certificate");
        ret = x509parse_crtfile(&cert, certfile);
        if(ret) {
            ELOG("Failed to load server certificate: %08x, %s",ret,strerror(errno));
            goto fail;
        }
    }
    else if(servermode){
        ELOG("A certificate is required in server mode");
        usage(1);
    }
    
    if(exitaftergen) {
        goto succeed;
    }

    // go to background
    if(!nofork) {
        daemonize();
    }
    
    // open listening socket
    int             srv_fd, client_fd;
    ret = net_bind( &srv_fd, srv_host, srv_port );
    if(ret) {
        ELOG("Failed to open server port %d: %08x, %s",srv_port,ret,strerror(errno));
        goto fail;
    }
    
    /*
     *  Main connection loop
     */
    unsigned char   client_ip[4];
    fd_set rs;
    
    NLOG("Listening for %s connections on server port %d",servermode ? "ssl" : "plain",srv_port);
    while (!quit) {
        FD_ZERO(&rs);
        FD_SET(srv_fd, &rs);
        
        if((ret = select(srv_fd+1,&rs,NULL,NULL,NULL))<0) {
            continue;
        }
        
        ret = net_accept( srv_fd, &client_fd, client_ip );
        if(ret) {
            ELOG("Failed to accept client on server port %d: %08x, %s",srv_port,ret,strerror(errno));
            goto fail;
        }
        
        ILOG("Got %s connection from %d.%d.%d.%d on server port %d",servermode ? "ssl" : "plain",
            client_ip[0],client_ip[1],client_ip[2],client_ip[3],srv_port);
        
        /*
         *  fork
         */
        
        if((ret=fork()) < 0) {
            // we got an error while forking. terminate.
            ELOG("fork() failed: %s (%d)",strerror(errno),errno);
            break;
        }
        else if(ret == 0) {
            // child
            close(srv_fd);
            proxy_connection(client_fd,client_ip,dst_host,dst_port,&cert,&key,servermode);
            exit(0);
        }
        // parent
        close(client_fd);
    }

succeed: 
    status=0;
    
fail:
    if(srv_port) {
        NLOG("Closing server port %d",srv_port);
        net_close(srv_fd);
    }

    x509_free( &cert );
    rsa_free( &key );
    
    if(!nosysl) {
        closelog();
    }
    
    NLOG("Terminated with status %d",status);
    exit(status);
}
