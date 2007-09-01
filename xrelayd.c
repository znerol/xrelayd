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
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>

#include <netinet/tcp.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#define SYSLOG_NAMES
#include <syslog.h>


#include "xyssl/havege.h"
#include "xyssl/certs.h"
#include "xyssl/x509.h"
#include "xyssl/ssl.h"
#include "xyssl/net.h"

// FIXME. implement some sort of DDOS prevention
#define MAXCONNCOUNT 16

// FIXME. configurable?
#define RUNNING_DIR "/"

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
    // TLS1_EDH_RSA_AES_256_SHA,
    // SSL3_EDH_RSA_DES_168_SHA,
    TLS1_RSA_AES_256_SHA,
    SSL3_RSA_DES_168_SHA,
    // SSL3_RSA_RC4_128_SHA,
    // SSL3_RSA_RC4_128_MD5,
    0
};

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
    ILOG("caugth signal. exiting...");
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
                    "    -D      syslog level (0...7)\n");
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
        getprio(prio,logprio,sizeof(logprio));
        fprintf(stderr,"[%-6s] ",logprio);
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
    signal(SIGHUP,kill_handler); /* catch hangup signal */
    signal(SIGTERM,kill_handler); /* catch kill signal */
}

int handle_sockerr(char* func,int res)
{
    switch( res ) {
        case ERR_NET_WOULD_BLOCK:
            DLOG( "%s connection would block.",func);
        case 0:
            return 0;
            
        case ERR_SSL_PEER_CLOSE_NOTIFY:
            ILOG( "%s connection closed by peer",func );
            break;

        case ERR_NET_CONN_RESET:
            ILOG( "%s connection was reset by peer",func );
            break;
            
        default:
            ELOG( "%s returned %08x", func, res );
            break;
    }
    return res;
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
    if( ( ret = ssl_init( &ssl, 0 ) ) != 0 ) {
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
    ssl_set_rng_func( &ssl, havege_rand, &hs );
    
    /* io */
    int     *ssl_fd = sslserver ? &client_fd : &server_fd;
    int     *plain_fd = sslserver ? &server_fd : &client_fd;
    ssl_set_io_files( &ssl, *ssl_fd, *ssl_fd );
    
    /* ciphers */
    ssl_set_ciphlist( &ssl, xrly_ciphers );
    
    if(cert && key) {
        ssl_set_ca_chain( &ssl, cert->next, NULL );
        ssl_set_rsa_cert( &ssl, cert, key );
    }
    if(sslserver){
        static unsigned char session_table[SSL_SESSION_TBL_LEN];
        ssl_set_sidtable( &ssl, session_table );
    }
    
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
        ret = ssl_server_start( &ssl );
        if(ret) {
            ELOG("Failed to start ssl server: %08x", ret);
            return;
        }
        ILOG("Handshake succeded");
    }
    
    
    /*
     *  Proxy stuff
     *  Its perfectly okay to only select on readsets because we don't want to
     *  buffer the data and thus block the process as long as we are not able
     *  to forward...
     */
    
    fd_set rs;
    int fdmax = 1 + (server_fd > client_fd ? server_fd : client_fd);
    
    unsigned char buf[1024];
    int len;
    
    net_set_nonblock(*plain_fd);
    net_set_nonblock(*ssl_fd);
    
    int done=0,rret,wret;
    
    while(!done) {
        FD_ZERO(&rs);
        FD_SET(server_fd, &rs);
        FD_SET(client_fd, &rs);
        
        DLOG("select with fdmax %d",fdmax);
        
        if((ret = select(fdmax,&rs,NULL,NULL,NULL))<0) {
            return;
        }
        if(ret == 0) {
            // timeout
            break;
        }
        
        DLOG("select returned %d. rs.fds_bits[0] %x",ret,rs.fds_bits[0]);
        
        if(FD_ISSET(*ssl_fd,&rs)) {
            DLOG("trying to ssl_read from fd %d",*ssl_fd);
            
            for(;;) {
                len=sizeof(buf);
                
                if((rret = ssl_read(&ssl, buf, &len)))
                    break;
                
                if((done=(len==0)))
                    break;
                
                DLOG("ssl_read: %d bytes",len);
                DLOG("trying to net_send on fd %d",*plain_fd);
                if((wret = net_send(*plain_fd,buf,&len))) break;
                DLOG("net_send: complete");
                DLOG("trying to ssl_read from fd %d",*ssl_fd);
            }
            
            if(handle_sockerr("ssl_read",rret)) break;
            if(handle_sockerr("net_send",wret)) break;
        }
        
        if(FD_ISSET(*plain_fd,&rs)) {
            DLOG("trying to net_recv from fd %d",*plain_fd);
            
            for(;;) {
                len=sizeof(buf);
                
                if((ret = net_recv(*plain_fd, buf, &len)))
                    break;
                
                if((done=(len==0)))
                    break;
                
                DLOG("net_recv: %d bytes",len);
                DLOG("trying to ssl_write on fd %d",*ssl_fd);
                if((wret = ssl_write(&ssl,buf,len))) break;
                DLOG("ssl_write: complete");
                DLOG("trying to net_recv from fd %d",*plain_fd);
            }
            
            if(handle_sockerr("net_recv",rret)) break;
            if(handle_sockerr("ssl_write",wret)) break;
            ssl_flush_output(&ssl);
        }
    }
    
    /*
     *  Cleanup
     */
    net_close(client_fd);
    ILOG("Closed %s connection from %d.%d.%d.%d",client_fd==*ssl_fd ? "ssl" : "plain",
        client_ip[0],client_ip[1],client_ip[2],client_ip[3]);
    net_close(server_fd);
    ILOG("Closed %s connection to %s:%d",server_fd==*ssl_fd ? "ssl" : "plain",srv_host,srv_port);
    
    ssl_free( &ssl );
    memset( &ssl, 0, sizeof( ssl ) );
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
    int             intarg,tmpport;
    char            c;
    
    // return code
    int             status=1;
    
    for (;;) {
        c = getopt (argc, argv, "VD:P:fo:cd:r:p:A:v:h");
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
                
            case '?':
            case 'h':
                usage(0);
                break;
            
            default:
                usage(1);
                break;
        }
    }
    
/* install handlers */
    signal(SIGCHLD,sigchld_handler); /* ignore child */
    signal(SIGHUP,kill_handler); /* catch hangup signal */
    signal(SIGTERM,kill_handler); /* catch kill signal */
    
    if(!nosysl) {
        openlog("xrelayd", LOG_PID, LOG_DAEMON);
        setlogmask(LOG_UPTO(loglevel));
    }
    
    x509_cert       cert;
    rsa_context     key;
    int             ret;
    
    memset( &cert, 0, sizeof( x509_cert ) );
    
    if(certfile) {
        ILOG("Loading the server certificate");
        ret = x509_read_crtfile( &cert, certfile);
        if(ret) {
            ELOG("Failed to load server certificate: %08x, %s",ret,strerror(errno));
            goto fail;
        }
    }
    else if(servermode){
        ELOG("A certificate is required in server mode");
        usage(1);
    }
    
    if(keyfile) {
        ILOG("Loading the private key");
        ret = x509_read_keyfile( &key, keyfile, NULL);
        if(ret) {
            ELOG("Failed to load private key: %08x, %s",ret,strerror(errno));
            goto fail;
        }
    }
    else if(servermode){
        ELOG("A private key is required in server mode");
        usage(1);
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
    
    NLOG("Listening for %s connections on server port %d",servermode ? "ssl" : "plain",srv_port);
    while (!quit) {
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
    
    status=0;
    
fail:
    NLOG("Closing server port %d",srv_port);
    net_close(srv_fd);
    
    x509_free_cert( &cert );
    rsa_free( &key );
    
    if(!nosysl) {
        closelog();
    }
    
    exit(status);
}
