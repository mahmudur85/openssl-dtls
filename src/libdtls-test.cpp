/**
 * https://github.com/openssl/openssl/issues/6934
 * https://gist.github.com/Jxck/b211a12423622fe304d2370b1f1d30d5
 * https://www.roxlu.com/2014/042/using-openssl-with-memory-bios
 * https://gist.github.com/darrenjs/4645f115d10aa4b5cebf57483ec82eca
 * https://gist.github.com/roxlu/9835067
 * https://stackoverflow.com/questions/22753221/directly-read-write-handshake-data-with-memory-bio
 * https://stackoverflow.com/questions/51672133/what-are-openssl-bios-how-do-they-work-how-are-bios-used-in-openssl
 */


#include <string>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <csignal>
#include <cstring>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <thread>
#include <cstdio>
#include <unordered_map>
#include <deque>

#include <sys/time.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

using namespace std;

#define dprint(a, b...) fprintf(stdout, "[DTLS] %s[%d]: " a "", __func__, __LINE__, ##b)
#define derror(a, b...) fprintf(stderr, "\n[DTLS ERROR] %s[%d]: " a "\n", __func__, __LINE__, ##b)

#define EPOLL_TIMEOUT 1000 // miliseconds
#define MAX_TUNNEL_EVENTS 10
#define BUFSIZE 2048
#define COOKIE_SECRET_LENGTH 16

static pthread_mutex_t* mutex_buf = NULL;

typedef struct conn_sockaddr_t {
    socklen_t length;
    struct sockaddr_storage address;
} conn_sockaddr;

struct custom_buffer {
    int cap;
    int len;
    unsigned char *buf;

    custom_buffer() {
        cap = 0;
        len = 0;
    }

    ~custom_buffer()
    {
        if (buf != nullptr){
            free(buf);
        }
        cap = 0;
        len = 0;
    }

    static custom_buffer* new_custom_buffer(unsigned int bufSize)
    {
        auto *p = new custom_buffer();
        p->buf = (unsigned char *)calloc(bufSize, sizeof(unsigned char));
        if(p->buf == nullptr){
            delete p;
            return nullptr;
        }

        p->cap = bufSize;
        p->len = 0;

        return(p);
    }
};

typedef struct connection_info_t {
    struct sockaddr_storage client_addr;
    struct addrinfo server;
    std::deque<void*> queue;
    SSL *ssl;
} client_info;

typedef struct server_info_t {
    unordered_map<in_addr_t, client_info *> conn_map;
} server_info;

struct pass_info {
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } client_addr;
    struct addrinfo server;
    SSL *ssl;
};

int verify_depth = 0;
int verify_quiet = 0;
int verify_error = X509_V_OK;
int verify_return_error = 0;
BIO *dtls_bio_err = NULL;

int cookie_initialized;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
BIO *dtls_bio_log = NULL;

static void locking_function(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&mutex_buf[n]);
    else
        pthread_mutex_unlock(&mutex_buf[n]);
}

static unsigned long id_function(void) {
    return (unsigned long) pthread_self();
}

int THREAD_setup() {
    int i;

    mutex_buf = (pthread_mutex_t*) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    if (!mutex_buf)
        return 0;
    for (i = 0; i < CRYPTO_num_locks(); i++)
            pthread_mutex_init(&mutex_buf[i], NULL);
    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    return 1;
}

int THREAD_cleanup() {
    int i;

    if (!mutex_buf)
        return 0;

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
            pthread_mutex_destroy(&mutex_buf[i]);
    free(mutex_buf);
    mutex_buf = NULL;
    return 1;
}

static void dtls_report_err(char *fmt, ...) {
    va_list args;

    va_start (args, fmt);

    vfprintf(stdout, fmt, args);
    ERR_print_errors(dtls_bio_log);
    va_end(args);
}

static int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
    /* This function should ask the user
     * if he trusts the received certificate.
     * Here we always trust.
     */
    dprint("Client certificate verified");
    return 1;
}

static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    /* Initialize a random secret */
    if (!cookie_initialized) {
        if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
            printf("error setting random cookie secret\n");
            return 0;
        }
        cookie_initialized = 1;
    }

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.ss.ss_family) {
        case AF_INET:
            length += sizeof(struct in_addr);
            break;
        case AF_INET6:
            length += sizeof(struct in6_addr);
            break;
        default:
            OPENSSL_assert(0);
            break;
    }
    length += sizeof(in_port_t);
    buffer = (unsigned char *) OPENSSL_malloc(length);

    if (buffer == NULL) {
        printf("out of memory\n");
        return 0;
    }

    switch (peer.ss.ss_family) {
        case AF_INET:
            memcpy(buffer,
                   &peer.s4.sin_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(peer.s4.sin_port),
                   &peer.s4.sin_addr,
                   sizeof(struct in_addr));
            break;
        case AF_INET6:
            memcpy(buffer,
                   &peer.s6.sin6_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s6.sin6_addr,
                   sizeof(struct in6_addr));
            break;
        default:
            OPENSSL_assert(0);
            break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void *) cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char *) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    /* If secret isn't initialized yet, the cookie can't be valid */
    if (!cookie_initialized)
        return 0;

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.ss.ss_family) {
        case AF_INET:
            length += sizeof(struct in_addr);
            break;
        case AF_INET6:
            length += sizeof(struct in6_addr);
            break;
        default:
            OPENSSL_assert(0);
            break;
    }
    length += sizeof(in_port_t);
    buffer = (unsigned char *) OPENSSL_malloc(length);

    if (buffer == NULL) {
        printf("out of memory\n");
        return 0;
    }

    switch (peer.ss.ss_family) {
        case AF_INET:
            memcpy(buffer,
                   &peer.s4.sin_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s4.sin_addr,
                   sizeof(struct in_addr));
            break;
        case AF_INET6:
            memcpy(buffer,
                   &peer.s6.sin6_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s6.sin6_addr,
                   sizeof(struct in6_addr));
            break;
        default:
            OPENSSL_assert(0);
            break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void *) cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char *) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
        return 1;

    return 0;
}


static void info_callback(const SSL *ssl, int where, int ret) {
    const char *str;
    int w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
        str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        str = "SSL_accept";
    else
        str = "undefined";

    if (where & SSL_CB_LOOP) {
        dtls_report_err((char *) "\t.. %s:%s\n", str, SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
        dtls_report_err((char *) "\t.. SSL3 alert %s:%s:%s\n", where & SSL_CB_READ ? "read" : "write", \
            SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            dtls_report_err((char *) "\t.. %s:failed in %s\n", str, SSL_state_string_long(ssl));
        } else if (ret < 0) {
            dtls_report_err((char *) "\t.. %s:error in %s\n", str, SSL_state_string_long(ssl));
        }
    }
}

void signal_handler(int sig) {
    if (sig == SIGINT)
        fprintf(stderr, "Interrupt from keyboard\n");
    else
        fprintf(stderr, "unknown signal[%d]\n", sig);
    fflush(stderr);
}


bool make_socket_non_blocking(int fd) {
    int flags, s;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return false;
    }

    flags |= O_NONBLOCK;
    s = fcntl(fd, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl");
        return false;
    }

    return true;
}


int get_server_socket_and_bind(std::string &bind_addr, std::string &port, struct addrinfo *server) {
    int sock = -1;
    struct addrinfo host;
    struct addrinfo *result;
    struct addrinfo *rp;

    int s;

    memset(&host, 0, sizeof(struct addrinfo));
    host.ai_family   = AF_INET;
    host.ai_socktype = SOCK_DGRAM/* | SOCK_NONBLOCK | SOCK_CLOEXEC*/; // UDP
    host.ai_flags    = AI_PASSIVE;

    s = getaddrinfo(bind_addr.c_str(), port.c_str(), &host, &result);
    if (s != 0) {
        perror("Could not getaddrinfo.\n");
        return false;
    }

    for (rp = result; rp != nullptr; rp = rp->ai_next) {
        int optval = 1;
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) {
            perror("socket() tunnel create_and_bind()");
            continue;
        }

        /* avoid EADDRINUSE error on bind() */
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &optval, sizeof(optval)) < 0) {
            perror("setsockopt()");
            continue;
        }

        s = bind(sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            // We managed to bind successfully!
            memcpy(server, rp, sizeof(struct addrinfo));
            break;
        }

        close(sock);
    }

    if (rp == nullptr) {
        perror("Could not bind tunnel");
        return false;
    }

    freeaddrinfo(result);

    if(!make_socket_non_blocking(sock)){
        perror("Could make socket non blocking");
        return false;
    }

    return sock;
}

/*void* connection_handle(void *info) {
    // ssize_t len, rlen;
    int optval = 1;
    char buf[BUFSIZE];
    // char rcvbuf[BUFSIZE];
    struct timeval timeout;

    struct pass_info *pinfo = (struct pass_info*) info;
    SSL *ssl = pinfo->ssl;
    int fd;
    int ret;
    // int count = 0, rcvcount = 0;
    // int num_timeouts = 0, max_timeouts = 5;

    pthread_detach(pthread_self());

    OPENSSL_assert(pinfo->client_addr.ss.ss_family == pinfo->server.ai_family);
    fd = socket(pinfo->client_addr.ss.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("client socket");
        goto cleanup;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &optval, sizeof(optval)) < 0) {
        perror("client setsockopt()");
        close(fd);
        goto cleanup;
    }

    if (bind(fd, pinfo->server.ai_addr, pinfo->server.ai_addrlen) < 0) {
        perror("client bind())");
        close(fd);
        goto cleanup;
    }

    if (connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(pinfo->client_addr)) < 0) {
        perror("client connect()");
        close(fd);
        goto cleanup;
    }

    if (!make_socket_non_blocking(fd)) {
        close(fd);
        goto cleanup;
    }

    // Set new fd and set 6 to connected
    BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr.ss);

    //Finish handshake
    do { ret = SSL_accept(ssl); }
    while (ret == 0);
    if (ret < 0) {
        perror("SSL_accept");
        printf("SSL_accept: %s\n", ERR_error_string(ERR_get_error(), buf));
        goto cleanup;
    }

    //Set and activate timeouts
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    SSL_shutdown(ssl);

cleanup:
    close(fd);
    free(info);
    SSL_free(ssl);
    dprint("Thread %lx: done, connection closed.\n", (long) pthread_self());
    pthread_exit( (void *) NULL );
}*/

SSL *new_ssl(SSL_CTX *ctx) {
    SSL *ssl;
    BIO *in_bio;
    BIO *out_bio;
    struct timeval timeout;

    /* Create BIOs */
    in_bio = BIO_new(BIO_s_mem());
    out_bio = BIO_new(BIO_s_mem());

    BIO_set_mem_eof_return(in_bio, -1); /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */
    BIO_set_mem_eof_return(out_bio, -1); /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */

    /* Set and activate timeouts */
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(in_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
    BIO_ctrl(out_bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);

    ssl = SSL_new(ctx);

    SSL_set_bio(ssl, in_bio, out_bio);
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

    SSL_set_accept_state(ssl);

    return ssl;
}

int dtls_send(SSL *ssl, conn_sockaddr *client_addr, int fd, char* data, int data_len){

    int writelen = SSL_write(ssl, data, data_len);
    if(writelen > 0) {
        char enc_buf[BUFSIZE];
        auto size = (size_t) BIO_read(SSL_get_wbio(ssl), enc_buf, sizeof(enc_buf));
        sendto(fd, enc_buf, size, 0, (struct sockaddr *) &client_addr->address,
                               (socklen_t) client_addr->length);
        return writelen;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    struct addrinfo server;
    int server_fd, epoll_fd, pid;
    struct epoll_event event = {};
    bool running = true;

    pthread_t tid;

    int ev_num;
    struct epoll_event events[10];
     time_t time_now=0;

    std::string bind_addr("192.168.2.2");
    std::string bind_port("9000");

    conn_sockaddr client_addr;
    struct pass_info *info;
    SSL *ssl;
    SSL_CTX *ctx;

    //struct custom_buffer *cbuf;

    THREAD_setup();
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    if (SSL_library_init() < 0) {
        derror("ERROR: Could not initialize the OpenSSL library!");
        return -1;
    }

    const SSL_METHOD *mtd = DTLS_server_method();
    ctx = SSL_CTX_new(mtd);
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);

    pid = getpid();
    if (!SSL_CTX_set_session_id_context(ctx, (const unsigned char *) &pid, sizeof pid)) {
        perror("SSL_CTX_set_session_id_context");
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_use_certificate_file(ctx, "../certs/server-cert.pem", SSL_FILETYPE_PEM)) {
        printf("\n[%d] ERROR: no certificate found!", __LINE__);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "../certs/server-key.pem", SSL_FILETYPE_PEM)) {
        printf("\n[%d] ERROR: no private key found!", __LINE__);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        printf("\n[%d] ERROR: invalid private key!", __LINE__);
        exit(EXIT_FAILURE);
    }

    /* Client has to authenticate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
    SSL_CTX_set_info_callback(ctx, info_callback);

    server_fd = get_server_socket_and_bind(bind_addr, bind_port, &server);

    if(server_fd < 0){
        exit(1);
    }

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd == -1) {
        exit(1);
    }

    event.data.fd = server_fd;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) < 0) {
        exit(1);
    }

    ssl = new_ssl(ctx);
    //cbuf = custom_buffer::new_custom_buffer(BUFSIZE);

    while (running){
        dprint("waiting for en event....\n");
        // Wait for something to happen on one of the file descriptors
        // we are waiting on
        do {
            ev_num = epoll_wait(epoll_fd, events, MAX_TUNNEL_EVENTS, EPOLL_TIMEOUT);
        } while (ev_num == -1 && errno == EINTR);
        if (ev_num < 0) {
            if (errno == EINTR) {
                perror("epoll_wait interrupted");
                running = false;
                break;
            } else {
                perror("epoll_wait failed");
                running = false;
                break;
            }
        }

        // time_now = time(NULL);

        for(int i=0; i < ev_num; i++){

            if ((events[i].events & EPOLLERR) ||
                (events[i].events & EPOLLHUP) ||
                (!(events[i].events & EPOLLIN))){
                /* An error has occured on this fd, or the socket is not
                   ready for reading (why were we notified then?) */
                perror("epoll error");
                close(events[i].data.fd);
                continue;
            }
            if(events[i].data.fd < 0){
                derror("invalid epoll event. fd:%d\n", events[i].data.fd);
                continue;
            }

            if((events[i].events & EPOLLIN)){
                char o_buffer[BUFSIZE];
                char i_buffer[BUFSIZE];
                int written = 0, read = 0, pending = 0;

                memset(&client_addr, 0, sizeof(conn_sockaddr));

                read = static_cast<int>(recvfrom(events[i].data.fd, i_buffer, sizeof(i_buffer), MSG_DONTWAIT,
                                                      (sockaddr *) &client_addr.address, &client_addr.length));

                if(read > 0) {
                    written = BIO_write(SSL_get_rbio(ssl), i_buffer, sizeof(i_buffer));
                }

                if (written > 0) {
                    if (!SSL_is_init_finished(ssl)) {
                        SSL_do_handshake(ssl);
                    } else {
                        int r = SSL_read(ssl,o_buffer, sizeof(o_buffer));
                        o_buffer[r] = '\0';
                        printf("%d bytes received: %s\n", r, o_buffer);
                        sprintf(o_buffer, "%d received '%s'", r, o_buffer);
                        dtls_send(ssl, &client_addr, events[i].data.fd, o_buffer, r);
                    }
                }

                pending = static_cast<int>(BIO_ctrl_pending(SSL_get_wbio(ssl)));

                if (pending) {
                    read = BIO_read(SSL_get_wbio(ssl), o_buffer, sizeof(o_buffer));
                    sendto(events[i].data.fd, o_buffer, read, 0, (struct sockaddr *) &client_addr.address,
                           (socklen_t) client_addr.length);
                }

                /*while (DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr) <= 0);

                info = (struct pass_info*) malloc (sizeof(struct pass_info));

                memcpy(&info->server, &server, sizeof(struct addrinfo));
                memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_storage));
                info->ssl = ssl;

                if (pthread_create( &tid, NULL, connection_handle, info) != 0) {
                    perror("pthread_create");
                    exit(-1);
                }*/
            }
        }
    }

    THREAD_cleanup();

    return 0;
}
