/**
 * https://github.com/openssl/openssl/issues/6934
 * https://gist.github.com/Jxck/b211a12423622fe304d2370b1f1d30d5
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
#include <unordered_map>

#include "Timer.hpp"

using namespace std;

#define dprint(a, b...) fprintf(stdout, "[DTLS] %s[%d]: " a "", __func__, __LINE__, ##b)
#define derror(a, b...) fprintf(stderr, "\n[DTLS ERROR] %s[%d]: " a "\n", __func__, __LINE__, ##b)

#define EPOLL_TIMEOUT 1000 // miliseconds
#define IDLE_CONNECTION_TIMER_INTERVAL 5 // seconds
#define SOCKET_IDLE_TIMEOUT 5 // seconds
#define MAX_TUNNEL_EVENTS 10
#define BUFSIZE 2048
#define COOKIE_SECRET_LENGTH 16

static pthread_mutex_t *mutex_buf = NULL;

typedef struct client_info_t {
    struct addrinfo server_address;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } client_addr;
    SSL *ssl;
    int client_fd;
    int epoll_fd;
    int num_timeouts;
    int state;
    long last_activity;
    unordered_map<in_addr_t, client_info_t *> *map;
} client_info;

typedef struct server_info_t {
    struct addrinfo address;
    int server_fd;
    int epoll_fd;
    SSL_CTX *ctx;
    bool running;
    unordered_map<in_addr_t, client_info_t *> conn_map;
} server_info;

struct pass_info {
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } client_addr;
    struct addrinfo server_address;
    int epoll_fd;
    SSL *ssl;
    unordered_map<in_addr_t, client_info_t *> *map;
};

enum ContextType {
    DEVICE = 1, TUNNEL = 2, CLIENT = 3
};

typedef struct Context_t {
    ContextType type;
    int fd;
    void *ptr;
} Context;

const static int max_timeout = 5;

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

    mutex_buf = (pthread_mutex_t *) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
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

static int dtls_verify_callback(int ok, X509_STORE_CTX *ctx) {
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

int handle_socket_error() {
    switch (errno) {
        case EINTR:
            /* Interrupted system call.
             * Just ignore.
             */
            printf("Interrupted system call!\n");
            return 1;
        case EBADF:
            /* Invalid socket.
             * Must close connection.
             */
            printf("Invalid socket!\n");
            return 0;
            break;
#ifdef EHOSTDOWN
        case EHOSTDOWN:
            /* Host is down.
             * Just ignore, might be an attacker
             * sending fake ICMP messages.
             */
            printf("Host is down!\n");
            return 1;
#endif
#ifdef ECONNRESET
        case ECONNRESET:
            /* Connection reset by peer.
             * Just ignore, might be an attacker
             * sending fake ICMP messages.
             */
            printf("Connection reset by peer!\n");
            return 1;
            break;
#endif
        case ENOMEM:
            /* Out of memory.
             * Must close connection.
             */
            printf("Out of memory!\n");
            return 0;
            break;
        case EACCES:
            /* Permission denied.
             * Just ignore, we might be blocked
             * by some firewall policy. Try again
             * and hope for the best.
             */
            printf("Permission denied!\n");
            return 1;
            break;
        default:
            /* Something unexpected happened */
            printf("Unexpected error! (errno = %d)\n", errno);
            return 0;
            break;
    }
    return 0;
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
    host.ai_family = AF_INET;
    host.ai_socktype = SOCK_DGRAM;
    host.ai_flags = AI_PASSIVE;
    host.ai_protocol = 0;

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

#ifdef SOCK_NON_BLOCKING
    if (!make_socket_non_blocking(sock)) {
        perror("Could make socket non blocking");
        return false;
    }
#endif

    return sock;
}

void *connection_handle(void *info) {
    int optval = 1;
    char buf[BUFSIZE];
    struct epoll_event event = {};
    struct timeval timeout;
    time_t  time_now = 0;
    client_info *cinfo = nullptr;
    Context *context = nullptr;

    struct pass_info *pinfo = (struct pass_info *) info;
    SSL *ssl = pinfo->ssl;
    int fd;
    int ret;
    // int count = 0, rcvcount = 0;
    // int num_timeouts = 0, max_timeouts = 5;

    pthread_detach(pthread_self());

    OPENSSL_assert(pinfo->client_addr.ss.ss_family == pinfo->server_address.ai_family);
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

    if (bind(fd, pinfo->server_address.ai_addr, pinfo->server_address.ai_addrlen) < 0) {
        perror("client bind())");
        close(fd);
        goto cleanup;
    }

    if (connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(pinfo->client_addr)) < 0) {
        perror("client connect()");
        close(fd);
        goto cleanup;
    }

#ifdef SOCK_NON_BLOCKING
    if (!make_socket_non_blocking(fd)) {
        close(fd);
        goto cleanup;
    }
#endif

    /* Set new fd and set BIO to connected */
    BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr.ss);

    /* Finish handshake */
    do { ret = SSL_accept(ssl); }
    while (ret == 0);
    if (ret < 0) {
        perror("SSL_accept");
        printf("SSL_accept: %s\n", ERR_error_string(ERR_get_error(), buf));
        goto cleanup;
    }

    /* Set and activate timeouts */
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    // add client to epoll event
    cinfo = new client_info;
    memcpy(&cinfo->server_address, &pinfo->server_address, sizeof(struct addrinfo));
    memcpy(&cinfo->client_addr, &pinfo->client_addr, sizeof(struct sockaddr_storage));
    cinfo->ssl = pinfo->ssl;
    cinfo->client_fd = fd;
    cinfo->epoll_fd = pinfo->epoll_fd;
    cinfo->num_timeouts = 0;
    cinfo->state = 1;
    cinfo->map = pinfo->map;
    cinfo->last_activity = time_now;

    context = new Context;
    context->ptr = (void *) cinfo;
    context->fd = fd;
    context->type = CLIENT;
    event.data.ptr = context;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(pinfo->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        perror("epoll_ctl()");
        if(SSL_shutdown(ssl) == 0){
            SSL_shutdown(ssl);
        }
        delete context;
        delete cinfo;
        goto cleanup;
    }
    (*cinfo->map)[cinfo->client_addr.s4.sin_addr.s_addr] = cinfo;

    delete info;
    dprint("\nThread %lx: done, new connection created.\n", (long) pthread_self());
    pthread_exit((void *) NULL);

cleanup:
    close(fd);
    delete info;
    SSL_free(ssl);
    dprint("Thread %lx: done, connection closed due to error.\n", (long) pthread_self());
    pthread_exit((void *) NULL);
}

void dtls_listener(server_info *sinfo) {
    pthread_t tid;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } client_addr;
    struct pass_info *info;
    SSL *ssl;
    BIO *bio;
    struct timeval timeout;

    THREAD_setup();

    while (sinfo->running) {
        dprint("waiting for listen event....\n");
        //clear client address buffer
        memset(&client_addr, 0, sizeof(struct sockaddr_storage));

        // create bio
        bio = BIO_new_dgram(sinfo->server_fd, BIO_NOCLOSE);

        /* Set and activate timeouts */
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        ssl = SSL_new(sinfo->ctx);

        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        while (DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr) <= 0);

        info = new pass_info;

        info->epoll_fd = sinfo->epoll_fd;
        memcpy(&info->server_address, &sinfo->address, sizeof(struct addrinfo));
        memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_storage));
        info->ssl = ssl;
        info->map = &sinfo->conn_map;

        if (pthread_create(&tid, NULL, connection_handle, info) != 0) {
            SSL_free(ssl);
            delete info;
            perror("pthread_create");
            exit(-1);
        }
    }

    THREAD_cleanup();
}

int send_to_client(client_info *client, const void * buf, int length){
    int count = -1;
    int len = SSL_write(client->ssl, buf, length);

    switch (SSL_get_error(client->ssl, len)) {
        case SSL_ERROR_NONE:
            printf("\nThread %lx: sent '%s' with %d bytes\n",  (long) pthread_self(),
                   (char *) buf, len);
            count = len;
            break;
        case SSL_ERROR_WANT_WRITE:
            /* Just try again later */
            count = 0;
            break;
        case SSL_ERROR_WANT_READ:
            /* continue with reading */
            count = 0;
            break;
        case SSL_ERROR_SYSCALL:
            printf("Socket write error: ");
            if (!handle_socket_error()) count = -1;
            break;
        case SSL_ERROR_SSL:
            count = -1;
            printf("SSL write error: ");
            printf("%s (%d)\n", ERR_error_string(ERR_get_error(), (char *) buf), SSL_get_error(client->ssl, len));
            break;
        default:
            count = -1;
            printf("Unexpected error while writing!\n");
            break;
    }

    return count;
}

static void remove_client(client_info *cinfo){
    if(cinfo) {
        //remove from epoll
        try {
            epoll_ctl(cinfo->epoll_fd, EPOLL_CTL_DEL, cinfo->client_fd, nullptr);
            /*dprint("client '%s:%s' removed from epoll events\n",
                   inet_ntoa(((struct sockaddr_in *) &cinfo->client_addr)->sin_addr),
                   ntohs(((struct sockaddr_in *) &cinfo->client_addr)->sin_port));*/
        } catch (exception &e) {
            derror("exception occurred while removing '%s':%s from epoll event control: %s",
                   inet_ntoa(((struct sockaddr_in *) &cinfo->client_addr)->sin_addr),
                   ntohs(((struct sockaddr_in *) &cinfo->client_addr)->sin_port), e.what());
        }
        if(SSL_shutdown(cinfo->ssl) == 0){
            SSL_shutdown(cinfo->ssl);
        }
        close(cinfo->client_fd);
        SSL_free(cinfo->ssl);
        // remove from map
        (*cinfo->map).erase(cinfo->client_addr.s4.sin_addr.s_addr);
        delete cinfo;
    }
}

void idle_connection_time_handler(size_t timer_id, void *user_data){
    struct timeval now = {};
    auto *sinfo = (server_info *) user_data;
    dprint("timer[%ld]: timer event, checking idle client connection\n", timer_id);
    gettimeofday(&now, nullptr);

    for( auto& client: sinfo->conn_map) {
        if((now.tv_sec - client.second->last_activity) >= SOCKET_IDLE_TIMEOUT) {
            struct sockaddr_in addr{};
            addr.sin_addr.s_addr = client.first;
            dprint("timer[%ld]: removing %s due as it was inactive for %d seconds\n", timer_id,
                   inet_ntoa(addr.sin_addr), SOCKET_IDLE_TIMEOUT);
            std::thread removeClientThread(remove_client, client.second);
            removeClientThread.detach();
        }
    }
}

int main(int argc, char *argv[]) {
    server_info *sinfo;
    int pid;
    struct epoll_event event = {};
    bool running = true;
    size_t idel_connection_timer = 0;

    int ev_num;
    struct epoll_event events[10];
    time_t time_now=0;

    std::string bind_addr("192.168.2.2");
    std::string bind_port("9000");

    /*
    SSL_CTX *ctx;*/
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    if (SSL_library_init() < 0) {
        derror("ERROR: Could not initialize the OpenSSL library!");
        return -1;
    }

    sinfo = new server_info;

    const SSL_METHOD *mtd = DTLS_server_method();
    sinfo->ctx = SSL_CTX_new(mtd);
    SSL_CTX_set_min_proto_version(sinfo->ctx, DTLS1_2_VERSION);

    pid = getpid();
    if (!SSL_CTX_set_session_id_context(sinfo->ctx, (const unsigned char *) &pid, sizeof pid)) {
        perror("SSL_CTX_set_session_id_context");
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_use_certificate_file(sinfo->ctx, "../certs/server-cert.pem", SSL_FILETYPE_PEM)) {
        printf("\n[%d] ERROR: no certificate found!", __LINE__);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_use_PrivateKey_file(sinfo->ctx, "../certs/server-key.pem", SSL_FILETYPE_PEM)) {
        printf("\n[%d] ERROR: no private key found!", __LINE__);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(sinfo->ctx)) {
        printf("\n[%d] ERROR: invalid private key!", __LINE__);
        exit(EXIT_FAILURE);
    }

    /* Client has to authenticate */
    SSL_CTX_set_verify(sinfo->ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
    SSL_CTX_set_cookie_generate_cb(sinfo->ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(sinfo->ctx, verify_cookie);
#ifdef DEBUG
    SSL_CTX_set_info_callback(sinfo->ctx, info_callback);
#endif

    sinfo->server_fd = get_server_socket_and_bind(bind_addr, bind_port, &sinfo->address);

    if (sinfo->server_fd < 0) {
        exit(1);
    }

    sinfo->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (sinfo->epoll_fd == -1) {
        exit(1);
    }

    std::thread dtlsListenThread(dtls_listener, sinfo);

    Timer::initialize();
    /*idel_connection_timer = Timer::start_timer(IDLE_CONNECTION_TIMER_INTERVAL, t_unit::SEC, idle_connection_time_handler,
                                               t_timer::TIMER_PERIODIC, sinfo);*/

    while (running) {
        dprint("waiting for epoll event....\n");
        // Wait for something to happen on one of the file descriptors
        // we are waiting on
        do {
            ev_num = epoll_wait(sinfo->epoll_fd, events, MAX_TUNNEL_EVENTS, -1);
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

        time_now = time(NULL);

        for (int i = 0; i < ev_num; i++) {
#ifdef WITH_EPOLL_DATA_PTR
            auto *context = (Context *) (events[i].data.ptr);
#endif

            if ((events[i].events & EPOLLERR) ||
                (events[i].events & EPOLLHUP) ||
                (!(events[i].events & EPOLLIN))) {
                /* An error has occured on this fd, or the socket is not
                   ready for reading (why were we notified then?) */
                perror("epoll error");
#ifndef WITH_EPOLL_DATA_PTR
                close(events[i].data.fd);
#else
                close(context->fd);
#endif
                continue;
            }

#ifndef WITH_EPOLL_DATA_PTR
            if(events[i].data.fd < 0){
                derror("invalid epoll event. fd:%d\n", events[i].data.fd);
                continue;
            }
#else
            if (context->fd < 0) {
                derror("invalid epoll event. fd:%d\n", context->fd);
                continue;
            }
#endif
            auto *client = (client_info *) context->ptr;
            client->last_activity = time_now;
            if ((events[i].events & EPOLLIN)) {
                char rcvbuf[BUFSIZE];
                char sentbuf[BUFSIZE];

                if (!SSL_get_shutdown(client->ssl)) {
                    int rlen = SSL_read(client->ssl, rcvbuf, sizeof(rcvbuf));
                    int ssl_err = SSL_get_error(client->ssl, rlen);
                    switch (ssl_err) {
                        case SSL_ERROR_NONE:
                            rcvbuf[rlen] = '\0';
                            printf("\nThread %lx: received '%s' with %d bytes\n", (long) pthread_self(), rcvbuf,
                                   (int) rlen);
                            sprintf(sentbuf, "received->'%s'",rcvbuf);
                            //echo back the received packet
                            if(send_to_client(client, (const void *) sentbuf, (int) strlen(sentbuf)) < 0)
                            client->state = 0;
                            break;
                        case SSL_ERROR_WANT_READ:
                            /* Handle socket timeouts */
                            if (BIO_ctrl(SSL_get_rbio(client->ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
                                client->num_timeouts++;
                                if (client->num_timeouts == max_timeout){
                                    client->state = 0;
                                }
                            }
                            /* Just try again */
                            break;
                        case SSL_ERROR_ZERO_RETURN:
                            client->state = 0;
                            break;
                        case SSL_ERROR_SYSCALL:
                            printf("Socket read error: ");
                            if (!handle_socket_error()) client->state = 0;
                            break;
                        case SSL_ERROR_SSL:
                            printf("SSL read error: ");
                            printf("%s (%d)\n", ERR_error_string(ERR_get_error(), rcvbuf),
                                   SSL_get_error(client->ssl, rlen));
                            client->state = 0;
                            break;
                        default:
                            printf("Unexpected error while reading!\n");
                            client->state = 0;
                            break;
                    }
                }else{
                    client->state = 0;
                }

                if(!client->state) {
                    //remove from epoll
                    remove_client(client);
                }
            }
        }
    }

    if (idel_connection_timer > 0) {
        Timer::stop_timer(idel_connection_timer);
    }

    sinfo->running = false;
    for (auto &it : sinfo->conn_map) {
        delete it.second;
    }
    sinfo->conn_map.clear();
    dtlsListenThread.join();
    delete sinfo;

    return 0;
}
