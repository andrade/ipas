#ifndef FOOSSL_CLIENT_H
#define FOOSSL_CLIENT_H

// #include "openssl/ssl.h"
//
// struct foossl_client_st {
// 	int sfd;
// 	SSL_CTX *ctx;
// 	SSL *ssl;
// };
//
// // functions return zero on success
//
// int foossl_client_connect(struct foossl_client_st *foossl,
// 		const char *host, int port);
// int foossl_client_destroy(struct foossl_client_st *foossl);
//
// // server certificate is not verified (its using a self-signed certificate)



/**
** Creates a plain socket and attempts to connect.
**
** Returns a file descriptor for the connected socket on success, and
** returns -1 on error.
**/
int socket_connect(const char *host, int port);

/**
** Reads n bytes from the socket source and copies them
** into the caller allocated buffer.
**
** The function keeps reading until the required number of bytes
** have been read or the source channel returns an error.
**
** Returns 0 on success.
** On failure, caller should release ssl-related resources.
**/
int socket_read(int fd, void *buffer, size_t n);

/**
** Writes n bytes from the source buffer into the target socket channel.
**
** The function keeps writing until the required numbers of bytes
** have been written or the target channel returns an error.
**
** Returns 0 on success.
** On failure, caller should release ssl-related resources.
**/
int socket_write(int fd, const void *buffer, size_t n);

#endif
