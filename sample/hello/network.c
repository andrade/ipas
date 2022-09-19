#define _POSIX_C_SOURCE 201112L

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include "debug.h"
#include "network.h"

// returns <0 on error?
int socket_connect(const char *host, int port)
{
	int sfd = -1;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	char service[sizeof(port) + 1];
	int ret;

	// convert port (see getaddrinfo(3))
	if (snprintf(service, sizeof(service), "%d", port) < 0) {
		return -1;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_protocol = 0;
	ret = getaddrinfo(host, service, &hints, &result);
	if (ret) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		return -1;
	}
	// try each address until successful, close on each failure
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;
		close(sfd);
	}
	freeaddrinfo(result); //FIXME  Before rp==NULL?
	if (rp == NULL) {
		fprintf(stderr, "could not connect\n");
		return -1;
	}

	return sfd;
}

// NOTE Não criei ainda função mas chamar close no socket no final.



int socket_read(int fd, void *buffer, size_t n)
{
	ssize_t br, total;

	for (total = 0; total < n; total += br) {
		br = read(fd, buffer + total, n - total);
		if (br <= 0) {
			int error = errno;
			LOG("socket_read (%zd, %zd, %d)\n", br, total, error);
			return error;
		}
	}
	LOG("total_r=%zd\n", total);

	return 0;
}

int socket_write(int fd, const void *buffer, size_t n)
{
	ssize_t bw, total;

	for (total = 0; total < n; total += bw) {
		bw = write(fd, buffer + total, n - total);
		if (bw <= 0) {
			int error = errno;
			LOG("socket_write (%zd, %zd, %d)\n", bw, total, error);
			return error;
		}
	}
	LOG("total_w=%zd\n", total);

	return 0;
}
