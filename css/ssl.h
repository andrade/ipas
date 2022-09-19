#pragma once

/**
** Receives and processes client data, writes response to client.
**
** Protocol:
**   Read data size, 4 octets in network byte order
**   Read data
**   <process client request, prepare reply>
**   Write data size, 4 octets in network byte order
**   Write data
**
** Callback may use the same buffer as wbuf/rbuf and
** the same buffer length variable as wlen/rlen since
** data is read from socket only after writing wbuf.
**
** [i]  ssl:                    file descriptor to an open channel
** [io] process_request:        callback to process client data
**         [o]  wbuf:           received data
**         [o]  wcap:           capacity of read buffer
**         [o]  wlen:           length of data in read buffer
**         [i]  rbuf:           data to write
**         [i]  rlen:           length of data to write
** [io] finalize:               final cleanup; returns integer passed in
**         [i]  result:         status value
**
** Returns zero on success, non-zero otherwise.
**/
int ssl_handle_request(SSL *ssl, int (*f)(uint8_t *, uint32_t, uint32_t *, const uint8_t *, uint32_t), int (*finalize)(int));
