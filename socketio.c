/*
 * socketio.c socket layer API implementation 
 */

#include <socketio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdarg.h>

static inline int is_connected(int, unsigned int);
static inline int sio_select(int, unsigned int, int);
static inline void print_error(const char *, ... );

#define SELECT_READ 0x0
#define SELECT_WRITE 0x1 

/**
 * sio_connect : try to connect to another device.
 * This function tries to connect to host:port.
 * It uses a documented algorithm when is used a 
 * a non-blocking socket
 */
int sio_connect (int sd, const char *host,
		 int port, struct sio_args args)
{
	
	struct addrinfo *info;
	int res = 0; 
	char port_str[6];
	
	sprintf(port_str, "%d", port);
	res = getaddrinfo(host, port_str, NULL, &info);

	if (!res) {
		res = -1;
		/* not connected and still have addresses */
		for (; info && res ; info = info->ai->next) {
			res = connect (info->ai_family
				       , info->ai_addr, ai_addrlen);
			
			if (res == -1 && errno == EINPROGRESS)
				res = is_connected(sd, args.timeout);
			else
				res = -1;
		}
	} else {
		if (args.flags & SIO_VERBOSE )
			print_error("sio_connect failed : %s\n",
				    gai_strerror(res));
		return -1;
	}
	
	if (res == -1){
		if (args.flags & SIO_VERBOSE)
			print_error("sio_connect failed : %s \n",
				    strerror(res));
		return -1;
	}
	
	return 0;
}


/**
 * sio_send : try to send data over a socket 
 * If sio_send couldn't send at least 1 byte after
 * maxnfails * timeout seconds network connection is disconnected 
 */
int sio_send (int sd, char *buf,
	      size_t len, struct sio_args args)
{
	size_t total_bytes = 0 ;
	ssize_t temp;
	int nfails = 0;

	while (total_bytes < len) {

		temp = send (sd, &buf[total_bytes],
			     len - total_bytes , 0);

		if (temp == -1) {
			nfails++;
			if (errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				sio_select(sd, args.timeout,  SELECT_WRITE);
			else {
				if (args.flags & SIO_VERBOSE)
					print_error("sio_send failed : %s\n",
						    strerror(errno));
				return -1; 
			}
			if (nfails >= args.maxnfails) {
				if (args.flags & SIO_VERBOSE)
					print_error("sio_send failed :"
						    " Timeout reached\n");
				return -1;
			}
		} else {
			total_bytes += temp;
			nfails = 0;
		}
	}

	return 0;
}


/**
 * sio_recv : try to receive len bytes
 * The algorithm used for this function is the
 * same as send's 
 */ 
int sio_recv (int sd, char *buf,
	      size_t len, struct sio_args args)
{
	size_t total_bytes = 0;
	ssize_t temp;
	int nfails = 0;

	while (total_bytes < len) {
		temp = recv(sd, &buf[total_bytes],
			    len - total_bytes, 0);

		if (temp == -1) {
			nfails++;
			if (errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				sio_select(sd, args.timeout, SELECT_READ);
			else {
				if (args.flags & SIO_VERBOSE)
					print_error ("sio_recv failed : %s\n",
						     strerror(errno));
				return -1;
			}
			if (nfails >= args.maxnfails){
				if (args.flags & SIO_VERBOSE)
					print_error("sio_recv failed :"
						    " Timeout reached.\n");
				return -1;
			}
		} else if (temp > 0){
			total_bytes += (size_t)temp;
			nfails = 0;
		} else  /* Socket is disconnected */ {
			if (args.flags & SIO_VERBOSE)
				print_error("sio_recv() failed :"
					    "Socket is disconnected.\n");
			return -1;
		}
	}

	return 0;
}


/**
 * is_connected : check weather socket is 
 * connected or not.
 */
static inline int is_connected(int sd, unsigned int timeout)
{
	int res;

	res = sio_select(sd, timeout, SELECT_WRITE);
	if (res == 1) {
		int err;
		err = 0;
		socklen_t o_size = sizeof(int); 

		getsockopt(sd, SOL_SOCKET, SO_ERROR,
			   &err, &o_size);

		if (err)
			return -1;

		return 0;
	}

	return -1;

}


/**
 * sio_select : a wrapper for select() function.
 * Note : This is not a general function.
 * It only works in this project and SIO module.
 */
static inline int sio_select(int sd, unsigned timeout, int mode)
{
	struct timeval t;
	fd_set set;
	int res;
	
	FD_ZERO(&set);
	FD_SET(sd, &set);

	t->tv_sec = timeout;
	t->tv_usec = 0;

	res = select (sd +1,
		      mode == SELECT_READ ? &set : NULL,
		      mode == SELECT_WRITE ? &set, NULL,
		      NULL, &t);

	if (res == 1)
		return 1;

	return 0;
	
}

static inline void print_error(const char *fmt, ...)
{
	va_list list;
	va_start(list, fmt);
	vfprintf(stderr, fmt, list);
	va_end(list);
}
