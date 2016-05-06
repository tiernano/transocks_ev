/**
 * tranSOCKS_ev
 * ------------
 * libevent-based non-forking transparent SOCKS5-Proxy
 * 
 * This is mainly inspired by transocks, available at
 * http://transocks.sourceforge.net/ and written by
 * Mike Fisk <mefisk@gmail.com>.
 * 
 * This work is distributed within the terms of
 * creative commons attribution-share alike 3.0 germany
 * 
 * See http://creativecommons.org/licenses/by-sa/3.0/ for more information
 * 
 * @author Bernd Holzmueller <bernd@tiggerswelt.net>
 * @author Chase Venters <chase.venters@gmail.com> (Performance/reliability enhancements, DNS, logging)
 * @author Silas S. Brown (Fix for crash using newer GCC)
 * @author Toni Spets (Pass-trough, privilege-dropping, pid-file)
 * @author Karsten N. (initial man-page)
 * @revision 07
 * @license http://creativecommons.org/licenses/by-sa/3.0/de/ Creative Commons Attribution-Share Alike 3.0 Germany
 * @homepage http://oss.tiggerswelt.net/transocks_ev/
 * @copyright Copyright &copy; 2015 tiggersWelt.net (and others, see above)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <signal.h>
#include <event.h>
#include <evdns.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <inttypes.h>

/* This caused errors on my maschine */
/* #include <linux/netfilter_ipv4.h> */

#ifndef SO_ORIGINAL_DST
# define SO_ORIGINAL_DST 80
#endif

#define READ_BUFFER	4096

enum {
  SOCKS5_HELLO,
  SOCKS5_CONNECT,
  SOCKS5_CONSUME,
  SOCKS5_CONNECTED
};

enum {
  EI_CLIENT = 0,
  EI_SERVER = 1,
};

enum {
  EP_PENDING_SHUTDOWN = (1 << 0),
  EP_SHUT_WR = (1 << 1),
};

struct endpoint {
  unsigned int flags;
  int fd;
  struct bufferevent *ev;
  uint64_t octets;
};

static int last_connid;

struct proxy_con {
  unsigned int id;
  int status;
  int consume;
  struct sockaddr_in dest;
  struct event connect_timeout;
  struct timespec conn_time;

  struct endpoint ep[2];
};

struct sockaddr_in socks_addr;
static char *sockshost;
static int connect_timeout = 60;
static int randfd = -1;
static int loglevel = 0;
static int passthrough = 0;

#define BE_ARGS \
  struct proxy_con *con = arg; \
  int ep = (ev == con->ep[EI_CLIENT].ev) ? EI_CLIENT : EI_SERVER; \
  int op = (ep + 1) & 1; \
  struct endpoint *epp = &con->ep[ep]; \
  struct endpoint *opp = &con->ep[op]

static struct timespec *ts_subtract (const struct timespec *a, const struct timespec *b, struct timespec *result) {
  if ((a->tv_sec < b->tv_sec) || ((a->tv_sec == b->tv_sec) && (a->tv_nsec <= b->tv_nsec))) {
      result->tv_sec = result->tv_nsec = 0;
  } else {
    result->tv_sec = a->tv_sec - b->tv_sec;
    if (a->tv_nsec < b->tv_nsec) {
      result->tv_nsec = a->tv_nsec + 1000000000L - b->tv_nsec;
      result->tv_sec--;
    } else {
      result->tv_nsec = a->tv_nsec - b->tv_nsec;
    }
  }

  return result;
}

const char *endpoint_name (int ep) {
  static const char *ep_names[] = { "CLIENT", "SERVER" };
  return ep_names[ep];
}

void endpoint_remove (struct endpoint *ep) {
  if (ep->ev) {
    bufferevent_free (ep->ev);
    ep->ev = NULL;
  }
  if (ep->fd != -1) {
    close (ep->fd);
    ep->fd = -1;
  }
}

void client_verror (struct proxy_con *con, int level, const char *msg, va_list args) {
  if (loglevel < level)
    return;
  fprintf (stderr, "%d,", con->id);
  vfprintf (stderr, msg, args);
  fprintf (stderr, "\n");
}

void client_error (struct proxy_con *con, int level, const char *msg, ...) {
  va_list args;

  va_start (args, msg);
  client_verror (con, level, msg, args);
  va_end (args);
}

void client_remove (struct proxy_con *con, const char *msg, ...) {
  double secs, client_rate, svr_rate;
  struct timespec now, interval;
  va_list args;

  if (msg != 0) {
    va_start (args, msg);
    client_verror (con, 1, msg, args);
    va_end (args);
  }
  else
    client_error (con, 2, "normal shutdown");

  if (loglevel >= 1) {
    /* compute statistics */
    clock_gettime (CLOCK_MONOTONIC, &now);
    ts_subtract (&now, &con->conn_time, &interval);
    secs = interval.tv_sec + (1.0 * interval.tv_nsec / 1000000000L); 
    svr_rate = con->ep[EI_SERVER].octets / secs / 1024;
    client_rate = con->ep[EI_CLIENT].octets / secs / 1024;

    client_error (con, 1, "c;%.2f;%"PRIu64";%.2f;%"PRIu64"%.2f", secs, con->ep[EI_SERVER].octets, svr_rate, con->ep[EI_CLIENT].octets, client_rate);
  }

  endpoint_remove (&con->ep[EI_CLIENT]); 
  endpoint_remove (&con->ep[EI_SERVER]); 
  
  event_del (&con->connect_timeout);

  free (con);
}

void client_cleanup (struct proxy_con *con) {
  if ((con->ep[0].flags & EP_SHUT_WR) &&
      (con->ep[1].flags & EP_SHUT_WR))
    client_remove (con, 0);
}

void client_shutdown_wr (struct proxy_con *con, int ep) {
  struct endpoint *epp = &con->ep[ep];
  struct endpoint *opp = &con->ep[(ep + 1) & 1];

  client_error (con, 3, "shutting down writing to %s", endpoint_name (ep));
  shutdown (epp->fd, SHUT_WR);
  shutdown (opp->fd, SHUT_RD);
  epp->flags |= EP_SHUT_WR;

  bufferevent_disable (epp->ev, EV_WRITE);
  bufferevent_disable (opp->ev, EV_READ);
}

void client_shutdown_rd (struct proxy_con *con, int ep) {
  return client_shutdown_wr (con, (ep + 1) & 1);
}

static void be_rdy_read (struct bufferevent *ev, void *arg) {
  BE_ARGS;
  char buffer[READ_BUFFER];
  ssize_t sz, ret;

  /* copy a chunk from one endpoint to the other */
  sz = bufferevent_read (epp->ev, buffer, READ_BUFFER);
  if (sz == -1) {
    client_shutdown_rd (con, ep);
    client_cleanup (con);
    return;
  }
  ret = bufferevent_write (opp->ev, buffer, sz);
  if (ret == -1) {
    client_shutdown_wr (con, op);
    client_cleanup (con);
    return;
  }

  opp->octets += sz;

  bufferevent_disable (epp->ev, EV_READ);
  bufferevent_enable (opp->ev, EV_WRITE);
}

static void be_rdy_write (struct bufferevent *ev, void *arg) {
  BE_ARGS;
  
  /* if we are done flushing the socket, shut it down now */
  if (epp->flags & EP_PENDING_SHUTDOWN) {
    client_shutdown_wr (con, ep);
    client_cleanup (con);
    return;
  }

  /* otherwise, allow the other end to resume processing */
  bufferevent_enable (opp->ev, EV_READ);
}

void start_passthrough(struct proxy_con *con);

static void be_error (struct bufferevent *ev, short what, void *arg) {
  BE_ARGS;
  int errnum = 0;
  char extrabuf[128];

  if (what & EVBUFFER_ERROR)
    errnum = errno;

  /* pre-connect processing */
  if (con->status != SOCKS5_CONNECTED && ep == EI_SERVER) {
    if (passthrough) {
      client_error (con, 1, "SOCKS5 server down, fallback to pass-through");

      /* remove old SOCKS server endpoint */
      bufferevent_disable (con->ep[EI_SERVER].ev, EV_READ);
      bufferevent_disable (con->ep[EI_SERVER].ev, EV_WRITE);
      endpoint_remove (&con->ep[EI_SERVER]);
      event_del (&con->connect_timeout);

      return start_passthrough(con);
    }

    if (errnum == 0)
      return client_remove (con, "SOCKS5 server hung up");
    else 
      return client_remove (con, "SOCKS5 server error before fully connected: %s (%d)", strerror (errnum), errnum);
  }

  /* shut down specified tunnel leg */
  if (what & (EVBUFFER_EOF | EVBUFFER_ERROR)) {
    if (what & EVBUFFER_READ) {
      if (opp->flags & EP_SHUT_WR)
        extrabuf [0] = 0; 
      else
        sprintf (extrabuf, ", pending shutdown for %s write", endpoint_name (op));
      client_error (con, 3, "shutting down read for %s%s", endpoint_name (ep), extrabuf);
      shutdown (epp->fd, SHUT_RD);
      bufferevent_disable (epp->ev, EV_READ);

      opp->flags |= EP_PENDING_SHUTDOWN;
      if (con->status == SOCKS5_CONNECTED)
        bufferevent_enable (opp->ev, EV_WRITE);
    }
    else if (what & EVBUFFER_WRITE) {
      client_shutdown_wr (con, ep);
    }
    else
      abort();
  }

  if (what & EVBUFFER_ERROR)
    client_error (con, 1, "%s error: %s (%d)", endpoint_name (ep), strerror (errnum), errnum);

  client_cleanup (con);
}

static void pt_be_error (struct bufferevent *ev, short what, void *arg) {
  BE_ARGS;
  int errnum = 0;
  char extrabuf[128];

  if (what & EVBUFFER_ERROR)
    errnum = errno;

  if (ep == EI_SERVER) {
    if (errnum == 0)
      return client_remove (con, "remote hung up");
    else  {
      return client_remove (con, "remote error before fully connected: %s (%d)", strerror (errnum), errnum);
    }
  }

  client_remove (con, "local client error before pass-through connection established: %s (%d)", strerror (errnum), errnum);
}

static void be_setcb_online (struct bufferevent *ev, struct proxy_con *con) {
  bufferevent_setcb (ev, &be_rdy_read, &be_rdy_write, &be_error, con);
}

static int endpoint_init (struct proxy_con *con, int ep, int fd) {
  struct endpoint *epp = &con->ep[ep];
  if (epp->ev != 0)
    return 0;

  epp->fd = fd;
  epp->ev = bufferevent_new (fd, &be_rdy_read, 0, &be_error, con);
  if (epp->ev == 0)
    return -1;
  return 0;
}

static void pt_svr_rdy_write (struct bufferevent *ev, void *arg) {
  BE_ARGS;

  /* We are connected */
  client_error (con, 2, "pass-through connected");
  con->status = SOCKS5_CONNECTED;

  /* Switch to copy callbacks, read any amount of data, start with read state */
  endpoint_init (con, op, con->ep[op].fd);
  opp = &con->ep[op];
  be_setcb_online (epp->ev, con);
  be_setcb_online (opp->ev, con);
  bufferevent_setwatermark (epp->ev, EV_READ, 0, READ_BUFFER);
  bufferevent_setwatermark (opp->ev, EV_READ, 0, READ_BUFFER);
  bufferevent_enable (epp->ev, EV_READ);
  bufferevent_enable (opp->ev, EV_READ);
  bufferevent_disable (epp->ev, EV_WRITE);
  bufferevent_disable (opp->ev, EV_WRITE);

  /* Cancel timeout */
  event_del (&con->connect_timeout);
}

static void svr_rdy_read (struct bufferevent *ev, void *arg) {
  BE_ARGS;
  unsigned char buffer[READ_BUFFER];
  ssize_t len, blen;

  switch (con->status) {
    case SOCKS5_HELLO:
      len = bufferevent_read (epp->ev, buffer, 2);
      if (len < 2)
        return client_remove (con, "SOCKS5 HELLO-read failed");

      /* Check for a SOCKS5-Signature */
      if (buffer [0] != 0x05) {
        return client_remove (con, "bad reply in SOCKS5 HELLO-State");
      }
      
      /* Handle authentication */
      switch (buffer [1]) {
        case 0x00:	/* No authentication needed */
          break;
        
        case 0xFF:	/* Our request were rejected */
        default:	/* Anything else is unsupported */
          return client_remove (con, "Unsupported authentication");
      }
      
      char resp [10];
      
      resp [0] = 0x05; /* We are SOCKS5 */
      resp [1] = 0x01; /* Create a TCP-Connection */
      resp [2] = 0x00;
      resp [3] = 0x01; /* Address is IPv4 */
      resp [4] = (con->dest.sin_addr.s_addr & 0xFF); /* 4-byte IPv4 */
      resp [5] = (con->dest.sin_addr.s_addr >> 8) & 0xFF;
      resp [6] = (con->dest.sin_addr.s_addr >> 16) & 0xFF;
      resp [7] = (con->dest.sin_addr.s_addr >> 24);
      resp [8] = con->dest.sin_port & 0xff; /* 2-Byte Port-Number */
      resp [9] = con->dest.sin_port >> 8;
      
      if (bufferevent_write (epp->ev, resp, 10) != 0)
        return client_remove (con, "unable to transmit SOCKS5 request");

      client_error (con, 2, "sent SOCKS5 request");
      
      /* Switch to connect state */
      con->status = SOCKS5_CONNECT;
      bufferevent_setwatermark (epp->ev, EV_READ, 7, READ_BUFFER);
      
      break;
    case SOCKS5_CONNECT:
      len = bufferevent_read (epp->ev, buffer, READ_BUFFER);
      if (len < 7)
        return client_remove (con, "SOCKS5 CONNECT-read failed");

      /* Check for a SOCKS5-Signature */
      if (buffer [0] != 0x05) {
        return client_remove (con, "bad reply in SOCKS5 CONNECT-State");
      }
      
      /* Check for success */
      if (buffer [1] != 0x00) {
        return client_remove (con, "SOCKS5 Connection failed with reason %d", buffer [1]);
      } 

      /* Consume the rest of the SOCKS5 response */
      con->status = SOCKS5_CONSUME;
      if (buffer [3] == 0x01) 
        blen = 4;
      else if (buffer [3] = 0x03) 
        blen = buffer [7];
      else if (buffer [3] = 0x04) 
        blen = 16;

      /* Figure out if we have the data we need to consume, if we have excess
         data or if we need to wait on the data we need to consume */
      con->consume = blen - (len - 6);
      if (con->consume > 0) {
        bufferevent_setwatermark (epp->ev, EV_READ, con->consume, READ_BUFFER);
        break;
      }
      else if (con->consume < 0) {
        endpoint_init (con, op, con->ep[op].fd);
        opp = &con->ep[op];
        bufferevent_write (opp->ev, buffer + 6 + blen, (-con->consume));
        opp->octets += (-con->consume);
      }

    case SOCKS5_CONSUME:
      if (con->consume > 0) {
        len = bufferevent_read (epp->ev, buffer, con->consume);
        if (len < con->consume)
          return client_remove (con, "SOCKS5 CONSUME-read failed");
      }

      /* We are connected */
      client_error (con, 2, "SOCKS5 connected");
      con->status = SOCKS5_CONNECTED;

      /* Switch to copy callbacks, read any amount of data, start with read state */
      endpoint_init (con, op, con->ep[op].fd);
      opp = &con->ep[op];
      be_setcb_online (epp->ev, con);
      be_setcb_online (opp->ev, con);
      bufferevent_setwatermark (epp->ev, EV_READ, 0, READ_BUFFER);
      bufferevent_setwatermark (opp->ev, EV_READ, 0, READ_BUFFER);
      bufferevent_enable (epp->ev, EV_READ);
      bufferevent_enable (opp->ev, EV_READ);
      bufferevent_disable (epp->ev, EV_WRITE);
      bufferevent_disable (opp->ev, EV_WRITE);

      /* Cancel timeout */
      event_del (&con->connect_timeout);
      
      break;
    default:
      abort();
  } 
}

static void be_setcb_connect (struct bufferevent *ev, struct proxy_con *con) {
  bufferevent_setcb (ev, &svr_rdy_read, 0, &be_error, con);
}

static void client_connect_timeout (int fd, short event, void *arg) {
  struct proxy_con *con = arg;

  /* shut down client */
  client_remove (con, "connecting timed out");
}

static int nonblock (int fd, int mode) {
  int data;

  data = fcntl (fd, F_GETFL);
  if (data == -1)
    return -1;
  if (mode)
    data |= O_NONBLOCK;
  else
    data &= ~O_NONBLOCK;
  return fcntl (fd, F_SETFL, data);
}

static void sockaddr_in_str (char *buf, const struct sockaddr *sa) {
  char pbuf[INET6_ADDRSTRLEN];
  unsigned short port = 0;
  int af = sa->sa_family;

  if (af == AF_INET) {
    inet_ntop (af, &(((const struct sockaddr_in *)sa)->sin_addr), pbuf, sizeof(pbuf));
    port = ((const struct sockaddr_in *)sa)->sin_port;
    sprintf (buf, "%s:%d", pbuf, ntohs(port));
  }
  else if (af == AF_INET6) {
    inet_ntop (af, &(((const struct sockaddr_in6 *)sa)->sin6_addr), pbuf, sizeof(pbuf));
    port = ((const struct sockaddr_in6 *)sa)->sin6_port;
    sprintf (buf, "[%s]:%d", pbuf, ntohs(port));
  }
  else {
    sprintf (buf, "unknown");
  }
}

void start_socks (struct proxy_con *con) {
  struct timeval conn_timeout_tv;
  int fd_server, fd_client = con->ep[EI_CLIENT].fd;
  char dststr[INET6_ADDRSTRLEN + 32];

  sockaddr_in_str (dststr, (struct sockaddr *)&socks_addr);
  client_error (con, 2, "connecting to SOCKS5 host %s", dststr);

  /* prepare socket */
  fd_server = socket (AF_INET, SOCK_STREAM, 0);
  if (fd_server < 0)
    return client_remove (con, "socket failed: %s (%d)", strerror(errno), errno);

  /* change sockets to non-blocking mode */ 
  if (nonblock (fd_server, 1) != 0)
    return client_remove (con, "nonblock failed: %s (%d)", strerror(errno), errno);

do_connect:
  /* Create the SOCKS-Client */
  if (connect (fd_server, (struct sockaddr *)&socks_addr, sizeof (socks_addr)) != 0) {
    if (errno == EINTR)
      goto do_connect;
    else if (errno == EINPROGRESS)
      /* nothing */;
    else 
      return client_remove (con, "connect failed: %s (%d)", strerror(errno), errno);
  }

  /* Setup events for this new connection */
  endpoint_init (con, EI_SERVER, fd_server);
  be_setcb_connect (con->ep[EI_SERVER].ev, con);
  
  /* Submit a SOCKS5 Hello */
  con->status = SOCKS5_HELLO;

  /* Set a timeout */
  timeout_set (&con->connect_timeout, &client_connect_timeout, con);
  conn_timeout_tv.tv_sec = connect_timeout;
  conn_timeout_tv.tv_usec = 0;
  timeout_add (&con->connect_timeout, &conn_timeout_tv);

  /* Send HELLO and wait for a 2 byte response */
  bufferevent_setwatermark (con->ep[EI_SERVER].ev, EV_READ, 2, READ_BUFFER);
  bufferevent_write (con->ep[EI_SERVER].ev, "\x05\x01\x00", 3);
  bufferevent_enable (con->ep[EI_SERVER].ev, EV_READ);
}

void start_passthrough(struct proxy_con *con) {

  struct timeval conn_timeout_tv;
  int fd_server, fd_client = con->ep[EI_CLIENT].fd;
  char dststr[INET6_ADDRSTRLEN + 32];

  sockaddr_in_str (dststr, (struct sockaddr *)&con->dest);
  client_error (con, 2, "connecting directly to host %s", dststr);

  /* prepare socket */
  fd_server = socket (AF_INET, SOCK_STREAM, 0);
  if (fd_server < 0)
    return client_remove (con, "socket failed: %s (%d)", strerror(errno), errno);

  /* change sockets to non-blocking mode */
  if (nonblock (fd_server, 1) != 0)
    return client_remove (con, "nonblock failed: %s (%d)", strerror(errno), errno);

pt_do_connect:
  if (connect (fd_server, (struct sockaddr *)&con->dest, sizeof (con->dest)) != 0) {
    if (errno == EINTR)
      goto pt_do_connect;
    else if (errno == EINPROGRESS)
      /* nothing */;
    else
      return client_remove (con, "pass-through connect failed: %s (%d)", strerror(errno), errno);
  }

  /* Setup events for this new connection */
  endpoint_init (con, EI_SERVER, fd_server);
  bufferevent_setcb (con->ep[EI_SERVER].ev, 0, pt_svr_rdy_write, &pt_be_error, con);
  bufferevent_enable (con->ep[EI_SERVER].ev, EV_WRITE);

  /* Set a timeout */
  timeout_set (&con->connect_timeout, &client_connect_timeout, con);
  conn_timeout_tv.tv_sec = connect_timeout;
  conn_timeout_tv.tv_usec = 0;
  timeout_add (&con->connect_timeout, &conn_timeout_tv);
}

static void dns_done (int result, char type, int count, int ttl, void *addresses, void *arg) {
  struct proxy_con *con = arg;
  unsigned char c;
  int ret, i;

  if (result != DNS_ERR_NONE) 
    return client_remove (con, "DNS lookup failed: %s", evdns_err_to_string (result));

  if (type != EVDNS_TYPE_A)
    return client_remove (con, "DNS lookup failed: bad record type");

  if (count < 1)
    return client_remove (con, "DNS lookup failed: no address");

  /* pick address at random */
  if (count > 1 && randfd != -1) {
    ret = read (randfd, &c, 1);
    if (ret == 1) {
      i = c % count;  
    }
    else
      i = 0;
  }
  else
    i = 0;

  socks_addr.sin_addr.s_addr = ((uint32_t *)addresses)[i]; 
  start_socks (con);
}

void new_connection (int fd, short event, void *arg) {
  struct sockaddr_in6 client_addr;
  int fd_client;
  struct proxy_con *con;
  char dststr[INET6_ADDRSTRLEN + 32];
  int len = 0;
  
  /* Allocate memory for new structure */
  con = malloc (sizeof (struct proxy_con));
  if (con == 0) {
    perror ("malloc failed");
    return;
  }
  bzero (con, sizeof (struct proxy_con));
  con->id = ++last_connid;
  clock_gettime (CLOCK_MONOTONIC, &con->conn_time);
  
  /* Reschedule ourself */
  event_add (arg, NULL);
  
  /* Accept incoming connection */
  memset (&client_addr, 0, sizeof(client_addr));
  if ((fd_client = accept (fd, (struct sockaddr *)&client_addr, &len)) <= 0) {
    free (con);
    return;
  }

  con->ep[EI_CLIENT].fd = fd_client; 
  con->ep[EI_SERVER].fd = -1;

  /* Set socket to nonblocking mode */
  if (nonblock (fd_client, 1) != 0)
    goto error;

  /* Determine where we should connect to */
  if (getsockopt (fd_client, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr *)&con->dest, &len) != 0) {
    perror ("Could not determine socket-destination");
    goto error;
  }

  sockaddr_in_str (dststr, (struct sockaddr *)&con->dest);
  client_error (con, 1, "-> %s", dststr);

  if (sockshost) {
    client_error (con, 3, "resolving SOCKS5 host %s in DNS", sockshost);
    if (evdns_resolve_ipv4 (sockshost, 0, &dns_done, con) != 0) {
      client_error (con, 1, "failed to transmit DNS query for %s", sockshost);
      goto error;
    }
  } else 
    start_socks (con);

  return;

error:
  close (fd_client);
  free (con);
}

int create_pidfile(const char *path)
{
  int fd;
  char buf[128];

  fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);

  if (fd == -1) {
    fprintf(stderr, "Failed to open() PID file %s: %s (%d)\n", path, strerror (errno), errno);
    goto error;
  }

  if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
    fprintf(stderr, "Failed to flock() PID file %s: %s (%d)\n", path, strerror (errno), errno);
    goto error;
  }

  if (ftruncate(fd, 0) == -1) {
    fprintf(stderr, "Failed to ftruncate() PID file %s: %s (%d)\n", path, strerror (errno), errno);
    goto error;
  }

  snprintf(buf, sizeof buf, "%ld\n", (long)getpid());
  if (write(fd, buf, strlen(buf)) != strlen(buf)) {
    fprintf(stderr, "Failed to write() PID file %s: %s (%d)\n", path, strerror (errno), errno);
    goto error;
  }

  return fd;

error:
  if (fd != -1)
    close(fd);
  return -1;
}

int main (int argc, char **argv) {
  struct sockaddr_in addr;
  struct event ev_server;
  int addrlen = sizeof (addr);
  int serverfd = 0;
  int on = 1;
  int foreground = 0;
  char *pidfile = NULL;
  int pid_fd = -1;
  int uid = 0;
  int gid = 0;
  
  short bindport = 1211;
  char *bindhost = "0.0.0.0";
  
  short socksport = 9050;
  
  char c;
  
  /* Parse the commandline */
  while ((c = getopt (argc, argv, "vfp:H:s:S:c:P:u:g:th")) != (char)EOF)
    switch (c) {
      case 'f': /* Keep in foreground */
        foreground = 1;
        break;
      
      case 'p': /* Try to bind to this port */
        if (!(bindport = atoi (optarg))) {
          fprintf (stderr, "Invalid port %s\n", optarg);
          return 1;
        }
        
        break;
      
      case 'H': /* Try to bind to this IP */
        bindhost = optarg;
        break;
      
      case 's': /* Use this port on the SOCKS5-Proxy */
        if (!(socksport = atoi (optarg))) {
          fprintf (stderr, "Invalid port %s\n", optarg);
          return 1;
        }
        
        break;

      case 'c': /* Use this connection timeout */
        if (!(connect_timeout = atoi (optarg))) {
          fprintf (stderr, "Invalid connection timeout %s\n", optarg);
          return 1;
        }
        
        break;

      case 'v':
        loglevel++;
        break;
      
      case 'S': /* Use this IP for the SOCKS5-Proxy */
        sockshost = optarg;
        break;

      case 'P':
        pidfile = optarg;
        break;

      case 'u':
        uid = atoi (optarg);
        break;

      case 'g':
        gid = atoi (optarg);
        break;

      case 't':
        passthrough = 1;
        break;
      
      case 'h': /* Print help */
        printf ("tranSOCKS-ev - libevent-based transparent SOCKS5-Proxy\n");
        printf ("Usage: %s [-f] [-t] [-v] [-p port] [-H ip-address] [-s port] -S hostname [-c timeout] [-u uid] [-g gid] [-P file]\n\n", argv [0]);
        printf ("\t-f\tDo not fork into background upon execution\n");
        printf ("\t-p\tBind our server-socket to this port (default: 1211)\n");
        printf ("\t-H\tListen on this IP-Address for incomming connections (default: all IP-Addresses)\n");
        printf ("\t-s\tExpect SOCKS5-Server on this Port (default: 9050)\n");
        printf ("\t-S\tExpect SOCKS5-Server at this address\n");
        printf ("\t-c\tConnection timeout (default 60 seconds)\n");
        printf ("\t-t\tPass through connections through if SOCKS5-Server down\n");
        printf ("\t-u\tUser ID to run as\n");
        printf ("\t-g\tGroup ID to run as\n");
        printf ("\t-P\tWrite PID-file to this location\n");
        printf ("\t-v\tVerbose operation (specify multiple times for additional verbosity)\n");
        printf ("\n");
        
        return 0;
    }

  if (sockshost == 0) {
    fprintf (stderr, "You must specify -S\n");
    return 1;
  }
  
  /* Handle the forking stuff */
  if (foreground != 1) {
    /* Try to fork into background */
    if ((foreground = fork ()) < 0) {
      perror("fork");
      return 1;
    }
    
    /* Fork was successfull and we are the parent */
    if (foreground)
      return 0;
    
    /* Close our filehandles */
    fclose (stdin);
    fclose (stdout);
    fclose (stderr);
    
    setsid ();
    setpgrp ();
    
    signal (SIGCHLD, SIG_IGN);
  }

  /* Create pidfile for child */
  if (pidfile != NULL) {
    pid_fd = create_pidfile(pidfile);
    if (pid_fd == -1) {
      return 1;
    }
  }

  /* Drop to unprivileged user and group if specified */
  if (gid > 0)
    if (setgid(gid) == -1) {
      fprintf(stderr, "Failed to setgid(%d): %s (%d)\n", gid, strerror (errno), errno);
      return 1;
    }

  if (uid > 0)
    if (setuid(uid) == -1) {
      fprintf(stderr, "Failed to setuid(%d): %s (%d)\n", uid, strerror (errno), errno);
      return 1;
    }
  
  /* it appears libevent bufferevent can cause a PIPE */
  signal (SIGPIPE, SIG_IGN);

  /* Prepare address of SOCKS5-Server */
  bzero (&socks_addr, sizeof (socks_addr));
  socks_addr.sin_family = AF_INET;
  socks_addr.sin_port = htons (socksport);
  
  if (inet_pton (AF_INET, sockshost, &socks_addr.sin_addr.s_addr) > 0)
    sockshost = 0;
  
  /* Create our server socket */
  if ((serverfd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
    perror ("Could not create socket");
    return 1;
  }
  
  bzero (&addr, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (bindport);
  
  if (inet_pton (AF_INET, bindhost, &addr.sin_addr.s_addr) <= 0) {
    perror ("Could not parse Host");
    return 1;
  }
  
  setsockopt (serverfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));
  
  if (bind (serverfd, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
    perror ("Could not bind our socket");
    return 1;
  }
  
  if (listen (serverfd, SOMAXCONN) < 0) {
    perror ("listen failed");
    return 1;
  }
  
  /* Setup Event-Handing */
  event_init ();
  if (sockshost != 0) {
    evdns_init ();
    randfd = open ("/dev/urandom", O_RDONLY);
    if (randfd == -1)
      fprintf (stderr, "can't open /dev/urandom: %s (%d). continuing, but will not randomize dns replies.\n");
  }    
 
  event_set (&ev_server, serverfd, EV_READ, new_connection, &ev_server);
  event_add (&ev_server, NULL);
  
  event_dispatch ();

  if (pid_fd > 0) {
    close(pid_fd);
  }
  
  return 0;
}

