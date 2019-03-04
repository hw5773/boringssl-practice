#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"

#define FAIL          -1
#define BUF_SIZE      16384
#define MAX_HOST_LEN  256

#define DELIMITER     "\r\n"
#define DELIMITER_LEN 2

#define INDEX_FILE      "/index.html"
#define INDEX_FILE_LEN  12

#define MAX_FILE_NAME_LEN 256

struct rinfo
{
  FILE *fp;
  uint8_t *domain;
  uint32_t dlen;
  uint8_t *content;
  uint32_t clen;
  uint32_t size;
  uint32_t sent;
};

int open_listener(int port);
SSL_CTX* init_server_ctx(void);
void load_certificates(SSL_CTX* ctx);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);
int running = 1;
int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r);
size_t fetch_content(uint8_t *buf, struct rinfo *r);
int fetch_cert(SSL *ssl, int *ad, void *arg);

void int_handler(int dummy)
{
  DEBUG_MSG("End of experiment");
  running = 0;
  exit(0);
}

int main(int count, char *strings[])
{  
	SSL *ssl;
	SSL_CTX *ctx;
	int server, client, sent = -1, rcvd = -1, offset = 0, success = 1, mlen = 0;
	char *portnum;

	if ( count != 2 )
	{
		DEBUG_MSG("Usage: %s <portnum>", strings[0]);
		exit(0);
	}

  signal(SIGINT, int_handler);
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];

	ctx = init_server_ctx();
  load_ecdh_params(ctx);
	load_certificates(ctx);

	server = open_listener(atoi(portnum));

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	while (running)
	{
    if ((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
      struct rinfo r;
      memset(&r, 0x0, sizeof(struct rinfo));
      char rbuf[BUF_SIZE] = {0};
      char wbuf[BUF_SIZE] = {0};

		  ssl = SSL_new(ctx);
		  SSL_set_fd(ssl, client);      

		  if (SSL_accept(ssl) == FAIL)
      {
			  ERR_print_errors_fp(stderr);
        success = 0;
      }
      DEBUG_MSG("Connected with %s\n", SSL_get_cipher(ssl));

      if (success)
      {
        while (rcvd < 0)
          rcvd = SSL_read(ssl, rbuf, BUF_SIZE);

        if (rcvd > 0)
        {
          http_parse_request(rbuf, rcvd, &r);
          fetch_content(wbuf, &r);
        }

        while (r.size > r.sent)
        {
          if ((r.size - r.sent) > BUF_SIZE)
            mlen = BUF_SIZE;
          else
            mlen = r.size - r.sent;
  		    r.sent += SSL_write(ssl, wbuf, mlen);
          fetch_content(wbuf, &r);
        }

        mlen = 0;
        offset = 0;
        rcvd = -1;
        sent = -1;
      }
      close(client);
      SSL_free(ssl);
      ssl = NULL;
      success = 1;

      memset(rbuf, 0x0, BUF_SIZE);
      memset(wbuf, 0x0, BUF_SIZE);
    }
	}

	SSL_CTX_free(ctx);
	close(server);

	return 0;
}

int open_listener(int port)
{   
  int sd;
	struct sockaddr_in addr;
  int enable;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	enable = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
  {
    perror("setsockopt(SO_REUSEADDR) failed");
    abort();
  }

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

SSL_CTX* init_server_ctx(void)
{   
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();
	method = (SSL_METHOD *) TLS_server_method();
	ctx = SSL_CTX_new(method);
	if ( ctx == NULL )
	{
		DEBUG_MSG("SSL_CTX init failed!");
		abort();
	}

  SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256");

	return ctx;
}

void load_certificates(SSL_CTX* ctx)
{
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

  SSL_CTX_set_tlsext_servername_callback(ctx, fetch_cert);
}

void load_dh_params(SSL_CTX *ctx, char *file)
{
  DH *ret = 0;
  BIO *bio;

  if ((bio = BIO_new_file(file, "r")) == NULL)
  {
    perror("Couldn't open DH file");
  }

  BIO_free(bio);

  if (SSL_CTX_set_tmp_dh(ctx, ret) < 0)
  {
    perror("Couldn't set DH parameters");
  }
}

void load_ecdh_params(SSL_CTX *ctx)
{
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    perror("Couldn't load the ec key");

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

int fetch_cert(SSL *ssl, int *ad, void *arg)
{
  (void) ad;
  (void) arg;

  int ret;
  uint8_t crt_path[MAX_HOST_LEN];
  uint8_t priv_path[MAX_HOST_LEN];
  uint8_t *p;
  uint32_t len;

  if (!ssl)
    return SSL_TLSEXT_ERR_NOACK;

  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

  if (!name || name[0] == '\0')
    return SSL_TLSEXT_ERR_NOACK;

  memset(crt_path, 0x0, MAX_HOST_LEN);
  memset(priv_path, 0x0, MAX_HOST_LEN);

  p = crt_path;
  len = strlen(name);
  memcpy(p, name, len);

  ret = mkdir(p, 0775);
  if (ret < 0)
  {
    if (errno == EEXIST)
    {
    }
    else
    {
      DEBUG_MSG("Other error");
    }
  }

  p += len;
  memcpy(p, "/cert.der", 9);

  p = priv_path;
  len = strlen(name);
  memcpy(p, name, len);

  p += len;
  memcpy(p, "/priv.der", 9);

  if (SSL_use_certificate_file(ssl, crt_path, SSL_FILETYPE_ASN1) != 1)
  {
    DEBUG_MSG("Loading the certificate error");
    return SSL_TLSEXT_ERR_NOACK;
  }

  DEBUG_MSG("Loading the certificate success");

  if (SSL_use_PrivateKey_file(ssl, priv_path, SSL_FILETYPE_ASN1) != 1)
  {
    DEBUG_MSG("Loading the private key error");
    return SSL_TLSEXT_ERR_NOACK;
  }
  
  DEBUG_MSG("Loading the private key success");

  if (SSL_check_private_key(ssl) != 1)
  {
    DEBUG_MSG("Checking the private key error");
    return SSL_TLSEXT_ERR_NOACK;
  }

  DEBUG_MSG("Checking the private key success");

  return SSL_TLSEXT_ERR_OK;
}

size_t fetch_content(uint8_t *buf, struct rinfo *r)
{
	const char *resp = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %ld\r\n"
		"\r\n";

  size_t total, sz;
  uint8_t path[MAX_HOST_LEN];
  uint8_t *p;
  int rlen;
  rlen = 0;

  if (r->size != 0 && r->size <= r->sent)
  {
    fclose(r->fp);
    goto ret;
  }

  if (!(r->fp))
  {
    memset(path, 0x0, MAX_HOST_LEN);
    p = path;

    memcpy(p, r->domain, r->dlen);
    p += r->dlen;
  
    memcpy(p, r->content, r->clen);

    r->fp = fopen(path, "rb");

    if (!(r->fp))
    {
      r->size = -1;
      goto ret;
    }
  }

  if (r->size == 0)
  {
    fseek(r->fp, 0L, SEEK_END);
    r->size = total = ftell(r->fp);
    sz = total - r->sent;
  }

  memset(buf, 0x0, BUF_SIZE);
  p = buf;
  
  if (r->sent == 0)
  {
    snprintf(p, BUF_SIZE, resp, sz);
    rlen = strlen(buf);
    r->size += rlen;
    p += rlen;
  }

  fseek(r->fp, r->sent, SEEK_SET);

  if (r->size - r->sent > BUF_SIZE)
  {
    if (r->sent == 0)
      sz = BUF_SIZE - (r->sent);
    else
      sz = BUF_SIZE;
  }
  else
  {
    sz = r->size - r->sent;
  }
  fread(p, 1, sz, r->fp);

ret:
  return r->size;
}

int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r)
{
  (void) mlen;
  int l;
  uint8_t *cptr, *nptr, *p, *q;
  struct rinfo *info;

  info = r;
  cptr = msg;

  while ((nptr = strstr(cptr, DELIMITER)))
  {
    l = nptr - cptr;
    p = cptr;
    
    while (*p == ' ')
      p++;

    if ((l > 0) && (strncmp((const char *)p, "GET", 3) == 0))
    {
      p += 3;

      while (*p != '/')
        p++;

      q = p;

      while (*q != ' ' && *q != '\r')
        q++;

      if (q - p == 1)
      {
        info->content = (uint8_t *)malloc(INDEX_FILE_LEN + 1);
        memset(info->content, 0x0, INDEX_FILE_LEN + 1);
        memcpy(info->content, INDEX_FILE, INDEX_FILE_LEN);
        info->clen = INDEX_FILE_LEN;
      }
      else
      {
        info->content = (uint8_t *)malloc(q - p + 1);
        memset(info->content, 0x0, q - p + 1);
        memcpy(info->content, p, q - p);
        info->clen = q - p;
      }
    }

    if ((l > 0) && (strncmp((const char *)p, "Host:", 5) == 0))
    {
      p += 5;

      while (*p == ' ')
        p++;

      info->domain = (uint8_t *)malloc(nptr - p + 1);
      memset(info->domain, 0x0, nptr - p + 1);
      memcpy(info->domain, p, nptr - p);
      info->dlen = nptr - p;
    }

    cptr = nptr + DELIMITER_LEN;
  }

  return 1;
}
