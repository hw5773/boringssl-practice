#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/opensslv.h>
#include <errno.h>

#include "log.h"

#define FAIL    -1
#define BUF_SIZE 16384
#define DELIMITER "\r\n"
#define DELIMITER_LEN 2

void *run(void *data);
int open_connection(const char *domain, int port);
SSL_CTX* init_client_ctx(void);
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file);
void load_ecdh_params(SSL_CTX *ctx);
SSL_CTX *ctx;
const char *domain, *portnum, *fname, *content;
int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content, uint32_t clen,
    uint8_t *msg, uint32_t *mlen);
int http_parse_response(uint8_t *msg, uint32_t mlen);
static int char_to_int(uint8_t *str, uint32_t slen);

// Client Prototype Implementation
int main(int count, char *strings[])
{   
  if ( count != 5 )
  {
    DEBUG_MSG("usage: %s <domain> <portnum> <content name> <num of threads>", strings[0]);
    exit(0);
  }

	int i, rc, num_of_threads;
	fname = strings[5];

	num_of_threads = atoi(strings[4]);

	pthread_t thread[num_of_threads];
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	void *status;

  SSL_library_init();
  domain = strings[1];
  portnum = strings[2];
  content = strings[3];

  ctx = init_client_ctx();
  load_ecdh_params(ctx);

	for (i=0; i<num_of_threads; i++)
	{
		rc = pthread_create(&thread[i], &attr, run, NULL);

		if (rc)
		{
			return 1;
		}
	}

	pthread_attr_destroy(&attr);

	for (i=0; i<num_of_threads; i++)
	{
		rc = pthread_join(thread[i], &status);

		if (rc)
		{
			return 1;
		}
	}

	SSL_CTX_free(ctx);        /* release context */

  return 0;
}

void *run(void *data)
{	
	int server, rcvd, sent, ret, dlen, clen, total = 0, offset = 0;
  unsigned char buf[BUF_SIZE];
	SSL *ssl;
  SSL_SESSION *session = NULL;
  char request[BUF_SIZE];
  int rlen;

	server = open_connection(domain, atoi(portnum));

  ssl = SSL_new(ctx);   
  SSL_set_fd(ssl, server);
  SSL_set_tlsext_host_name(ssl, domain);

  if (session != NULL)
    SSL_set_session(ssl, session);

  dlen = strlen(domain);
  clen = strlen(content);

  if ( (ret = SSL_connect(ssl)) < 0 )
  {
    ERR_print_errors_fp(stderr);
    goto err;
  }
	else
	{
    DEBUG_MSG("Connected with %s\n", SSL_get_cipher(ssl));

    http_make_request((uint8_t *)domain, dlen, (uint8_t *)content, clen, request, &rlen);
    sent = SSL_write(ssl, request, rlen);
    rcvd = -1;

    do {
      while (rcvd <= 0)
        rcvd = SSL_read(ssl, buf, BUF_SIZE);

      if (rcvd > 0)
      {
        buf[rcvd] = 0;

        if (total <= 0)
        {
          total = http_parse_response(buf, rcvd);
        }
        offset += rcvd;
      }
      rcvd = -1;
    } while (total > offset);

		buf[rcvd] = 0;
    SSL_shutdown(ssl);
	}
       
err:
  if (!session)
    SSL_SESSION_free(session);
  if (!ssl)
  {
    SSL_free(ssl);
    ssl = NULL;
  }
  if (server != -1)
    close(server);

  return NULL;
}

int open_connection(const char *domain, int port)
{   
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;
            
  if ( (host = gethostbyname(domain)) == NULL )
  {
    perror(domain);
    abort();
  }
    
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
  {
    close(sd);
    perror(domain);
    abort();
  }
         
  return sd;
}

SSL_CTX* init_client_ctx(void)
{   
  SSL_METHOD *method;
  SSL_CTX *ctx;
        
  //OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
  SSL_load_error_strings();   /* Bring in and register error messages */
  method = (SSL_METHOD *)TLS_client_method();  /* Create new client-method instance */
  ctx = SSL_CTX_new(method);   /* Create new context */
  
  if ( ctx == NULL )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }

  return ctx;
}
 
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file)
{
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		DEBUG_MSG("SSL_CTX_load_verify_locations success\n");

	if ( SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		DEBUG_MSG("SSL_CTX_set_default_verify_paths success\n");

  /* set the local certificate from CertFile */
  if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
  {
    ERR_print_errors_fp(stderr);
    abort();
	}
  else
		DEBUG_MSG("SSL_CTX_use_certificate_file success\n");

	/* set the private key from KeyFile (may be the same as CertFile) */
  if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
	else
		DEBUG_MSG("SSL_CTX_use_PrivateKey_file success\n");
    
	/* verify private key */
  if ( !SSL_CTX_check_private_key(ctx) )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
	else
	   	DEBUG_MSG("Private key matches the public certificate\n");

//	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	ERR_print_errors_fp(stderr);
	SSL_CTX_set_verify_depth(ctx, 4);
	ERR_print_errors_fp(stderr);
  SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256");
}

void load_ecdh_params(SSL_CTX *ctx)
{
  EC_KEY *ecdh;
  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    perror("Couldn't load the ec key");

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content, uint32_t clen,
    uint8_t *msg, uint32_t *mlen)
{
  const uint8_t *get = "GET /";
  const uint8_t *http = " HTTP/1.1";
  const uint8_t *host = "Host: ";
  const uint8_t *header =
    "User-Agent: Wget/1.17.1 (linux-gnu)\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: identity\r\n\r\n";
  uint32_t hlen;
  uint8_t *p;

  hlen = strlen(header);

  p = msg;

  memcpy(p, get, 5);
  p += 5;

  if (clen > 0)
  {
    memcpy(p, content, clen);
    p += clen;
  }
  memcpy(p, http, 9);
  p += 9;

  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;
  memcpy(p, host, 6);
  p += 6;
  memcpy(p, domain, dlen);
  p += dlen;
  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;

  memcpy(p, header, hlen);
  p += hlen;

  memcpy(p, domain, dlen);
  p += dlen;
  *(p++) = 0;

  *mlen = p - msg;

  return *mlen;
}

int http_parse_response(uint8_t *msg, uint32_t mlen)
{
  int ret;
  uint32_t i, j, l;
  uint8_t *cptr, *nptr, *p;
  cptr = msg;

  while ((nptr = strstr(cptr, DELIMITER)))
  {
    l = nptr - cptr;
    p = cptr;

    for (i=0; i<l; i++)
    {
      if (p[i] == ' ')
        break;
    }

    if ((l > 0) && (strncmp((const char *)p, "Content-Length:", i) == 0))
    {
      for (j=i+1; j<l; j++)
      {
        if (p[j] == ' ')
          break;
      }
      ret = char_to_int(p + i + 1, j - i);
    }

    cptr = nptr + DELIMITER_LEN;
  }

  return ret;
}

static int char_to_int(uint8_t *str, uint32_t slen)
{
  int i;
  int ret = 0;
  uint8_t ch;

  for (i=0; i<slen; i++)
  {
    ch = str[i];
    if (ch == ' ')
      break;

    switch(ch)
    {
      case '0':
        ret *= 10;
        continue;
      case '1':
        ret = ret * 10 + 1;
        continue;
      case '2':
        ret = ret * 10 + 2;
        continue;
      case '3':
        ret = ret * 10 + 3;
        continue;
      case '4':
        ret = ret * 10 + 4;
        continue;
      case '5':
        ret = ret * 10 + 5;
        continue;
      case '6':
        ret = ret * 10 + 6;
        continue;
      case '7':
        ret = ret * 10 + 7;
        continue;
      case '8':
        ret = ret * 10 + 8;
        continue;
      case '9':
        ret = ret * 10 + 9;
        continue;
    }
  }

  return ret;
}
