/* A TCP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

//SERVER

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <glib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>

#include <time.h>
#include <glib.h>
#include <glib/gprintf.h>


/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
     const struct sockaddr_in *_addr1 = addr1;
     const struct sockaddr_in *_addr2 = addr2;

     /* If either of the pointers is NULL or the addresses
        belong to different families, we abort. */
     g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
              (_addr1->sin_family != _addr2->sin_family));

     if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
          return -1;
     } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
          return 1;
     } else if (_addr1->sin_port < _addr2->sin_port) {
          return -1;
     } else if (_addr1->sin_port > _addr2->sin_port) {
          return 1;
     }
     return 0;
}


/* This can be used to build instances of GTree that index on
   the file descriptor of a connection. */
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data)
{
     return GPOINTER_TO_INT(fd1) - GPOINTER_TO_INT(fd2);
}



int main(int argc, char **argv)
{ 
  const int server_port = strtol(argv[1], NULL, 10);
  int err,sock;
  struct sockaddr_in server, client;
  socklen_t len;
  int listen_sock;
  SSL_METHOD *meth;
  SSL_CTX *ssl_ctx;
  static SSL *server_ssl;
  SSL_library_init();
  SSL_load_error_strings();

  meth = TLSv1_server_method();
  ssl_ctx = SSL_CTX_new(meth);
  
  const char* certificate;
  certificate = "fd.crt";  
  if(SSL_CTX_use_certificate_file(ssl_ctx, certificate, SSL_FILETYPE_PEM) <= 0){
      //ERR_print_errors(bio_err);
      printf("error loading certificate \n");
      exit(1);
  }

  const char* privatekey;
  privatekey = "fd.key";
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, privatekey, SSL_FILETYPE_PEM) <= 0){
      printf("error loading private key \n");
      exit(1);
  }

  listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  
    //CHK_ERR(listen_sock, "socket");

  memset(&server, 0, sizeof(server));
  server.sin_family      = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port        = htons(server_port);      /* Server Port number */
     
  err = bind(listen_sock, (struct sockaddr*)&server,sizeof(server));
     
  /* Receive a TCP connection. */
  err = listen(listen_sock, 5);
  //CHK_ERR(err, "listen");

    
      //BIO_printf(bio_c_out, "Connection from %lx, port %x\n", 
      //sa_cli.sin_addr.s_addr, sa_cli.sin_port);

  if (argc != 2) {
      fprintf(stderr, "Usage: %s <port>\n", argv[0]);
      exit(EXIT_FAILURE);
  }

  char buf[4096];


  for(;;){
    len = (socklen_t) sizeof(client);
    sock = accept(listen_sock, (struct sockaddr*)&client, &len);
    /* Initialize OpenSSL */
    server_ssl = SSL_new(ssl_ctx);

    /* Get current date */
    time_t mytime;
    time(&mytime);  
 
    char *ip_addr = inet_ntoa(client.sin_addr);
    int *port_addr = ntohs(client.sin_port);
    

    if(server_ssl){
      SSL_set_fd(server_ssl, sock);
      err = SSL_accept(server_ssl);
      printf("%s : <%s>:<%d> connected\n",g_strstrip(ctime(&mytime)), ip_addr, port_addr);

      err = SSL_write(server_ssl, "Server: Welcome!", 16);
    }
    
  }

  err = SSL_shutdown(server_ssl);
  err = close(sock);
  SSL_free(server_ssl);
  SSL_CTX_free(ssl_ctx);
  
  exit(EXIT_SUCCESS);
}
