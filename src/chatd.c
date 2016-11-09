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

struct user{
  char *username;
  SSL *ssl;
  int fd;
}user;

struct chatroom{
  char *name;
}chatroom;


GTree *connections;
GString *ListOfUsers;
GTree *chatrooms;
GString *ListOfChatrooms;

static SSL *server_ssl;

fd_set rfds;

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
     const struct sockaddr_in *_addr1 = addr1;
     const struct sockaddr_in *_addr2 = addr2;

     /* If either of the pointers is NULL or the addresses
        belong to different families, we abort. */
     g_assert((_addr1 != NULL) && (_addr2 != NULL) &&
              (_addr1->sin_family == _addr2->sin_family));

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

static gint AddToUserList(gpointer key, gpointer uservalue, gpointer ret){
    struct user *user_adding = (struct user*)uservalue;
    ListOfUsers = g_string_append(ListOfUsers,user_adding->username);
    ListOfUsers = g_string_append(ListOfUsers,"\n");
    return 0;
}

static gint AddToChatroomList(gpointer key, gpointer chatroomvalue, gpointer ret){
  struct chatroom *chatroom_adding = (struct chatroom*)chatroomvalue;
  ListOfChatrooms = g_string_append(ListOfChatrooms,chatroom_adding->name);
  ListOfChatrooms = g_string_append(ListOfChatrooms,"\n");
  return 0;
}

gboolean readData(gpointer key, gpointer value, gpointer data){
  struct user *current_user = (struct user *) value;
  fd_set *current_set = (fd_set *) data;
  int err;
  char buf[2048];
  
  if(FD_ISSET(current_user->fd, current_set)){
      memset(buf, 0, 2048);
      err = SSL_read(current_user->ssl, buf, sizeof(buf) - 1);
      if(err <= 0){
        //printf("disconnecting client");
        //add timetampt disconnect
      }
      else if(err > 0){
        if(strncmp("/who",buf,4) == 0){
            ListOfUsers = g_string_new("All Users:\n");
            g_tree_foreach(connections,AddToUserList,current_set);

            SSL_write(current_user->ssl,ListOfUsers->str, strlen(ListOfUsers->str));
            g_string_free(ListOfUsers,1);
        }
        if(strncmp("/list", buf, 5) == 0){
          ListOfChatrooms = g_string_new("All Chatrooms:\n");
          g_tree_foreach(chatrooms,AddToChatroomList,NULL);

          SSL_write(current_user->ssl,ListOfChatrooms->str,strlen(ListOfChatrooms->str));
          g_string_free(ListOfChatrooms,1);
        }
      }
      
  }
  
  return FALSE;
}

gboolean setFd(gpointer key, gpointer user, gpointer ret){
  int user_fd = ((struct user*) user)->fd;
  int ret_fd = *(int *)ret;
  FD_SET(user_fd,&rfds);
  if(user_fd > ret_fd){
    *(int *)ret = user_fd;
  }
  return FALSE;
}



int main(int argc, char **argv)
{ 
  const int server_port = strtol(argv[1], NULL, 10);
  int err,sock;
  struct sockaddr_in server;
  struct sockaddr_in *client;
  socklen_t len;
  int listen_sock;
  SSL_METHOD *meth;
  SSL_CTX *ssl_ctx;
  
  SSL_library_init();
  SSL_load_error_strings();

  connections = g_tree_new(sockaddr_in_cmp);
  chatrooms = g_tree_new(sockaddr_in_cmp);

  struct chatroom *new_chatroom = g_new0(struct chatroom, 1);
              new_chatroom->name = "Public";

  g_tree_insert(chatrooms,"Public",new_chatroom);

  /*struct chatroom *new_chatroom2 = g_new0(struct chatroom, 1);
              new_chatroom2->name = "TSAM";

  g_tree_insert(chatrooms,"TSAM",new_chatroom2);*/

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

  memset(&server, 0, sizeof(server));
  server.sin_family      = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port        = htons(server_port);
     
  err = bind(listen_sock, (struct sockaddr*)&server,sizeof(server));
     
  /* Receive a TCP connection. */
  listen(listen_sock, 1);
  

  if (argc != 2) {
      fprintf(stderr, "Usage: %s <port>\n", argv[0]);
      exit(EXIT_FAILURE);
  }

  char buf[4096];


  for(;;){
    FD_ZERO(&rfds);
    FD_SET(listen_sock, &rfds);
    struct timeval tv;
    int retval;
    int highest_fd = -1;

    g_tree_foreach(connections,setFd,&highest_fd);

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    retval = select(((highest_fd > listen_sock) ? highest_fd : listen_sock) + 1, &rfds, NULL, NULL, &tv);

    if(retval == -1){
      perror("select()");
    }
    else if(retval > 0){
      //got a new connection
      if(FD_ISSET(listen_sock, &rfds)){
          client = g_new0(struct sockaddr_in, 1);

          len = (socklen_t) sizeof(client);
          sock = accept(listen_sock, (struct sockaddr*)client, &len);
            /* Initialize OpenSSL */
          server_ssl = SSL_new(ssl_ctx);

          /* Get current date */
          time_t mytime;
          time(&mytime);  
     
          char *ip_addr = inet_ntoa(client->sin_addr);
          int *port_addr = ntohs(client->sin_port);
        

          if(server_ssl){
            SSL_set_fd(server_ssl, sock);
            err = SSL_accept(server_ssl);
            if(err == -1){
              printf("SSL connection failed\n");
            }
            else{
              printf("%s : <%s>:<%d> connected\n",g_strstrip(ctime(&mytime)), ip_addr, port_addr);

              /*construct a new user instance*/
              struct user *new_user = g_new0(struct user, 1);
              new_user->username = "Anonymous";
              new_user->fd = sock;
              new_user->ssl = server_ssl;

              g_tree_insert(connections,client,new_user);

              err = SSL_write(server_ssl, "Server: Welcome!", 16);
            }
            
          }
          else{
            printf("SSL connection failed\n");
          }
      }
      g_tree_foreach(connections,readData, &rfds);
        
    }
    else{
      printf("No message recieved in the last 5 seconds\n");
    }
  }

  err = SSL_shutdown(server_ssl);
  err = close(sock);
  SSL_free(server_ssl);
  SSL_CTX_free(ssl_ctx);
  
  exit(EXIT_SUCCESS);
}
