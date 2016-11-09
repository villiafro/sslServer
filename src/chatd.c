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

struct user{
  char *username;
  char *chatroom;
  SSL *ssl;
  int fd;
  char *ip_addr;
  int *port_addr;
}user;

struct chatroom{
  GList *rooms;
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
  ListOfChatrooms = g_string_append(ListOfChatrooms,key);
  ListOfChatrooms = g_string_append(ListOfChatrooms,"\n");
  return 0;
}

void joinRoom(char *roomName, gpointer userinfo){
  struct user* current_user = (struct user*)userinfo;

  //removing from current room, if any
  GSList *current_room = g_tree_lookup(chatrooms, current_user->chatroom);
  current_room = g_slist_remove(current_room, current_user);
  g_tree_insert(chatrooms,current_user->chatroom, current_room);
  

  //add user to room 
  GSList *users_in_room = g_tree_lookup(chatrooms,roomName);
  users_in_room = g_slist_prepend(users_in_room,current_user);
  g_tree_insert(chatrooms,roomName,users_in_room);

  current_user->chatroom = strdup(roomName);

  //send a welcome message to the user
  //char welcomeMessage[100];
  //sprintf(welcomeMessage, "Welcome to %s \n", roomName);
  int err = SSL_write(current_user->ssl, "Welcome to room", 15);
}

void changeUserName(char *new_username, gpointer userinfo){
  struct user* current_user = (struct user*)userinfo;

  current_user->username = strdup(new_username);

  int err = SSL_write(current_user->ssl, "Username changed", 16);
}

void sentToChatroom(gpointer key, gpointer data){
  char *message = data;
  struct user *recievingUser = (struct user *)key;
  SSL_write(recievingUser->ssl, message, strlen(message));
  return 0;
}

void logConnection(char *ip_addr, int *port_addr, int connecting){
  /* Get current date */
          time_t mytime;
          time(&mytime); 
  if(connecting == 1){
      printf("%s : <%s>:<%d> connected\n",g_strstrip(ctime(&mytime)), ip_addr, port_addr);
  }
  else{
      printf("%s : <%s>:<%d> disconnected\n",g_strstrip(ctime(&mytime)), ip_addr, port_addr);
  }

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
        logConnection(current_user->ip_addr, current_user->port_addr,0);
        //add timetampt disconnect
      }
      else if(err > 0){
        if(strncmp("/who",buf,4) == 0){
            buf[err] = "\0";
            ListOfUsers = g_string_new("All Users:\n");
            g_tree_foreach(connections,AddToUserList,current_set);

            SSL_write(current_user->ssl,ListOfUsers->str, strlen(ListOfUsers->str));
            g_string_free(ListOfUsers,1);
        }
        else if(strncmp("/list", buf, 5) == 0){
          buf[err] = "\0";
          ListOfChatrooms = g_string_new("All Chatrooms:\n");
          g_tree_foreach(chatrooms,AddToChatroomList,NULL);

          SSL_write(current_user->ssl,ListOfChatrooms->str,strlen(ListOfChatrooms->str));
          g_string_free(ListOfChatrooms,1);
        }
        else if(strncmp("/join",buf, 5) == 0){
          int i = 5;
          while (buf[i] != '\0' && isspace(buf[i])) { i++; }
          char *chatroom = g_new0(char, strlen(buf) - 5);
          strcpy(chatroom, buf+i);

          joinRoom(chatroom, current_user);
        }
        else if(strncmp("/bye", buf, 4) == 0){
          logConnection(current_user->ip_addr, current_user->port_addr,0);
          g_tree_remove(connections, key);
        }
        else if(strncmp("/say", buf, 4) == 0){
          int i = 4;
          while (buf[i] != '\0' && isspace(buf[i])) { i++; }

          int j = i+1;
          while (buf[j] != '\0' && isgraph(buf[j])) { j++; }

          //char *receiver = strndup(&(line[i]), j - i - 1);
          //char *message = strndup(&(line[j]), j - i - 1);

          //char *receiver = g_new0(char, strlen(buf) - 4);
          //strcpy(receiver, buf+i);

          //sendPM();
        }
        else if(strncmp("/user", buf, 5) == 0){
          int i = 5;
          while (buf[i] != '\0' && isspace(buf[i])) { i++; }
          char *user = g_new0(char, strlen(buf) - 5);
          strcpy(user, buf+i);

          changeUserName(user, current_user);
        }
        else{
          //meaning a message to your room 
          GSList *users_in_room = g_tree_lookup(chatrooms,current_user->chatroom);
          g_slist_foreach(users_in_room, sentToChatroom, buf);

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
  chatrooms = g_tree_new((GCompareFunc)strcmp);

  g_tree_insert(chatrooms,"Public",NULL);
  g_tree_insert(chatrooms,"TSAM",NULL);

  meth = TLSv1_server_method();
  ssl_ctx = SSL_CTX_new(meth);
  
  const char* certificate;
  certificate = "fd.crt";  
  if(SSL_CTX_use_certificate_file(ssl_ctx, certificate, SSL_FILETYPE_PEM) <= 0){
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
     
          char *ip_addr = inet_ntoa(client->sin_addr);
          int *port_addr = ntohs(client->sin_port);
        

          if(server_ssl){
            SSL_set_fd(server_ssl, sock);
            err = SSL_accept(server_ssl);
            if(err == -1){
              printf("SSL connection failed\n");
            }
            else{
              logConnection(ip_addr,port_addr,1);

              /*construct a new user instance*/
              struct user *new_user = g_new0(struct user, 1);
              new_user->username = "Anonymous";
              new_user->fd = sock;
              new_user->ssl = server_ssl;
              new_user->chatroom = "Public";
              new_user->ip_addr = ip_addr;
              new_user->port_addr = port_addr;

              GSList *rooms = g_tree_lookup(chatrooms,"Public");
              rooms = g_slist_prepend(rooms,new_user);
              g_tree_insert(chatrooms,"Public",rooms);

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
