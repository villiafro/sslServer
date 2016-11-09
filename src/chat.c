/* A UDP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

//CLIENT

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <dirent.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>


/* This variable holds a file descriptor of a pipe on which we send a
 * number if a signal is received. */
static int exitfd[2];


/* If someone kills the client, it should still clean up the readline
   library, otherwise the terminal is in a inconsistent state. The
   signal number is sent through a self pipe to notify the main loop
   of the received signal. This avoids a race condition in select. */
void
signal_handler(int signum)
{
    int _errno = errno;
    if (write(exitfd[1], &signum, sizeof(signum)) == -1 && errno != EAGAIN) {
        abort();
    }
    fsync(exitfd[1]);
    errno = _errno;
}


static void initialize_exitfd(void)
{
        /* Establish the self pipe for signal handling. */
    if (pipe(exitfd) == -1) {
        perror("pipe()");
        exit(EXIT_FAILURE);
    }

        /* Make read and write ends of pipe nonblocking */
    int flags;        
    flags = fcntl(exitfd[0], F_GETFL);
    if (flags == -1) {
        perror("fcntl-F_GETFL");
        exit(EXIT_FAILURE);
    }        
        flags |= O_NONBLOCK;                /* Make read end nonblocking */
    if (fcntl(exitfd[0], F_SETFL, flags) == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }

    flags = fcntl(exitfd[1], F_GETFL);
    if (flags == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }
        flags |= O_NONBLOCK;                /* Make write end nonblocking */
    if (fcntl(exitfd[1], F_SETFL, flags) == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }

        /* Set the signal handler. */
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;           /* Restart interrupted reads()s */
    sa.sa_handler = signal_handler;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }       
}


/* The next two variables are used to access the encrypted stream to
 * the server. The socket file descriptor server_fd is provided for
 * select (if needed), while the encrypted communication should use
 * server_ssl and the SSL API of OpenSSL.
 */
static int server_fd;
static SSL *server_ssl;
static struct sockaddr_in server_addr;

/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
static char *user;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static char *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;
int active = 1;



/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */

void sendToServer(char *message){
    int server_message = SSL_write(server_ssl, message, strlen(message));
    if(server_message == -1) { printf("Error sending message to server\n"); }
}

void readline_callback(char *line)
{
    int err;
    char hello[80];
    char buffer[256];

    if (NULL == line) {
        rl_callback_handler_remove();
        signal_handler(SIGTERM);
        return;
    }
    if (strlen(line) > 0) {
        add_history(line);
    }
    if ((strncmp("/bye", line, 4) == 0) || (strncmp("/quit", line, 5) == 0)) {
        sendToServer("/bye");
        active = 0;
        rl_callback_handler_remove();
        signal_handler(SIGTERM);
        return;
    }
    if (strncmp("/game", line, 5) == 0) {
                    /* Skip whitespace */
        int i = 4;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /game username\n",
              29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
                    /* Start game */
        return;
    }
    if (strncmp("/join", line, 5) == 0) {
        int i = 5;
                    /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }

        char *chatroom = strdup(&(line[i]));
        sendToServer(line);

    /* Process and send this information to the server. */

    /* Maybe update the prompt. */
    //char *chatroomprompt;
    //sprintf(chatroomprompt, "%s > ", chatroom);

    //free(prompt);
    //prompt = strdup(chatroomprompt); /* What should the new prompt look like? */
    //rl_set_prompt(prompt);
    return;
}
if (strncmp("/list", line, 5) == 0) {
                /* Query all available chat rooms */
    sendToServer("/list");
    return;
}
if (strncmp("/roll", line, 5) == 0) {
                /* roll dice and declare winner. */
    
    return;
}
if (strncmp("/say", line, 4) == 0) {
                /* Skip whitespace */
    int i = 4;
    while (line[i] != '\0' && isspace(line[i])) { i++; }
    if (line[i] == '\0') {
        write(STDOUT_FILENO, "Usage: /say username message\n",29);
        fsync(STDOUT_FILENO);
        rl_redisplay();
        return;
    }
                /* Skip whitespace */
    int j = i+1;
    while (line[j] != '\0' && isgraph(line[j])) { j++; }
    if (line[j] == '\0') {
        write(STDOUT_FILENO, "Usage: /say username message\n",29);
        fsync(STDOUT_FILENO);
        rl_redisplay();
        return;
    }
    char *receiver = strndup(&(line[i]), j - i - 1);
    char *message = strndup(&(line[j]), j - i - 1);

                /* Send private message to receiver. */
    sendToServer(line);
    return;
}
if (strncmp("/user", line, 5) == 0) {
    int i = 5;
                /* Skip whitespace */
    while (line[i] != '\0' && isspace(line[i])) { i++; }
    if (line[i] == '\0') {
        write(STDOUT_FILENO, "Usage: /user username\n", 22);
        fsync(STDOUT_FILENO);
        rl_redisplay();
        return;
    }
    char *new_user = strdup(&(line[i]));
    //char passwd[48];
    //getpasswd("Password: ", passwd, 48);

                /* Process and send this information to the server. */

                /* Maybe update the prompt. */
    //free(prompt);
    //prompt = NULL; /* What should the new prompt look like? */
    //rl_set_prompt(prompt);
    sendToServer(line);
    return;
}
if (strncmp("/who", line, 4) == 0) {
                /* Query all available users */
    sendToServer("/who");

    return;
}
        /* Sent the buffer to the server. */

sendToServer(line);
return;
}

int main(int argc, char **argv)
{
    initialize_exitfd();

        /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    SSL_METHOD *meth;
    SSL_CTX *ssl_ctx;
    int err,sock;
    
    const char *s_ipaddr = "127.0.0.1";
    const int server_port = strtol(argv[1], NULL, 10);
    char buf [4096];

    
    meth = TLSv1_client_method();
    ssl_ctx = SSL_CTX_new(meth);

    if(ssl_ctx == NULL){
        printf("couldnt initalize ssl_cts\n");
    }

    const char* certificate;
    certificate = "clientkey.crt";
    if(SSL_CTX_use_certificate_file(ssl_ctx,certificate, SSL_FILETYPE_PEM) <= 0){
            printf("error loading certificate \n");
            exit(1);
    }

    const char* privatekey;
    privatekey = "client.key";
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, privatekey, SSL_FILETYPE_PEM) <= 0){
        printf("error loading private key \n");
        exit(1);
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock == -1){
        printf("sock error\n");
    }

    memset (&server_addr, '\0', sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(server_port); /* Server Port number */
    server_addr.sin_addr.s_addr = inet_addr(s_ipaddr); 

    /* TCP/IP Connection */
    err = connect(sock, (struct sockaddr*) &server_addr, sizeof(server_addr));

    if(err == -1){
        printf("failed to create TCP/IP connection \n");
    }

    /* Use the socket for the SSL connection. */
    server_ssl = SSL_new(ssl_ctx);
    if(server_ssl == NULL){
        printf("server_ssl is NULL\n");
    }

    SSL_set_fd(server_ssl, sock);

    int handshake = SSL_connect(server_ssl);
    if(handshake == -1){
        printf("error connecting on SSL \n");
    }

    prompt = strdup("> ");
    rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
     
    while(active == 1){        
        fd_set rfds;
        struct timeval timeout;

        /* You must change this. Keep exitfd[0] in the read set to
        receive the message from the signal handler. Otherwise,
        the chat client can break in terrible ways. */
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(exitfd[0], &rfds);
        FD_SET(sock,&rfds);
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        //int r = select(exitfd[0] + 1, &rfds, NULL, NULL, &timeout);
        int r = select(((sock > STDIN_FILENO) ? sock: STDIN_FILENO) + 1, &rfds, NULL, NULL, &timeout);
        if (r < 0) {
            if (errno == EINTR) {
                                    /* This should either retry the call or
                                       exit the loop, depending on whether we
                                       received a SIGTERM. */
                continue;
            }
                            /* Not interrupted, maybe nothing we can do? */
            perror("select()");
            break;
        }
        /*if (r == 0) {
            write(STDOUT_FILENO, "No message?\n", 12);
            fsync(STDOUT_FILENO);
                            // Whenever you print out a message, call this
                               to reprint the current input line. 
            rl_redisplay();
            continue;
        }
        if (FD_ISSET(exitfd[0], &rfds)) {
            printf ("revieved a signal \n");
                            // We received a signal.
            int signum;
            for (;;) {
                if (read(exitfd[0], &signum, sizeof(signum)) == -1) {
                    if (errno == EAGAIN) {
                        printf ("error EAGAIN \n");
                        break;
                    } else {
                        perror("read()");
                        exit(EXIT_FAILURE);
                    }
                }

            }
            if (signum == SIGINT) {
                                    // Don't do anything.
            } else if (signum == SIGTERM) {
                                    // Clean-up and exit. 
                break;
            }

        }*/
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            rl_callback_read_char();            
        }
        if(FD_ISSET(sock, &rfds)) {
            int message_worked = SSL_read(server_ssl, buf, sizeof(buf) - 1);

            if(message_worked == -1) {
                printf("Error reading form server\n");
                break;
            }

            if(message_worked == 0) {
                /* Connection terminated */
                break;
            }

            buf[message_worked] = '\0';
            write(STDOUT_FILENO, buf, strlen(buf));
            write(STDOUT_FILENO, "\n", 1);
            write(STDOUT_FILENO, prompt, strlen(prompt));
            fsync(STDOUT_FILENO);
        }
    }

    	/* Now we can create BIOs and use them instead of the socket.
    	 * The BIO is responsible for maintaining the state of the
    	 * encrypted connection and the actual encryption. Reads and
    	 * writes to sock_fd will insert unencrypted data into the
    	 * stream, which even may crash the server.
    	 */

            /* Set up secure connection to the chatd server. */


    /* Read characters from the keyboard while waiting for input.*/

    //prompt = strdup("> ");
    //rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);


    err = SSL_shutdown(server_ssl);
    err = close(sock);
    SSL_free(server_ssl);
    SSL_CTX_free(ssl_ctx);
}
