#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define DEFAULT_PORT_CLIENT_LISTEN 1080
#define DEFAULT_PORT_SERVER_LISTEN 1081
#define DEFAULT_PORT_SERVER_WRITE 80

int main(int argc, const char **argv) {
    const char * error_msg = NULL;

    const int clientListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);    
    const int serverListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!(clientListenSocket && serverListenSocket)) {
        error_msg = "unable to create socket";
        goto error;
    }

    struct sockaddr_in clientaddr;
    clientaddr.sin_addr.s_addr = INADDR_ANY;
    clientaddr.sin_family = AF_INET;
    clientaddr.sin_port = htons(DEFAULT_PORT_CLIENT_LISTEN);
    if(bind(clientListenSocket, (struct sockaddr *) &clientaddr, sizeof(clientaddr)) < 0) {
        error_msg = "bind client socket error";
        goto error;
    } 

    if (listen(clientListenSocket, 1) < 0) {
        error_msg = "listen client socket error";
        goto error;
    }

    struct sockaddr_in serveraddr;
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(DEFAULT_PORT_SERVER_LISTEN);
    if(bind(serverListenSocket, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
        error_msg = "bind server socket error";
        goto error;
    }

    if (listen(serverListenSocket, 1) < 0) {
        error_msg = "listen server socket error";
        goto error;
    }
    
    while(1) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(serverListenSocket, &read_fds);
        FD_SET(clientListenSocket, &read_fds);

        struct timeval timeout;
        timeout.tv_sec = 100; // 10 seconds timeout
        printf("PRESELECT\n");
        if(select(5,&read_fds, NULL, NULL, NULL) < 0) {
            error_msg = "select error";
            goto error;
        }
        printf("SELECT\n");

        if (FD_ISSET(serverListenSocket, &read_fds)) {
            // FD_SET(clientListenSocket, &write_fds);
            printf("NUEVA CONEXION SERVER\n");
            int fd = accept(serverListenSocket, NULL, NULL); //TODO: chequear error
            char buf[1024];
            int len;

            //BLOQUEANTE
            while((len = read(fd, buf, 1023)) > 0) {
                buf[len]=0;
                printf("%s", buf);
            }
        }
        if (FD_ISSET(clientListenSocket, &read_fds)) {
            printf("NUEVA CONEXION CLIENTE\n");
            int fd = accept(clientListenSocket, NULL, NULL); //TODO: chequear error
            char buf[1024];
            int len;

            //BLOQUEANTE
            while((len = read(fd, buf, 1023)) > 0) {
                buf[len]=0;
                printf("%s", buf);
            }
        }
    }
    
    error:
        if (error_msg){
            perror(error_msg);
            return -1;
        }
}
