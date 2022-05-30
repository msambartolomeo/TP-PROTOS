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
#include <arpa/inet.h>

#define DEFAULT_PORT_CLIENT_LISTEN 1080
#define DEFAULT_PORT_SERVER_LISTEN 1081
#define DEFAULT_PORT_SERVER_WRITE 80

int main(int argc, const char **argv) {
    const char * error_msg = NULL;

    int clientSocket = -1;

    const int passiveSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!(passiveSocket)) {
        error_msg = "unable to create socket";
        goto error;
    }
    
    setsockopt(passiveSocket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    struct sockaddr_in passiveaddr;
    passiveaddr.sin_addr.s_addr = INADDR_ANY;
    passiveaddr.sin_family = AF_INET;
    passiveaddr.sin_port = htons(DEFAULT_PORT_CLIENT_LISTEN);
    if(bind(passiveSocket, (struct sockaddr *) &passiveaddr, sizeof(passiveaddr)) < 0) {
        error_msg = "bind client socket error";
        goto error;
    } 

    if (listen(passiveSocket, 1) < 0) {
        error_msg = "listen client socket error";
        goto error;
    }

    int serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(!passiveSocket) {
        error_msg = "unable to create socket";
    }
    
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(1081);
    
    if(inet_aton("127.0.0.1", &serveraddr.sin_addr) <= 0) {
        error_msg = "inet_aton error";
        goto error;
    }

    if(connect(serverSocket, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr_in)) < 0) {
        error_msg = "couldn't connect to server";
        goto error;
    }

    while(1) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(passiveSocket, &read_fds);
        FD_SET(serverSocket, &read_fds);

        if(clientSocket != -1)
            FD_SET(clientSocket, &read_fds);           

        struct timeval timeout;
        timeout.tv_sec = 100; // 10 seconds timeout
        if(select(10,&read_fds, NULL, NULL, &timeout) < 0) {
            error_msg = "select error";
            goto error;
        }

        if (FD_ISSET(passiveSocket, &read_fds)) {
            int fd = accept(passiveSocket, NULL, NULL); //TODO: chequear error
            
            if(clientSocket != -1){
                close(clientSocket);
                printf("CLIENT CONNECTION CLOSED\n");
            }

            clientSocket = fd;
            printf("NEW CLIENT CONNECTION\n");
        }

        if(clientSocket != -1 && FD_ISSET(clientSocket, &read_fds)) {
            char buf[1024];
            int len = recv(clientSocket, buf, 1023, MSG_DONTWAIT);

            if(len <= 0){
                if(len == -1)
                    perror("CLIENT READ ERROR: ");

                close(clientSocket);
                clientSocket = -1;
                printf("CLIENT CONNECTION CLOSED\n");

                close(serverSocket);
                serverSocket = -1;
                printf("SERVER CONNECTION CLOSED\n");

                return 0;
            }
            else {
                //BLOQUEANTE
                if(serverSocket != -1)
                    send(serverSocket, buf, len, 0);
            }
        }

        if(serverSocket != -1 && FD_ISSET(serverSocket, &read_fds)) {
            char buf[1024];
            int len = recv(serverSocket, buf, 1023, MSG_DONTWAIT);

            if(len <= 0){
                if(len == -1)
                    perror("SERVER READ ERROR: ");

                close(serverSocket);
                serverSocket = -1;
                printf("SERVER CONNECTION CLOSED\n");

                close(clientSocket);
                clientSocket = -1;
                printf("CLIENT CONNECTION CLOSED\n");

                return 0;
            }
            else {
                //BLOQUEANTE
                if(clientSocket != -1)
                    send(clientSocket, buf, len, 0);
            }
        }
    }
    
error:
    // close(passiveSocket);
    // close(clientSocket);
    // close(serverSocket);

    if (error_msg){
        perror(error_msg);
        return -1;
    }
}
