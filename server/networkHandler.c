#include "networkHandler.h"

#define DEFAULT_CLIENT_PORT 1080
#define DEFAULT_SERVER_PORT 80
#define SEND_BUF_SIZE 1024

static buffer serverSendBuf;
static buffer clientSendBuf;
static uint8_t serverSendBufData[SEND_BUF_SIZE];
static uint8_t clientSendBufData[SEND_BUF_SIZE];

static int clientSocket = -1;
static int serverSocket = -1;

void closeConnection() {
    if(serverSocket != -1)
        close(serverSocket);
    if(clientSocket != -1)
        close(clientSocket);
    serverSocket = -1;
    clientSocket = -1;
    buffer_reset(&serverSendBuf);
    buffer_reset(&clientSendBuf);
    printf("CONNECTION CLOSED\n");
}

void networkHandlerCleanup() {
    closeConnection();
}

int networkHandler() {
    char * error_msg = NULL;

    const int passiveSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!(passiveSocket)) {
        error_msg = "unable to create socket";
        goto error;
    }
    
    setsockopt(passiveSocket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    struct sockaddr_in passiveaddr = {0};
    passiveaddr.sin_addr.s_addr = INADDR_ANY;
    passiveaddr.sin_family = AF_INET;
    passiveaddr.sin_port = htons(DEFAULT_CLIENT_PORT);
    if(bind(passiveSocket, (struct sockaddr *) &passiveaddr, sizeof(passiveaddr)) < 0) {
        error_msg = "bind client socket error";
        goto error;
    } 

    if (listen(passiveSocket, 1) < 0) {
        error_msg = "listen client socket error";
        goto error;
    }

    buffer_init(&clientSendBuf, SEND_BUF_SIZE, clientSendBufData);
    buffer_init(&serverSendBuf, SEND_BUF_SIZE, serverSendBufData);

    while(1) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(passiveSocket, &read_fds);

        if(clientSocket != -1) {
            if(buffer_can_write(&serverSendBuf))
                FD_SET(clientSocket, &read_fds);
            if(buffer_can_read(&clientSendBuf))
                FD_SET(clientSocket, &write_fds);   
        }
            
        if(serverSocket != -1) {
            if(buffer_can_write(&clientSendBuf))
                FD_SET(serverSocket, &read_fds);
            if(buffer_can_read(&serverSendBuf))
                FD_SET(serverSocket, &write_fds);
        } 

        struct timeval timeout = {0};
        timeout.tv_sec = 100; // 10 seconds timeout
        if(select(20, &read_fds, &write_fds, NULL, &timeout) < 0) {
            error_msg = "select error";
            goto error;
        }

        if (FD_ISSET(passiveSocket, &read_fds)) {
            int fd = accept(passiveSocket, NULL, NULL); //TODO: chequear error
            
            if(clientSocket != -1){
                closeConnection();
            }

            clientSocket = fd;

            serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if(!serverSocket) {
                error_msg = "unable to create socket";
            }
            
            struct sockaddr_in serveraddr = {0};
            serveraddr.sin_family = AF_INET;
            serveraddr.sin_port = htons(DEFAULT_SERVER_PORT);
            
            if(inet_aton("127.0.0.1", &serveraddr.sin_addr) <= 0) {
                error_msg = "inet_aton error";
                goto error;
            }

            if(connect(serverSocket, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr_in)) < 0) {
                perror("SERVER CONNECTION ERROR");
                closeConnection();
            }
            else {
                printf("NEW CONNECTION\n");
            }
        }

        if(clientSocket != -1 && FD_ISSET(clientSocket, &read_fds)) {
            size_t wbytes;
            uint8_t* bufptr = buffer_write_ptr(&serverSendBuf, &wbytes);
            
            int len = recv(clientSocket, bufptr, wbytes, MSG_DONTWAIT);

            if(len <= 0){
                if(len == -1)
                    perror("CLIENT READ ERROR");

                closeConnection();
            }
            else {
                write(STDOUT_FILENO, bufptr, len);
                printf("\n\n");

                buffer_write_adv(&serverSendBuf, len);
            }
        }

        if(serverSocket != -1 && FD_ISSET(serverSocket, &read_fds)) {
            size_t wbytes;
            uint8_t* bufptr = buffer_write_ptr(&clientSendBuf, &wbytes);

            int len = recv(serverSocket, bufptr, wbytes, MSG_DONTWAIT);

            if(len <= 0){
                if(len == -1 && errno != EWOULDBLOCK)
                    perror("SERVER READ ERROR");

                closeConnection();

                return 0;
            }
            else if(clientSocket != -1) {
                write(STDOUT_FILENO, bufptr, len);
                printf("\n\n");

                buffer_write_adv(&clientSendBuf, len);
            }
        }

        if(serverSocket != -1 && FD_ISSET(serverSocket, &write_fds)) {
            size_t rbytes;
            uint8_t* bufptr = buffer_read_ptr(&serverSendBuf, &rbytes);

            int len = send(serverSocket, bufptr, rbytes, MSG_DONTWAIT);
            if(len == -1) {
                if(errno != EWOULDBLOCK) {
                    error_msg = "SERVER WRITE FAILED";
                    goto error;
                }
            }
            else {
                buffer_read_adv(&serverSendBuf, len);
            }
        }

        if(clientSocket != -1 && FD_ISSET(clientSocket, &write_fds)) {
            size_t rbytes;
            uint8_t* bufptr = buffer_read_ptr(&clientSendBuf, &rbytes);

            int len = send(clientSocket, bufptr, rbytes, MSG_DONTWAIT);
            if(len == -1) {
                if(errno != EWOULDBLOCK) {
                    error_msg = "SERVER WRITE FAILED";
                    goto error;
                }
            }
            else {
                buffer_read_adv(&clientSendBuf, len);
            }
        }
    }

error:
    if (error_msg){
        perror(error_msg);
        return -1;
    }

    return 0;
}

