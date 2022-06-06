#include "networkHandler.h"

#define DEFAULT_CLIENT_PORT 1080
#define DEFAULT_SERVER_PORT 80
#define SEND_BUF_SIZE 1024
#define SELECTOR_TIMEOUT 100

static buffer serverSendBuf;
static buffer clientSendBuf;
static uint8_t serverSendBufData[SEND_BUF_SIZE];
static uint8_t clientSendBufData[SEND_BUF_SIZE];

static fd_selector selector;

static int serverSocket = -1, clientSocket = -1;
static int serverInterests = 0, clientInterests = 0;

void networkSelectorSignalHandler()
{
    printf("SIGCHLD SIGNAL");
}

void closeConnection()
{
    if (serverSocket != -1)
    {
        selector_unregister_fd(selector, serverSocket);
        close(serverSocket);
    }
    if (clientSocket != -1)
    {
        selector_unregister_fd(selector, clientSocket);
        close(clientSocket);
    }
    serverSocket = -1;
    clientSocket = -1;
    buffer_reset(&serverSendBuf);
    buffer_reset(&clientSendBuf);
    printf("CONNECTION CLOSED\n");
}

void networkHandlerCleanup()
{
    closeConnection();
    selector_close();
}

void serverSocketReadHandler(struct selector_key *key)
{
    if(!buffer_can_write(&clientSendBuf)){
        serverInterests &= ~OP_READ;
        selector_set_interest(selector, serverSocket, serverInterests);
        return;
    }

    size_t wbytes;
    uint8_t *bufptr = buffer_write_ptr(&clientSendBuf, &wbytes);

    int len = recv(serverSocket, bufptr, wbytes, MSG_DONTWAIT);

    if (len <= 0)
    {
        if (len == -1 && errno != EWOULDBLOCK)
            perror("SERVER READ ERROR");

        closeConnection();

        return;
    }
    else if (clientSocket != -1)
    {
        write(STDOUT_FILENO, bufptr, len);
        printf("\n\n");

        buffer_write_adv(&clientSendBuf, len);

        clientInterests |= OP_WRITE; 
        selector_set_interest(selector, clientSocket, clientInterests);
    }
}


void serverSocketWriteHandler(struct selector_key *key)
{
    if(!buffer_can_read(&serverSendBuf)){
        serverInterests &= ~OP_WRITE;
        selector_set_interest(selector, serverSocket, serverInterests);
        return;
    }

    size_t rbytes;
    uint8_t *bufptr = buffer_read_ptr(&serverSendBuf, &rbytes);

    int len = send(serverSocket, bufptr, rbytes, MSG_DONTWAIT);
    if (len == -1)
    {
        if (errno != EWOULDBLOCK)
        {
            perror("SERVER WRITE FAILED");
            exit(1);
        }
    }
    else
    {
        buffer_read_adv(&serverSendBuf, len);
        clientInterests |= OP_READ;
        selector_set_interest(selector, clientSocket, clientInterests);
    }
}

void clientSocketReadHandler(struct selector_key *key)
{
    if(!buffer_can_write(&serverSendBuf)){
        clientInterests &= ~OP_READ;
        selector_set_interest(selector, clientSocket, clientInterests);
        return;
    }

    size_t wbytes;
    uint8_t *bufptr = buffer_write_ptr(&serverSendBuf, &wbytes);

    int len = recv(clientSocket, bufptr, wbytes, MSG_DONTWAIT);

    if (len <= 0)
    {
        if (len == -1) {
            perror("CLIENT READ ERROR");
        }

        closeConnection();
    }
    else
    {
        write(STDOUT_FILENO, bufptr, len);
        printf("\n\n");

        buffer_write_adv(&serverSendBuf, len);

        serverInterests |= OP_WRITE;
        selector_set_interest(selector, serverSocket, serverInterests);
    }
}

void clientSocketWriteHandler(struct selector_key *key)
{
    if(!buffer_can_read(&clientSendBuf)) {
        clientInterests &= ~OP_WRITE;
        selector_set_interest(selector, clientSocket, clientInterests);
        return;
    }

    size_t rbytes;
    uint8_t *bufptr = buffer_read_ptr(&clientSendBuf, &rbytes);

    int len = send(clientSocket, bufptr, rbytes, MSG_DONTWAIT);
    if (len == -1)
    {
        if (errno != EWOULDBLOCK)
        {
            perror("SERVER WRITE FAILED");
            closeConnection();
        }
    }
    else
    {
        buffer_read_adv(&clientSendBuf, len);
        serverInterests |= OP_READ;
        selector_set_interest(selector, serverSocket, serverInterests);
    }
}

const struct fd_handler selectorClientFdHandler = {clientSocketReadHandler, clientSocketWriteHandler, 0};
const struct fd_handler selectorServerFdHandler = {serverSocketReadHandler, serverSocketWriteHandler, 0};

void passiveSocketHandler(struct selector_key *key)
{
    int fd = key->fd;

    if (clientSocket != -1 || serverSocket != -1)
    {
        closeConnection();
    }

    clientSocket = accept(fd, NULL, NULL); // TODO: chequear error
    if (clientSocket == -1)
    {
        perror("Couldn't connect to client");
        return;
    }

    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!serverSocket)
    {
        perror("unable to create socket");
        closeConnection();
        return;
    }

    struct sockaddr_in serveraddr = {0};
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(DEFAULT_SERVER_PORT);

    if (inet_aton("127.0.0.1", &serveraddr.sin_addr) <= 0)
    {
        perror("inet_aton error");
        closeConnection();
        return;
    }

    // TODO: CONNECT NO BLOQUEANTE
    if (connect(serverSocket, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in)) < 0)
    {
        perror("SERVER CONNECTION ERROR");
        closeConnection();
        return;
    }

    serverInterests = clientInterests = OP_READ;
    selector_register(selector, serverSocket, &selectorServerFdHandler, serverInterests, NULL); // TODO: CHEQUEAR ERROR
    selector_register(selector, clientSocket, &selectorClientFdHandler, clientInterests, NULL); // TODO: CHEQUEAR ERROR

    printf("NEW CONNECTION\n");
}

const struct fd_handler passiveSocketFdHandler = {passiveSocketHandler, 0};

int networkHandler()
{
    char *error_msg = NULL;

    signal(SIGCHLD, networkSelectorSignalHandler);

    struct timespec select_timeout = {0};
    select_timeout.tv_sec = SELECTOR_TIMEOUT;
    struct selector_init select_init_struct = {SIGCHLD, select_timeout};

    int selector_init_ret;
    if ((selector_init_ret = selector_init(&select_init_struct)) != SELECTOR_SUCCESS)
    {
        fprintf(stderr, "Selector init error: %s", selector_error(selector_init_ret));
        goto error;
    }

    selector = selector_new(20);
    if (selector == NULL)
    {
        error_msg = "No se pudo instanciar el selector.";
        goto error;
    }

    const int passiveSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!(passiveSocket))
    {
        error_msg = "unable to create socket";
        goto error;
    }

    setsockopt(passiveSocket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    struct sockaddr_in passiveaddr = {0};
    passiveaddr.sin_addr.s_addr = INADDR_ANY;
    passiveaddr.sin_family = AF_INET;
    passiveaddr.sin_port = htons(DEFAULT_CLIENT_PORT);
    if (bind(passiveSocket, (struct sockaddr *)&passiveaddr, sizeof(passiveaddr)) < 0)
    {
        error_msg = "bind client socket error";
        goto error;
    }

    if (listen(passiveSocket, 1) < 0)
    {
        error_msg = "listen client socket error";
        goto error;
    }

    int registerRet;
    if((registerRet = selector_register(selector, passiveSocket, &passiveSocketFdHandler, OP_READ, NULL)) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Passive socket register error: %s", selector_error(registerRet));
        exit(1);
    }

    buffer_init(&clientSendBuf, SEND_BUF_SIZE, clientSendBufData);
    buffer_init(&serverSendBuf, SEND_BUF_SIZE, serverSendBufData);

    while (1)
    {
        int selectorStatus = selector_select(selector);
        if(selectorStatus != SELECTOR_SUCCESS) {
            fprintf(stderr, "Selector Select Error: %s", selector_error(selectorStatus));
            exit(1);
        }
        fflush(stdout);
    }

error:
    if (error_msg)
    {
        perror(error_msg);
        return -1;
    }

    return 0;
}
