#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "stm.h"
#include "socks5.h"
#include "selector.h"
#include "networkHandler.h"
#include <errno.h>

// CONNECTION_READ
static void connection_read_init(unsigned state, struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    connection_parser_init(&conn->parser.connection);
}

static unsigned connection_read(struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct connectionParser * parser = &conn->parser.connection;

    if (!buffer_can_write(&conn->client_buf)) {

    }

    size_t wbytes;
    uint8_t *bufptr = buffer_write_ptr(&conn->client_buf, &wbytes);

    ssize_t len = recv(conn->client_socket, bufptr, wbytes, MSG_DONTWAIT);

    if (len <= 0)
    {
        return ERROR;
    } else {
        buffer_write_adv(&conn->client_buf, len);
    }

    bool error = false;
    enum connectionState parser_state = connection_parse(parser, &conn->client_buf, &error);

    bool done = is_connection_finished(parser_state, &error);

    if (error) {
        return ERROR;
    }

    if (done) {
        return CONNECTION_WRITE;
    }

    conn->client_interests = OP_WRITE; // TODO ver si es necesario para algo
    selector_set_interest_key(key, OP_WRITE);
    return CONNECTION_READ;
}

// CONNECTION_WRITE

static unsigned connection_write(struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct connectionParser * parser = &conn->parser.connection;

    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&conn->client_buf, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return ERROR;
    }
    else {
        buffer_read_adv(&conn->client_buf, len);
        if (!buffer_can_read(&conn->client_buf)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                return REQUEST_READ;
            }
            return ERROR;
        }
    }
    return CONNECTION_WRITE;
}

static const struct state_definition states[] = {
    {
        .state = CONNECTION_READ,
        .on_arrival = connection_read_init,
        .on_read_ready = connection_read,
    }, {
        .state = CONNECTION_WRITE,
        .on_write_ready = connection_write,
    }
};

const struct state_definition * get_socks5_states() {
    return states;
}
