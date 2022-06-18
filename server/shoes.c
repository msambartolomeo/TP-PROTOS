#include <stdio.h>
#include <memory.h>
#include "shoes.h"

// SHOES_AUTHENTICATION_READ
static unsigned authentication_read(struct selector_key *key) {

    shoes_connection *conn = (shoes_connection *)key->data;
    struct authenticationParser *parser = &conn->parser.authenticationParser;

    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);

    if (len <= 0) {
        return SHOES_ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    bool error = false;
    enum authenticationState state = authentication_parse(parser, &conn->read_buffer, &error);

    bool done = is_authentication_finished(state, &error);
    if (error) {
        fprintf(stderr, "%s", authentication_error(state));
        return SHOES_ERROR;
    }

    if (done) {
        // TODO: authenticate user in SHOES
        shoesResponse response;
        response.status = 1;
        response.dataLen = 1;
        response.data = &(uint8_t){0}; //TODO
        if ((SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE))
            || !writeResponse(&conn->write_buffer, &response)) {
            return SHOES_ERROR;
        }
    }
    return SHOES_AUTHENTICATION_WRITE;
}

// SHOES_AUTHENTICATION_WRITE
static unsigned authentication_write(struct selector_key *key) {
    shoes_connection *conn = (shoes_connection *)key->data;

    size_t count;
    uint8_t *bufptr = buffer_read_ptr(&conn->write_buffer, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return SHOES_ERROR;
    }
    buffer_read_adv(&conn->write_buffer, len);
    if (!buffer_can_read(&conn->write_buffer)) {
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ)) {
            return SHOES_ERROR;
        }
        return SHOES_REQUEST_READ;
    }
    return SHOES_AUTHENTICATION_WRITE;
}

static void request_init(unsigned state, struct selector_key *key) {
    shoes_connection *conn = (shoes_connection *) key->data;
    memset(&conn->parser, 0, sizeof(conn->parser));
}

// SHOES_REQUEST_READ
static unsigned request_read(struct selector_key *key) {
    shoes_connection *conn = (shoes_connection *) key->data;
    struct shoesParser *parser = &conn->parser.shoesRequestParser;

    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len <= 0) {
        return SHOES_ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    shoes_request_parse(parser, &conn->read_buffer);

    if (parser->state == PARSE_DONE) {
        if(!writeResponse(&conn->write_buffer, &parser->response) ||
            SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE)) {
            fprintf(stderr, "Buffer out of space. This error should not be reachable.\n");
            return SHOES_ERROR;
        }
        return SHOES_REQUEST_WRITE;
    }

    return SHOES_REQUEST_READ;
}

// SHOES_REQUEST_WRITE
static unsigned request_write(struct selector_key *key) {
    shoes_connection *conn = (shoes_connection *) key->data;

    size_t count;
    uint8_t *bufptr = buffer_read_ptr(&conn->write_buffer, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return SHOES_ERROR;
    }
    buffer_read_adv(&conn->write_buffer, len);
    if (!buffer_can_read(&conn->write_buffer)) {
        if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ)) {
            return SHOES_ERROR;
        }
        return SHOES_REQUEST_READ;
    }

    return SHOES_REQUEST_WRITE;
}

static const struct state_definition states[] = {
        {
                .state = SHOES_AUTHENTICATION_READ,
                .on_read_ready = authentication_read,
        }, {
                .state = SHOES_AUTHENTICATION_WRITE,
                .on_write_ready = authentication_write,
        }, {
                .state = SHOES_REQUEST_READ,
                .on_arrival = request_init,
                .on_read_ready = request_read,
        }, {
                .state = SHOES_REQUEST_WRITE,
                .on_write_ready = request_write,
        }, {
                .state = SHOES_ERROR,
        }
};

const struct state_definition * get_shoes_states() {
    return states;
}
