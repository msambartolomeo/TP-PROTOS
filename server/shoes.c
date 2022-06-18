#include <stdio.h>
#include <memory.h>
#include "shoes.h"

// AUTHENTICATION_READ
static unsigned authentication_read(struct selector_key *key) {

    shoes_connection *conn = (shoes_connection *)key->data;
    struct authenticationParser *parser = &conn->parser.authenticationParser;

    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);

    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    bool error = false;
    enum authenticationState state = authentication_parse(parser, &conn->read_buffer, &error);

    bool done = is_authentication_finished(state, &error);
    if (error) {
        fprintf(stderr, "%s", authentication_error(state));
        return ERROR;
    }

    if (done) {
        enum authenticationStatus status; // TODO: authenticate user in SHOES
        if ((SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE))
            || generate_authentication_response(&conn->write_buffer, status) != -1) {
            return ERROR;
        }
    }
    return AUTHENTICATION_WRITE;
}

// AUTHENTICATION_WRITE
static unsigned authentication_write(struct selector_key *key) {
    shoes_connection *conn = (shoes_connection *)key->data;

    size_t count;
    uint8_t *bufptr = buffer_read_ptr(&conn->write_buffer, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return ERROR;
    }
    buffer_read_adv(&conn->write_buffer, len);
    if (!buffer_can_read(&conn->write_buffer)) {
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ)) {
            return REQUEST_READ;
        }
        return ERROR;
    }
    return AUTHENTICATION_WRITE;
}

// REQUEST_READ
static unsigned request_read(struct selector_key *key) {
    shoes_connection *conn = (shoes_connection *) key->data;
    struct shoesParser *parser = &conn->parser.shoesRequestParser;

    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    shoes_request_parse(parser, &conn->read_buffer);

    if (parser->state == PARSE_DONE) {
        if(!writeResponse(&conn->write_buffer, &parser->response)) {
            fprintf(stderr, "Buffer out of space. This error should not be reachable.\n");
            return ERROR;
        }
        return REQUEST_WRITE;
    }

    return REQUEST_READ;
}

// REQUEST_WRITE
static unsigned request_write(struct selector_key *key) {
    shoes_connection *conn = (shoes_connection *) key->data;
    struct shoesParser *parser = &conn->parser.shoesRequestParser;

    size_t count;
    uint8_t *bufptr = buffer_read_ptr(&conn->write_buffer, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return ERROR;
    }
    buffer_read_adv(&conn->write_buffer, len);
    if (!buffer_can_read(&conn->write_buffer)) {
        return REQUEST_READ;
    }

    return REQUEST_WRITE;
}

static const struct state_definition states[] = {
        {
                .state = AUTHENTICATION_READ,
                .on_read_ready = authentication_read,
        }, {
                .state = AUTHENTICATION_WRITE,
                .on_write_ready = authentication_write,
        }, {
                .state = AUTHENTICATION_READ,
                .on_read_ready = authentication_read,
        }, {
                .state = AUTHENTICATION_WRITE,
                .on_write_ready = authentication_write,
        }, {
                .state = REQUEST_READ,
                .on_read_ready = request_read,
        }, {
                .state = REQUEST_WRITE,
                .on_write_ready = request_write,
        }, {
                .state = ERROR,
        }
};

const struct state_definition * get_socks5_states() {
    return states;
}
