#include "shoes.h"
#include "users.h"
#include <memory.h>
#include <stdio.h>

// SHOES_AUTHENTICATION_READ
static unsigned authentication_read(struct selector_key * key) {

    shoes_connection * conn = (shoes_connection *)key->data;
    struct authentication_parser * parser = &conn->parser.authentication_parser;

    size_t count;
    uint8_t * bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);

    if (len <= 0) {
        return SHOES_ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    bool error = false;
    enum authentication_state state =
        authentication_parse(parser, &conn->read_buffer, &error);

    bool done = is_authentication_finished(state, &error);
    if (error) {
        fprintf(stderr, "%s", authentication_error(state));
        return SHOES_ERROR;
    }

    if (done) {
        uint8_t auth_status = authenticate_shoes_user(&parser->credentials) ==
                                      AUTHENTICATION_STATUS_OK
                                  ? 0x00
                                  : 0x03;
        if (auth_status == RESPONSE_SUCCESS) {
            conn->is_authenticated = true;
        }

        if (!buffer_can_write(&conn->write_buffer)) {
            return SHOES_ERROR;
        }

        size_t n_buf;
        uint8_t * buf_ptr = buffer_write_ptr(&conn->write_buffer, &n_buf);

        if (n_buf < 2) {
            return SHOES_ERROR;
        }

        buf_ptr[0] = 1;
        buf_ptr[1] = auth_status;
        buffer_write_adv(&conn->write_buffer, 2);

        if ((SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE))) {
            return SHOES_ERROR;
        }

        return SHOES_AUTHENTICATION_WRITE;
    }
    return SHOES_AUTHENTICATION_READ;
}

// SHOES_AUTHENTICATION_WRITE
static unsigned authentication_write(struct selector_key * key) {
    shoes_connection * conn = (shoes_connection *)key->data;

    size_t count;
    uint8_t * bufptr = buffer_read_ptr(&conn->write_buffer, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return SHOES_ERROR;
    }
    buffer_read_adv(&conn->write_buffer, len);
    if (!buffer_can_read(&conn->write_buffer)) {
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ)) {
            return SHOES_ERROR;
        }

        if (conn->is_authenticated) {
            return SHOES_REQUEST_READ;
        }

        return SHOES_AUTHENTICATION_READ;
    }
    return SHOES_AUTHENTICATION_WRITE;
}

static void request_init(unsigned state, struct selector_key * key) {
    shoes_connection * conn = (shoes_connection *)key->data;
    memset(&conn->parser, 0, sizeof(conn->parser));
}

// SHOES_REQUEST_READ
static unsigned request_read(struct selector_key * key) {
    shoes_connection * conn = (shoes_connection *)key->data;
    struct shoes_parser * parser = &conn->parser.shoes_request_parser;

    size_t count;
    uint8_t * bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len <= 0) {
        return SHOES_ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    shoes_request_parse(parser, &conn->read_buffer);

    if (parser->state == PARSE_DONE) {
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE)) {
            fprintf(stderr, "Selector error.\n");
            return SHOES_ERROR;
        }
        return SHOES_REQUEST_WRITE;
    }

    return SHOES_REQUEST_READ;
}

// SHOES_REQUEST_WRITE
static unsigned request_write(struct selector_key * key) {
    shoes_connection * conn = (shoes_connection *)key->data;

    enum write_response_status status = write_response(
        &conn->write_buffer, &conn->parser.shoes_request_parser.response);

    size_t count;
    uint8_t * bufptr = buffer_read_ptr(&conn->write_buffer, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return SHOES_ERROR;
    }
    buffer_read_adv(&conn->write_buffer, len);
    if (!buffer_can_read(&conn->write_buffer) &&
        status != WRITE_RESPONSE_NOT_DONE) {
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ) ||
            status == WRITE_RESPONSE_FAIL) {
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
    },
    {
        .state = SHOES_AUTHENTICATION_WRITE,
        .on_write_ready = authentication_write,
    },
    {
        .state = SHOES_REQUEST_READ,
        .on_arrival = request_init,
        .on_read_ready = request_read,
    },
    {
        .state = SHOES_REQUEST_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state = SHOES_ERROR,
    }};

const struct state_definition * get_shoes_states() { return states; }
