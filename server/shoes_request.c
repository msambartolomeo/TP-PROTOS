#include <memory.h>
#include <stdio.h>

#include "metrics.h"
#include "pswrdDiss.h"
#include "shoes_request.h"
#include "socks5.h"
#include "users.h"

enum write_response_status write_response(buffer * buf,
                                          shoes_response * response) {
    if (!buffer_can_write(buf))
        return WRITE_RESPONSE_FAIL;

    size_t available;
    uint8_t * buf_ptr = buffer_write_ptr(buf, &available);

    size_t size = response->remaining;
    if (available < size) {
        size = available;
    }

    if (size > 0) {
        size_t written_status = 0;
        if (response->remaining == response->data_size + sizeof(uint8_t)) {
            *buf_ptr++ = response->status;
            written_status = sizeof(uint8_t);
        }

        size_t index =
            response->data_size - (response->remaining - written_status);
        if (size > 1)
            memcpy(buf_ptr, &response->data[index], size - written_status);
        buffer_write_adv(buf, (ssize_t)size);
        response->remaining -= (size - written_status);
    }

    // if (response->status == RESPONSE_SERV_FAIL) {
    //     buf_ptr[0] = RESPONSE_SERV_FAIL;
    //     //TODO: FREE
    //     return WRITE_RESPONSE_SUCCESS;
    // }

    if (response->remaining == 0) {
        // Se imprimió toda la response
        if (response->data_size > 0)
            free(response->data);

        response->status = RESPONSE_SUCCESS;
        response->data = NULL;
        response->data_size = 0;

        return WRITE_RESPONSE_SUCCESS;
    }

    return WRITE_RESPONSE_NOT_DONE;
}

static inline void fill_response(shoes_response * response,
                                 shoes_response_status status, uint8_t * data,
                                 size_t data_size) {
    response->status = status;
    response->data = data;
    response->data_size = data_size;
    response->remaining = data_size + sizeof(uint8_t);
}

static void request_add_user(shoes_parser * parser) {
    enum add_user_response add_status =
        add_user((char *)parser->put_parser.add_edit_user_parser.username,
                 (char *)parser->put_parser.add_edit_user_parser.password);
    enum shoes_response_status response_status;
    switch (add_status) {
    case ADD_USER_SUCCESS:
        response_status = RESPONSE_SUCCESS;
        break;
    case ADD_USER_ALREADY_EXISTS:
        response_status = RESPONSE_CMD_FAIL_04;
        break;
    case ADD_USER_MAX_REACHED:
        response_status = RESPONSE_CMD_FAIL_05;
        break;
    case ADD_USER_SERV_ERROR:
    default:
        response_status = RESPONSE_SERV_FAIL;
        break;
    }
    fill_response(&parser->response, response_status, NULL, 0);
}

static void request_edit_user(shoes_parser * parser) {
    enum edit_user_response edit_status =
        edit_user((char *)parser->put_parser.add_edit_user_parser.username,
                  (char *)parser->put_parser.add_edit_user_parser.password);
    enum shoes_response_status response_status;
    switch (edit_status) {
    case EDIT_USER_SUCCESS:
        response_status = RESPONSE_SUCCESS;
        break;
    case EDIT_USER_NOT_FOUND:
        response_status = RESPONSE_CMD_FAIL_04;
        break;
    case EDIT_USER_SERV_ERROR:
    default:
        response_status = RESPONSE_SERV_FAIL;
        break;
    }
    fill_response(&parser->response, response_status, NULL, 0);
}

// TODO: Al agregar un usuario programáticamente habría que agregar el
// NULL-termination
static void shoes_parse_add_edit_user(shoes_parser * parser, uint8_t byte) {
    switch (parser->put_parser.add_edit_user_parser.state) {
    case PARSE_ADD_EDIT_USER_ULEN:
        if (byte == 0) {
            parser->response.status = RESPONSE_CMD_FAIL_04;
            parser->state = PARSE_DONE;
            break;
        }
        parser->put_parser.add_edit_user_parser.remaining = byte;
        parser->put_parser.add_edit_user_parser.pointer =
            (uint8_t *)&(parser->put_parser.add_edit_user_parser.username);
        parser->put_parser.add_edit_user_parser.state =
            PARSE_ADD_EDIT_USER_USER;
        break;
    case PARSE_ADD_EDIT_USER_USER:
        *(parser->put_parser.add_edit_user_parser.pointer++) = byte;
        parser->put_parser.add_edit_user_parser.remaining--;
        if (parser->put_parser.add_edit_user_parser.remaining <= 0) {
            parser->put_parser.add_edit_user_parser.state =
                PARSE_ADD_EDIT_USER_PLEN;
        }
        break;
    case PARSE_ADD_EDIT_USER_PLEN:
        if (byte == 0) {
            parser->response.status = RESPONSE_CMD_FAIL_04;
            parser->state = PARSE_DONE;
            break;
        }
        parser->put_parser.add_edit_user_parser.remaining = byte;
        parser->put_parser.add_edit_user_parser.pointer =
            (uint8_t *)&(parser->put_parser.add_edit_user_parser.password);
        parser->put_parser.add_edit_user_parser.state =
            PARSE_ADD_EDIT_USER_PASS;
        break;
    case PARSE_ADD_EDIT_USER_PASS:
        *(parser->put_parser.add_edit_user_parser.pointer++) = byte;
        parser->put_parser.add_edit_user_parser.remaining--;
        if (parser->put_parser.add_edit_user_parser.remaining <= 0) {
            switch (parser->cmd.put) {
            case CMD_ADD_USER:
                request_add_user(parser);
                break;
            case CMD_EDIT_USER:
                request_edit_user(parser);
                break;
            default:
                fill_response(&parser->response, RESPONSE_SERV_FAIL, NULL, 0);
                parser->state = PARSE_DONE;
                break;
            }
            parser->state = PARSE_DONE;
        }
        break;
    }
}

static void shoes_parse_remove_user(shoes_parser * parser, uint8_t byte) {
    switch (parser->put_parser.remove_user_parser.state) {
    case PARSE_REMOVE_USER_ULEN:
        if (byte == 0) {
            parser->response.status = RESPONSE_CMD_FAIL_04;
            parser->state = PARSE_DONE;
            break;
        }
        parser->put_parser.remove_user_parser.remaining = byte;
        parser->put_parser.remove_user_parser.pointer =
            (uint8_t *)&(parser->put_parser.remove_user_parser.username);
        parser->put_parser.remove_user_parser.state = PARSE_REMOVE_USER_USER;
        break;
    case PARSE_REMOVE_USER_USER:
        *(parser->put_parser.remove_user_parser.pointer++) = byte;
        parser->put_parser.remove_user_parser.remaining--;
        if (parser->put_parser.remove_user_parser.remaining <= 0) {
            if (remove_user(
                    (char *)parser->put_parser.remove_user_parser.username)) {
                fill_response(&parser->response, RESPONSE_SUCCESS, NULL, 0);
            } else {
                fill_response(&parser->response, RESPONSE_CMD_FAIL_04, NULL, 0);
            }
            parser->state = PARSE_DONE;
        }
        break;
    }
}

static void shoes_parse_modify_buffer(shoes_parser * parser, uint8_t byte) {
    *(parser->put_parser.modify_buffer_parser.pointer++) = byte;
    parser->put_parser.modify_buffer_parser.remaining--;
    if (parser->put_parser.modify_buffer_parser.remaining == 0) {
        if (parser->put_parser.modify_buffer_parser.buffer_size < BUFSIZE_MIN_LENGTH) {
            fill_response(&parser->response, RESPONSE_CMD_FAIL_04, NULL, 0);
        } else {
            socks_change_buf_size(
                    parser->put_parser.modify_buffer_parser.buffer_size);
            fill_response(&parser->response, RESPONSE_SUCCESS, NULL, 0);
        }
        parser->state = PARSE_DONE;
    }
}

static void shoes_parse_modify_spoof(shoes_parser * parser, uint8_t byte) {
    shoes_response_status status;

    if (byte != false && byte != true) {
        status = RESPONSE_CMD_FAIL_04;
    } else {
        change_dissector_state((bool)byte);
        status = RESPONSE_SUCCESS;
        printf("Modified spoofing: %d\n", byte);
    }

    fill_response(&parser->response, status, NULL, 0);
    parser->state = PARSE_DONE;
}

static void generate_metrics_response(shoes_response * response) {
    const size_t metrics_size = 2 * sizeof(uint32_t) + sizeof(uint64_t);
    uint32_t * metrics = malloc(metrics_size);
    if (metrics == NULL) {
        fill_response(response, RESPONSE_SERV_FAIL, NULL, 0);
        return;
    }

    metrics[0] = get_historic_connections();
    metrics[1] = get_socks_current_connections();
    uint64_t bytes_transferred = get_bytes_transferred();
    memcpy(&metrics[2], &bytes_transferred, sizeof(uint64_t));

    fill_response(response, RESPONSE_SUCCESS, (uint8_t *)metrics, metrics_size);
}

static void generate_list_response(shoes_response * response) {
    uint8_t u_count = 0;
    struct user ** users = get_socks_users(&u_count);
    if (u_count == 0) {
        fill_response(response, RESPONSE_SUCCESS, NULL, 0);
        return;
    }

    uint8_t * ptr = malloc(1);
    if (ptr == NULL) {
        fill_response(response, RESPONSE_SERV_FAIL, NULL, 0);
        return;
    }
    ptr[0] = u_count;
    size_t k = 1;
    for (int i = 0; i < u_count; i++) {
        size_t u_len = strlen(users[i]->name);
        ptr = realloc(ptr, (1 + u_len + k) * sizeof(uint8_t));
        if (ptr == NULL) {
            fill_response(response, RESPONSE_SERV_FAIL, NULL, 0);
            free(ptr);
            return;
        }
        ptr[k++] = u_len;
        memcpy(ptr + k, users[i]->name, u_len);
        k += u_len;
    }

    fill_response(response, RESPONSE_SUCCESS, ptr, k * sizeof(uint8_t));
}

static void generate_spoof_response(shoes_response * response) {
    uint8_t * spoof_status = malloc(sizeof(uint8_t));
    if (spoof_status == NULL) {
        fill_response(response, RESPONSE_SERV_FAIL, NULL, 0);
        return;
    }
    spoof_status[0] = (uint8_t)dissector_is_on();
    fill_response(response, RESPONSE_SUCCESS, spoof_status, sizeof(uint8_t));
}

static void shoes_request_parse_byte(shoes_parser * parser, uint8_t byte) {
    switch (parser->state) {
    case PARSE_FMLY:
        if (byte != SHOES_GET && byte != SHOES_PUT) {
            parser->state = PARSE_ERROR_UNSUPPORTED_FMLY;
        } else {
            parser->family = byte;
            parser->state = PARSE_CMD;
        }
        break;

    case PARSE_CMD:
        switch (parser->family) {
        case SHOES_GET:
            switch (byte) {
            case CMD_METRICS:
                parser->cmd.get = CMD_METRICS;
                generate_metrics_response(&parser->response);
                parser->state = PARSE_DONE;
                break;
            case CMD_LIST_USERS:
                parser->cmd.get = CMD_LIST_USERS;
                generate_list_response(&parser->response);
                parser->state = PARSE_DONE;
                break;
            case CMD_SPOOFING_STATUS:
                parser->cmd.get = CMD_SPOOFING_STATUS;
                generate_spoof_response(&parser->response);
                parser->state = PARSE_DONE;
                break;
            default:
                parser->state = PARSE_ERROR_UNSUPPORTED_CMD;
                break;
            }
            break;
        case SHOES_PUT:
            switch (byte) {
            case CMD_ADD_USER:
                parser->state = PARSE_DATA;
                parser->cmd.put = CMD_ADD_USER;
                parser->put_parser.add_edit_user_parser.state =
                    PARSE_ADD_EDIT_USER_ULEN;
                parser->parse = shoes_parse_add_edit_user;
                break;
            case CMD_EDIT_USER:
                parser->state = PARSE_DATA;
                parser->cmd.put = CMD_EDIT_USER;
                parser->put_parser.add_edit_user_parser.state =
                    PARSE_ADD_EDIT_USER_ULEN;
                parser->parse = shoes_parse_add_edit_user;
                break;
            case CMD_REMOVE_USER:
                parser->state = PARSE_DATA;
                parser->cmd.put = CMD_REMOVE_USER;
                parser->put_parser.remove_user_parser.state =
                    PARSE_REMOVE_USER_ULEN;
                parser->parse = shoes_parse_remove_user;
                break;
            case CMD_MODIFY_BUFFER:
                parser->state = PARSE_DATA;
                parser->cmd.put = CMD_MODIFY_BUFFER;
                parser->put_parser.modify_buffer_parser.state =
                    PARSE_BUFFER_SIZE;
                parser->put_parser.modify_buffer_parser.remaining = 2;
                parser->put_parser.modify_buffer_parser.buffer_size = 0;
                parser->put_parser.modify_buffer_parser.pointer = (uint8_t *)&(
                    parser->put_parser.modify_buffer_parser.buffer_size);
                parser->parse = shoes_parse_modify_buffer;
                break;
            case CMD_MODIFY_SPOOF:
                parser->state = PARSE_DATA;
                parser->cmd.put = CMD_MODIFY_SPOOF;
                parser->parse = shoes_parse_modify_spoof;
                break;
            default:
                parser->state = PARSE_ERROR_UNSUPPORTED_CMD;
                break;
            }
            break;
        default:
            parser->state = PARSE_ERROR_UNSUPPORTED_FMLY;
            break;
        }
        break;

    case PARSE_DATA:
        if (parser->parse != NULL) {
            parser->parse(parser, byte);
        } else {
            parser->state = PARSE_DONE;
        }
        break;

    case PARSE_ERROR_UNSUPPORTED_CMD:
        parser->response.status = RESPONSE_CMD_NOT_SUPPORTED;
        break;

    case PARSE_ERROR_UNSUPPORTED_FMLY:
        parser->response.status = RESPONSE_FMLY_NOT_SUPPORTED;
        break;

    case PARSE_DONE:
    default:
        break;
    }
}

bool finished_request_parsing(shoes_parser * parser) {
    switch (parser->state) {
    case PARSE_DONE:
    case PARSE_ERROR_UNSUPPORTED_CMD:
    case PARSE_ERROR_UNSUPPORTED_FMLY:
        return true;
    default:
        return false;
    }
}

void shoes_request_parse(shoes_parser * parser, buffer * buf) {
    while (buffer_can_read(buf)) {
        uint8_t byte = buffer_read(buf);
        shoes_request_parse_byte(parser, byte);

        if (finished_request_parsing(parser))
            break;
    }
}
