#include <memory.h>
#include <stdio.h>

#include "metrics.h"
#include "pswrdDiss.h"
#include "shoes_request.h"
#include "socks5.h"
#include "users.h"

enum writeResponseStatus writeResponse(buffer * buf, shoesResponse * response) {
    if (!buffer_can_write(buf))
        return WRITE_RESPONSE_FAIL;

    size_t available;
    uint8_t * bufPtr = buffer_write_ptr(buf, &available);

    size_t size = response->remaining;
    if (available < size) {
        size = available;
    }

    if (size > 0) {
        size_t writtenStatus = 0;
        if (response->remaining == response->dataSize + sizeof(uint8_t)) {
            *bufPtr++ = response->status;
            writtenStatus = sizeof(uint8_t);
        }

        size_t index =
            response->dataSize - (response->remaining - writtenStatus);
        if (size > 1)
            memcpy(bufPtr, &response->data[index], size - writtenStatus);
        buffer_write_adv(buf, (ssize_t)size);
        response->remaining -= (size - writtenStatus);
    }

    // if (response->status == RESPONSE_SERV_FAIL) {
    //     bufPtr[0] = RESPONSE_SERV_FAIL;
    //     //TODO: FREE
    //     return WRITE_RESPONSE_SUCCESS;
    // }

    if (response->remaining == 0) {
        // Se imprimió toda la response
        if (response->dataSize > 0)
            free(response->data);

        response->status = RESPONSE_SUCCESS;
        response->data = NULL;
        response->dataSize = 0;

        return WRITE_RESPONSE_SUCCESS;
    }

    return WRITE_RESPONSE_NOT_DONE;
}

static inline void fillResponse(shoesResponse * response,
                                shoesResponseStatus status, uint8_t * data,
                                size_t dataSize) {
    response->status = status;
    response->data = data;
    response->dataSize = dataSize;
    response->remaining = dataSize + sizeof(uint8_t);
}

static void request_add_user(shoesParser * parser) {
    enum addUserResponse addStatus =
        addUser((char *)parser->putParser.addEditUserParser.username,
                (char *)parser->putParser.addEditUserParser.password);
    enum shoesResponseStatus responseStatus;
    switch (addStatus) {
    case ADD_USER_SUCCESS:
        responseStatus = RESPONSE_SUCCESS;
        break;
    case ADD_USER_ALREADY_EXISTS:
        responseStatus = RESPONSE_CMD_FAIL_04;
        break;
    case ADD_USER_MAX_REACHED:
        responseStatus = RESPONSE_CMD_FAIL_05;
        break;
    case ADD_USER_SERV_ERROR:
    default:
        responseStatus = RESPONSE_SERV_FAIL;
        break;
    }
    fillResponse(&parser->response, responseStatus, NULL, 0);
}

static void request_edit_user(shoesParser * parser) {
    enum editUserResponse editStatus =
        editUser((char *)parser->putParser.addEditUserParser.username,
                 (char *)parser->putParser.addEditUserParser.password);
    enum shoesResponseStatus responseStatus;
    switch (editStatus) {
    case EDIT_USER_SUCCESS:
        responseStatus = RESPONSE_SUCCESS;
        break;
    case EDIT_USER_NOT_FOUND:
        responseStatus = RESPONSE_CMD_FAIL_04;
        break;
    case EDIT_USER_SERV_ERROR:
    default:
        responseStatus = RESPONSE_SERV_FAIL;
        break;
    }
    fillResponse(&parser->response, responseStatus, NULL, 0);
}

// TODO: Al agregar un usuario programáticamente habría que agregar el
// NULL-termination
static void shoes_parse_add_edit_user(shoesParser * parser, uint8_t byte) {
    switch (parser->putParser.addEditUserParser.state) {
    case PARSE_ADD_EDIT_USER_ULEN:
        if (byte == 0) {
            parser->response.status = RESPONSE_CMD_FAIL_04;
            parser->state = PARSE_DONE;
            break;
        }
        parser->putParser.addEditUserParser.remaining = byte;
        parser->putParser.addEditUserParser.pointer =
            (uint8_t *)&(parser->putParser.addEditUserParser.username);
        parser->putParser.addEditUserParser.state = PARSE_ADD_EDIT_USER_USER;
        break;
    case PARSE_ADD_EDIT_USER_USER:
        *(parser->putParser.addEditUserParser.pointer++) = byte;
        parser->putParser.addEditUserParser.remaining--;
        if (parser->putParser.addEditUserParser.remaining <= 0) {
            parser->putParser.addEditUserParser.state =
                PARSE_ADD_EDIT_USER_PLEN;
        }
        break;
    case PARSE_ADD_EDIT_USER_PLEN:
        if (byte == 0) {
            parser->response.status = RESPONSE_CMD_FAIL_04;
            parser->state = PARSE_DONE;
            break;
        }
        parser->putParser.addEditUserParser.remaining = byte;
        parser->putParser.addEditUserParser.pointer =
            (uint8_t *)&(parser->putParser.addEditUserParser.password);
        parser->putParser.addEditUserParser.state = PARSE_ADD_EDIT_USER_PASS;
        break;
    case PARSE_ADD_EDIT_USER_PASS:
        *(parser->putParser.addEditUserParser.pointer++) = byte;
        parser->putParser.addEditUserParser.remaining--;
        if (parser->putParser.addEditUserParser.remaining <= 0) {
            switch (parser->cmd.put) {
            case CMD_ADD_USER:
                request_add_user(parser);
                break;
            case CMD_EDIT_USER:
                request_edit_user(parser);
                break;
            default:
                fillResponse(&parser->response, RESPONSE_SERV_FAIL, NULL, 0);
                parser->state = PARSE_DONE;
                break;
            }
            parser->state = PARSE_DONE;
        }
        break;
    }
}

static void shoes_parse_remove_user(shoesParser * parser, uint8_t byte) {
    switch (parser->putParser.removeUserParser.state) {
    case PARSE_REMOVE_USER_ULEN:
        if (byte == 0) {
            parser->response.status = RESPONSE_CMD_FAIL_04;
            parser->state = PARSE_DONE;
            break;
        }
        parser->putParser.removeUserParser.remaining = byte;
        parser->putParser.removeUserParser.pointer =
            (uint8_t *)&(parser->putParser.removeUserParser.username);
        parser->putParser.removeUserParser.state = PARSE_REMOVE_USER_USER;
        break;
    case PARSE_REMOVE_USER_USER:
        *(parser->putParser.removeUserParser.pointer++) = byte;
        parser->putParser.removeUserParser.remaining--;
        if (parser->putParser.removeUserParser.remaining <= 0) {
            if (removeUser(
                    (char *)parser->putParser.removeUserParser.username)) {
                fillResponse(&parser->response, RESPONSE_SUCCESS, NULL, 0);
            } else {
                fillResponse(&parser->response, RESPONSE_CMD_FAIL_04, NULL, 0);
            }
            parser->state = PARSE_DONE;
        }
        break;
    }
}

static void shoes_parse_modify_buffer(shoesParser * parser, uint8_t byte) {
    *(parser->putParser.modifyBufferParser.pointer++) = byte;
    parser->putParser.modifyBufferParser.remaining--;
    if (parser->putParser.modifyBufferParser.remaining == 0) {
        socksChangeBufSize(parser->putParser.modifyBufferParser.bufferSize);
        fillResponse(&parser->response, RESPONSE_SUCCESS, NULL, 0);
        parser->state = PARSE_DONE;
    }
}

static void shoes_parse_modify_spoof(shoesParser * parser, uint8_t byte) {
    shoesResponseStatus status;

    if (byte != false && byte != true) {
        status = RESPONSE_CMD_FAIL_04;
    } else {
        change_dissector_state((bool)byte);
        status = RESPONSE_SUCCESS;
        printf("Modified spoofing: %d\n", byte);
    }

    fillResponse(&parser->response, status, NULL, 0);
    parser->state = PARSE_DONE;
}

static void generateMetricsResponse(shoesResponse * response) {
    const size_t metricsSize = 2 * sizeof(uint32_t) + sizeof(uint64_t);
    uint32_t * metrics = malloc(metricsSize);
    if (metrics == NULL) {
        fillResponse(response, RESPONSE_SERV_FAIL, NULL, 0);
        return;
    }

    metrics[0] = getHistoricConnections();
    metrics[1] = getSocksCurrentConnections();
    uint64_t bytesTransferred = getBytesTransferred();
    memcpy(&metrics[2], &bytesTransferred, sizeof(uint64_t));

    fillResponse(response, RESPONSE_SUCCESS, (uint8_t *)metrics, metricsSize);
}

static void generateListResponse(shoesResponse * response) {
    uint8_t uCount = 0;
    struct user ** users = get_socks_users(&uCount);
    if (uCount == 0) {
        fillResponse(response, RESPONSE_SUCCESS, NULL, 0);
        return;
    }

    uint8_t * ptr = malloc(1);
    if (ptr == NULL) {
        fillResponse(response, RESPONSE_SERV_FAIL, NULL, 0);
        return;
    }
    ptr[0] = uCount;
    size_t k = 1;
    for (int i = 0; i < uCount; i++) {
        size_t uLen = strlen(users[i]->name);
        ptr = realloc(ptr, (1 + uLen + k) * sizeof(uint8_t));
        if (ptr == NULL) {
            fillResponse(response, RESPONSE_SERV_FAIL, NULL, 0);
            free(ptr);
            return;
        }
        ptr[k++] = uLen;
        memcpy(ptr + k, users[i]->name, uLen);
        k += uLen;
    }

    fillResponse(response, RESPONSE_SUCCESS, ptr, k * sizeof(uint8_t));
}

static void generateSpoofResponse(shoesResponse * response) {
    uint8_t * spoofStatus = malloc(sizeof(uint8_t));
    if (spoofStatus == NULL) {
        fillResponse(response, RESPONSE_SERV_FAIL, NULL, 0);
        return;
    }
    spoofStatus[0] = (uint8_t)dissector_is_on();
    fillResponse(response, RESPONSE_SUCCESS, spoofStatus, sizeof(uint8_t));
}

static void shoes_request_parse_byte(shoesParser * parser, uint8_t byte) {
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
                generateMetricsResponse(&parser->response);
                parser->state = PARSE_DONE;
                break;
            case CMD_LIST_USERS:
                parser->cmd.get = CMD_LIST_USERS;
                generateListResponse(&parser->response);
                parser->state = PARSE_DONE;
                break;
            case CMD_SPOOFING_STATUS:
                parser->cmd.get = CMD_SPOOFING_STATUS;
                generateSpoofResponse(&parser->response);
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
                parser->putParser.addEditUserParser.state =
                    PARSE_ADD_EDIT_USER_ULEN;
                parser->parse = shoes_parse_add_edit_user;
                break;
            case CMD_EDIT_USER:
                parser->state = PARSE_DATA;
                parser->cmd.put = CMD_EDIT_USER;
                parser->putParser.addEditUserParser.state =
                    PARSE_ADD_EDIT_USER_ULEN;
                parser->parse = shoes_parse_add_edit_user;
                break;
            case CMD_REMOVE_USER:
                parser->state = PARSE_DATA;
                parser->cmd.put = CMD_REMOVE_USER;
                parser->putParser.removeUserParser.state =
                    PARSE_REMOVE_USER_ULEN;
                parser->parse = shoes_parse_remove_user;
                break;
            case CMD_MODIFY_BUFFER:
                parser->state = PARSE_DATA;
                parser->cmd.put = CMD_MODIFY_BUFFER;
                parser->putParser.modifyBufferParser.state = PARSE_BUFFER_SIZE;
                parser->putParser.modifyBufferParser.remaining = 2;
                parser->putParser.modifyBufferParser.bufferSize = 0;
                parser->putParser.modifyBufferParser.pointer = (uint8_t *)&(
                    parser->putParser.modifyBufferParser.bufferSize);
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

bool finished_request_parsing(shoesParser * parser) {
    switch (parser->state) {
    case PARSE_DONE:
    case PARSE_ERROR_UNSUPPORTED_CMD:
    case PARSE_ERROR_UNSUPPORTED_FMLY:
        return true;
    default:
        return false;
    }
}

void shoes_request_parse(shoesParser * parser, buffer * buf) {
    while (buffer_can_read(buf)) {
        uint8_t byte = buffer_read(buf);
        shoes_request_parse_byte(parser, byte);

        if (finished_request_parsing(parser))
            break;
    }
}
