#include "shoes_request.h"
#include <memory.h>
#include <stdio.h>

bool writeResponse(buffer *buf, shoesResponse* response) {
    if(!buffer_can_write(buf)) return false;

    size_t n;
    uint8_t* bufPtr = buffer_write_ptr(buf, &n);

    size_t size = response->dataLen + 1;
    if(n < size) return false;

    *bufPtr++ = response->status;
    memcpy(bufPtr, response->data, response->dataLen);

    buffer_write_adv(buf, size);

    //TODO
    //if(response->dataLen > 0)
    //    free(response->data);

    //Clean response
    response->status = RESPONSE_SUCCESS;
    response->data = NULL;
    response->dataLen = 0;

    return true;
}

static void shoes_parse_add_edit_user(shoesParser * parser, uint8_t byte) {
    switch (parser->putParser.addEditUserParser.state) {
        case PARSE_ADD_EDIT_USER_ULEN:
            if (byte == 0) {
                parser->response.status = RESPONSE_CMD_FAIL;
                parser->state = PARSE_DONE;
                break;
            }
            parser->putParser.addEditUserParser.remaining = byte;
            parser->putParser.addEditUserParser.pointer = (uint8_t *) &(parser->putParser.addEditUserParser.username);
            parser->putParser.addEditUserParser.state =
                PARSE_ADD_EDIT_USER_USER;
            break;
        case PARSE_ADD_EDIT_USER_USER:
            *(parser->putParser.removeUserParser.pointer++) = byte;
            parser->putParser.removeUserParser.remaining--;
            if (parser->putParser.removeUserParser.remaining == 0) {
                parser->putParser.addEditUserParser.state =
                    PARSE_ADD_EDIT_USER_PLEN;
            }
            break;
        case PARSE_ADD_EDIT_USER_PLEN:
            if (byte == 0) {
                parser->response.status = RESPONSE_CMD_FAIL;
                parser->state = PARSE_DONE;
                break;
            }
            parser->putParser.addEditUserParser.remaining = byte;
            parser->putParser.addEditUserParser.pointer = (uint8_t *) &(parser->putParser.addEditUserParser.password);
            parser->putParser.addEditUserParser.state =
                PARSE_ADD_EDIT_USER_PASS;
            break;
        case PARSE_ADD_EDIT_USER_PASS:
            *(parser->putParser.removeUserParser.pointer++) = byte;
            parser->putParser.removeUserParser.remaining--;
            if (parser->putParser.removeUserParser.remaining == 0) {
                // TODO: Add/Edit user
                printf("Added user '%s' with pass '%s'\n",
                       parser->putParser.addEditUserParser.username,
                       parser->putParser.addEditUserParser.password);
                parser->state = PARSE_DONE;
            }
            break;
    }
}

static void shoes_parse_remove_user(shoesParser * parser, uint8_t byte) {
    switch (parser->putParser.removeUserParser.state) {
        case PARSE_REMOVE_USER_ULEN:
            if (byte == 0) {
                parser->response.status = RESPONSE_CMD_FAIL;
                parser->state =  PARSE_DONE;
                break;
            }
            parser->putParser.removeUserParser.remaining = byte;
            parser->putParser.removeUserParser.pointer = (uint8_t *) &(parser->putParser.removeUserParser.username);
            parser->putParser.removeUserParser.state = PARSE_REMOVE_USER_USER;
            break;
        case PARSE_REMOVE_USER_USER:
            *(parser->putParser.removeUserParser.pointer++) = byte;
            parser->putParser.removeUserParser.remaining--;
            if (parser->putParser.removeUserParser.remaining == 0) {
                // TODO: Remove user and check for errors
                // TODO: Send status 0x00 if no errors, 0x04 if errors

                printf("Removed user '%s'\n",
                       parser->putParser.removeUserParser.username);

                parser->response.status = RESPONSE_SUCCESS;
                parser->state = PARSE_DONE;
            }
            break;
    }
}

static void shoes_parse_modify_buffer(shoesParser * parser, uint8_t byte) {
    switch (parser->putParser.modifyBufferParser.state) {
        case PARSE_BUFFER_SIZE:
            *(parser->putParser.modifyBufferParser.pointer++) = byte; // TODO: See endianness
            parser->putParser.modifyBufferParser.remaining--;
            if (parser->putParser.modifyBufferParser.remaining == 0) {
                // TODO: Actually change the buffer size
                printf("Modified buffer: %d\n",
                       parser->putParser.modifyBufferParser.bufferSize);
                parser->putParser.modifyBufferParser.state = PARSE_BUFFER_DONE;
            }
            break;
        case PARSE_ERROR_BUFSIZE_OUT_OF_RANGE:
            parser->response.status = RESPONSE_CMD_FAIL;
            parser->state = PARSE_DONE;
            break;
        case PARSE_BUFFER_DONE:
            parser->response.status = RESPONSE_SUCCESS;
            parser->state = PARSE_DONE;
            break;
    }
}

static void shoes_parse_modify_spoof(shoesParser * parser, uint8_t byte) {
    if (byte != false && byte != true) {
        parser->response.status = RESPONSE_CMD_FAIL; //TODO: Better status
    } else {
        // TODO: Actually modify spoofing status
        parser->response.status = RESPONSE_SUCCESS;
        printf("Modified spoofing: %d\n", byte);
    }

    parser->state = PARSE_DONE;
}

static void generateMetricsResponse(shoesResponse* response) {
    printf("BUENAS\n");
}

static void generateListResponse(shoesResponse* response) {
    //TODO
}

static void generateSpoofResponse(shoesResponse* response) {
    //TODO
}

static void shoes_request_parse_byte(shoesParser* parser, uint8_t byte) {
    switch (parser->state) {
    case PARSE_FMLY:
        if (byte != SHOES_GET && byte != SHOES_PUT) {
            parser->state = PARSE_ERROR_UNSUPPORTED_FMLY;
        }
        else {
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
            case CMD_EDIT_USER:
                parser->state = PARSE_DATA;
                parser->cmd.put = CMD_ADD_USER;
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
                parser->putParser.modifyBufferParser.pointer = (uint8_t *) &(parser->putParser.modifyBufferParser.bufferSize);
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
        }
        else {
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

bool finished_request_parsing(shoesParser* parser) {
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
    while(buffer_can_read(buf)) {
        uint8_t byte = buffer_read(buf);
        shoes_request_parse_byte(parser, byte);

        if(finished_request_parsing(parser)) break;
    }
}
