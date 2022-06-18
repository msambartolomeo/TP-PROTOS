#include <memory.h>
#include "shoes_request.h"
#include "buffer.h"

bool sendResponse(buffer *buf, shoesResponse* response) {
    if(!buffer_can_write(buf)) return false;

    size_t n;
    uint8_t* bufPtr = buffer_write_ptr(buf, &n);

    size_t size = response->dataLen + 1;
    if(n < size) return -1;

    *bufPtr++ = response->status;
    memcpy(bufPtr, response->data, response->dataLen);

    return true;
}

static void shoes_parse_add_edit_user(shoesParser * parser, uint8_t byte) {
    switch (parser->putParser.addEditUserParser.state) {
        case PARSE_USERNAME_LENGHT_ADD_EDIT_USER:
            if (byte == 0) {
                // TODO: Handle error
            }
            parser->putParser.addEditUserParser.remaining = byte;
            parser->putParser.addEditUserParser.pointer = (uint8_t *) &(parser->putParser.addEditUserParser.username);
            break;
        case PARSE_USERNAME_ADD_EDIT_USER:
            *(parser->putParser.removeUserParser.pointer++) = byte;
            parser->putParser.removeUserParser.remaining--;
            if (parser->putParser.removeUserParser.remaining == 0) {
                parser->putParser.addEditUserParser.state = PARSE_PASSWORD_LENGTH_ADD_EDIT_USER;
            }
            break;
        case PARSE_PASSWORD_LENGTH_ADD_EDIT_USER:
            if (byte == 0) {
                // TODO: Handle error
            }
            parser->putParser.addEditUserParser.remaining = byte;
            parser->putParser.addEditUserParser.pointer = (uint8_t *) &(parser->putParser.addEditUserParser.password);
            break;
        case PARSE_PASSWORD_ADD_EDIT_USER:
            *(parser->putParser.removeUserParser.pointer++) = byte;
            parser->putParser.removeUserParser.remaining--;
            if (parser->putParser.removeUserParser.remaining == 0) {
                // TODO: Add/Edit user
            }
            break;
    }
}

static void shoes_parse_remove_user(shoesParser * parser, uint8_t byte) {
    switch (parser->putParser.removeUserParser.state) {
        case PARSE_USERNAME_LENGHT_REMOVE_USER:
            if (byte == 0) {
                // TODO: Handle error
            }
            parser->putParser.removeUserParser.remaining = byte;
            parser->putParser.removeUserParser.pointer = (uint8_t *) &(parser->putParser.removeUserParser.username);
            parser->putParser.removeUserParser.state = PARSE_USERNAME_REMOVE_USER;
            break;
        case PARSE_USERNAME_REMOVE_USER:
            *(parser->putParser.removeUserParser.pointer++) = byte;
            parser->putParser.removeUserParser.remaining--;
            if (parser->putParser.removeUserParser.remaining == 0) {
                // TODO: Remove user and check for errors
                // TODO: Send status 0x00 if no errors, 0x04 if errors
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
                parser->putParser.modifyBufferParser.state = PARSE_BUFFER_DONE;
            }
            // TODO: Actually change the buffer size
            break;
        case PARSE_ERROR_BUFSIZE_OUT_OF_RANGE:
            break;
        case PARSE_BUFFER_DONE:
            break;
    }


}

static void shoes_parse_modify_spoof(shoesParser * parser, uint8_t byte) {
    if (byte != false && byte != true) {
        // TODO: Handle unsupported value error
        sendResponse()
    } else {
        // TODO: Actually modify spoofing status
        parser->state = PARSE_DONE;
    }
}


static void shoes_parse_request(shoesParser * parser, uint8_t byte) {
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
                            parser->state = PARSE_DATA;
                            parser->cmd.get = CMD_METRICS;
                            // TODO: Generate responses to each get
                            break;
                        case CMD_LIST_USERS:
                            parser->state = PARSE_DATA;
                            parser->cmd.get = CMD_LIST_USERS;
                            break;
                        case CMD_SPOOFING_STATUS:
                            parser->state = PARSE_DATA;
                            parser->cmd.get = CMD_SPOOFING_STATUS;
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
                            parser->putParser.addEditUserParser.state = PARSE_USERNAME_LENGHT_ADD_EDIT_USER;
                            break;
                        case CMD_REMOVE_USER:
                            parser->state = PARSE_DATA;
                            parser->cmd.put = CMD_REMOVE_USER;
                            parser->putParser.removeUserParser.state = PARSE_USERNAME_LENGHT_REMOVE_USER;
                            break;
                        case CMD_MODIFY_BUFFER:
                            parser->state = PARSE_DATA;
                            parser->cmd.put = CMD_MODIFY_BUFFER;
                            parser->putParser.modifyBufferParser.state = PARSE_BUFFER_SIZE;
                            parser->putParser.modifyBufferParser.remaining = 2;
                            parser->putParser.modifyBufferParser.bufferSize = 0;
                            parser->putParser.modifyBufferParser.pointer = (uint8_t *) &(parser->putParser.modifyBufferParser.bufferSize);
                            break;
                        case CMD_MODIFY_SPOOF:
                            parser->state = PARSE_DATA;
                            parser->cmd.put = CMD_MODIFY_SPOOF;
                            parser->putParser.modifySpoofParser.state = PARSE_SPOOF_STATUS;
                            parser->parse = shoes_parse_modify_spoof;
                            break;
                        default:
                            parser->state = PARSE_ERROR_UNSUPPORTED_CMD;
                            break;
                    }
                    break;
                default:
                    // TODO: Error
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
        case PARSE_DONE:
            break;

        case PARSE_ERROR_UNSUPPORTED_FMLY:
            break;

        case PARSE_ERROR_UNSUPPORTED_CMD:
            break;
    }
}

void shoes_request_parse(shoesParser * parser, buffer * buf, bool * error) {
    while(buffer_can_read(buf)) {
        uint8_t byte = buffer_read(buf);
        shoes_parse_request(parser, byte);
    }
}
