#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "logger.h"

struct ip_and_port {
    char ip[INET6_ADDRSTRLEN + 1];
    in_port_t port;
};

static struct ip_and_port *sockaddr_to_human(struct ip_and_port *ip_port, const struct sockaddr *addr) {
    if(addr == 0) {
        return NULL;
    }
    void *p;

    switch(addr->sa_family) {
        case AF_INET:
            p = &((struct sockaddr_in *) addr)->sin_addr;
            ip_port->port = ((struct sockaddr_in *) addr)->sin_port;
            break;
        case AF_INET6:
            p = &((struct sockaddr_in6 *) addr)->sin6_addr;
            ip_port->port = ((struct sockaddr_in6 *) addr)->sin6_port;
            break;
        default:
            return NULL;
    }

    memset(ip_port->ip, 0, INET6_ADDRSTRLEN + 1);

    if (inet_ntop(addr->sa_family, p,  ip_port->ip, INET6_ADDRSTRLEN + 1) == NULL) {
        return NULL;
    }

    return ip_port;
}

void logger(enum logType type, socks5_connection *conn) {
    const char *destination;
    struct ip_and_port destination_ip_port;
    struct ip_and_port source_ip_port;

    switch (conn->parser.request.request.address_type) {
        case ADDRESS_TYPE_IPV4:
            destination = sockaddr_to_human(&destination_ip_port, (struct sockaddr *) &conn->parser.request.request.destination.ipv4)->ip;
            break;
        case ADDRESS_TYPE_DOMAINNAME:
            destination = (char *) conn->parser.request.request.destination.fqdn;
            break;
        case ADDRESS_TYPE_IPV6:
            destination = sockaddr_to_human(&destination_ip_port, (struct sockaddr *) &conn->parser.request.request.destination.ipv6)->ip;
            break;
        default:
            return;
    }

    // TODO agregar fecha en formato ISO-8601
    // TODO agregar user que se conecta
    switch (type) {
        case LOG_ACCESS:
            sockaddr_to_human(&source_ip_port, (struct sockaddr*) &conn->client_addr);
            printf("%s\t%s\t%c\t%s\t%hu\t%s\t%hu\t%d\n", "fecha", "user", type, source_ip_port.ip,
                   htons(source_ip_port.port), destination, ntohs(conn->parser.request.request.port), conn->parser.request.response.status);
            break;
        case LOG_PASSWORD:
            printf("%s\t%s\t%c\tPOP3\t%s\t%hu\t%s\t%s\n", "fecha", "user", type, destination,
                   ntohs(conn->parser.request.request.port), conn->pop3.info.user, conn->pop3.info.pass);
            break;
        default:
            return;
    }
}
