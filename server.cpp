#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "util.hpp"

/*
struct sockaddr_in {
    uint16_t sin_family; // AF_INET or others
    uint16_t sin_port;   // port
    struct _in_addr sin_addr; // ip
};

struct _in_addr {
    uint32_t s_addr;    // ipv4 in big endien
};

struct sockaddr_in6 {
    uint16_t sin6_family; // AF_INET6
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    struct _in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};

struct _in6_addr {
    uint8_t _s6_addr[16];
};
*/

static void do_something(int fd);
static int32_t one_request(int fd);

int main() 
{
    int fd = socket(AF_INET, SOCK_STREAM, 0); // IPv4 + TCP
    if (fd < 0)
    {
        die("socket()");
    }
    int so_reuseaddr_val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr_val, sizeof(so_reuseaddr_val)); // set SO_REUSEADDR option to 1, so that we can reuse the port?
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
    
    int rv = bind(fd, (const struct sockaddr*)&addr, sizeof(addr));
    if (rv)
    {
        die("bind()");
    }
    // why const pointer? -> because we don't want to modify the value
    
    rv = listen(fd, SOMAXCONN);
    
    if (rv)
    {
        die("listen()");
    }
    
    while (true)
    {
        sockaddr_in client_addr = {};
        socklen_t client_addr_len = sizeof(client_addr);
        
        int conn_fd = accept(fd, (sockaddr*)&client_addr, &client_addr_len);
        if (conn_fd < 0)
        {
            continue;
        }
        
        while (true)
        {
            int32_t err = one_request(conn_fd);
            if (err)
            {
                break;
            }
        }

        close(conn_fd);
    }
}

static int32_t one_request(int fd)
{
    char buf[4 + K_MAX_MSG] = {};
    errno = 0; // change only when syscall failed
    int32_t err = read_full(fd, buf, 4);
    if (err)
    {
        msg(errno == 0 ? "EOF" : "read() error");
        return err;
    }
    
    u_int32_t len = 0;
    memcpy(&len, buf, 4);
    if (len > K_MAX_MSG)
    {
        msg("message too long");
        return -1;
    };

    err = read_full(fd, buf + 4, len);
    if (err)
    {
        msg("read() error");
        return err;
    }
    
    printf("client says: %s\n", buf + 4);
    
    const char *reply = "world";
    char wbuf[4 + sizeof(reply)] = {};
    len = (u_int32_t)(strlen(reply));
    memcpy(wbuf, &len, 4);
    memcpy(wbuf + 4, reply, len);
    
    return write_full(fd, wbuf, 4 + len);
}

static void do_something(int fd)
{
    char rbuf[64] = {};
    ssize_t n = read(fd, rbuf, sizeof(rbuf) - 1); // or recv()
    if (n < 0)
    {
        msg("read() error");
        return;
    }
    
    printf("client says: %s\n", rbuf);
    
    char wbuf[] = "world";
    write(fd, wbuf, strlen(wbuf)); // or send()
}