#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "util.hpp"

static int32_t query(int fd, const char *query);

int main() 
{
    int fd = socket(AF_INET, SOCK_STREAM, 0); // IPv4 + TCP
    if (fd < 0)
    {
        die("socket()");
    }
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    
    int rv = connect(fd, (const struct sockaddr*)&addr, sizeof(addr));
    if (rv)
    {
        die("connect()");
    }
    
    int32_t err = query(fd, "hello1");
    if (err)
    {
        goto L_DONE;
    }
    
    err = query(fd, "hello2");
    if (err)
    {
        goto L_DONE;
    }

 L_DONE:
    close(fd);
    return 0;
}

static int32_t query(int fd, const char *query)
{
    uint32_t n = (uint32_t)strlen(query);
    if (n > K_MAX_MSG)
    {
        return -1;
    }
    
    char wbuf[K_MAX_MSG + 4] = {};
    memcpy(wbuf, &n, 4);
    memcpy(wbuf + 4, query, n);
    if (int32_t err = write_full(fd, wbuf, n + 4))
    {
        return err;
    }
    
    char rbuf[K_MAX_MSG + 4] = {};
    errno = 0;
    int32_t err = read_full(fd, rbuf, 4);
    if (err)
    {
        msg(errno ? "read() error" : "EOF");
        return err;
    }
    memcpy(&n, rbuf, 4);
    if (n > K_MAX_MSG)
    {
        msg("too long");
        return -1;
    }
    
    if (int32_t err = read_full(fd, rbuf + 4, n))
    {
        msg("read() error");
        return err;
    }
    
    printf("server says: %s\n", rbuf + 4);
    return 0;
}