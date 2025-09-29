#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "util.hpp"

void die(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void msg(const char* msg) {
    std::cout << msg << std::endl;
}

int32_t read_full(int fd, char *buf, size_t n)
{
    while(n > 0)
    {
        ssize_t rv = read(fd, buf, n);
        errno = 0;
        if (rv <= 0)
        {
            if (rv == -1 && errno == EINTR) continue;
            return -1; // error or unexpcted EOF
        }
        
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

int32_t write_full(int fd, const char *buf, size_t n)
{
    while(n > 0)
    {
        ssize_t rv = write(fd, buf, n);
        if (rv <= 0)
        {
            return -1; // error or unexpcted EOF
        }
        
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

