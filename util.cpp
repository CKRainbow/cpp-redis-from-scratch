#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <poll.h>

#include <vector>

#include "util.hpp"

void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void msg(const char *msg)
{
    std::cout << msg << std::endl;
}

int32_t read_full(int fd, char *buf, size_t n)
{
    while (n > 0)
    {
        ssize_t rv = read(fd, buf, n);
        errno = 0;
        if (rv <= 0)
        {
            if (rv == -1 && errno == EINTR)
                continue;
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
    while (n > 0)
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

void buf_append(Buffer &buf, const uint8_t *data, size_t len)
{
    buf.insert(buf.end(), data, data + len);
}

void buf_consume(Buffer &buf, size_t len)
{
    buf.erase(buf.begin(), buf.begin() + len);
}

void buf_append_u8(Buffer &buf, uint8_t v)
{
    buf.push_back(v);
}

void buf_append_u32(Buffer &buf, uint32_t v)
{
    buf_append(buf, (const uint8_t *)&v, 4);
}

void buf_append_i64(Buffer &buf, int64_t v)
{
    buf_append(buf, (const uint8_t *)&v, 8);
}

void buf_append_dbl(Buffer &buf, double v)
{
    buf_append(buf, (const uint8_t *)&v, 8);
}

void fd_set_nonblock(int fd)
{
    errno = 0;
    int flags = fcntl(fd, F_GETFL, 0); // get the flags
    if (errno)
    {
        die("fcntl error");
        return;
    }

    flags |= O_NONBLOCK;
    errno = 0;
    (void)fcntl(fd, F_SETFL, flags); // set the flags
    if (errno)
    {
        die("fcntl error");
        return;
    }
}

uint64_t str_hash(const uint8_t *str, size_t len)
{
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len; i++)
    {
        h = (h + str[i]) * 0x01000193;
    }
    return h;
}
