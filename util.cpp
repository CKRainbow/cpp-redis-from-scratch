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

void buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len)
{
    buf.insert(buf.end(), data, data + len);
}

void buf_consume(std::vector<uint8_t> &buf, size_t len)
{
    buf.erase(buf.begin(), buf.begin() + len);
}

// void buf_append(struct Buffer &buf, const uint8_t *data, size_t len)
// {
// }

// void buf_consume(struct Buffer &buf, size_t len)
// {
//     assert(buf.data_begin - buf.data_end >= len);
//     buf.data_begin += len;
// }

void fd_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0); // get the flags
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags); // set the flags
    // TODO: handle errors
}
