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

void fd_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0); // get the flags
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags); // set the flags
    // TODO: handle errors
}

Conn *handle_accept(int fd)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    int connfd = accept(fd, (struct sockaddr *)&addr, &len);
    if (connfd < 0)
    {
        return NULL;
    }

    fd_set_nonblock(connfd);
    Conn *conn = new Conn();
    conn->fd = connfd;
    conn->want_read = true;
    return conn;
}

void handle_read(Conn *conn)
{
    uint8_t buf[64 * 1024];
    // non-blocking read
    ssize_t rv = read(conn->fd, buf, sizeof(buf));
    if (rv <= 0)
    {
        conn->want_close = true;
        return;
    }

    // append to read_buf
    buf_append(conn->read_buf, buf, (size_t)rv);

    // try to parse the buf
    try_one_request(conn);

    if (conn->write_buf.size() > 0)
    {
        conn->want_write = true;
        conn->want_read = false;
    }
}

bool try_one_request(Conn *conn)
{
    if (conn->read_buf.size() < 4)
    {
        return false;
    }

    uint32_t len = 0;
    memcpy(&len, conn->read_buf.data(), 4);
    if (len > K_MAX_MSG) // protocol error
    {
        conn->want_close = true;
        return false;
    }

    if (4 + len > conn->read_buf.size()) // not ready
    {
        return false;
    }

    const uint8_t *request = &conn->read_buf[4];

    printf("[%d] request: %.*s\n", conn->fd, (int)len, request);

    // TODO: parse the request body

    // generate response (echo)
    buf_append(conn->write_buf, (const uint8_t *)&len, 4);
    buf_append(conn->write_buf, request, len);

    buf_consume(conn->read_buf, 4 + len);
    return true;
}

void handle_write(Conn *conn)
{
    assert(conn->write_buf.size() > 0);
    ssize_t rv = write(conn->fd, conn->write_buf.data(), conn->write_buf.size());
    if (rv < 0)
    {
        conn->want_close = true;
        return;
    }

    buf_consume(conn->write_buf, rv);

    if (conn->write_buf.size() == 0)
    {
        conn->want_write = false;
        conn->want_read = true;
    }
}