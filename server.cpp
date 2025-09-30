#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>

#include <vector>

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

int event_loop(int fd)
{
    std::vector<Conn *> fd2Conn;
    std::vector<struct pollfd> poll_args;
    while (true)
    {
        poll_args.clear();

        struct pollfd pfd = {fd, POLLIN, 0};
        poll_args.push_back(pfd);

        for (Conn *conn : fd2Conn)
        {
            if (!conn)
                continue;

            struct pollfd pfd = {conn->fd, POLLERR, 0};
            if (conn->want_read)
                pfd.events |= POLLIN;
            if (conn->want_write)
                pfd.events |= POLLOUT;

            poll_args.push_back(pfd);
        }

        errno = 0;
        // blocking here
        int rv = poll(poll_args.data(), (nfds_t)poll_args.size(), -1); // data() is a pointer to the first element in the vector
        if (rv < 0)
        {
            if (errno == EINTR)
                continue;
            die("poll()");
        }

        if (poll_args[0].revents)
        {
            if (Conn *conn = handle_accept(poll_args[0].fd))
            {
                if (fd2Conn.size() < (size_t)conn->fd)
                {
                    fd2Conn.resize(conn->fd + 1);
                }
                fd2Conn[conn->fd] = conn;
            }
        }

        for (size_t i = 1; i < poll_args.size(); i++)
        {
            uint32_t ready = poll_args[i].revents;
            Conn *conn = fd2Conn[poll_args[i].fd];
            if (ready & POLLIN)
            {
                handle_read(conn); // non-blocking
            }
            if (ready & POLLOUT)
            {
                handle_write(conn); // non-blocking
            }

            if (ready & POLLERR || conn->want_close)
            {
                (void)close(conn->fd); // (void) means ignore return value
                fd2Conn[conn->fd] = NULL;
                delete conn;
            }
        }
    }
}

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

    int rv = bind(fd, (const struct sockaddr *)&addr, sizeof(addr));
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

    event_loop(fd);
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