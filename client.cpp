#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include <vector>

#include "util.hpp"

static int32_t query(int fd, const char *query);

static int32_t send_req(int fd, std::vector<std::string> &cmd)
{
    uint32_t len = 4; // nstr len
    for (const std::string &query : cmd)
    {
        len += query.size() + 4; // single query len
    }

    if (len > K_MAX_MSG)
    {
        return -1;
    }

    char buf[4 + K_MAX_MSG];
    memcpy(buf, &len, 4);
    uint32_t nstr = cmd.size();
    memcpy(buf + 4, &nstr, 4);
    size_t cur = 8;

    for (const std::string &query : cmd)
    {
        uint32_t qlen = (uint32_t)query.size();
        memcpy(buf + cur, &qlen, 4);
        memcpy(buf + cur + 4, query.data(), query.size());
        cur += 4 + query.size();
    }
    return write_full(fd, (const char *)buf, len + 4);
}

static int32_t read_res(int fd)
{
    char buf[4 + K_MAX_MSG];

    errno = 0;
    int32_t err = read_full(fd, (char *)buf, 4); // read len
    if (err)
    {
        msg(errno ? "read() error" : "EOF");
        return err;
    }

    uint32_t n;
    memcpy(&n, buf, 4);
    if (n > K_MAX_MSG)
    {
        msg("too long");
        return -1;
    }

    errno = 0;
    err = read_full(fd, (char *)buf + 4, n);
    if (err)
    {
        msg(errno ? "read() error" : "EOF");
        return err;
    }

    uint32_t status_code = 0;
    if (n < 4)
    {
        msg("bad response");
        return -1;
    }
    memcpy(&status_code, buf + 4, 4);

    printf("server says: [%u] %.*s\n", status_code, n - 4, buf + 8);
    return 0;
}

int main(int argc, char **argv)
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

    int rv = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (rv)
    {
        die("connect()");
    }

    std::vector<std::string> cmd;
    for (int i = 1; i < argc; i++)
    {
        cmd.push_back(argv[i]);
    }

    int32_t err = send_req(fd, cmd);
    if (err)
    {
        goto L_DONE;
    }
    err = read_res(fd);
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