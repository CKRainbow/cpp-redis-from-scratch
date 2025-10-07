#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include <vector>

#include "util.hpp"

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

static int32_t print_response(const uint8_t *data, size_t size)
{
    if (size < 1)
    {
        msg("bad response");
        return -1;
    }

    switch (data[0])
    {
    case data_tag::TAG_NIL:
        printf("(nil)\n");
        return 1;
    case data_tag::TAG_ERR:
        if (size < 1 + 1 + 4)
        {
            msg("bad response");
            return -1;
        }
        {
            err_code code = (err_code)data[1];
            uint32_t len = 0;
            memcpy(&len, data + 2, 4);
            if (size < 1 + 1 + 4 + len)
            {
                msg("bad response");
                return -1;
            }
            printf("server says: [%u] %.*s\n", code, len, data + 1 + 1 + 4);
            return 1 + 1 + 4 + len;
        }
    case data_tag::TAG_STR:
        if (size < 1 + 4)
        {
            msg("bad response");
            return -1;
        }
        {
            uint32_t len = 0;
            memcpy(&len, data + 1, 4);
            if (size < 1 + 4 + len)
            {
                msg("bad response");
                return -1;
            }
            printf("%.*s\n", len, data + 1 + 4);
            return 1 + 4 + len;
        }
    case data_tag::TAG_INT:
        if (size < 1 + 8)
        {
            msg("bad response");
            return -1;
        }
        {
            int64_t v = 0;
            memcpy(&v, data + 1, 8);
            printf("%ld\n", v);
            return 1 + 8;
        }
    case data_tag::TAG_DBL:
        if (size < 1 + 8)
        {
            msg("bad response");
            return -1;
        }
        {
            double v = 0;
            memcpy(&v, data + 1, 8);
            printf("%f\n", v);
            return 1 + 8;
        }
    case data_tag::TAG_ARR:
        if (size < 1 + 4)
        {
            msg("bad response");
            return -1;
        }
        {
            uint32_t len;
            memcpy(&len, data + 1, 4);
            printf("(arr) len=%u\n", len);
            size_t arr_bytes = 1 + 4;
            for (uint32_t i = 0; i < len; i++)
            {
                int32_t rv = print_response(data + arr_bytes, size - arr_bytes);
                if (rv < 0)
                {
                    return rv;
                }
                arr_bytes += (size_t)rv;
            }
            printf("(arr) end\n");
            return arr_bytes;
        }
    default:
        msg("bad response");
        return -1;
    }
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

    int32_t rv = print_response((uint8_t *)buf + 4, n);
    if (rv > 0 && (uint32_t)rv != n)
    {
        msg("bad response");
        rv = -1;
    }
    return rv;
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