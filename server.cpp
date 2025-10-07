#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>

#include <vector>
#include <map>

#include "hashtable.hpp"
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

// find the head of struct T
#define container_of(ptr, T, member) \
    ((T *)((char *)ptr - offsetof(T, member)))

Conn *handle_accept(int fd);
void handle_read(Conn *conn);
void handle_write(Conn *conn);

bool try_one_request(Conn *conn);

int32_t parse_req(const uint8_t *data, size_t size, std::vector<std::string> &out);
bool read_u32(const uint8_t *&data, const uint8_t *end, uint32_t &len);
bool read_string(const uint8_t *&data, const uint8_t *end, uint32_t len, std::string &out);

void do_request(std::vector<std::string> &cmd, Buffer &buf);

static void response_begin(Buffer &buf, size_t *header_pos);
static void response_end(Buffer &buf, size_t header_pos);

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
    while (try_one_request(conn))
    {
    }

    if (conn->write_buf.size() > 0)
    {
        conn->want_write = true;
        conn->want_read = false;

        return handle_write(conn);
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

    std::vector<std::string> cmd;
    if (parse_req(request, len, cmd))
    {
        msg("bad request");
        conn->want_close = true;
        return false;
    }

    // Response response;
    // do_request(cmd, response);
    // make_response(response, conn->write_buf);

    size_t header_pos = 0;
    response_begin(conn->write_buf, &header_pos);
    do_request(cmd, conn->write_buf);
    response_end(conn->write_buf, header_pos);

    buf_consume(conn->read_buf, 4 + len);
    return true;
}

void handle_write(Conn *conn)
{
    assert(conn->write_buf.size() > 0);
    errno = 0;
    ssize_t rv = write(conn->fd, conn->write_buf.data(), conn->write_buf.size());
    if (rv < 0)
    {
        if (errno == EAGAIN) // buffer may be full
        {
            return;
        }
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

int32_t parse_req(const uint8_t *data, size_t len, std::vector<std::string> &out)
{
    const uint8_t *end = data + len;
    uint32_t nstr = 0;
    if (!read_u32(data, end, nstr))
    {
        return -1;
    }
    if (nstr > K_MAX_ARG)
    {
        return -1;
    }
    // printf("parse_req: nstr = %d\n", nstr);

    while (out.size() < nstr)
    {
        uint32_t len = 0;
        if (!read_u32(data, end, len))
        {
            return -1;
        }
        // printf("parse_req: len = %d\n", len);
        out.push_back(std::string());
        if (!read_string(data, end, len, out.back()))
        {
            return -1;
        }
        // printf("parse_req: out.back() = %s\n", out.back().c_str());
    }
    if (data != end)
    {
        return -1; // trailing garbage
    }
    return 0;
}

bool read_u32(const uint8_t *&data, const uint8_t *end, uint32_t &out)
{
    if (data + 4 > end)
    {
        return false;
    }
    memcpy(&out, data, 4);
    data += 4;
    return true;
}

bool read_string(const uint8_t *&data, const uint8_t *end, uint32_t len, std::string &out)
{
    if (data + len > end)
    {
        return false;
    }
    out.assign(data, data + len);
    data += len;
    return true;
}

static struct
{
    HMap map;
} g_data;

struct Entry
{
    struct HNode node; // hash table node
    std::string key;
    std::string value;
};

static bool entry_eq(HNode *lhs, HNode *rhs)
{
    struct Entry *a_entry = container_of(lhs, struct Entry, node);
    struct Entry *b_entry = container_of(rhs, struct Entry, node);
    return a_entry->key == b_entry->key;
}

// std::map<std::string, std::string>
//     g_data;

static void out_str(Buffer &out, const char *str, size_t len)
{
    buf_append_u8(out, data_tag::TAG_STR);
    buf_append_u32(out, len);
    buf_append(out, (const uint8_t *)str, len);
}

static void out_nil(Buffer &out)
{
    buf_append_u8(out, data_tag::TAG_NIL);
}

static void out_err(Buffer &out, err_code code, const std::string &msg)
{
    buf_append_u8(out, data_tag::TAG_ERR);
    buf_append_u8(out, (uint8_t)code);
    buf_append_u32(out, msg.size());
    buf_append(out, (const uint8_t *)msg.data(), msg.size());
}

static void out_int(Buffer &out, int64_t val)
{
    buf_append_u8(out, data_tag::TAG_INT);
    buf_append_i64(out, val);
}

static void out_dbl(Buffer &out, double val)
{
    buf_append_u8(out, data_tag::TAG_DBL);
    buf_append_dbl(out, val);
}

static void out_arr(Buffer &out, size_t len)
{
    buf_append_u8(out, data_tag::TAG_ARR);
    buf_append_u32(out, len);
}

static void response_begin(Buffer &out, size_t *header_pos)
{
    *header_pos = out.size(); // previous data
    buf_append_u32(out, 0);   // reserve space for header
}

static size_t response_size(Buffer &out, size_t header_pos)
{
    return out.size() - header_pos - 4;
}

static void response_end(Buffer &out, size_t header_pos)
{
    size_t msg_size = response_size(out, header_pos);
    if (msg_size > K_MAX_MSG)
    {
        out.resize(header_pos + 4);
        out_err(out, err_code::ERR_TOO_BIG, "response too large");
        msg_size = response_size(out, header_pos);
    }
    uint32_t len = (uint32_t)msg_size;
    memcpy(&out[header_pos], &len, 4);
}

static void do_get(std::vector<std::string> &cmd, Buffer &out)
{
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((const uint8_t *)key.key.data(), key.key.size());

    HNode *lookup_node = hm_lookup(&g_data.map, &key.node, &entry_eq);
    if (!lookup_node)
    {
        out_nil(out); // FIXME
        return;
    }

    Entry *entry = container_of(lookup_node, Entry, node);

    const std::string &val = entry->value; // reference instead of copying
    assert(val.size() < K_MAX_MSG);
    out_str(out, val.data(), val.size());
}

static void do_set(std::vector<std::string> &cmd, Buffer &out)
{
    Entry entry;
    entry.key.swap(cmd[1]);
    entry.node.hcode = str_hash((const uint8_t *)entry.key.data(), entry.key.size());

    HNode *lookup_node = hm_lookup(&g_data.map, &entry.node, &entry_eq);
    if (lookup_node)
    {
        container_of(lookup_node, Entry, node)->value.swap(cmd[2]);
    }
    else
    {
        Entry *new_entry = new Entry();
        new_entry->key.swap(entry.key);
        new_entry->value.swap(cmd[2]);
        new_entry->node.hcode = entry.node.hcode;
        hm_insert(&g_data.map, &new_entry->node);
    }
    out_nil(out);
}

static void do_del(std::vector<std::string> &cmd, Buffer &out)
{
    Entry entry;
    entry.key.swap(cmd[1]);
    entry.node.hcode = str_hash((const uint8_t *)entry.key.data(), entry.key.size());

    HNode *del_node = hm_delete(&g_data.map, &entry.node, &entry_eq);
    if (del_node)
    {
        delete container_of(del_node, Entry, node);
    }
    out_int(out, del_node ? 1 : 0); // deleted number
}

static bool cb_keys(HNode *_node, void *arg)
{
    Buffer *out = (Buffer *)arg;
    const std::string &key = container_of(_node, Entry, node)->key;
    out_str(*out, key.data(), key.size());
    return true;
}

static void do_keys(std::vector<std::string> &, Buffer &out)
{
    out_arr(out, (uint32_t)hm_size(&g_data.map));
    hm_foreach(&g_data.map, &cb_keys, (void *)&out);
}

void do_request(std::vector<std::string> &cmd, Buffer &out)
{
    if (cmd.size() == 2 && cmd[0] == "get")
    {
        do_get(cmd, out);
    }
    else if (cmd.size() == 3 && cmd[0] == "set")
    {
        do_set(cmd, out);
    }
    else if (cmd.size() == 2 && cmd[0] == "del")
    {
        do_del(cmd, out);
    }
    else if (cmd.size() == 1 && cmd[0] == "keys")
    {
        do_keys(cmd, out);
    }
    else
    {
        out_err(out, err_code::ERR_UNKNOWN, "unknown command");
    }
}

// Exercise: Optimize the code so that the response data goes directly to Conn::outgoing.