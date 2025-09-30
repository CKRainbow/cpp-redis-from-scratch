#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <vector>

const size_t K_MAX_MSG = 4096;

struct Conn
{
    int fd;
    bool want_read;
    bool want_write;
    bool want_close;
    std::vector<uint8_t> read_buf;
    std::vector<uint8_t> write_buf;
};

void die(const char *msg);

void msg(const char *msg);

int32_t read_full(int fd, char *buf, size_t n);
int32_t write_full(int fd, const char *buf, size_t n);

void buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len);
void buf_consume(std::vector<uint8_t> &buf, size_t len);

void fd_set_nonblock(int fd);

Conn *handle_accept(int fd);
void handle_read(Conn *conn);
void handle_write(Conn *conn);

bool try_one_request(Conn *conn);