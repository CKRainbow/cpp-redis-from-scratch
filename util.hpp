#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <vector>

const size_t K_MAX_MSG = 32 << 15;
const size_t K_MAX_ARG = 32;

const uint32_t RES_NX = 404;
const uint32_t RES_ERR = 500;
const uint32_t RES_OK = 0;

struct Buffer
{
    uint8_t *buffer_begin;
    uint8_t *buffer_end;
    uint8_t *data_begin;
    uint8_t *data_end;
    std::vector<uint8_t> content;
};

struct Conn
{
    int fd;
    bool want_read;
    bool want_write;
    bool want_close;
    std::vector<uint8_t> read_buf;
    std::vector<uint8_t> write_buf;
};

struct Response
{
    uint32_t status;
    std::vector<int8_t> data;
};

void die(const char *msg);

void msg(const char *msg);

int32_t read_full(int fd, char *buf, size_t n);
int32_t write_full(int fd, const char *buf, size_t n);

void buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len);
void buf_consume(std::vector<uint8_t> &buf, size_t len);

// void buf_append(struct Buffer &buf, const uint8_t *data, size_t len);
// void buf_consume(struct Buffer &buf, size_t len);

void fd_set_nonblock(int fd);
uint64_t str_hash(const uint8_t *str, size_t len);