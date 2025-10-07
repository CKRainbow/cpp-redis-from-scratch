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

enum data_tag : uint8_t
{
    TAG_NIL = 0,
    TAG_ERR = 1,
    TAG_STR = 2,
    TAG_INT = 3,
    TAG_DBL = 4, // double
    TAG_ARR = 5,
};

enum err_code : uint8_t
{
    ERR_UNKNOWN = 0,
    ERR_TOO_BIG = 1,
};

// struct Buffer
// {
//     uint8_t *buffer_begin;
//     uint8_t *buffer_end;
//     uint8_t *data_begin;
//     uint8_t *data_end;
//     std::vector<uint8_t> content;
// };

typedef std::vector<uint8_t>
    Buffer;

struct Conn
{
    int fd;
    bool want_read;
    bool want_write;
    bool want_close;
    Buffer read_buf;
    Buffer write_buf;
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

// void buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len);
// void buf_consume(std::vector<uint8_t> &buf, size_t len);

void buf_append(Buffer &buf, const uint8_t *data, size_t len);
void buf_consume(Buffer &buf, size_t len);
void buf_append_u8(Buffer &buf, uint8_t v);
void buf_append_u32(Buffer &buf, uint32_t v);
void buf_append_i64(Buffer &buf, int64_t v);
void buf_append_dbl(Buffer &buf, double v);

void fd_set_nonblock(int fd);
uint64_t str_hash(const uint8_t *str, size_t len);