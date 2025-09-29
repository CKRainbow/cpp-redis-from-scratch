#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

const size_t K_MAX_MSG = 4096;

void die(const char *msg);

void msg(const char *msg);

int32_t read_full(int fd, char *buf, size_t n);
int32_t write_full(int fd, const char *buf, size_t n);