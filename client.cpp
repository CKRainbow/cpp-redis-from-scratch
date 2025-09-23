#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

void die(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void msg(const char* msg) {
    std::cout << msg << std::endl;
}

int main() 
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
    
    int rv = connect(fd, (const struct sockaddr*)&addr, sizeof(addr));
    if (rv)
    {
        die("connect()");
    }
    
    char message[] = "hello";
    write(fd, message, strlen(message));
    
    char rbuf[64] = {};
    int n = read(fd, rbuf, sizeof(rbuf) - 1);
    if (n < 0)
    {
        die("read()");
    }
    printf("server says: %s\n", rbuf);

    close(fd);
}