#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    int                *good        = (int *)(size_t)0xdead0;
    int                 fd          = -1;
    int                 connfd      = -1;
    struct sockaddr_in  addr        = { 0 };
    struct sockaddr_in  connaddr    = { 0 };
    socklen_t           connaddrlen = 0;
    ssize_t             n           = 0;
    char                buf[64]     = { 0 };
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) {
        puts("Failed creating socket");
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

    if(bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        puts("Failed binding socket");
        exit(1);
    }
    if(listen(fd, 10)) {
        puts("Failed listening on socket");
        exit(1);
    }

    connfd = accept(fd, (struct sockaddr *)&connaddr, &connaddrlen);
    if(connfd < 0) {
        puts("Failed accepting connection");
        exit(1);
	}

    n = read(connfd, buf, sizeof(buf));
    if(n < 0) {
        puts("Failed reading from connection");
        close(connfd);
        close(fd);
        exit(1);
    }

    buf[n] = '\0';

    printf("Got %s from connection\n", buf);
    if (strcmp(buf, "Hello, world!")) {
        puts("FAILURE");
        close(connfd);
        close(fd);
        exit(1);
    }
    puts("SUCCESS!");

    close(connfd);
    close(fd);

    return *good;
}
