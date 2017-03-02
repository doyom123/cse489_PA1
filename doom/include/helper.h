#ifndef HELPER_H_
#define HELPER_H_

// #include <netinet/in.h>?
#include <stddef.h>


typedef int bool;
#define false 0
#define true 1

#define PORTSIZE 65535
void nop();
bool isValidInt(const char *input);
bool isValidIP(const char *address);
int sendall(int s, char *buf, int *len);
int recvall(int s, char *buf, int *len);

#endif
