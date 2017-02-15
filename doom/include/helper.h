#ifndef HELPER_H_
#define HELPER_H_

#include <stddef.h>



typedef int bool;
#define false 0
#define true 1

#define PORTSIZE 65535

bool isValidInt(const char *input);
void printStats();
char** splitString();
// char* ip_string(const struct sockaddr *sa,  char *dst, size_t size);

#endif
