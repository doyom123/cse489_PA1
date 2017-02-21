#include <ctype.h>
#include <helper.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

void
nop() {};

bool 
isValidInt(const char *input) {
	int i = 0;
	if(input[i] == '-') return false;
	for(; input[i] != '\0'; i++) {
		if(!isdigit(input[i])) return false;
	}
	return true;
}

bool
isValidIP(const char *address) {
	struct sockaddr_in sa;
	if(inet_pton(AF_INET, address, &(sa.sin_addr)) <= 0) {
		// printf("false\n");
		return false;
	}
	// printf("true\n");
	return true;	
}



	// char *token = strtok(clients, "\n");
 //    while(token != NULL) {
 //        printf("token: %s\n", token);
 //        char *ret;
 //        ret = strstr(token, address);
 //     	printf("ret: %s\n", ret);
 //        if(ret != NULL) {
 //            return true;
 //        }
 //        token = strtok(NULL, "\n");
	// }
	// return false;

// char* ip_string(const struct sockaddr *sa,  char *dst, size_t size) {
// 	if(sa->sa_family == AF_INET) {
// 		inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
// 				dst, size);
// 	} else if(sa->sa_family == AF_INET6) {
// 		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
// 				dst, size);
// 	} else {
// 		return NULL;
// 	}

// 	return dst;
// }

// void
// printStats(struct sockaddr_storage& sas ) {
// 	if(sas->sa_family_t == AF_INET4) {

// 	} else {

// 	}
// }

