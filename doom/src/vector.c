#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "vector.h"
#include "logger.h"
#include "helper.h"

// VectorBlocked Functions
void vecstr_init(VectorStr *vs) {
	vs->size = 0;
	vs->capacity = INITIAL_CAPACITY;
	vs->data = malloc(sizeof(256) * vs->capacity);
}

void vecstr_double_size_if_full(VectorStr *vs) {
	if(vs->size >= vs->capacity) {
		vs->capacity *= 2;
		vs->data = realloc(vs->data, sizeof(256) * vs->capacity);
	}
}
void vecstr_append(VectorStr *vs, char *address) {
	for(int i = 0; i < vs->size; i++) {
		if(strcmp(vs->data[i], address) == 0) {
			return;
		}
	}
	vecstr_double_size_if_full(vs);
	vs->data[vs->size++] = address;
}

int vecstr_find(VectorStr *vs, char *address) {
	int index = -1;
	for(int i = 0; i < vs->size; i++) {
		if(strcmp(vs->data[i], address) == 0) {
			index = i;
			break;
		}
	}
	return index;
}

void vecstr_remove(VectorStr *vs, char *address) {
	int index = vecstr_find(vs, address);
	printf("vecstrremove: %d\n", index);
	if(index != -1) {
		for(int i = index; i < vs->size-1; i++) {
			vs->data[i] = vs->data[i + 1];
		}
		vs->size--;
	}
}

void vecstr_free(VectorStr *vs) {
	free(vs->data);
}


void listing_init(Listing *l) {
	// l->hostname = "";
	// l->address = "";
	l->msg_sent = 0;
	l->msg_recv = 0;
	l->fd = -1;
	strncpy(l->status, "logged-in", sizeof(l->status));
	l->port = 0;
	// strcpy(l->port, port);
	vecstr_init(&(l->blocked));
	vecstr_init(&(l->buf_msg));

}

void vec_init(Vector *vec) {
	vec->size = 0;
	vec->num_loggedin = 0;
	vec->capacity = INITIAL_CAPACITY;

	vec->data = malloc(sizeof(Listing *) * vec->capacity);	
}

void vec_double_size_if_full(Vector *vec) {
	if(vec->size >= vec->capacity) {
		vec->capacity *= 2;
		vec->data = realloc(vec->data, sizeof(Listing *) * vec->capacity);
	}
}

void vec_append(Vector *vec, Listing *l) {
	vec_double_size_if_full(vec);
	vec->num_loggedin++;
	// listing_init(list);
	// list->hostname = l.hostname;
	// list->port = l.port;
	// list->address = l.address;
	vec->data[vec->size++] = l;
	printf("insert completed");
}

// New login return 1
// exisintg  return 2
int vec_insert_sorted(Vector *vec, Listing *l) {
	// check if already in vec
	for(int i = 0; i < vec->size; i++) {
		Listing *curr = vec->data[i];
		if(strcmp(curr->address, l->address) == 0) {
			char *status = "logged-in";
			strncpy(curr->status, status, sizeof(curr->status));
			printf("status: %s\n", curr->status);
			return 1;
		}
	}

	vec_double_size_if_full(vec);
	vec->num_loggedin++;
	if(vec->size == 0) {
		vec->data[0] = l;
		vec->size++;
		return 2;
	}

	int port = l->port;

	int insertion_index = 0;
	for(int i = 0; i < vec->size; i++) {
		if(port > vec->data[i]->port) {
			insertion_index = i+1;
		}
	}

	for(int i = vec->size; i > insertion_index; i--) {
		vec->data[i] = vec->data[i-1];
	}
	vec->data[insertion_index] = l;
	vec->size++;
	return 2;
}

void vec_remove(Vector *vec, char *address) {
	int index = -1;
	for(int i = 0; i < vec->size; i++) {
		Listing *curr = vec->data[i];
		if(strcmp(curr->address, address) == 0) {
			index = i;
			break;
		}
	}
	if(index != -1) {
		free(vec->data[index]);
		for(int i = index; i < vec->size-1; i++) {
			vec->data[i] = vec->data[i+1];
		}
		vec->size--;
	}
}

// 	for(int i = index; i < vec->size-1; i++) {
// 		vec->data[i] = vec->data[i + 1];
// 	}
// 	vec->size--;
// }

// Listing vec_get(Vector *vec, int index) {
// 	return vec->data[index];
// }

// void vec_set(Vector *vec, int index, Listing l) {
// 	vec->data[index] = l;
// }

void vec_block(Vector *vec, char *address, char *block_address) {
	for(int i = 0; i < vec->size; i++) {
		Listing *curr = vec->data[i];
		if(strcmp(curr->address, address) == 0) {
			vecstr_append(&(curr->blocked), block_address);
			printf("blocked: %s\n", curr->blocked.data[0]);
			break;
		}
	}
}

void vec_unblock(Vector *vec, char *address, char *unblock_address) {
	for(int i = 0; i < vec->size; i++) {
		Listing *curr = vec->data[i];
		if(strcmp(curr->address, address) == 0) {
			vecstr_remove(&(curr->blocked), unblock_address);
			break; 
		}
	}
}


void vec_free(Vector *vec) {
	for(int i = 0; i < vec->size; i++) {
		free(vec->data[i]->blocked.data);
		free(vec->data[i]->buf_msg.data);
		free(vec->data[i]);
	}
	free(vec->data);
}
void vec_print(Vector *vec, char *address) {
	for(int i = 0; i < vec->size; i++) {
		Listing *curr = vec->data[i];
		if(strcmp(vec->data[i]->address, address) == 0) {
			printf("%-5d%-35s%-20s%-8d\n", i+1, curr->hostname, curr->address, curr->port);
		}
	}
}

void vec_print_list(Vector *vec) {
	int j = 0;
	cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
	for(int i = 0; i < vec->size; i++) {
		Listing *curr = vec->data[i];
		// printf("***host: %s, addr: %s port: %d fd: %d\n", vec->data[i]->hostname, vec->data[i]->address, vec->data[i]->port, vec->data[i]->fd);
		if(strcmp(vec->data[i]->status, "logged-in") == 0) {
			cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", j+1, curr->hostname, curr->address, curr->port);
			// printf("address: %s  port: %s\n", curr.address, curr.port);
			j++;
		}

	}
    cse4589_print_and_log("[%s:END]\n", "LIST");

}

void vec_print_statistic(Vector *vec) {
	cse4589_print_and_log("[%s:SUCCESS]\n", "STATISTICS");
	for(int i = 0; i < vec->size; i++) {
		Listing *curr = vec->data[i];
		cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", i+1, curr->hostname, curr->msg_sent, curr->msg_recv, curr->status);
	}
    cse4589_print_and_log("[%s:END]\n", "STATISTICS");
}

void vec_print_blocked(Vector *vec, char *address) {
	// Check if valid IP
	if(!isValidIP(address)) {
		cse4589_print_and_log("[%s:ERROR]\n", "BLOCKED");
	    cse4589_print_and_log("[%s:END]\n", "BLOCKED");
		return;	
	}

	VectorStr vs = { .size = -1 };
	
	for(int i = 0; i < vec->size; i++) {
		Listing *curr = vec->data[i];
		// printf("cad: %s\naddr: %s\n", curr->address, address);
		if(strcmp(curr->address, address) == 0) {
			vs = vec->data[i]->blocked;
			break;			
		}
	}
	if(vs.size == -1) {
		cse4589_print_and_log("[%s:ERROR]\n", "BLOCKED");
	} else {
		cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCKED");
		for(int i = 0; i < vs.size; i++) {
			Listing *curr = vec->data[i];
			// cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", j+1, curr->hostname, curr->address, curr->port);
			// printf("vs: %s\n", vs.data[i]);
		}
	}
    cse4589_print_and_log("[%s:END]\n", "BLOCKED");
}

void vec_clients(Vector *vec, char *str_array) {
	int j = 0;
	for(int i = 0; i < vec->size; i++) {
		Listing *curr = vec->data[i];
		if(strcmp(curr->status, "logged-in") == 0) {
			char listing[256];
            snprintf(listing, sizeof(listing), "%-5d%-35s%-20s%-8d\n", j+1, curr->hostname, curr->address, curr->port);
			strcat(str_array, listing);
			j++;
		}
	}
	// printf("strarray: %s\n", str_array);
}


int vec_get_fd(Vector *vec, char *address) {
	int result = -1;
	for(int i = 0; i < vec->size; i++) {
		if(strcmp(vec->data[i]->address, address) == 0) {
			result = vec->data[i]->fd;
			break;
		}
	}
	return result;
}

void vec_logout(Vector *vec, char *address) {
	for(int i = 0; i < vec->size; i++) {
		if(strcmp(vec->data[i]->address, address) == 0) {
			char *status = "logged-out";
			memset(vec->data[i]->status, 0, sizeof(vec->data[i]->status));
			strncpy(vec->data[i]->status, status, sizeof(vec->data[i]->status));
			break;
		}
	}
}
