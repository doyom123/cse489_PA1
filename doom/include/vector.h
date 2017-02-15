// https://www.happybearsoftware.com/implementing-a-dynamic-array
#include <limits.h>

#define INITIAL_CAPACITY 10
typedef struct {
	int size;
	int capacity;
	char **data;
} VectorStr;

typedef struct {
	char hostname[HOST_NAME_MAX];
	char address[INET_ADDRSTRLEN];
	int port;
	int msg_sent;
	int msg_recv;
	char status[20];
	int fd;
	VectorStr blocked;
	VectorStr buf_msg;
} Listing;


typedef struct {
	int size;
	int num_loggedin;
	int capacity;
	Listing **data;

} Vector;

void vecstr_init(VectorStr *vs);
void vecstr_double_size_if_full(VectorStr *vs);
void vecstr_append(VectorStr *vs, char *address);
void vecstr_remove(VectorStr *vs, char *address);
int vecstr_find(VectorStr *vs, char *address);
void vecstr_free(VectorStr *vs);

void listing_init(Listing *l);
void vec_init(Vector *vec);
void vec_double_size_if_full(Vector *vec);
void vec_print(Vector *vec, char *address);
void vec_print_list(Vector *vec);
void vec_print_statistic(Vector *vec);
void vec_print_blocked(Vector *vec, char *address);
void vec_clients(Vector *vec, char *str_array);
void vec_block(Vector *vec, char *address, char *block_address);
void vec_unblock(Vector *vec, char *address, char *unblock_address);

void vec_append(Vector *vec, Listing *l);
void vec_free(Vector *vec);
void vec_remove(Vector *vec, char *address);
void vec_logout(Vector *vec, char *address);
int vec_insert_sorted(Vector *vec, Listing *l);
Listing vec_get(Vector *vec, int index);
void vec_set(Vector *vec, int index, Listing l);
int vec_get_fd(Vector *vec, char *address);