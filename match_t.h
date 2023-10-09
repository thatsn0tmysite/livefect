#include <sys/types.h>

#ifndef H_LIVEFECT_MATCH_T
#define H_LIVEFECT_MATCH_T
/*Typedefs*/
typedef struct match_t {
    pid_t pid;
    char* path;
    char* perms;

    void* start;
    void* end;
    struct match_t * next;
} match_t;

/*Prototypes*/
void match_t_push(match_t** head, pid_t pid, void* start, void* end, char* perms, char* path);

#endif