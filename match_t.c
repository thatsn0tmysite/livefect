#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "match_t.h"

void match_t_push(match_t** head, pid_t pid, void* start, void* end, char* perms, char* path) {
    //TODO: if head is NULL or has 0 elements, alloc first element and set its values, else perform push.
    if(head == NULL) {
        head[0]=(match_t*)malloc(sizeof(match_t));
        head[0]->start=start;
        head[0]->end=end;
        head[0]->pid=pid;
        head[0]->path=path;
        head[0]->perms=perms;
        head[0]->next=NULL;
        return;
    }
    match_t * new_node = (match_t *) malloc(sizeof(match_t));

    new_node->start = start;
    new_node->end = end;
    new_node->pid = pid;
    new_node->path = strdup(path);
    new_node->perms = strndup(perms, 4);

    new_node->next = *head;
    *head = new_node;
}