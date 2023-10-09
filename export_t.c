
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "export_t.h"

void export_t_push(export_t** head, pid_t pid, char* perms, char* name, void* addr, size_t len) {
    //TODO: if head is NULL or has 0 elements, alloc first element and set its values, else perform push.
    if(head==NULL) {
        head[0]=(export_t*)malloc(sizeof(export_t));
        head[0]->pid=pid;
        head[0]->len=len;
        head[0]->addr=addr;
        head[0]->name=name;
        head[0]->perms=perms;
        head[0]->next=NULL;
        return;
    }
    export_t * new_node = (export_t *) malloc(sizeof(export_t));
    
    new_node->pid = pid;
    new_node->name = strdup(name);
    new_node->addr = addr;
    new_node->len = len;
    new_node->perms = perms;

    new_node->next = *head;
    *head = new_node;
}