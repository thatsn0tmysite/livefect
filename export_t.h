#include <sys/types.h>

#ifndef H_LIVEFECT_EXPORT_T
#define H_LIVEFECT_EXPORT_T
/*Typedefs*/
typedef struct export_t {
  pid_t pid;
  char *name;
  void *addr;
  size_t len;
  char *perms;

  struct export_t *next;
} export_t;

/*Prototypes*/
void export_t_push(export_t **head, pid_t pid, char *perms, char *name,
                   void *addr, size_t len);
#endif