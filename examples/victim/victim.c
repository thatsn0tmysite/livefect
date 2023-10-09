#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

void test() { return; }

int main() {
  char *error;
  pid_t pid = getpid();
  // char* mem = malloc(1024);
  char *mem =
      mmap(NULL, 1024 * sizeof(char), PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  // int err = mprotect(mem, 1024, PROT_READ|PROT_WRITE|PROT_EXEC);
  if (mem == MAP_FAILED) {
    printf("Failed to call mmap @ %p (errno: %d).\n", mem, errno);
    return 1;
  }

  void *handle = dlopen("./victim.so", RTLD_NOW); // RTLD_NOW
  if (!handle) {
    fprintf(stderr, "%s\n", dlerror());
    exit(EXIT_FAILURE);
  }
  dlerror(); /* Clear any existing error */

  int (*external_func)(int) = (int (*)(int))dlsym(handle, "external_func");
  error = dlerror();
  if (error != NULL) {
    fprintf(stderr, "%s\n", error);
    exit(EXIT_FAILURE);
  }

  while (1) {
    printf("External function (FUN_ADDR: %p | VAR_ADDR: %p) called, returned: "
           "%d\n",
           external_func, &external_func, external_func(0));
    printf("Victim - PID: %d | F: %p | MEM(%p): ", pid, test, mem);

    for (int i = 0; i < 10; i++) {
      if (*mem != 0x00) { // test shellcode injection
        void (*code)() = (void (*)())mem;
        code();
      }
      printf("%x ", mem[i]);
    }

    printf("\n");

    external_func(0);
    sleep(1);
  }

  dlclose(handle);
  free(mem);
  return 0;
}