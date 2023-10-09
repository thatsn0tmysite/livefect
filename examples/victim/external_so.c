#include <stdio.h>

extern int external_func(int);
 
int external_func(int a) {
    printf("EXTERNAL_FUNC_CALLED\n");
    return a+1;
}
