#include <stdio.h>

void message(void);

__attribute__((visibility("default"))) void message(void)
{
    printf("message!\n");
}
