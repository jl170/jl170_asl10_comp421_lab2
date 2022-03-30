
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <comp421/hardware.h>
#include <comp421/yalnix.h>
#include <comp421/loadinfo.h>

int main()
{
    printf("hihi, pid of this process is: %d\n", GetPid());
    Delay(2);
    printf("delay 2 finished\n");
    Delay(1);
    printf("delay 1 finished\n");
    
    int *intarr = malloc(sizeof(int) * 1025);
    intarr[1024] = 6;
    printf("intarr[1024]: %d\n", intarr[1024]);
    free(intarr);
    int *intarr2 = malloc(sizeof(int) * 2050);
    intarr2[2049] = 100;
    printf("intarr2[2049]: %d\n", intarr2[2049]);
    free(intarr2);

    int ret = Fork();
    printf("returned from fork: %d\n", ret);
    return 0;
}