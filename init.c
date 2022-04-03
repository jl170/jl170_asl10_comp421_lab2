
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <comp421/hardware.h>
#include <comp421/yalnix.h>
#include <comp421/loadinfo.h>

int main()
{
    printf("hihi, pid of this process is: %d\n", GetPid());
    char *idle_args[2] = {"testExec", NULL};
    //Delay(2);
    //printf("delay 2 finished\n");
    //Delay(1);
    //printf("delay 1 finished\n");
    
    //int *intarr = malloc(sizeof(int) * 1025);
    //intarr[1024] = 6;
    //printf("intarr[1024]: %d\n", intarr[1024]);
    //free(intarr);
    //int *intarr2 = malloc(sizeof(int) * 2050);
    //intarr2[2049] = 100;
    //printf("intarr2[2049]: %d\n", intarr2[2049]);
    //free(intarr2);


    int ret = Fork();
    printf("%d returned from fork with return: %d\n", GetPid(), ret);
    if (ret != 0) {
        //int status;
        //int childPid = Wait(&status);
        //printf("waited for child %d with status %d\n", childPid, status);
        //char *idle_args[2] = {"testExec", NULL};
        //Exec("testExec", &idle_args[0]);
        //Exec("testExec", &idle_args[0]);
        //Delay(2);
    } else {
        
        Delay(5);
    }

    
    //Exec("testExec", &idle_args[0]);
    
    int ret2 = Fork();
    printf("%d returned from fork2 with return: %d %d\n", GetPid(), ret, ret2);
    int ret3 = Fork();
    printf("%d returned from fork3 with return: %d %d %d\n", GetPid(), ret, ret2, ret3);
    int ret4 = Fork();
    printf("%d returned from fork4 with return: %d %d %d %d\n", GetPid(), ret, ret2, ret3, ret4);
    Exec("testExec", &idle_args[0]);
    (void)idle_args;
    // (void)ret;
    // (void)ret2;
    // (void)ret3;
    return 0;
}