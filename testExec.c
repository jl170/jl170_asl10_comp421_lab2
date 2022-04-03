
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <comp421/hardware.h>
#include <comp421/yalnix.h>
#include <comp421/loadinfo.h>

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;
    int count;
    printf("hihi, this is exec. pid of this process is: %d\n", GetPid());
    Delay(1);
    printf("I am %d. I just delayed\n", GetPid());
    char buf[11];
    count = TtyRead(0, (void *) buf, 10);
    buf[count] = '\0';
    printf("Message Received: %s\n", buf);
    // int ret = Fork();
    // printf("returned from fork: %d\n", ret);
    // if (ret != 0) {
    //     int status;
    //     int childPid = Wait(&status);
    //     printf("waited for child %d with status %d\n", childPid, status);
        
    // } else {
    //     Delay(5);
    // }
    // int ret2 = Fork();
    // printf("returned from fork2: %d %d\n", ret, ret2);
    // int ret3 = Fork();
    // printf("returned from fork3: %d %d %d\n", ret, ret2, ret3);
    return 0;
}