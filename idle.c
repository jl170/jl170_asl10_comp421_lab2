#include <comp421/hardware.h>
#include <comp421/yalnix.h>
#include <comp421/loadinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main()
{
    printf("in Idle\n");
    while (1) {
        printf("in loop of Idle\n");
        Pause();
    }
}