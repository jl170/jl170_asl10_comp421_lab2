Amanda Lu asl10
John Lee jl170

COMP 421 Lab 2 Yalnix Operating System Kernel

This project is an implementation of a Yalnix operating system kernel. Memory is divided into user (0) and kernel (1) regions, and physical pages in use are mapped to virtual addresses accessible through page tables. All interrupts, exceptions, and traps outlined in the project specification are handled as expected in the specification. All Yalnix kernel calls outlined in the specification are also implemented. 


Data Structures Overview:
We defined several different types of data structures in order to handle and store necessary data in accessible ways. Some of these are outlined below.
pcb: This data structure stores information that defines a particular process, including process ID, page table 0 address, a linked list of exited children, address of the parent if still alive, a pointer to the data structure outlining the page table in memory, and a pointer to a next pcb. The list of exited children allows a process to save the exit information and pid of exited child processes for use in yalnix_wait. The next pointer allows pcbs to be linked together into linked lists for things such as the ready queue. Every process that exists has a pcb. 
ptNode: This data structure describes memory that does/can store a page table. Using and managing this data structure allows the page table memory to be allocated without using a malloc call, which does not guarantee a space in memory that fits contiguously in one page in physical memory. A single page in memory can store exactly two page tables, so this structure reserves pages for storing just page tables, allowing each page to store two tables. This is efficient because the entire page in physical memory can be used. When a process is ended and the memory deallocated, the half of the page is marked as unused and can be used for another process.
exitedChild: This data structure is used to save the pid and exit status of processes that have exited so that the parent process can collect the exit information on a Wait call. When the child exits, an exitedChild is allocated, the pid copied over, and the pcb and other allocated memory for the exiting child freed. The exitedChild lasts until a parent process has collected it. 


Algorithms Overview:
Some of the more interesting algorithms are described below.
fork: When fork is called, a new child pcb is allocated and initialized, including the page table. In order to find a continuous section of memory to put the page table in, we first check if there is an existing empty slot in the memory managed by the ptNode structs. If so, we find it and use it, and if not, we allocate a new physical page and create and add a new ptNode. After the child pcb has been initialized with the proper values, we add the parent pcb to the ready queue and context switch in order to return first as the child. 


Testing:
We created and ran extensive tests to verify that the operation of our code was as expected. We generally followed the plan of attack as outlined in the project specification, and in that order tested the functionality of all the calls up to that point. We also made several helper functions to help us validate our memory management systems, including the page tables and free page lists. Additionally, we had very extensive TracePrint statements in each function to make sure the function calls were as expected. Along with running our own tests, we also ran the provided tests and made sure the results were as expected.


