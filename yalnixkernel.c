#include <comp421/hardware.h>
#include <comp421/yalnix.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>

void KernelStart(ExceptionInfo *info, unsigned int pmem_size, void *orig_brk, char **cmd_args);

void TRAP_KERNEL_handler(ExceptionInfo *info);
void TRAP_CLOCK_handler(ExceptionInfo *info);
void TRAP_ILLEGAL_handler(ExceptionInfo *info);
void TRAP_MEMORY_handler(ExceptionInfo *info);
void TRAP_MATH_handler(ExceptionInfo *info);
void TRAP_TTY_RECEIVE_handler(ExceptionInfo *info);
void TRAP_TRANSMIt_handler(ExceptionInfo *info);

int freePages = 0;
uintptr_t nextFreePage;
struct pte pageTable0[PAGE_TABLE_LEN];
struct pte pageTable1[PAGE_TABLE_LEN];

void TRAP_KERNEL_handler(ExceptionInfo *info)
{

}

void TRAP_CLOCK_handler(ExceptionInfo *info);
{

}

void TRAP_ILLEGAL_handler(ExceptionInfo *info);
{

}

void TRAP_MEMORY_handler(ExceptionInfo *info);
{

}

void TRAP_MATH_handler(ExceptionInfo *info);
{

}

void TRAP_TTY_RECEIVE_handler(ExceptionInfo *info);
{

}

void TRAP_TRANSMIT_handler(ExceptionInfo *info);
{

}

/**
 * -- From section 3.3
 * info: pointer to an initial exceptioninfo structure. KernelStart is called in the same way as the interrupt handlers
 *      this ExceptionInfo records the state of the machine at boot time, and any changes made here control how and where the machine
 *      will execute when KernelStart returns
 * pmem_size: total size of physical memory of the machine (bytes)
 * orig_brk: Initial value of the Kernel's "break" (first address not part of kernel's initial heap)
 * cmd_args: vector of strings, containing a pointer to each argument from the boot command line (from our Linux terminal)
 */
void KernelStart(ExceptionInfo *info, unsigned int pmem_size, void *orig_brk, char **cmd_args)
{
    int i;
    uintptr_t nextPage, origBreak;
    // Remeber: virtual memory is not enabled here
    
    // Initialize interrupt vector table entries for each type of interrupt, exception, or trap
    void (*handlers) (ExceptionInfo *info) = calloc(TRAP_VECTOR_SIZE, 1);
    handlers[TRAP_KERNEL] = &TRAP_KERNEL_handler;
    handlers[TRAP_CLOCK] = &TRAP_CLOCK_handler;
    handlers[TRAP_ILLEGAL] = &TRAP_ILLEGAL_handler;
    handlers[TRAP_MEMORY] = &TRAP_MEMORY_handler;
    handlers[TRAP_MATH] = &TRAP_MATH_handler;
    handlers[TRAP_TTY_RECEIVE] = &TRAP_RECEIVE_handler;
    handlers[TRAP_TTY_TRANSMIT] = &TRAP_TRANSMIT_handler;

    // Intialize the REG_VECTOR_BASE privileged machine register to point to your interrupt vector table
    WriteRegister(REG_VECTOR_BASE, (RCS421RegVal) &handlers[0]);

    // Build a structure to keep track of what page frames in physical memory are free
        // use linked list of physical frames, implemented in frames themselves
        // or a separate structure
        // this list of free page frames should be based on the pmem_size argument passed on to your KernelStart
    
    nextFreePage = (uintptr_t) MEM_INVALID_SIZE;
    for (nextPage = nextFreePage; nextPage < KERNEL_STACK_BASE - PAGESIZE; nextPage = nextPage + PAGESIZE) {
        *((uintptr_t *) nextPage) = nextPage + PAGESIZE;
        freePages += 1;
    }
    origBreak = (uintptr_t) orig_brk;
    *((uintptr_t *) nextPage) = origBreak;
    for (; origBreak < pmem_size - 2*PAGESIZE; origBreak = origBreak + PAGESIZE) {
        *((uintptr_t *) origBreak) = origBreak + PAGESIZE;
        freePages += 1;
    }

    // be careful not to accidentally end up using the same page of physical memory twice for different uses at the same time
    // when you free a page, add it back to the linked list. When you allocate it, remove it from the linked list.

    // Build the initial page tabels for Region 0 and Region 1
    for (i = 0; i < KERNEL_STACK_BASE >> PAGESHIFT; i++) {
        struct pte entry;
        entry.valid = 0;
        pageTable0[i] = entry;
    }
    for (i = KERNEL_STACK_BASE >> PAGESHIFT; i < KERNEL_STACK_LIMIT >> PAGESHIFT; i++ ) {
        struct pte entry;
        entry.valid = 1;
        entry.kprot = (PROT_READ|PROT_WRITE);
        entry.uprot = PROT_NONE;
        entry.pfn = i;
        pageTable0[i] = entry;
    }

    for (i = VMEM_0_LIMIT >> PAGESHIFT; i < &_etext >> PAGESHIFT; i++) {
        struct pte entry;
        entry.valid = 1;
        entry.kprot = (PROT_READ|PROT_EXEC);
        entry.uprot = PROT_NONE;
        entry.pfn = i;
        pageTable1[i] = entry;
    }
    for (i = &_etext >> PAGESHIFT; i < orig_brk >> PAGESHIFT; i++) {
        struct pte entry;
        entry.valid = 1;
        entry.kprot = (PROT_READ|PROT_WRITE);
        entry.uprot = PROT_NONE;
        entry.pfn = i;
        pageTable1[i] = entry;
    }

    // Initialize registers REG_PTR0 and REG_PTR1 to define these initial page tables
    WriteRegister(REG_PTR0, (RCS421RegVal) &pageTable0[0]);
    WriteRegister(REG_PTR0, (RCS421RegVal) &pageTable1[0]);

    // Enable virtual memory
    WriteRegister(REG_VM_ENABLE, 1); //cast to RCS421RegVal?

    // create an "idle" process to be run by the kernel when there are no other runnable (ready) processes in the system.
    // The process should be a loop that executes the Pause machine instruction on each iteration
    // Can be loaded from a file using LoadProgram, or have it "built into" the rest of the code
        // initialize the pc value for this idle process to the address of the code for idle

    // create the first "regular" process, (init process) and load the initial program into it.
    // guide yourself by the file load.template (shows procedure how to load executalble from a Linux file into memory as Yalnix Process)
    // When process exits, its children continue to run without parents
    // To run initial program you should put file name if the init program on the command line when your run your kernel. It will then be passed to
    // KernelStart as one of the cmd_args strings

    // return from KernelStart routine. The machine will begin running the program defined by the current page tables and by the
    // values returned in the ExceptionInfo structure

}