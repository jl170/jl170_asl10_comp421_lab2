#include <comp421/hardware.h>
#include <comp421/yalnix.h>
#include <comp421/loadinfo.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdbool.h>

struct ptNode {
    struct ptNode *next;
    uintptr_t addr[2];
    bool valid[2];
};

struct pcb {
    int pid;
    SavedContext *ctx;
    struct pte *PT0; // virtual address of its page table
    struct pcb *next;
    void *brkAddr;
    void *stackAddr;
    struct ptNode *ptNode;
    int ptNodeIdx;
};

bool vm_enabled = false;  // indicates if virtual memory has been enabled, used in SetKernelBrk
void *kernel_brk;  // first address not part of kernel heap
int setKernelBrkCount = 0;

int freePages = 0;
uintptr_t nextFreePage;
struct pte pageTable1[PAGE_TABLE_LEN];

struct pcb *active_pcb;
struct pcb *ready_pcb_head;  // queue
struct pcb *ready_pcb_tail;
struct pcb *blocked_pcb;  // one for each reason?
struct pcb *idle_pcb;

struct ptNode *startptNode;
int numProcesses = 0;
int numSlots = 0;

int countargs;

void KernelStart(ExceptionInfo *info, unsigned int pmem_size, void *orig_brk, char **cmd_args);

void TRAP_KERNEL_handler(ExceptionInfo *info);
void TRAP_CLOCK_handler(ExceptionInfo *info);
void TRAP_ILLEGAL_handler(ExceptionInfo *info);
void TRAP_MEMORY_handler(ExceptionInfo *info);
void TRAP_MATH_handler(ExceptionInfo *info);
void TRAP_TTY_RECEIVE_handler(ExceptionInfo *info);
void TRAP_TRANSMIT_handler(ExceptionInfo *info);

int yalnix_fork();
int yalnix_exec();
void yalnix_exit();
int yalnix_wait();
int yalnix_getpid();
int yalnix_brk();
int yalnix_delay();
int yalnix_tty_read();
int yalnix_tty_write();

void idle_process();
int get_free_page();
int LoadProgram(char *name, char **args, ExceptionInfo *info, struct pcb *loadPcb);

/*
 results from kernel call, all kernel call requests enter through here
 code gives kernel call number indicating which service being requested
 
 args beginning in regs[1]
 return value from kernel call should be returned to user process in regs[0]
 */
void TRAP_KERNEL_handler(ExceptionInfo *info)
{
    TracePrintf(0, "In TRAP_KERNEL_handler");
    
    int result;
    int code = info->code;
    
    if (code == 1) {
        result = yalnix_fork();
    } else if (code == 2) {
        result = yalnix_exec();
    } else if (code == 3) {
        yalnix_exit();  // TODO: exit has no return
        return;
    } else if (code == 4) {
        result = yalnix_wait();
    } else if (code == 5) {
        result = yalnix_getpid();
    } else if (code == 6) {
        result = yalnix_brk();
    } else if (code == 7) {
        result = yalnix_delay();
    } else if (code == 21) {
        result = yalnix_tty_read();
    } else if (code == 22) {
        result = yalnix_tty_write();
    }  // if code not defined then not good

    info->regs[0] = result;
}

void TRAP_CLOCK_handler(ExceptionInfo *info)
{
    TracePrintf(0, "In TRAP_CLOCK_handler\n");
    Halt();
    (void) info;
}

void TRAP_ILLEGAL_handler(ExceptionInfo *info)
{
    TracePrintf(0, "In TRAP_ILLEGAL_handler\n");
    Halt();
    (void) info;
}

void TRAP_MEMORY_handler(ExceptionInfo *info)
{
    TracePrintf(0, "In TRAP_MEMORY_handler with addr: %d %d %d %d %d %d\n", (uintptr_t) info->addr, (uintptr_t) info->code, SEGV_MAPERR, SEGV_ACCERR, SI_KERNEL, SI_USER);
    // if address is below the user stack and above the brk + 1 page, then
    if (info->addr < active_pcb->stackAddr && info->addr > active_pcb->brkAddr) {
        // grow the user stack to cover the address
        while (active_pcb->stackAddr > info->addr) {
            active_pcb->stackAddr -= PAGESIZE;
            struct pte *validNow = &active_pcb->PT0[(uintptr_t)(active_pcb->stackAddr) >> PAGESHIFT];
            validNow->valid = 1;
            validNow->uprot = PROT_READ | PROT_WRITE;
            validNow->kprot = PROT_READ | PROT_WRITE;
            validNow->pfn = get_free_page();
            WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) (active_pcb->stackAddr));
        }

    } else {
        // In all other cases, terminate the process
        TracePrintf(0, "In TRAP_MEMORY_handler else\n" );

    }
}

void TRAP_MATH_handler(ExceptionInfo *info)
{
    TracePrintf(0, "In TRAP_MATH_handler\n");
    Halt();
    (void) info;
}

void TRAP_TTY_RECEIVE_handler(ExceptionInfo *info)
{
    TracePrintf(0, "In TRAP_TTY_RECEIVE_handler\n");
    Halt();
    (void) info;
}

void TRAP_TRANSMIT_handler(ExceptionInfo *info)
{
    TracePrintf(0, "In TRAP_TRANSMIT_handler\n");
    Halt();
    (void) info;
}

// procedures for Yalnix kernel calls

/*
 create a new process
 
 memory image of child should be a copy of the parent
 return value of parent should be process ID of child, return value of
 child should be 0
 can return first as child or parent, otherwise return error
 
 */
int yalnix_fork() {
    // create new process id
    // allocate new PCB
    // copy parent kernel stsack including exception info
    // allocate new memory for child process
    // copy parent address space into child
    
    // create a new region 0 page table
    // That means Region 0 page tables must be dynamically allocated and initialized (but, be careful, you cannot use malloc for this).
    
    // ExceptionInfo is on the kernel stack, and each process has its own kernel stack, so each has its own ExceptionInfo.  You don't ever need to save and restore the ExecptionInfo
    
    // return” in both processes by scheduling both to run in our queue(s)
    TracePrintf(0, "In yalnix_fork");
    Halt();
}

int yalnix_exec() {
    TracePrintf(0, "In yalnix_exec");
    Halt();
}

void yalnix_exit() {
//    Exit(int status)
    
    // resources used by calling process should be freed
    TracePrintf(0, "In yalnix_exit");
    Halt();
}

int yalnix_wait() {
    TracePrintf(0, "In yalnix_wait");
    Halt();
}

int yalnix_getpid() {
    TracePrintf(0, "In yalnix_getpid");
    Halt();
}

int yalnix_brk() {
    TracePrintf(0, "In yalnix_brk");
    Halt();
}

int yalnix_delay() {
    TracePrintf(0, "In yalnix_delay");
    Halt();
}

int yalnix_tty_read() {
    TracePrintf(0, "In yalnix_tty_read");
    Halt();
}

int yalnix_tty_write() {
    TracePrintf(0, "In yalnix_tty_write");
    Halt();
}


/*
 called when kernel needs more pages added to kernel heap
 before virtual memory enabled:
    move break location to new location specified as addr
 after virtual memory enabled: allocate physical memory page frames, map as necessary to make addr new kernel break
 if run out of physical memory or other issue return -1

 ** issues may arise if malloc is called after page table structures are set up
 but before virtual memory is enabled **
 */
int
SetKernelBrk(void *addr)
{
    //racePrintf(0, "SetKernelBrk called\n");
    //racePrintf(0, "attempt to change kernel_brk to : %d\n", (int) (uintptr_t)addr);
    unsigned int i;
    
    if (vm_enabled) {  // virtual memory enabled, allocate page frame and map
        // from vpn of current kernel_brk to vpn of addr
        for (i = (uintptr_t) kernel_brk >> PAGESHIFT; i < (uintptr_t) addr >> PAGESHIFT; i++) {
            // make the PTE valid
            pageTable1[i - PAGE_TABLE_LEN].valid = 1;
            pageTable1[i - PAGE_TABLE_LEN].uprot = PROT_NONE;
            pageTable1[i - PAGE_TABLE_LEN].kprot = PROT_READ | PROT_WRITE;
            pageTable1[i - PAGE_TABLE_LEN].pfn = get_free_page();
            WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) (i << PAGESHIFT));
        }
    }
    // if vm not enabled, simply move break location to addr
    kernel_brk = addr;
    
    
    return 0;
}

// SavedContext *
// DumbMySwitchFunc(SavedContext *ctxp, void *p1, void *p2) {
//     TracePrintf(0, "in DumbMySwitchFunc\n");
//     struct pcb *pcb1 = (struct pcb *) p1;
//     pcb1->ctx = ctxp;
//     (void) p2;
//     return ctxp;
// }

SavedContext *
MySwitchFunc(SavedContext *ctxp, void *p1, void *p2) {
    struct pcb *pcb1 = (struct pcb *) p1;
    struct pcb *pcb2 = (struct pcb *) p2;
    uintptr_t i;
    struct pte svdPTE;
    svdPTE.pfn = pageTable1[PAGE_TABLE_LEN - 1].pfn; // REMINDER: this might be fatal if our Kernel heap gets too large
    svdPTE.kprot = pageTable1[PAGE_TABLE_LEN - 1].kprot;
    svdPTE.valid = pageTable1[PAGE_TABLE_LEN - 1].valid;
    pageTable1[PAGE_TABLE_LEN - 1].valid = 1;
    pageTable1[PAGE_TABLE_LEN - 1].kprot = PROT_READ | PROT_WRITE;
    
    for (i = KERNEL_STACK_BASE; i < KERNEL_STACK_LIMIT; i += PAGESIZE) {
        pageTable1[PAGE_TABLE_LEN - 1].pfn = pcb2->PT0[i >> PAGESHIFT].pfn;
        memcpy((void *)((PAGE_TABLE_LEN - 1) << PAGESHIFT), (void *) i, PAGESIZE);
        WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) (PAGE_TABLE_LEN - 1) << PAGESHIFT);
    }
    
    pageTable1[PAGE_TABLE_LEN - 1].kprot = svdPTE.kprot;
    pageTable1[PAGE_TABLE_LEN - 1].valid = svdPTE.valid;
    pageTable1[PAGE_TABLE_LEN - 1].pfn = svdPTE.pfn;
    
    pcb1->ctx = ctxp;
    memcpy((void*) pcb2->ctx, (void*) pcb1->ctx, sizeof(SavedContext));
    TracePrintf(0, "In MySwitchFunc: %d %d\n", pcb1->ptNode->addr[pcb1->ptNodeIdx], pcb2->ptNode->addr[pcb2->ptNodeIdx]);
    WriteRegister(REG_PTR0, (RCS421RegVal) pcb1->ptNode->addr[pcb1->ptNodeIdx]);
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);
    //memcpy((void*) pcb2->ctx, (void*) pcb1->ctx, sizeof(SavedContext));
    //pcb2->ctx = ctxp;
    TracePrintf(0, "Returning from myswitchfunc..");
    return pcb2->ctx;
    
    //return pcb2->ctx;
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
    unsigned int i;
    uintptr_t nextPage, kernelBreak;
    // Remeber: virtual memory is not enabled here
    kernel_brk = orig_brk;
    
    // Initialize interrupt vector table entries for each type of interrupt, exception, or trap
    //void (*handlers[TRAP_VECTOR_SIZE])(ExceptionInfo*) = calloc(TRAP_VECTOR_SIZE, 4);
    void **handlers = calloc(TRAP_VECTOR_SIZE, 4);
    TracePrintf(0, "Interrupt vector: %d\n", (int)(uintptr_t) handlers[3]);
    handlers[TRAP_KERNEL] = &TRAP_KERNEL_handler;
    handlers[TRAP_CLOCK] = &TRAP_CLOCK_handler;
    handlers[TRAP_ILLEGAL] = &TRAP_ILLEGAL_handler;
    handlers[TRAP_MEMORY] = &TRAP_MEMORY_handler;
    //TracePrintf(0, "Addr or memory handler: %d\n", (uintptr_t) &TRAP_MEMORY_handler);
    handlers[TRAP_MATH] = &TRAP_MATH_handler;
    handlers[TRAP_TTY_RECEIVE] = &TRAP_TTY_RECEIVE_handler;
    handlers[TRAP_TTY_TRANSMIT] = &TRAP_TRANSMIT_handler;

    // Intialize the REG_VECTOR_BASE privileged machine register to point to your interrupt vector table
    WriteRegister(REG_VECTOR_BASE, (RCS421RegVal) &handlers[0]);
    TracePrintf(0, "Interrupt vector: %d\n", (int)(uintptr_t) handlers[3]);
    TracePrintf(0, "Interrupt vector: %d\n", (int)(uintptr_t) handlers[4]);
    TracePrintf(0, "Interrupt vector: %d\n", (int)(uintptr_t) TRAP_VECTOR_SIZE);
        
    idle_pcb = malloc(sizeof(struct pcb));
    active_pcb = malloc(sizeof(struct pcb));
    startptNode = malloc(sizeof(struct ptNode));
    idle_pcb->ctx = malloc(sizeof(SavedContext));
    active_pcb->ctx = malloc(sizeof(SavedContext));
    startptNode->addr[0] = (uintptr_t) kernel_brk;
    startptNode->addr[1] = (uintptr_t) kernel_brk + PAGESIZE/2;
    startptNode->valid[0] = 1;
    startptNode->valid[1] = 1;
    numProcesses = 2;
    numSlots = 2;
    kernel_brk += PAGESIZE;
    //struct pte *pageTable0 = malloc(sizeof(struct pte) * PAGE_TABLE_LEN);  // need to malloc before building page table structures

    idle_pcb->next = NULL;
    active_pcb->next = NULL;
    idle_pcb->PT0 = (struct pte *) startptNode->addr[0];
    active_pcb->PT0 = (struct pte *) startptNode->addr[1];
    struct pte *idlePageTable0 = idle_pcb->PT0;
    struct pte *pageTable0 = active_pcb->PT0;
    idle_pcb->pid = 0;
    active_pcb->pid = 1;
    idle_pcb->ptNode = startptNode;
    active_pcb->ptNode = startptNode;
    idle_pcb->ptNodeIdx = 0;
    active_pcb->ptNodeIdx = 1;

    // Build a structure to keep track of what page frames in physical memory are free
        // use linked list of physical frames, implemented in frames themselves
        // or a separate structure
        // this list of free page frames should be based on the pmem_size argument passed on to your KernelStart
    nextFreePage = (uintptr_t) MEM_INVALID_SIZE;
    for (nextPage = nextFreePage; nextPage < KERNEL_STACK_BASE - PAGESIZE - KERNEL_STACK_PAGES*PAGESIZE; nextPage = nextPage + PAGESIZE) { // save 4 more pages for init
        *((uintptr_t *) nextPage) = nextPage + PAGESIZE;
        freePages += 1;
    }
    kernelBreak = (uintptr_t) kernel_brk;
    *((uintptr_t *) nextPage) = kernelBreak;
    for (; kernelBreak < pmem_size - 2*PAGESIZE; kernelBreak = kernelBreak + PAGESIZE) {
        *((uintptr_t *) kernelBreak) = kernelBreak + PAGESIZE;
        freePages += 1;
    }
    
    // be careful not to accidentally end up using the same page of physical memory twice for different uses at the same time
    // when you free a page, add it back to the linked list. When you allocate it, remove it from the linked list.

    // Build the initial page tabels for Region 0 and Region 1
    kernelBreak = (uintptr_t) kernel_brk;

    // Region 0 before kernel stack
    for (i = 0; i < KERNEL_STACK_BASE >> PAGESHIFT; i++) {
        struct pte entry;
        entry.valid = 0;
        pageTable0[i] = entry;
        
        struct pte entry2;
        entry2.valid = 0;
        idlePageTable0[i] = entry2;
    }
    
    // Region 0 Kernel stack
    for (i = KERNEL_STACK_BASE >> PAGESHIFT; i < KERNEL_STACK_LIMIT >> PAGESHIFT; i++ ) {
        struct pte entry;
        entry.valid = 1;
        entry.kprot = (PROT_READ|PROT_WRITE);
        entry.uprot = PROT_NONE;
        entry.pfn = i;
        idlePageTable0[i] = entry;

        struct pte entry2;
        entry2.valid = 1;
        entry2.kprot = (PROT_READ|PROT_WRITE);
        entry2.uprot = PROT_NONE;
        entry2.pfn = i - KERNEL_STACK_PAGES;
        idlePageTable0[i - KERNEL_STACK_PAGES] = entry2;
    }

    // Region 1 Kernel Text
    for (i = VMEM_0_LIMIT >> PAGESHIFT; i < ((uintptr_t) &_etext) >> PAGESHIFT; i++) {
        //racePrintf(0, "allocating text: %d\n", i);
        struct pte entry;
        entry.valid = 1;
        entry.kprot = (PROT_READ|PROT_EXEC);
        entry.uprot = PROT_NONE;
        entry.pfn = i;
        pageTable1[i - PAGE_TABLE_LEN] = entry;
    }

    // Region 1 Kernel data bss
    for (i = ((uintptr_t) &_etext) >> PAGESHIFT; i < (uintptr_t) kernel_brk >> PAGESHIFT; i++) {
        //racePrintf(0, "allocating databss: %d\n", i);
        struct pte entry;
        entry.valid = 1;
        entry.kprot = (PROT_READ|PROT_WRITE);
        entry.uprot = PROT_NONE;
        entry.pfn = i;
        pageTable1[i - PAGE_TABLE_LEN] = entry;
    }

    // Region 1 above data bss
    for (kernelBreak = ((uintptr_t) kernel_brk) >> PAGESHIFT; kernelBreak < VMEM_LIMIT >> PAGESHIFT; kernelBreak++) {
        //racePrintf(0, "setting rest to zero: %d\n", i);
        struct pte entry;
        entry.valid = 0;
        pageTable1[kernelBreak - PAGE_TABLE_LEN] = entry;
    }
    

    // Initialize registers REG_PTR0 and REG_PTR1 to define these initial page tables
    WriteRegister(REG_PTR0, (RCS421RegVal) &idlePageTable0[0]);
    WriteRegister(REG_PTR1, (RCS421RegVal) &pageTable1[0]);

    // Enable virtual memory
    // for (i = 0; i < PAGE_TABLE_LEN; i++) {
    //     racePrintf(0, "%d, %d \n", i, pageTable0[i].valid);
    // }
    // for (i = 0; i < PAGE_TABLE_LEN; i++) {
    //     racePrintf(0, "%d, %d \n", i, pageTable1[i].valid);
    // }
    WriteRegister(REG_VM_ENABLE, 1); //cast to RCS421RegVal?
    vm_enabled = true;

    // create an "idle" process to be run by the kernel when there are no other runnable (ready) processes in the system.
    // The process should be a loop that executes the Pause machine instruction on each iteration
    // Can be loaded from a file using LoadProgram, or have it "built into" the rest of the code
        // initialize the pc value for this idle process to the address of the code for idle


    
    // loadprogram for idle

    // create the first "regular" process, (init process) and load the initial program into it.
    // guide yourself by the file load.template (shows procedure how to load executalble from a Linux file into memory as Yalnix Process)
    // When process exits, its children continue to run without parents
    // To run initial program you should put file name if the init program on the command line when your run your kernel. It will then be passed to
    // KernelStart as one of the cmd_args strings
    struct pcb *init_pcb = active_pcb;
    active_pcb = idle_pcb;
    char *idle_args[2] = {"idle", NULL};
    TracePrintf(0, "Starting loadProgram\n");
    LoadProgram(idle_args[0], &idle_args[0], info, active_pcb);
    

    TracePrintf(0, "Starting contextswitch...\n");
    //ContextSwitch(DumbMySwitchFunc, init_pcb->ctx, init_pcb, init_pcb);
    //TracePrintf(0, "Finished first contextSwitch\n");
    ContextSwitch(MySwitchFunc, active_pcb->ctx, active_pcb, init_pcb);
    Halt();
    //active_pcb = init_pcb;

    //ExceptionInfo *info2 = malloc(sizeof(ExceptionInfo));
    //LoadProgram(cmd_args[0], cmd_args, info2, active_pcb);
    //LoadProgram(cmd_args[0], cmd_args, info, active_pcb);
    
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) TLB_FLUSH_ALL);
    //(void) init_pcb;
    (void) cmd_args;
    return;
}


/*
 Return pfn of next free page
 */
int get_free_page() {
    if (freePages <= 0) {
        return -1;
    }
    
    //1. save nextFreePage
    uintptr_t svdPage = nextFreePage;
//    TracePrintf(0, "initial nextFreePage %d\n", nextFreePage);
    //2. Go to PTE indexed by PAGE_TABLE_LEN - 1
        // and save values of the PTE first,
        // plug in nextFreePage >> PAGESHIFT in pfn field
    struct pte svdPTE;
    svdPTE.pfn = pageTable1[PAGE_TABLE_LEN - 1].pfn; // REMINDER: this might be fatal if our Kernel heap gets too large
    svdPTE.kprot = pageTable1[PAGE_TABLE_LEN - 1].kprot;
    svdPTE.valid = pageTable1[PAGE_TABLE_LEN - 1].valid;
    pageTable1[PAGE_TABLE_LEN - 1].valid = 1;
    pageTable1[PAGE_TABLE_LEN - 1].pfn = nextFreePage >> PAGESHIFT;
    pageTable1[PAGE_TABLE_LEN - 1].kprot = PROT_READ | PROT_WRITE;
    
    //3. access VMEM_1_LIMIT - PAGESIZE and set nextFreePage to be that
    nextFreePage = *((uintptr_t *) (VMEM_1_LIMIT - PAGESIZE));
//    TracePrintf(0, "new nextFreePage %d\n", nextFreePage);
    //4. decrease freePage by 1
    freePages -= 1;
    
    //5. restore PTE
    pageTable1[PAGE_TABLE_LEN - 1].kprot = svdPTE.kprot;
    pageTable1[PAGE_TABLE_LEN - 1].valid = svdPTE.valid;
    pageTable1[PAGE_TABLE_LEN - 1].pfn = svdPTE.pfn;
    
    //6. Flush from TLB
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) (VMEM_1_LIMIT - PAGESIZE));
    int ret = svdPage >> PAGESHIFT;
//    TracePrintf(0, "getFreePage returns pfn: %d\n", ret);
    return ret;
}

void free_physical_page(int index) {
    // Set the first offset of the page of the address to the previous nextfreepage
    uintptr_t addrNum = 0;
    addrNum += index << PAGESHIFT;
    uintptr_t *actualAddr = (uintptr_t *) addrNum;
    *actualAddr = nextFreePage;
    
    // struct pte svdPTE;
    // svdPTE.pfn = pageTable1[PAGE_TABLE_LEN - 1].pfn; // REMINDER: this might be fatal if our Kernel heap gets too large
    // svdPTE.kprot = pageTable1[PAGE_TABLE_LEN - 1].kprot;
    // svdPTE.valid = pageTable1[PAGE_TABLE_LEN - 1].valid;
    // pageTable1[PAGE_TABLE_LEN - 1].valid = 1;
    // pageTable1[PAGE_TABLE_LEN - 1].pfn = index;
    // pageTable1[PAGE_TABLE_LEN - 1].kprot = PROT_READ | PROT_WRITE;

    // set nextFreePage to the physical address of the pfn of the page to be freed
    nextFreePage = (uintptr_t) ((active_pcb->PT0[index].pfn) << PAGESHIFT);
    
    // increment freePages
    freePages += 1;
    
    // flush tlb
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) (addrNum));
    
    // set valid bit to 0
    active_pcb->PT0[index].valid = 0;
}


int
LoadProgram(char *name, char **args, ExceptionInfo *info, struct pcb *loadPcb)
{
    int fd;
    int status;
    struct loadinfo li;
    char *cp;
    char *cp2;
    char **cpp;
    char *argbuf;
    int i, j, k;
    unsigned long argcount;
    int size;
    int text_npg;
    int data_bss_npg;
    int stack_npg;
    
    int toBeFreePages;

    TracePrintf(0, "LoadProgram '%s', args %p\n", name, args);

    if ((fd = open(name, O_RDONLY)) < 0) {
    TracePrintf(0, "LoadProgram: can't open file '%s'\n", name);
    return (-1);
    }

    status = LoadInfo(fd, &li);
    TracePrintf(0, "LoadProgram: LoadInfo status %d\n", status);
    switch (status) {
    case LI_SUCCESS:
        break;
    case LI_FORMAT_ERROR:
        TracePrintf(0,
        "LoadProgram: '%s' not in Yalnix format\n", name);
        close(fd);
        return (-1);
    case LI_OTHER_ERROR:
        TracePrintf(0, "LoadProgram: '%s' other error\n", name);
        close(fd);
        return (-1);
    default:
        TracePrintf(0, "LoadProgram: '%s' unknown error\n", name);
        close(fd);
        return (-1);
    }
    TracePrintf(0, "text_size 0x%lx, data_size 0x%lx, bss_size 0x%lx\n",
    li.text_size, li.data_size, li.bss_size);
    TracePrintf(0, "entry 0x%lx\n", li.entry);

    /*
     *  Figure out how many bytes are needed to hold the arguments on
     *  the new stack that we are building.  Also count the number of
     *  arguments, to become the argc that the new "main" gets called with.
     */
    size = 0;
    for (i = 0; args[i] != NULL; i++) {
    size += strlen(args[i]) + 1;
    }
    argcount = i;
    TracePrintf(0, "LoadProgram: size %d, argcount %d\n", size, argcount);

    /*
     *  Now save the arguments in a separate buffer in Region 1, since
     *  we are about to delete all of Region 0.
     */
    cp = argbuf = (char *)malloc(size);
    for (i = 0; args[i] != NULL; i++) {
        strcpy(cp, args[i]);
        cp += strlen(cp) + 1;
    }
  
    /*
     *  The arguments will get copied starting at "cp" as set below,
     *  and the argv pointers to the arguments (and the argc value)
     *  will get built starting at "cpp" as set below.  The value for
     *  "cpp" is computed by subtracting off space for the number of
     *  arguments plus 4 (for the argc value, a 0 (AT_NULL) to
     *  terminate the auxiliary vector, a NULL pointer terminating
     *  the argv pointers, and a NULL pointer terminating the envp
     *  pointers) times the size of each (sizeof(void *)).  The
     *  value must also be aligned down to a multiple of 8 boundary.
     */
    cp = ((char *)USER_STACK_LIMIT) - size;
    cpp = (char **)((unsigned long)cp & (-1 << 4));    /* align cpp */
    cpp = (char **)((unsigned long)cpp - ((argcount + 4) * sizeof(void *)));

    text_npg = li.text_size >> PAGESHIFT;
    data_bss_npg = UP_TO_PAGE(li.data_size + li.bss_size) >> PAGESHIFT;
    stack_npg = (USER_STACK_LIMIT - DOWN_TO_PAGE(cpp)) >> PAGESHIFT;

    TracePrintf(0, "LoadProgram: text_npg %d, data_bss_npg %d, stack_npg %d\n",
    text_npg, data_bss_npg, stack_npg);

    /*
     *  Make sure we have enough *virtual* memory to fit everything within
     *  the size of a page table, including leaving at least one page
     *  between the heap and the user stack
     */
    if (MEM_INVALID_PAGES + text_npg + data_bss_npg + 1 + stack_npg +
    1 + KERNEL_STACK_PAGES > PAGE_TABLE_LEN) {
    TracePrintf(0,
        "LoadProgram: program '%s' size too large for VIRTUAL memory\n",
        name);
    free(argbuf);
    close(fd);
    return (-1);
    }

    /*
     *  And make sure there will be enough *physical* memory to
     *  load the new program.
     */
    toBeFreePages = 0;
        /*
         *  And make sure there will be enough physical memory to
         *  load the new program.
         */
    for (j = MEM_INVALID_PAGES >> PAGESHIFT; j < KERNEL_STACK_BASE >> PAGESHIFT; j++) {
        // will all be invalid for init and idle
        if (loadPcb->PT0[j].valid) {
            toBeFreePages += 1;
        }
    }
            
//    >>>> The new program will require text_npg pages of text,
//    >>>> data_bss_npg pages of data/bss, and stack_npg pages of
//    >>>> stack.  In checking that there is enough free physical
//    >>>> memory for this, be sure to allow for the physical memory
//    >>>> pages already allocated to this process that will be
//    >>>> freed below before we allocate the needed pages for
//    >>>> the new program being loaded.
        
        
    if (text_npg + data_bss_npg + stack_npg > toBeFreePages + freePages) {
        TracePrintf(0,
        "LoadProgram: program '%s' size too large for PHYSICAL memory\n",
        name);
        free(argbuf);
        close(fd);
        return (-1);
    }

    
//    >>>> Initialize sp for the current process to (void *)cpp.
    info->sp = (void *)cpp;
//    >>>> The value of cpp was initialized above.

    /*
     *  Free all the old physical memory belonging to this process,
     *  but be sure to leave the kernel stack for this process (which
     *  is also in Region 0) alone.
     */
//    >>>> Loop over all PTEs for the current processs Region 0,
//    >>>> except for those corresponding to the kernel stack (between
//    >>>> address KERNEL_STACK_BASE and KERNEL_STACK_LIMIT).  For
//    >>>> any of these PTEs that are valid, free the physical memory
//    >>>> memory page indicated by that PTEs pfn field.  Set all
//    >>>> of these PTEs to be no longer valid.
    
    for (j = MEM_INVALID_PAGES >> PAGESHIFT; j < KERNEL_STACK_BASE >> PAGESHIFT; j++) {
        // will all be invalid for init and idle
        if (loadPcb->PT0[j].valid) {
            free_physical_page(j);
            //active_pcb->PT0[j]->valid = 0;  // set invalid
        }
    }
    
    /*
     *  Fill in the page table with the right number of text,
     *  data+bss, and stack pages.  We set all the text pages
     *  here to be read/write, just like the data+bss and
     *  stack pages, so that we can read the text into them
     *  from the file.  We then change them read/execute.
     */

//    >>>> Leave the first MEM_INVALID_PAGES number of PTEs in the
//    >>>> Region 0 page table unused (and thus invalid)
    for (j = 0; j < MEM_INVALID_PAGES; j++) {
        loadPcb->PT0[j].valid = 0;  // set invalid
    }
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) TLB_FLUSH_0);

    /* First, the text pages */
//    >>>> For the next text_npg number of PTEs in the Region 0
//    >>>> page table, initialize each PTE:
//    >>>>     valid = 1
//    >>>>     kprot = PROT_READ | PROT_WRITE
//    >>>>     uprot = PROT_READ | PROT_EXEC
//    >>>>     pfn   = a new page of physical memory
    
    for (j = MEM_INVALID_PAGES; j < MEM_INVALID_PAGES + text_npg; j++) {
        loadPcb->PT0[j].valid = 1;
        loadPcb->PT0[j].kprot = PROT_READ | PROT_WRITE;
        loadPcb->PT0[j].uprot = PROT_READ | PROT_EXEC;
        loadPcb->PT0[j].pfn = get_free_page();
    }
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) TLB_FLUSH_0);

    /* Then the data and bss pages */
//    >>>> For the next data_bss_npg number of PTEs in the Region 0
//    >>>> page table, initialize each PTE:
//    >>>>     valid = 1
//    >>>>     kprot = PROT_READ | PROT_WRITE
//    >>>>     uprot = PROT_READ | PROT_WRITE
//    >>>>     pfn   = a new page of physical memory
    
    for (j = MEM_INVALID_PAGES + text_npg; j < MEM_INVALID_PAGES + text_npg + data_bss_npg; j++) {
        loadPcb->PT0[j].valid = 1;
        loadPcb->PT0[j].kprot = PROT_READ | PROT_WRITE;
        loadPcb->PT0[j].uprot = PROT_READ | PROT_WRITE;
        loadPcb->PT0[j].pfn = get_free_page();
    }
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) TLB_FLUSH_0);

    loadPcb->brkAddr = (void *) (uintptr_t) (j << PAGESHIFT);
    // TracePrintf(0, "User Break: %d\n", MEM_INVALID_PAGES);
    // TracePrintf(0, "User Break: %d\n", MEM_INVALID_PAGES << PAGESHIFT);
    // TracePrintf(0, "User Break: %d\n", text_npg);
    // TracePrintf(0, "User Break: %d\n", data_bss_npg);
    // TracePrintf(0, "User Break: %d\n", loadPcb->brk);

    /* And finally the user stack pages */
//    >>>> For stack_npg number of PTEs in the Region 0 page table
//    >>>> corresponding to the user stack (the last page of the
//    >>>> user stack *ends* at virtual address USER_STACK_LIMIT),
//    >>>> initialize each PTE:
//    >>>>     valid = 1
//    >>>>     kprot = PROT_READ | PROT_WRITE
//    >>>>     uprot = PROT_READ | PROT_WRITE
//    >>>>     pfn   = a new page of physical memory
    
    j = (USER_STACK_LIMIT >> PAGESHIFT) - 1;
    for (k = 0; k < stack_npg; k++) {
        loadPcb->PT0[j].valid = 1;
        loadPcb->PT0[j].kprot = PROT_READ | PROT_WRITE;
        loadPcb->PT0[j].uprot = PROT_READ | PROT_WRITE;
        loadPcb->PT0[j].pfn = get_free_page();
        j -= 1;
    }
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) TLB_FLUSH_0);

    loadPcb->stackAddr = (void *) (uintptr_t) ((j+1) << PAGESHIFT);
    
    TracePrintf(0, "brkAddr: %d, stackAddr: %d\n", (uintptr_t) loadPcb->brkAddr, (uintptr_t) loadPcb->stackAddr);

    TracePrintf(0, "Page table setting all done \n");
    
    // for (k = VMEM_0_BASE >> PAGESHIFT; k < VMEM_0_LIMIT >> PAGESHIFT; k++) {
    //     TracePrintf(0, "page: %d, pfn: %d\n", k, (uintptr_t) loadPcb->PT0[k].pfn);
    // }
    
    
    /*
     *  All pages for the new address space are now in place.  Flush
     *  the TLB to get rid of all the old PTEs from this process, so
     *  we'll be able to do the read() into the new pages below.
     */
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);

    /*
     *  Read the text and data from the file into memory.
     */
    if (read(fd, (void *)MEM_INVALID_SIZE, li.text_size+li.data_size) != (int)(li.text_size+li.data_size)) {
    TracePrintf(0, "LoadProgram: couldn't read for '%s'\n", name);
    free(argbuf);
    close(fd);
//    >>>> Since we are returning -2 here, this should mean to
//    >>>> the rest of the kernel that the current process should
//    >>>> be terminated with an exit status of ERROR reported
//    >>>> to its parent process.
    return (-2);
    }

    close(fd);            /* we've read it all now */

    /*
     *  Now set the page table entries for the program text to be readable
     *  and executable, but not writable.
     */
//    >>>> For text_npg number of PTEs corresponding to the user text
//    >>>> pages, set each PTEs kprot to PROT_READ | PROT_EXEC.
    for (j = MEM_INVALID_PAGES; j < MEM_INVALID_PAGES + text_npg; j++) {
        loadPcb->PT0[j].kprot = PROT_READ | PROT_EXEC;
    }
    
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);

    /*
     *  Zero out the bss
     */
    memset((void *)(MEM_INVALID_SIZE + li.text_size + li.data_size),
    '\0', li.bss_size);

    /*
     *  Set the entry point in the ExceptionInfo.
     */
//    >>>> Initialize pc for the current process to (void *)li.entry
    info->pc = (void *)li.entry;
    /*
     *  Now, finally, build the argument list on the new stack.
     */
    *cpp++ = (char *)argcount;        /* the first value at cpp is argc */
    cp2 = argbuf;
    for (i = 0; (unsigned int) i < argcount; i++) {      /* copy each argument and set argv */
    *cpp++ = cp;
    strcpy(cp, cp2);
    cp += strlen(cp) + 1;
    cp2 += strlen(cp2) + 1;
    }
    free(argbuf);
    *cpp++ = NULL;    /* the last argv is a NULL pointer */
    *cpp++ = NULL;    /* a NULL pointer for an empty envp */
    *cpp++ = 0;        /* and terminate the auxiliary vector */

    /*
     *  Initialize all regs[] registers for the current process to 0,
     *  initialize the PSR for the current process also to 0.  This
     *  value for the PSR will make the process run in user mode,
     *  since this PSR value of 0 does not have the PSR_MODE bit set.
     */
//    >>>> Initialize regs[0] through regs[NUM_REGS-1] for the
//    >>>> current process to 0.
//    >>>> Initialize psr for the current process to 0.
    for (j = 0; j < NUM_REGS; j++) {
        info->regs[j] = 0;
    }
    info->psr = 0;
    TracePrintf(0, "Returning from LoadProgram...\n");
    return (0);
}


