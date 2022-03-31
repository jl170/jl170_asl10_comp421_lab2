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
    uintptr_t VA[2];
};

struct exitedChild {
    int pid;
    int exitStatus;
    struct exitedChild *next;
};

struct activeChild {
    struct pcb *childPCB;
    struct activeChild *next;
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
    int delay;
    int forkReturn;
    struct exitedChild *exitedChildHead;
    struct exitedChild *exitedChildTail;
    struct activeChild *children;
    struct pcb *parent;
};

bool vm_enabled = false;  // indicates if virtual memory has been enabled, used in SetKernelBrk
bool initLoaded = false;
void *kernel_brk;  // first address not part of kernel heap
int setKernelBrkCount = 0;
int nextProcessID = 2;

int freePages = 0;
uintptr_t nextFreePage;
struct pte pageTable1[PAGE_TABLE_LEN];

struct pcb *active_pcb;
struct pcb *init_pcb;
struct pcb *ready_pcb_head = NULL;  // queue
struct pcb *ready_pcb_tail = NULL;
struct pcb *blocked_pcb;  // one for each reason?
struct pcb *next_delay_pcb = NULL;
struct pcb *idle_pcb;

struct ptNode *startptNode;
int numProcesses; // number of total processes
int numSlots; // number of slots total
int numReadyProcesses = 0;
int processTickCount = 0;
uintptr_t nextVAforPageTable = VMEM_1_LIMIT - PAGESIZE * 2;

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
void yalnix_exit(int status);
int yalnix_wait();
int yalnix_getpid();
int yalnix_brk(uintptr_t addr);
int yalnix_delay(int clock_ticks);
int yalnix_tty_read();
int yalnix_tty_write();

void idle_process();
int get_free_page();
void free_physical_page(int index);

void addToReadyQ (struct pcb *add);
struct pcb *createDefaultPCB();

int LoadProgram(char *name, char **args, ExceptionInfo *info, struct pcb *loadPcb);
SavedContext *MySwitchFuncNormal(SavedContext *ctxp, void *p1, void *p2); 
SavedContext *MySwitchFuncIdleInit(SavedContext *ctxp, void *p1, void *p2);
SavedContext *mySwitchFuncFork(SavedContext *ctxp, void *p1, void *p2);

void printPT(struct pte *PT, int printValid);

struct pcb *
createDefaultPCB() {
    struct pcb *ret = malloc(sizeof(struct pcb));

    ret->pid = -1;
    ret->ctx = NULL;
    ret-> PT0 = NULL;
    ret->next = NULL;
    ret->brkAddr = NULL;
    ret->stackAddr = NULL;
    ret->ptNode = NULL;
    ret->ptNodeIdx = -1;
    ret->delay = 0;
    ret->forkReturn = -1;
    ret->exitedChildHead = NULL;
    ret->exitedChildTail = NULL;
    ret->children = NULL;
    ret->parent = NULL;

    return ret;
};

/*
 results from kernel call, all kernel call requests enter through here
 code gives kernel call number indicating which service being requested
 
 args beginning in regs[1]
 return value from kernel call should be returned to user process in regs[0]
 */
void TRAP_KERNEL_handler(ExceptionInfo *info)
{
    TracePrintf(0, "\n\nIn TRAP_KERNEL_handler\n");
    
    int result;
    int code = info->code;
    
    if (code == YALNIX_FORK) {
        result = yalnix_fork();
    } else if (code == YALNIX_EXEC) {
        result = yalnix_exec();
    } else if (code == YALNIX_EXIT) {
        yalnix_exit((int) info->regs[1]);  // TODO: exit has no return
        return;
    } else if (code == YALNIX_WAIT) {
        result = yalnix_wait();
    } else if (code == YALNIX_GETPID) {
        result = yalnix_getpid();
    } else if (code == YALNIX_BRK) {
        result = yalnix_brk((uintptr_t) info->regs[1]);
    } else if (code == YALNIX_DELAY) {
        result = yalnix_delay((int) info->regs[1]);
    } else if (code == YALNIX_TTY_READ) {
        result = yalnix_tty_read();
    } else if (code == YALNIX_TTY_WRITE) {
        result = yalnix_tty_write();
    }  // if code not defined then not good

    info->regs[0] = result;
}

void TRAP_CLOCK_handler(ExceptionInfo *info)
{
    TracePrintf(0, "\n\nIn TRAP_CLOCK_handler\n");
    // Decrement all delay counts in the delay linked list
        // if they reach zero, then take them out of the delay list and put them in the ready queue
    struct pcb *currDelayProcess = next_delay_pcb;
    struct pcb *prev, *nextDelayProcess;
    while (currDelayProcess) {
        TracePrintf(0, "Process %d delay %d left\n", currDelayProcess->pid, currDelayProcess->delay - 1);
        if (--currDelayProcess->delay == 0) { // decrement delay, and if delay reaches zero, (alter the linked list of delayed processes)
            if (currDelayProcess == next_delay_pcb) { // if this is the first delay process in the list,
                next_delay_pcb = next_delay_pcb->next; // changed the head of the list
            } else {
                prev->next = currDelayProcess->next; // else, set the previous process's next field
            }
            nextDelayProcess = currDelayProcess->next; // save the next of currDelayProcess here, b/c we need to set next field to zero and we aren't done with using currDelayProcess
            currDelayProcess->next = NULL;
            if (!ready_pcb_tail) { // If ready_pcb_tail is NULL (there we no ready processes), set tail and head
                ready_pcb_tail = currDelayProcess;
                ready_pcb_head = currDelayProcess;
            } else { // else (there are ready processes), set next field of tail and set tail
                ready_pcb_tail->next = currDelayProcess;
                ready_pcb_tail = currDelayProcess;
            }
            TracePrintf(0, "In clock handler, after adding 0 delay to ready list: head: %d, tail: %d\n", (uintptr_t)ready_pcb_head, (uintptr_t)ready_pcb_tail);
            prev = currDelayProcess;
            currDelayProcess = nextDelayProcess; // after we're all done, move pointer to currDelayProcess for next step
        } else { // if delay is not zero, then just move on
            prev = currDelayProcess;
            currDelayProcess = currDelayProcess->next;
        }

    }
    TracePrintf(0, "From Clock handler: processTickCount: %d\n", processTickCount);
    // increment processTickCount if processTickCount < 2
    if (processTickCount >= 2 || active_pcb->pid == 0) { // if tick count is >= 2,
        TracePrintf(0, "ready_pcb_head: %d, tail: %d\n", (uintptr_t) ready_pcb_head, (uintptr_t) ready_pcb_tail);
        if (ready_pcb_head) { // if there is a process to switch to,
            if (active_pcb->pid == 0) {
                TracePrintf(0, "idle was running, so contextSwitch from process %d to process: %d\n", active_pcb->pid, ready_pcb_tail->pid);
            } else {
                TracePrintf(0, "processTickCount is >= 2, contextSwitch from process %d to process: %d\n", active_pcb->pid, ready_pcb_tail->pid);
            }
            struct pcb *switchFrom;
            if (active_pcb->pid != 0) {
                ready_pcb_tail->next = active_pcb; // set the next of the original tail
                ready_pcb_tail = active_pcb; // set the tail pointer
                switchFrom = ready_pcb_tail;
            } else {
                switchFrom = idle_pcb;
            }
            active_pcb = ready_pcb_head; // set new active pcb
            if (ready_pcb_head->next == NULL) {
                ready_pcb_tail = NULL;
            }
            ready_pcb_head = ready_pcb_head->next; // set the new head
            active_pcb->next = NULL; // set the next of the active pcb

            // context switch from the original process (which is now in ready_pcb_tail) to the ready process next in line (which is now active_pcb)
            ContextSwitch(MySwitchFuncNormal, switchFrom->ctx, switchFrom, active_pcb); 
        }
    } else if (processTickCount < 2) {
        processTickCount++;
    }
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
    TracePrintf(0, "In yalnix_fork\n");
    // create new process id
    int newId = nextProcessID++;

    // allocate new PCB
    struct pcb *childPCB = createDefaultPCB();
    childPCB->pid = newId;

    // set and allocate page table for region 0
    if (numSlots > numProcesses) { // if there is a slot left,
        struct ptNode *currPTNode = startptNode;
        while (currPTNode->valid[0] == 1 && currPTNode->valid[1] == 1) {
            currPTNode = currPTNode->next;
            if (currPTNode == NULL) {
                TracePrintf(0, "Fork: VERY BAD: reached end of ptNodes but found no empty slot\n");
                Halt();
            }
        }
        if (currPTNode->valid[0] == 0) {
            childPCB->PT0 = (struct pte *) currPTNode->VA[0];
            childPCB->ptNodeIdx = 0;
        } else if (currPTNode->valid[1] == 0) {
            childPCB->PT0 = (struct pte *) currPTNode->VA[1];
            childPCB->ptNodeIdx = 1;
        } else {
            TracePrintf(0, "Fork: VERY BAD: no empty slot!!\n");
            Halt();
        }
        childPCB->ptNode = currPTNode;
    } else if (numSlots == numProcesses) { // if there are no slots left
        struct ptNode *newNode = malloc(sizeof(struct ptNode));
        newNode->next = startptNode->next;
        startptNode->next = newNode;
        uintptr_t freePagePA = (uintptr_t) (get_free_page() << PAGESHIFT);
        newNode->addr[0] = freePagePA;
        newNode->addr[1] = freePagePA + PAGESIZE/2;
        newNode->valid[0] = 1;
        newNode->valid[1] = 0;
        newNode->VA[0] = nextVAforPageTable;
        newNode->VA[1] = nextVAforPageTable + PAGESIZE/2;

        int freePagePT1Idx = (nextVAforPageTable >> PAGESHIFT) - PAGE_TABLE_LEN;
        pageTable1[freePagePT1Idx].valid = 1;
        pageTable1[freePagePT1Idx].kprot = PROT_READ | PROT_WRITE;
        pageTable1[freePagePT1Idx].uprot = PROT_READ | PROT_WRITE;
        pageTable1[freePagePT1Idx].pfn = freePagePA >> PAGESHIFT;
        nextVAforPageTable -= PAGESIZE;
        numSlots += 2;
        
        childPCB->PT0 = (struct pte *) newNode->VA[0];
        childPCB->ptNode = newNode;
        childPCB->ptNodeIdx = 0;
    }
    numProcesses += 1;


    childPCB->brkAddr = active_pcb->brkAddr;
    childPCB->stackAddr = active_pcb->stackAddr;
    childPCB->delay = 0;
    

    // struct pcb {
    // SavedContext *ctx;
    // struct pcb *next;

    // copy parent kernel stack including exception info

    // copy text data bss heap

    // allocate new memory for child process
    // copy parent address space into child
    
    // create a new region 0 page table
    // That means Region 0 page tables must be dynamically allocated and initialized (but, be careful, you cannot use malloc for this).
    
    // ExceptionInfo is on the kernel stack, and each process has its own kernel stack, so each has its own ExceptionInfo.  You don't ever need to save and restore the ExecptionInfo
    
    // return” in both processes by scheduling both to run in our queue(s)

    // initialize and assign activeChild struct
    struct activeChild *activeChildStruct = malloc(sizeof(struct activeChild));
    activeChildStruct->childPCB = childPCB;
    activeChildStruct->next = active_pcb->children;
    active_pcb->children = activeChildStruct;

    // set parent of child
    childPCB->parent = active_pcb;

    active_pcb->forkReturn = childPCB->pid;
    childPCB->forkReturn = 0;

    struct pcb* prev_pcb = active_pcb;
    addToReadyQ(active_pcb);
    active_pcb = childPCB;
    
    if (childPCB->ctx == NULL) {
        childPCB->ctx = malloc(sizeof(SavedContext));
    }

    ContextSwitch(mySwitchFuncFork, prev_pcb->ctx, prev_pcb, active_pcb);

    // In mySwitchFuncFork:
        // The savedcontext that is returned should be the one that's been updated by ContextSwitch
        // Switch the page table to child
        // return as the child


    return active_pcb->forkReturn;
}

void
addToReadyQ (struct pcb *add) {
    if (ready_pcb_head == NULL && ready_pcb_tail == NULL) {
        ready_pcb_head = add;
        ready_pcb_tail = add;
    } else if (ready_pcb_head == NULL || ready_pcb_tail == NULL) {
        TracePrintf(0, "addToReadyQ: YOU IDIOT you messed up bookeeping for head and tail\n");
        Halt();
    } else {
        ready_pcb_tail->next = add;
        ready_pcb_tail = add;
    }
}

struct pcb *
popFromReadyQ() {
    if (ready_pcb_head == NULL && ready_pcb_tail == NULL) {
        TracePrintf(0, "popFromReadyQ: nothing in Q\n");
        return NULL;
    } else if (ready_pcb_head == NULL || ready_pcb_tail == NULL) {
        TracePrintf(0, "addToReadyQ: YOU IDIOT you messed up bookeeping for head and tail\n");
        Halt();
    } else if (ready_pcb_head == ready_pcb_tail) {
        struct pcb *ret = ready_pcb_head;
        ready_pcb_tail = NULL;
        ready_pcb_head = NULL;
        return ret;
    } else {
        struct pcb *ret = ready_pcb_head;
        ready_pcb_head = ready_pcb_head->next;
        return ret;
    }
}

SavedContext *
mySwitchFuncFork(SavedContext *ctxp, void *p1, void *p2) {
    struct pcb *parent = (struct pcb *)p1;
    struct pcb *child = (struct pcb *)p2;
    uintptr_t i;
    //child->ctx = malloc(sizeof(SavedContext));
    //memcpy((void *)child->ctx, (void *)ctxp, sizeof(SavedContext));
    //TracePrintf(0, "CHILD CTX: %d\n", (uintptr_t)child->ctx);
    
    // copy page tables,
    struct pte svdPTE;
    int borrowpfn = PAGE_TABLE_LEN - 1;
    uintptr_t borrowedAddrVA = (uintptr_t) (VMEM_1_LIMIT - PAGESIZE);

    svdPTE.pfn = pageTable1[borrowpfn].pfn; // REMINDER: this might be fatal if our Kernel heap gets too large
    svdPTE.kprot = pageTable1[borrowpfn].kprot;
    svdPTE.valid = pageTable1[borrowpfn].valid;
    pageTable1[borrowpfn].valid = 1;
    pageTable1[borrowpfn].kprot = PROT_READ | PROT_WRITE;

    for (i = 0; i < KERNEL_STACK_LIMIT >> PAGESHIFT; i++ ) {
        //TracePrintf(0, "In mySwitchFuncFork, i = %d\n", i);
        struct pte newEntry;
        // check if pte is valid in parent's page table
        if (parent->PT0[i].valid == 1) { // if it is, allocate a page,  memcpy it to child's address
            //TracePrintf(0, "In mySwitchFuncFork If\n");
            newEntry.valid = 1;
            newEntry.kprot = parent->PT0[i].kprot;
            newEntry.uprot = parent->PT0[i].uprot;
            newEntry.pfn = get_free_page();
            child->PT0[i] = newEntry;

            pageTable1[borrowpfn].pfn = child->PT0[i].pfn;
            memcpy((void *)(borrowedAddrVA), (void *) (i << PAGESHIFT), PAGESIZE);
            TracePrintf(0, "copied from %d to %d, index %d, VA %d to %d\n", parent->PT0[i].pfn, child->PT0[i].pfn, i, i << PAGESHIFT, borrowedAddrVA);
            WriteRegister(REG_TLB_FLUSH, (RCS421RegVal)borrowedAddrVA); // flush borrowed pte
        } else { // if it's not, assign 0 to valid bit
            //TracePrintf(0, "In mySwitchFuncFork else\n");
            newEntry.valid = 0;
            child->PT0[i] = newEntry;
        }
    }

    pageTable1[PAGE_TABLE_LEN - 1].kprot = svdPTE.kprot;
    pageTable1[PAGE_TABLE_LEN - 1].valid = svdPTE.valid;
    pageTable1[PAGE_TABLE_LEN - 1].pfn = svdPTE.pfn;

    WriteRegister(REG_PTR0, child->ptNode->addr[child->ptNodeIdx]);
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);

    // PLEASE FLUSH PLEASE FLUSH PLEASE FLUSH PLEASE FLUSH PLEASE FLUSH PLEASE FLUSH 
    // return as ctxp
    return ctxp;
}
    
int yalnix_exec() {
    TracePrintf(0, "In yalnix_exec\n");
    Halt();
}

/*
 when process exits, if has children then children should conintue to run normally but w/out parent
 when orphan exits, exit status is not saved or reported to parent
 all resources should be freed except status (if not orphan)
 
 when exits for last process (or last terminated by kernel), execute Halt
 */
void yalnix_exit(int status) {
    TracePrintf(0, "In yalnix_exit\n");
    // if process has a parent (that is still running- check if parent is NULL), handle the exit structure
    // malloc an exited_child struct and update the fields
    if (active_pcb->parent != NULL) {
        struct exitedChild *eChild = malloc(sizeof(struct exitedChild));
        eChild->pid = active_pcb->pid;
        eChild->exitStatus = status;

        // take this pcb out of the parent's children list
        if (active_pcb->parent->children->childPCB == active_pcb) {
            struct activeChild *store = active_pcb->parent->children;
            active_pcb->parent->children = active_pcb->parent->children->next;
            free(store);
        } else {
            struct activeChild *nextChild = active_pcb->parent->children;
            while (nextChild->next->childPCB != active_pcb) {
                nextChild = nextChild->next;
                if (nextChild == NULL) {
                    TracePrintf(0, "yalnix_exit: YOU IDIOT YOU MESSED UP BOOKKEEPING FOR CHILDREN LIST");
                }
            }
            struct activeChild *store = nextChild->next;
            nextChild->next = nextChild->next->next;
            free(store);
        }

        // update parent exitedchild queue // get the parent pcb and add the struct to the llist of exited children
        if (active_pcb->parent->exitedChildHead == NULL && active_pcb->parent->exitedChildTail == NULL) { // nothing in exitedChildQ
            active_pcb->parent->exitedChildHead = eChild;
            active_pcb->parent->exitedChildTail = eChild;
        } else if (active_pcb->parent->exitedChildHead == NULL || active_pcb->parent->exitedChildTail == NULL) {
            TracePrintf(0, "yalnix_exit: YOU IDIOT YOU MESSED UP BOOKKEEPING\n");
            Halt();
        } else { // something in exitedChildQ
            active_pcb->parent->exitedChildTail->next = eChild;
            active_pcb->parent->exitedChildTail = eChild;
        }
    }

    // for all children of this process, set parent to null
    struct activeChild *currChild = active_pcb->children;
    while (currChild != NULL) {
        currChild->childPCB->parent = NULL;
        currChild = currChild->next;
    }

    // free physical pages used in PT0:
    // for each valid PTE, use free_physical_page, then set valid bit to 0
    int i;
    for (i = 0; i < USER_STACK_LIMIT >> PAGESHIFT; i++) {
        TracePrintf(0, "yalnix_exit: free physical pages in pt0: %d / %d\n", i, USER_STACK_LIMIT >> PAGESHIFT);
        if (active_pcb->PT0[i].valid) {
            free_physical_page(active_pcb->PT0[i].pfn);
            active_pcb->PT0[i].valid = 0;
            TracePrintf(0, "yalnix_exit: freed physical page: %d\n", i);
        }
    }

    
    
    // update ptNode llist (free PT0 allocated memory):
        // if other slot in ptNode is also free, then free page, free ptNode, and remove from llist
    struct ptNode *thisNode = active_pcb->ptNode;
    if (thisNode->valid[1 - active_pcb->ptNodeIdx] == 0) {
        free_physical_page((int) (thisNode->addr[0] >> PAGESHIFT));
        struct ptNode *currNode = startptNode;
        while (currNode->next != thisNode) { // don't need to check for first one because the init-idle block is going to be first
            currNode = thisNode->next;
        }
        currNode->next = currNode->next->next;
        free(thisNode);
        numSlots -= 2;
    } else { // otherwise, set ptNode valid to valid
        thisNode->valid[active_pcb->ptNodeIdx] = 0;
    }
    // update numProcesses (down), numSlots (up)
    numProcesses -= 1;
    
    // NEED TODO? free any internal fields that were malloced NEED TODO?
    // free PCB:
    free(active_pcb);
    
    // if this was last process (nothing in ready or blocked)
        // also free idle
        // Halt();
    if (ready_pcb_head == NULL && ready_pcb_tail == NULL) {
        if (next_delay_pcb == NULL) {
            TracePrintf(0, "No ready, no delayed processes. Bye Bye!\n");
            // NEED TODO? free idle
            Halt();
        } else { // nothing ready but something delayed, so switch to idle
            active_pcb = idle_pcb;
            ContextSwitch(MySwitchFuncNormal, active_pcb->ctx, active_pcb, active_pcb); // the middle two arguments don't really matter here, we don't want to save ctx anyway
        }
    } else if (ready_pcb_head == NULL || ready_pcb_tail == NULL) {
        TracePrintf(0, "yalnix_exit: IDIOTIC BOOKKEEPING\n");
        Halt();
    } else {
        struct pcb *next_pcb = popFromReadyQ();
        if (next_pcb == NULL) {
            TracePrintf(0, "yalnix_exit: something's wrong (null case already taken care of above)\n");
            Halt();
        }
        TracePrintf(0, "Next pcb: %d\n", (uintptr_t)next_pcb->pid);
        struct pcb *prev_pcb = active_pcb;
        active_pcb = next_pcb;
        if (active_pcb->ctx == NULL) {
            active_pcb->ctx = malloc(sizeof(SavedContext));
        }
        //TracePrintf(0, "CHILD CTX: %d\n", (uintptr_t)active_pcb->ctx);
        ContextSwitch(MySwitchFuncNormal, prev_pcb->ctx, prev_pcb, active_pcb); // the middle two arguments don't really matter here, we don't want to save ctx anyway
    }
    
    // set a new active_pcb and context switch to it? (or handle active_pcb is null elsewhere)
    TracePrintf(0, "yalnix_exit: we... shouldn't get here");
    Halt();
}

/*
 collect the process ID, exit status returned by child process of calling program
 when child exits, exit status should be added to queue of child processes not yet collected by parent
 child info removed after wait
 if has no child processes (exited or running) should return ERROR, status_ptr unchanced

 */
int yalnix_wait() {
    TracePrintf(0, "In yalnix_wait\n");
    Halt();
    /*
     waiting for any child process to exit? doesn't matter which child process
     */
    
    // if there are no child processes (exited or running)
        // return ERROR
    
    
    // if a child process has already exited (if next_exit != NULL)
        // get exit status, etc. from exited_child struct
        // update exited children llist (remove child from next_exit llist)
        // return child process's exit status information
    
    // if no child processes have exited yet (next_exit == NULL)
        // block until next child exits/terminated
        // add pcb to blocked queue- need to have specific wait_block queue, check in clock handler
        // set new active pcb, context switch to it? (or handle null active pcb)
    
    /*
     each process (pcb) needs to know
        state (running/exited) of each child
        exit status and pid of exited children
        its parent (to update info when exit)
        
     struct exited_child {
        int state = 0;
        int pid = 0;
        exit status;
        struct *exit_info next;
     }
     
     add to pcb:    struct exited_child *next_exit; // llist of exited children and their status/pid
                    maybe also a tail bc this needs to be a queue
                    struct pcb *run_children; llist of running children
                    struct pcb *next_child;
                    struct pcb *parent; // pointer to parent
                    
     
     or might be better to just make an exit_status struct that all pcbs have
        state, pid, exit status, child llist, parent
     
     ** make sure to update new pcb fields for idle, init **
        
     */
    
}

int yalnix_getpid() {
    TracePrintf(0, "In yalnix_getpid\n");
    return active_pcb->pid;
    Halt();
}

int yalnix_brk(uintptr_t addr) {
    printPT(active_pcb->PT0, 1);
    unsigned int i;
    TracePrintf(0, "In yalnix_brk\n");
    
    if (addr >= USER_STACK_LIMIT) {
        return ERROR;
    }
    
    // round up addr to see which page we need to allocate to or free
    uintptr_t roundedAddr = UP_TO_PAGE(addr);
    // If they're the same, don't do anything
    if ((uintptr_t) active_pcb->brkAddr == roundedAddr) {
        // don't do anything
    } else if ((uintptr_t) active_pcb->brkAddr <= roundedAddr) { // If roundedAddr > breakAddr, 
        // then allocate pages and update ptes in pt0, and breakAddr accordingly
        for (i = (uintptr_t) active_pcb->brkAddr >> PAGESHIFT; i < roundedAddr >> PAGESHIFT; i++) {
            active_pcb->PT0[i].valid = 1;
            active_pcb->PT0[i].kprot = PROT_READ | PROT_WRITE;
            active_pcb->PT0[i].uprot = PROT_READ | PROT_WRITE;
            active_pcb->PT0[i].pfn = get_free_page();
        }
        active_pcb->brkAddr = (void *) roundedAddr;
    } else if ((uintptr_t) active_pcb->brkAddr <= roundedAddr) { // If roundedAddr < breakAddr
        // then free pages and update pt0, and breakAddr accordingly
        for (i = roundedAddr >> PAGESHIFT; i < (uintptr_t) active_pcb->brkAddr >> PAGESHIFT; i++) {
            free_physical_page(i);
            active_pcb->PT0[i].valid = 0;
        }
        active_pcb->brkAddr = (void *) roundedAddr;
    }

    // PLEASE FLUSH PLEASE FLUSHPLEASE FLUSHPLEASE FLUSHPLEASE FLUSHPLEASE FLUSHPLEASE FLUSHPLEASE FLUSHPLEASE FLUSH
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);
    return 0;
}

int yalnix_delay(int clock_ticks) {
    TracePrintf(0, "In yalnix_delay: %d ticks\n", clock_ticks);
    if (clock_ticks > 0) {
        active_pcb->delay = clock_ticks;
        struct pcb *prev_pcb = active_pcb;
        active_pcb->next = next_delay_pcb;
        next_delay_pcb = active_pcb;
        if (numReadyProcesses > 0) {
            active_pcb = ready_pcb_head; // the ready process head becomes the active process
            ready_pcb_head = ready_pcb_head->next; // the "next" of the ready process head becomes the ready process head
            active_pcb->next = NULL; // the new active process has its next field reset
            numReadyProcesses -= 1; // we essentially pulled a node out of the ready process
            if (numReadyProcesses == 0) { // if ready Q is empty
                ready_pcb_tail = NULL;
            }
        } else {
            active_pcb = idle_pcb;
        }
        ContextSwitch(MySwitchFuncNormal, prev_pcb->ctx, prev_pcb, active_pcb);
    } else if (clock_ticks < 0) {
        return ERROR;
    }
    return 0;
}

int yalnix_tty_read() {
    TracePrintf(0, "In yalnix_tty_read\n");
    Halt();
}

int yalnix_tty_write() {
    TracePrintf(0, "In yalnix_tty_write\n");
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
MySwitchFuncIdleInit(SavedContext *ctxp, void *p1, void *p2) {
    struct pcb *pcb1 = (struct pcb *) p1;
    (void)pcb1;
    struct pcb *pcb2 = (struct pcb *) p2;
    uintptr_t i;
    struct pte svdPTE;

    int borrowpfn = PAGE_TABLE_LEN - 1;
    uintptr_t borrowedAddrVA = (uintptr_t) (VMEM_1_LIMIT - PAGESIZE);
    svdPTE.pfn = pageTable1[borrowpfn].pfn; // REMINDER: this might be fatal if our Kernel heap gets too large
    svdPTE.kprot = pageTable1[borrowpfn].kprot;
    svdPTE.valid = pageTable1[borrowpfn].valid;
    pageTable1[borrowpfn].valid = 1;
    pageTable1[borrowpfn].kprot = PROT_READ | PROT_WRITE;
    
    
    for (i = KERNEL_STACK_BASE; i < KERNEL_STACK_LIMIT; i += PAGESIZE) {
        struct pte *entry2 = malloc(sizeof(struct pte));
        //TracePrintf(0, "YOYO: %d\n", (uintptr_t) entry2);
        entry2->valid = 1;
        entry2->kprot = (PROT_READ|PROT_WRITE);
        entry2->uprot = PROT_NONE;
        entry2->pfn = get_free_page();
        pcb2->PT0[i >> PAGESHIFT] = *entry2; // fix this
        
        pageTable1[borrowpfn].pfn = pcb2->PT0[i >> PAGESHIFT].pfn;
        memcpy((void *)(borrowedAddrVA), (void *) i, PAGESIZE);
        WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) borrowedAddrVA);
    }
    
    pageTable1[PAGE_TABLE_LEN - 1].kprot = svdPTE.kprot;
    pageTable1[PAGE_TABLE_LEN - 1].valid = svdPTE.valid;
    pageTable1[PAGE_TABLE_LEN - 1].pfn = svdPTE.pfn;
    
    //pcb1->ctx = ctxp;
    //memcpy((void*) pcb2->ctx, (void*) pcb1->ctx, sizeof(SavedContext));
    //TracePrintf(0, "In MySwitchFunc: %d %d\n", pcb1->ptNode->addr[pcb1->ptNodeIdx], pcb2->ptNode->addr[pcb2->ptNodeIdx]);
    WriteRegister(REG_PTR0, (RCS421RegVal) pcb2->ptNode->addr[pcb2->ptNodeIdx]);
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);
    //memcpy((void*) pcb2->ctx, (void*) pcb1->ctx, sizeof(SavedContext));
    //pcb2->ctx = ctxp;
    TracePrintf(0, "Returning from myswitchfuncIdleInit..\n");
    active_pcb = pcb2;
    processTickCount = 0;
    return ctxp;
    
    //return pcb2->ctx;
}

SavedContext *
MySwitchFuncNormal(SavedContext *ctxp, void *p1, void *p2) {
    TracePrintf(0, "In mySwitchFuncNormal\n");
    struct pcb *pcb1 = (struct pcb *) p1;
    (void)pcb1;
    (void)ctxp;
    struct pcb *pcb2 = (struct pcb *) p2;
    // uintptr_t i;
    // struct pte svdPTE;

    // int borrowpfn = PAGE_TABLE_LEN - 1;
    // uintptr_t borrowedAddrVA = (uintptr_t) (VMEM_1_LIMIT - PAGESIZE);
    // svdPTE.pfn = pageTable1[borrowpfn].pfn; // REMINDER: this might be fatal if our Kernel heap gets too large
    // svdPTE.kprot = pageTable1[borrowpfn].kprot;
    // svdPTE.valid = pageTable1[borrowpfn].valid;
    // pageTable1[borrowpfn].valid = 1;
    // pageTable1[borrowpfn].kprot = PROT_READ | PROT_WRITE;
    // pageTable1[borrowpfn].pfn = pcb2->PT0[i >> PAGESHIFT].pfn;
    
    // pageTable1[PAGE_TABLE_LEN - 1].kprot = svdPTE.kprot;
    // pageTable1[PAGE_TABLE_LEN - 1].valid = svdPTE.valid;
    // pageTable1[PAGE_TABLE_LEN - 1].pfn = svdPTE.pfn;

    WriteRegister(REG_PTR0, (RCS421RegVal) pcb2->ptNode->addr[pcb2->ptNodeIdx]);
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);
    TracePrintf(0, "Returning from MySwitchFuncNormal..\n");
    processTickCount = 0;
    return pcb2->ctx;
}

void
printPCBInfo(struct pcb *pcb1) {
    TracePrintf(0, "printPCBInfo | pid: %d, SavedContext Addr: %d, PT0 VA: %d, PT0 PA: %d, \nbrkAddr: %d, stackAddr: %d, ptNode addr: %d, ptNodeIdx: %d\n", pcb1->pid, (uintptr_t)(pcb1->ctx), (uintptr_t)(pcb1->PT0), pcb1->ptNode->addr[pcb1->ptNodeIdx],(uintptr_t)pcb1->brkAddr, (uintptr_t)pcb1->stackAddr, (uintptr_t)pcb1->ptNode, pcb1->ptNodeIdx);
}

void
printPT(struct pte *PT, int printValid) {
    unsigned int i;
    for (i = 0; i < PAGE_TABLE_LEN; i++) {
        if (printValid) {
            if (PT[i].valid) {
                TracePrintf(0, "vpn %d, valid %d, pfn %d, first byte: %d\n", i, PT[i].valid, PT[i].pfn, *(uintptr_t *)(uintptr_t)(i << PAGESHIFT));
            }
        } else {
            TracePrintf(0, "vpn %d, valid %d, pfn %d, first byte: %d\n", i, PT[i].valid, PT[i].pfn, *(uintptr_t *)(uintptr_t)(i << PAGESHIFT));
        }
    }
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
    startptNode->VA[0] = (uintptr_t) kernel_brk;
    startptNode->VA[1] = (uintptr_t) kernel_brk + PAGESIZE/2;
    startptNode->next = NULL;
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
    for (nextPage = nextFreePage; nextPage < KERNEL_STACK_BASE - PAGESIZE; nextPage = nextPage + PAGESIZE) {
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
       // TracePrintf(0, "YOYO entry: %d\n", (uintptr_t) &entry);
        entry.valid = 0;
        pageTable0[i] = entry;
        
        struct pte entry2;
        entry2.valid = 0;
        idlePageTable0[i] = entry2;
        //TracePrintf(0, "YOYO entry2: %d\n", (uintptr_t) &entry2);
    }
    
    // Region 0 Kernel stack
    for (i = KERNEL_STACK_BASE >> PAGESHIFT; i < KERNEL_STACK_LIMIT >> PAGESHIFT; i++ ) {
        struct pte entry;
        entry.valid = 1;
        entry.kprot = (PROT_READ|PROT_WRITE);
        entry.uprot = PROT_NONE;
        entry.pfn = i;
        idlePageTable0[i] = entry;
        //TracePrintf(0, "YOYO stack entry: %d\n", (uintptr_t) &entry);

        // struct pte entry2;
        // entry2.valid = 1;
        // entry2.kprot = (PROT_READ|PROT_WRITE);
        // entry2.uprot = PROT_NONE;
        // entry2.pfn = i - KERNEL_STACK_PAGES;
        // pageTable0[i - KERNEL_STACK_PAGES] = entry2;
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
        //TracePrintf(0, "YOYO text entry: %d\n", (uintptr_t) &entry);
        //TracePrintf(0, "YOYO text entry inside: %d\n", &(*((struct pte *)(&(pageTable1[i - PAGE_TABLE_LEN])))));
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
        //TracePrintf(0, "YOYO data bss entry: %d\n", (uintptr_t) &entry);
    }

    // Region 1 above data bss
    for (kernelBreak = ((uintptr_t) kernel_brk) >> PAGESHIFT; kernelBreak < VMEM_LIMIT >> PAGESHIFT; kernelBreak++) {
        //racePrintf(0, "setting rest to zero: %d\n", i);
        struct pte entry;
        entry.valid = 0;
        pageTable1[kernelBreak - PAGE_TABLE_LEN] = entry;
        //TracePrintf(0, "YOYO above data bss entry: %d\n", (uintptr_t) &entry);
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
    printPCBInfo(active_pcb);
    printPCBInfo(idle_pcb);

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
    init_pcb = active_pcb;
    active_pcb = idle_pcb;
    char *idle_args[2] = {"idle", NULL};
    TracePrintf(0, "Starting loadProgram\n");
    LoadProgram(idle_args[0], &idle_args[0], info, active_pcb);
    

    TracePrintf(0, "Starting contextswitch...\n");
    //ContextSwitch(DumbMySwitchFunc, init_pcb->ctx, init_pcb, init_pcb);
    //TracePrintf(0, "Finished first contextSwitch\n");
    ContextSwitch(MySwitchFuncIdleInit, active_pcb->ctx, active_pcb, init_pcb);
    //Halt();
    TracePrintf(0, "regptr0: %d, regidle: %d, reginit: %d\n", (uintptr_t) ReadRegister(REG_PTR0), idle_pcb->ptNode->addr[idle_pcb->ptNodeIdx], init_pcb->ptNode->addr[init_pcb->ptNodeIdx]);
    if (initLoaded) {
        return;
    } else {
        initLoaded = true;
    }

    //ExceptionInfo *info2 = malloc(sizeof(ExceptionInfo));
    //LoadProgram(cmd_args[0], cmd_args, info2, active_pcb);
    //TracePrintf(0, "idle: %d, init: %d, active; %d\n", (uintptr_t) idle_pcb, (uintptr_t) init_pcb, (uintptr_t) active_pcb);
    LoadProgram(cmd_args[0], cmd_args, info, active_pcb);
    
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) TLB_FLUSH_ALL);
    //(void) init_pcb;
    //(void) cmd_args;
    //(void) idle_args;
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

/**
 * Index should be pfn
 */
void free_physical_page(int index) {
    TracePrintf(0, "freeing physical page with index: %d\n", index);
    uintptr_t addrNum = 0;
    addrNum += index << PAGESHIFT;
    if (!vm_enabled) {
        uintptr_t *actualAddr = (uintptr_t *) addrNum;
        // Set the first offset of the page of the address to the previous nextfreepage
        *actualAddr = nextFreePage;
    } else {
        struct pte svdPTE;
        int borrowpfn = PAGE_TABLE_LEN - 1;
        uintptr_t borrowedAddrVA = (uintptr_t) (VMEM_1_LIMIT - PAGESIZE);
        svdPTE.pfn = pageTable1[borrowpfn].pfn; // REMINDER: this might be fatal if our Kernel heap gets too large
        svdPTE.kprot = pageTable1[borrowpfn].kprot;
        svdPTE.valid = pageTable1[borrowpfn].valid;
        pageTable1[borrowpfn].valid = 1;
        pageTable1[borrowpfn].kprot = PROT_READ | PROT_WRITE;
        pageTable1[borrowpfn].pfn = index;

        *((uintptr_t *) borrowedAddrVA) = nextFreePage;
        //*actualAddr = nextFreePage;

        pageTable1[PAGE_TABLE_LEN - 1].kprot = svdPTE.kprot;
        pageTable1[PAGE_TABLE_LEN - 1].valid = svdPTE.valid;
        pageTable1[PAGE_TABLE_LEN - 1].pfn = svdPTE.pfn;
        WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) (borrowedAddrVA));
    }
    // for (i = KERNEL_STACK_BASE; i < KERNEL_STACK_LIMIT; i += PAGESIZE) {
    //     struct pte entry2;
    //     entry2.valid = 1;
    //     entry2.kprot = (PROT_READ|PROT_WRITE);
    //     entry2.uprot = PROT_NONE;
    //     entry2.pfn = get_free_page();
    //     pcb2->PT0[i >> PAGESHIFT] = entry2; // fix this
        
    //     pageTable1[borrowpfn].pfn = pcb2->PT0[i >> PAGESHIFT].pfn;
    //     memcpy((void *)(borrowedAddrVA), (void *) i, PAGESIZE);
    //     WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) borrowedAddrVA);
    // }
    


    // set nextFreePage to the physical address of the pfn of the page to be freed
    nextFreePage = (uintptr_t) addrNum;
    //nextFreePage = (uintptr_t) ((active_pcb->PT0[index].pfn) << PAGESHIFT);
    
    // increment freePages
    freePages += 1;
    
    // flush tlb
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) (addrNum));
    
    // set valid bit to 0 (do this after returning?)
    //active_pcb->PT0[index].valid = 0;
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
            active_pcb->PT0[j].valid = 0;  // set invalid
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


