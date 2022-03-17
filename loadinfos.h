#ifndef	_loadinfo_h
#define _loadinfo_h

#include <sys/types.h>

/*
 *  Define the external interface to the LoadInfo() function.
 *
 *  LoadInfo() is passed an open file descriptor number and a pointer
 *  to a "struct loadinfo".  The file descriptor should be open
 *  to an ELF format executable file that has been linked to
 *  execute as a Yalnix user process.  On successful return,
 *  LoadInfo will have filled in the struct loadinfo with the
 *  information needed by LoadProgram() to load the Yalnix user
 *  program into memory and set it up for execution.
 *
 *  LoadInfo() returns 0 (= LI_SUCCESS) on success.  Any other
 *  return value indicates an error, as defined by the other LI_*
 *  values below.
 */

struct loadinfo {
    size_t text_size;	/* size of text */
    size_t data_size;	/* size of data */
    size_t bss_size;	/* size of bss */
    void *entry;	/* entry point of executable */
};

extern int LoadInfo(int, struct loadinfo *);

#define LI_SUCCESS	0
#define LI_FORMAT_ERROR	1	/* not linked as a Yalnix user program */
#define LI_OTHER_ERROR	2

#endif /*!_loadinfo_h*/
