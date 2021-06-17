/********************************************************************
* FILE NAME: proc.h
*
*
* PURPOSE: headerfile of proc. 
*
* 
* NOTES:
*
* 
* DEVELOPMENT HISTORY: 
* 
* Date Author Release  Description Of Change 
* ---- ----- ---------------------------- 
*2014.8.8, wxu, initial coding.
*
****************************************************************/

#ifndef _KTEST_PROC_H_
#define _KTEST_PROC_H_

#include "pnvme_drv.h"

extern _u64 g_bch_fail;
extern void ktest_proc_init(void);
extern void ktest_proc_exit(void);

#endif /* _KTEST_PROC_H_ */
