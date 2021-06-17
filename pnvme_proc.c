/********************************************************************
* FILE NAME: proc.c
*
*
* PURPOSE: proc of ktest module
*
* 
* NOTES:
*
* 
* DEVELOPMENT HISTORY: 
* 
* Date Author Release  Description Of Change 
* ---- ----- ---------------------------- 
*2020.09.11, liangmin, initial coding.
*
****************************************************************/
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "pnvme_proc.h"

static int ktest_proc_show(struct seq_file *m, void *v)
{
        
    seq_printf(m, "-- %s start\n", KTEST_NAME);
    seq_printf(m, "    %8s:\n", "debug");
    seq_printf(m, "-- %s end\n", KTEST_NAME);

    return 0;
}

static int ktest_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, ktest_proc_show, NULL);
}

static struct file_operations ktest_proc_fops = {
    .owner        = THIS_MODULE,
    .open        = ktest_proc_open,
    .read        = seq_read,
    .llseek        = seq_lseek,
    .release    = single_release,
};


/*******************************************************************
*
*FUNCTION DESCRIPTION: proc init function
* 
*FUNCTION NAME: ktest_proc_init
*
*PARAMTERS:
*        INPUT:
*        OUTPUT: 
*        RETURN:
*
*******************************************************************/
void ktest_proc_init(void)
{
    proc_create(KTEST_NAME, 0, NULL, &ktest_proc_fops);

    return;
}

/*******************************************************************
*
*FUNCTION DESCRIPTION: proc exit function
* 
*FUNCTION NAME: ktest_proc_exit
*
*PARAMTERS:
*        INPUT:
*        OUTPUT: 
*        RETURN:
*
*******************************************************************/
void ktest_proc_exit(void)
{
    remove_proc_entry(KTEST_NAME, NULL);
    
    return;
}

