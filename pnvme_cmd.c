/********************************************************************
* FILE NAME: ktest_cmd.c
*
*
* PURPOSE:
*
*
* DEVELOPMENT HISTORY: 
*
* 
* Date Author Release  Description Of Change 
* ---- ----- ---------------------------- 
*2020.09.11, liangmin, initial coding.
*
****************************************************************/

#include "pnvme_drv.h"
#include "pnvme_cmd.h"
#include "pnvme_lba.h"


 struct cmd_ioctl_stru cmd_ioctl_list[] = 
{
	//{IOCTL_TIMEOUT_HANDLE, trans_nvme_cmd},
	//{IOCTL_CHECK_SQE_INFO, check_sqe_info},
	{PNVME_ADMIN_PASSTHROUGH, pnvme_admin_passthrough},
	{PNVME_IO_SYNC, pnvme_lba_sync},
	{PNVME_IO_ASYNC, pnvme_lba_async},
	{PNVME_IO_ATOMIC, pnvme_atomic},
	{PNVME_PI_IO, pnvme_pi_sync},
	{PNVME_SGL_SYNC, pnvme_sgl_cmd},
	{PNVME_CRT_CQ, pnvme_crt_cq},
	{PNVME_DEL_CQ, pnvme_del_cq},
	{PNVME_CRT_SQ, pnvme_crt_sq},
	{PNVME_DEL_SQ, pnvme_del_sq},
	{PNVME_PRINT_SQES, pnvme_print_sqes},
	{PNVME_PRINT_CQES, pnvme_print_cqes},
    {PNVME_DEBUG, pnvme_debug_cmd},
	//{IOCTL_WRITE_UNCORRECTABLE,ioctl_lba_write_zero},/*can use the same ioctl function*/
	//{IOCTL_WRITE_ZERO,ioctl_lba_write_zero},
};

const int cmd_ioctl_list_size = sizeof(cmd_ioctl_list)/sizeof(struct cmd_ioctl_stru);

