/********************************************************************
* FILE NAME: ioctl_cmd.h
*
*
* PURPOSE: headerfile of this application. 
*
* 
* NOTES:
*
* 
* DEVELOPMENT HISTORY: 
* 
* Date Author Release  Description Of Change 
* ---- ----- ---------------------------- 
*2016.3.11, zcheng, initial coding.
****************************************************************/
#ifndef _IOCTL_CMD_H
#define _IOCTL_CMD_H
#include <linux/nvme_ioctl.h>
#include "ioctl_str.h"

/******************ktest cmd*************************/

#define PNVME_ADMIN_PASSTHROUGH           _IOWR('E', 0x01, struct nvme_passthru_cmd)
#define PNVME_IO_SYNC                     _IOWR('E', 0x02, struct nvme_lba_command)
#define PNVME_IO_ASYNC                    _IOWR('E', 0x03, struct nvme_lba_command)
#define PNVME_IO_ATOMIC                   _IOWR('E', 0x04, struct nvme_lba_command)
#define PNVME_PI_IO                       _IOWR('E', 0x05, struct nvme_lba_command)
#define PNVME_SGL_SYNC                    _IOWR('E', 0x06, struct nvme_lba_command)
#define PNVME_CRT_CQ                      _IOWR('E', 0x07, struct nvme_passthru_cmd)
#define PNVME_DEL_CQ                      _IOWR('E', 0x08, struct nvme_passthru_cmd)
#define PNVME_CRT_SQ                      _IOWR('E', 0x09, struct nvme_passthru_cmd)
#define PNVME_DEL_SQ                      _IOWR('E', 0x0A, struct nvme_passthru_cmd)



#define PNVME_PRINT_SQES                  _IOWR('G', 0x01, unsigned int)
#define PNVME_PRINT_CQES                  _IOWR('G', 0x02, unsigned int)
#define PNVME_DEBUG                       _IOWR('G', 0x03, unsigned int)


#endif
