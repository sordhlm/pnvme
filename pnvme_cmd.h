#ifndef _KTEST_CMD_H
#define _KTEST_CMD_H

#include <linux/types.h>
 
struct cmd_ioctl_stru
{
    unsigned int cmd;
    int (*fn)(struct nvme_dev *, unsigned long);
};

extern struct cmd_ioctl_stru cmd_ioctl_list[];
extern const int cmd_ioctl_list_size;


#endif
