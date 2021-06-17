/*
 * NVM Express device driver
 * Copyright (c) 2011-2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * Sections of this file have been modified by CNEX Labs, Inc. (referred to
 * hereafter as “CNEX Modifications”).
 *
 * Copyright 2013 – 2014 CNEX Labs, Inc.
 *
 * You may redistribute the CNEX Modifications and/or modify the CNEX
 * Modifications under the terms and conditions of the GNU General Public
 * License, version 2.
 */

/********************************************************************
* FILE NAME: nexus_if.h
*
* PURPOSE: heade file of nexus_if.c, declare function which is define in nexus_if.c
*
* NOTES:
*
****************************************************************/
#ifndef _NEXUS_IF_H
#define _NEXUS_IF_H

#include <linux/version.h>
#include <linux/nvme.h>
#include "pnvme_drv.h"
#include "pnvme_lba.h"



/* Since 2.6.35, we've exposed irq_set_affinity_hint to modules.  Bodge
 *  * it for earlier kernels by looking up the address of irq_set_affinity
 *   * in kallsyms and passing it as a module parameter */

/* 2.6.34 renamed this function */
#ifndef for_each_set_bit
#define for_each_set_bit for_each_bit
#endif

#define dma_set_coherent_mask(dev, mask)	\
				pci_set_consistent_dma_mask(pdev, mask)

int pnvme_create_cq_sync(struct nvme_dev *dev, int cqid , int vector, int qsize, _u8 cq_where);
int pnvme_create_sq_sync(struct nvme_dev *dev, int sqid, int cqid, int sq_flags,
                                int qsize, _u8 sq_where);
int pnvme_delete_sq_sync(struct nvme_dev *dev, _u16 qid);
int pnvme_delete_cq_sync(struct nvme_dev *dev, _u16 qid);

int pnvme_delete_sq_cmd(struct nvme_dev *dev, _u16 qid);
int pnvme_delete_cq_cmd(struct nvme_dev *dev, _u16 qid);
int pnvme_process_cq(struct pnvme_queue *nvmeq);
void pnvme_cancel_ios(struct pnvme_queue *nvmeq, bool timeout);
void pnvme_free_nvmesq(struct pnvme_queue *nvmeq);
void pnvme_free_nvmecq(struct pnvme_completion_queue *nvmecq);
int get_data_size(struct nvme_ctrl *dev, _u32 nsid, _u32 *data_size, _u16 *meta_size);
int lba_set_prplist(struct nvme_dev *dev, struct lba_handle_str *ptr);
struct pnvme_cmd_info *get_this_cmdinfo(struct pnvme_queue *nvmeq, int cmdid);
void special_completion(struct nvme_dev *dev, void *ctx, struct nvme_completion *cqe);
struct pnvme_cmd_info *pnvme_get_cmd_info(struct pnvme_queue *nvmeq);
void q_lock_test(struct pnvme_queue *nvmeq, int id);

int set_async_data(void *pdata, _u64 slba, _u16 nlb, _u32 data_size, bool keep_order);
int key_operate(_u64 lba, _u32 *key, _u8 mode, bool keep_order);
int data_key_setup(int key_num_in_table, int num);
int cmdid_bit_clear(int bit, struct pnvme_queue *nvmeq);
struct pnvme_cmd_info *get_cmdinfo(struct pnvme_queue *nvmeq);
_u64 get_data_pat(_u64 lba, _u32 key);
_u32 chk_pi(struct nvme_dev *dev, struct nvme_lba_command * nvme_lba_command, struct lba_handle_str *ptr);
void crt_pi(struct nvme_dev *dev, struct nvme_lba_command *nvme_lba_command, struct lba_handle_str *ptr);
void print_cmd_trace(void);

extern int *db_sw;
extern volatile struct debug_info *debug_trace;

struct lba_meta_data
{
    _u32 dw0;
    _u32 dw1;
    _u32 lba_num;
    _u32 dw3;
};

struct lba_meta_pi
{
    _u16 app_tag;
    _u16 guard;
	_u32 ref_tag;
};

/*PI control bit state*/
enum{
    DISABLE = 0,
    ENABLE  = 1,
};

enum{
    CHKPI_FAIL    = 0,
    CHKPI_SUCCESS = 1,
};

enum{
    PI_TYPE0 = 0,   //PI Disable
    PI_TYPE1 = 1,
    PI_TYPE2 = 2,
    PI_TYPE3 = 3,
};

/*NVM format register bit field*/
struct nvm_format
{
  union
  {
    struct
    {
        _u32 lbaf      : 4; // LBA Format
        _u32 ms        : 1; // Metadata Setting
        _u32 pi        : 3; // Protection Information
        _u32 pil       : 1; // Protection Information Location
        _u32 ses       : 3; // Secure Erase Settings
        _u32 rsv       : 20;// Reserved
    } reg;

    _u32 value;
  };
};
struct dw12_control
{
  union
  {
    struct
    {
      _u16 rsv         : 10;// Reserved
      _u16 reftag      : 1; // Reference Tag
      _u16 apptag      : 1; // Application Tag
      _u16 guard       : 1; // Guard
      _u16 pract       : 1; // Protection Information Action
      _u16 fua         : 1; // Force Unit Access
      _u16 lr          : 1; // Limited Retry
    } reg;

    _u16 control;
  };
};

#endif/* _NEXUS_IF_H */

