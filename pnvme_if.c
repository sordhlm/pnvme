
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
 * hereafter as “CNEX Modifications?.
 *
 * Copyright 2013 ?2014 CNEX Labs, Inc.
 *
 * You may redistribute the CNEX Modifications and/or modify the CNEX
 * Modifications under the terms and conditions of the GNU General Public
 * License, version 2.
 */

/***************************************************************************
*FILE NAME: nexus_if.c
*
*DESCRIPTION: Cnex export kernel interface for modules
*
*NOTES:
*
***************************************************************************/
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/blkdev.h>
#include <linux/idr.h>
#include "pnvme_if.h"



//#define NO_EXCEPTION_CREATE_DELETEQUEUE
/* allocate new ID for namespace name */

extern spinlock_t dev_list_lock;
static spinlock_t key_lock;
volatile struct debug_info *debug_trace;
volatile _u32 cid = 0;


_u32 power(_u32 base, int exponent){
	_u32 result = 1;
    int i;
	for (i = 0; i < exponent; i++){
		result *= base;
	}
	return result;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: get extra memory space for cmdid_data and
*                      nexus_cmd_info when alloc nvme_queue
*
*FUNCTION NAME: nexus_queue_extra()
*
*PARAMTERS:
*       INPUT:
*       OUTPUT:
*       RETURN:
*              the extra memory space for cmdid_data and nexus_cmd_info
*              when alloc nvme_queue
*
***************************************************************************/
_u32 pnvme_queue_extra(void)
{
    return DIV_ROUND_UP(NVME_Q_DEPTH, 8) + (NVME_Q_DEPTH * sizeof(struct pnvme_cmd_info));
}
struct pnvme_cmd_info *get_cmdinfo(struct pnvme_queue *nvmeq)
{
    /*check paramter*/
    if(nvmeq==NULL){
        print_err("there is no this queue, please check it");
        return NULL;
    }

    return (struct pnvme_cmd_info *)nvmeq->cmd_info;
}

struct pnvme_cmd_info *pnvme_get_cmd_info(struct pnvme_queue *nvmeq)
{
    return (void *)nvmeq->cmd_info; // this is fixed location after bitmask, should be calculated only once
}
EXPORT_SYMBOL(pnvme_get_cmd_info);


struct pnvme_cmd_info *get_this_cmdinfo(struct pnvme_queue *nvmeq, int cmdid)
{
    struct pnvme_cmd_info *cmdinfo_base;

    if (cmdid >= nvmeq->q_depth) {
        print_err("cmdid=%d exceed the qdepth-1(%d)", cmdid, nvmeq->q_depth-1);
        return NULL;
    }

    cmdinfo_base = get_cmdinfo(nvmeq);
    if (cmdinfo_base == NULL) {
        print_err("cmdinfo_base NULL");
        return NULL;
    }

    return cmdinfo_base + cmdid;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: free the memory nexus_alloc_nvmecq alloced
*
*FUNCTION NAME: nexus_free_nvmecq()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: The c queue to free the memory
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
void pnvme_free_nvmecq(struct pnvme_completion_queue *nvmecq)
{
    u16 qid = nvmecq->qid;
    u32 depth = (nvmecq->q_depth ? nvmecq->q_depth : 1);
	

    print_wrn("delete CQ%d at HOST", qid);
    dma_free_coherent(nvmecq->q_dmadev, (2 * PNVME_PAGE_SIZE) \
        + CQ_SIZE(depth), (void *)nvmecq->cq_dma_base, nvmecq->cq_dma_base_addr);
    //dma_pool_free(nvmecq->dev->mps_cqueue_pool, (void *)nvmecq->cqes, nvmecq->cq_dma_addr);

    //nvmecq->dev->cqueue_count --;
    kfree(nvmecq);
}
/***************************************************************************
*
*FUNCTION DESCRIPTION: free the memory nexus_alloc_nvmesq alloced
*
*FUNCTION NAME: nexus_free_nvmesq()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: The s queue to free the memory
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
void pnvme_free_nvmesq(struct pnvme_queue *nvmeq)
{
    u16 qid = nvmeq->qid;
    u32 depth = (nvmeq->q_depth ? nvmeq->q_depth : 1);

    print_wrn("delete SQ%d at HOST", qid);
    //dma_pool_free(nvmeq->dev->mps_squeue_pool, (void *)nvmeq->sq_cmds, nvmeq->sq_dma_addr);
    dma_free_coherent(nvmeq->q_dmadev, (2 * PNVME_PAGE_SIZE) + \
        SQ_SIZE(depth), nvmeq->sq_dma_base, nvmeq->sq_dma_base_addr);

    //nvmeq->dev->squeue_count --;
    kfree(nvmeq);
}
/***************************************************************************
*
*FUNCTION DESCRIPTION: alloc nvme_queue struct and init it
*
*FUNCTION NAME: nexus_alloc_nvmesq()
*
*PARAMTERS:
*       INPUT:
*             dev: pointer to the nexus_dev data structure
*             qid: 0-admin queue positive-io queue
*             depth: queue depth
*             vector: MSI-X interrupt vector
*       OUTPUT:
*       RETURN:
*              nvmeq, pointer to the allocated buff
*              NULL, alloc buffer failed
*
***************************************************************************/
struct pnvme_queue *pnvme_alloc_nvmesq(struct nvme_dev *dev, int sqid, int depth, u8 sq_where)
{
    //int i;
    //u32 sqzone_used = 0;
    u32 tmp_depth = (depth ? depth : 1);
    struct device *dmadev = dev->dev;
    u32 extra = pnvme_queue_extra();
    struct pnvme_queue *nvmeq = kzalloc(sizeof(*nvmeq) + extra, GFP_KERNEL);
    //u32 memory_page_size = PNVME_PAGE_SIZE;

    if( (sqid == 0) && (tmp_depth > 4096))
    {
        print_err("admin sq:%x qdepth:%x too large", sqid, tmp_depth);
        return NULL;
    }

    if (!nvmeq)
        return NULL;

    //nvmeq->sq_cmds = dma_pool_alloc(dev->mps_squeue_pool , GFP_KERNEL, &nvmeq->sq_dma_addr);
    //print_dbg("alloc_sq: dma_alloc[dev: 0x%x, size: %d]", dmadev, (2 * PNVME_PAGE_SIZE) + CQ_SIZE(tmp_depth));
    nvmeq->sq_dma_base = dma_alloc_coherent(dmadev, (2 * PNVME_PAGE_SIZE) + \
        SQ_SIZE(tmp_depth),&nvmeq->sq_dma_base_addr, GFP_KERNEL);
	print_dbg("alloc_sq: dma_alloc[dev: 0x%x, size: %d][addr:%llx, dma:%llx]", \
		dmadev, (2 * PNVME_PAGE_SIZE) + CQ_SIZE(tmp_depth), (_u64)nvmeq->sq_dma_base_addr, (_u64)nvmeq->sq_dma_base);
    if (!nvmeq->sq_dma_base)
        goto free_nvmeq;
    print_wrn("Create SQ%d base ,mem:0x%llx dma_addr:0x%llx", sqid, (_u64)nvmeq->sq_dma_base, (_u64)nvmeq->sq_dma_base_addr);

    if( nvmeq->sq_dma_base_addr & (PNVME_PAGE_SIZE - 1)){
        nvmeq->sq_dma_addr = (nvmeq->sq_dma_base_addr & (~((_u64)(PNVME_PAGE_SIZE - 1)))) + PNVME_PAGE_SIZE;
        nvmeq->sq_cmds = (void *)((((_u64)nvmeq->sq_dma_base ) & (~((_u64)(PNVME_PAGE_SIZE - 1)))) + PNVME_PAGE_SIZE);
    }
    else{
        nvmeq->sq_dma_addr = nvmeq->sq_dma_base_addr;
        nvmeq->sq_cmds = nvmeq->sq_dma_base;
    }

    memset((void *)nvmeq->sq_cmds, 0, SQ_SIZE(tmp_depth));
    print_wrn("Create SQ%d on %d(0-Host  1-DDR  2-CMB), mem:0x%llx, dma_addr:0x%llx", sqid, sq_where, (_u64)nvmeq->sq_cmds ,(_u64)nvmeq->sq_dma_addr);

    nvmeq->q_dmadev = dmadev;
    nvmeq->dev = dev;

    spin_lock_init(&nvmeq->q_lock);
    init_waitqueue_head(&nvmeq->sq_full);
    //nvmeq->q_db = &dev->dbs[sqid << (dev->db_stride + 1)];
    nvmeq->q_db = &dev->dbs[sqid * 2 * dev->db_stride];
	print_dbg("doorbell base 0x%llx, db[1]:%llx", dev->dbs, &dev->dbs[1]);
    print_dbg("sq[%d] doorbell 0x%llx",sqid, nvmeq->q_db);
	print_dbg("db_stride: %d, db idx: %d", dev->db_stride, (sqid * 2 * dev->db_stride));

    nvmeq->q_depth = tmp_depth;

    nvmeq->qid = sqid;
    nvmeq->q_suspended = 1;
    //dev->squeue_count++;

    return nvmeq;

 free_nvmeq:
    print_wrn("Create SQ%d on %d(0-Host  1-DDR  2-CMB)  fail", sqid, sq_where);
    kfree(nvmeq);
    return NULL;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: alloc nvme_completion_queue struct and init it
*
*FUNCTION NAME: nexus_alloc_nvmecq()
*
*PARAMTERS:
*       INPUT:
*             dev: pointer to the nexus_dev data structure
*             qid: 0-admin queue positive-io queue
*             depth: queue depth
*             vector: MSI-X interrupt vector
*       OUTPUT:
*       RETURN:
*              nvmeq, pointer to the allocated buff
*              NULL, alloc buffer failed
*
***************************************************************************/
struct pnvme_completion_queue *pnvme_alloc_nvmecq(struct nvme_dev *dev, int cqid,int depth, int vector, u8 cq_where)
{
    //int i;
    //u32 cqzone_used = 0;
    u32 tmp_depth = (depth ? depth : 1);
    struct device *dmadev = dev->dev;
    struct pnvme_completion_queue *nvmecq = kzalloc(sizeof(*nvmecq), GFP_KERNEL);
    u32 memory_page_size = PNVME_PAGE_SIZE;

    if( (cqid == 0) && (tmp_depth > 4096))
    {
        print_err("admin cq:%x qdepth:%x too large", cqid, tmp_depth);
        return NULL;
    }

    if (!nvmecq)
        return NULL;


        //nvmecq->cqes = dma_pool_alloc(dev->mps_cqueue_pool , GFP_KERNEL, &nvmecq->cq_dma_addr);
    nvmecq->cq_dma_base = dma_alloc_coherent(dmadev, (2 * memory_page_size) + \
        CQ_SIZE(tmp_depth),&nvmecq->cq_dma_base_addr, GFP_KERNEL);
	print_dbg("alloc_cq: dma_alloc[dev: 0x%x, size: %d][addr:%x, dma:%x]", \
		dmadev, (2 * memory_page_size) + CQ_SIZE(tmp_depth), nvmecq->cq_dma_base_addr, nvmecq->cq_dma_base);
    if (!nvmecq->cq_dma_base)
        goto free_nvmeq;
    print_wrn("Create CQ%d base ,mem:0x%llx dma_addr:0x%llx", cqid, (u64)nvmecq->cq_dma_base, (u64)nvmecq->cq_dma_base_addr);
    if( nvmecq->cq_dma_base_addr & (memory_page_size - 1)){
        nvmecq->cq_dma_addr = (nvmecq->cq_dma_base_addr & (~((u64)(memory_page_size - 1)))) + memory_page_size;
        nvmecq->cqes = (void *)((((u64)nvmecq->cq_dma_base ) & (~((u64)(memory_page_size - 1)))) + memory_page_size);
    }
    else{
        nvmecq->cq_dma_addr = nvmecq->cq_dma_base_addr;
        nvmecq->cqes = nvmecq->cq_dma_base;
    }

    memset((void *)nvmecq->cqes, 0, CQ_SIZE(tmp_depth));
    print_wrn("Create CQ%d on %d(0-Host  1-DDR  2-CMB) mem:0x%llx dma_addr:0x%llx", cqid,
        cq_where, (u64)nvmecq->cqes, (u64)nvmecq->cq_dma_addr);

    nvmecq->q_dmadev = dmadev;
    nvmecq->dev = dev;
    snprintf(nvmecq->irqname, sizeof(nvmecq->irqname), "pnvmeq%d", cqid);
    nvmecq->cq_head = 0;
    nvmecq->cq_phase = 1;

    nvmecq->q_db = &dev->dbs[((2 * cqid + 1) * dev->db_stride)];
    //print_wrn("cq doorbell 0x%llx", nvmecq->q_db);
    print_dbg("db_stride: %d", dev->db_stride);
    print_dbg("cq[%d] doorbell 0x%llx", cqid, nvmecq->q_db);
	
    nvmecq->q_depth = tmp_depth;
    nvmecq->ref_cnt = 0;

    nvmecq->cq_vector = vector;
    print_wrn("Create CQ%d vector:0x%x", cqid,nvmecq->cq_vector);


    nvmecq->qid = cqid;
    //dev->cqueue_count++;
    return nvmecq;

 free_nvmeq:
    print_wrn("Create CQ%d on %d(0-Host  1-DDR  2-CMB)  fail", cqid, cq_where);
    kfree(nvmecq);
    return NULL;
}
/***************************************************************************
*
*FUNCTION DESCRIPTION: special for completion routine
*
*FUNCTION NAME: special_completion()
*
*PARAMTERS:
*       INPUT:
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
void special_completion(struct nvme_dev *dev, void *ctx,
                        struct nvme_completion *cqe)
{
    if (ctx == CMD_CTX_CANCELLED) {
        return;
    } else if (ctx == CMD_CTX_FLUSH) {
        return;
    } else if (ctx == CMD_CTX_COMPLETED) {
        print_wrn("completed id %d twice on queue %d",
                cqe->command_id, le16_to_cpup(&cqe->sq_id));
        return;
    } else if (ctx == CMD_CTX_INVALID) {
        print_wrn("invalid id %d completed on queue %d",
                cqe->command_id, le16_to_cpup(&cqe->sq_id));
        return;
    } else if (ctx == CMD_CTX_THROTTLED) {
        return;
    } else  {
        print_wrn("Unknown special completion %p", ctx);
        return;
    }
}



/***************************************************************************
*
*FUNCTION DESCRIPTION: Cancel outstanding I/Os
*
*FUNCTION NAME: nexus_cancel_ios()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: The queue to cancel I/Os on
*             timeout: True to only cancel I/Os which have timed out
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
void pnvme_cancel_ios(struct pnvme_queue *nvmeq, bool timeout)
{
    int depth = nvmeq->q_depth - 1;
    struct pnvme_cmd_info *info = pnvme_get_cmd_info(nvmeq);
    unsigned long now = jiffies;
    u16 cmdid;
    unsigned long flags;

    spin_lock_irqsave(&nvmeq->bit_lock, flags);
    for_each_set_bit(cmdid, nvmeq->cmdid_data, depth) {
        void *ctx;
        nvme_completion_fn fn;
        static struct nvme_completion cqe = {
            .status = cpu_to_le16(NVME_SC_ABORT_REQ << 1),
        };

        if (timeout && !time_after(now, info[cmdid].timeout))
            continue;
        if (info[cmdid].ctx == CMD_CTX_CANCELLED)
            continue;

        print_wrn("Cancelling I/O  qid=%d  cmdid=0x%x  opcode=0x%x  nlb=%d", nvmeq->qid, cmdid, info[cmdid].opcode, info[cmdid].nlb);
        print_wrn("sq_t:0x%x cq_h:0x%x", nvmeq->sq_tail, nvmeq->nvmecq->cq_head);
        ctx = cancel_cmdid(nvmeq, cmdid, &fn);
        cqe.command_id = cpu_to_le16(cmdid);
        cqe.sq_id = cpu_to_le16(nvmeq->qid);
        fn(nvmeq->dev, ctx, &cqe);
    }
    spin_unlock_irqrestore(&nvmeq->bit_lock, flags);
}


/***************************************************************************
*
*FUNCTION DESCRIPTION: get context and function for each command
*
*FUNCTION NAME: get_ctx_fn()
*
*PARAMTERS:
*       INPUT:
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
void *get_ctx_fn(struct pnvme_queue *nvmeq, u16 cmdid,
                        nvme_completion_fn *fn)
{
    void *ctx;
    struct pnvme_cmd_info *info = pnvme_get_cmd_info(nvmeq);

    if (cmdid >= nvmeq->q_depth) {
        *fn = special_completion;
        return CMD_CTX_INVALID;
    }
    if (fn) {
        *fn = info[cmdid].fn;
    }
    ctx = info[cmdid].ctx;

    info[cmdid].fn = special_completion;
    info[cmdid].ctx = CMD_CTX_COMPLETED;
    return ctx;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: clear cmdid bit in cmdid_data
*
*FUNCTION NAME: cmdid_bit_clear()
*
*PARAMTERS:
*       INPUT:
*             bit: The cmdid number
*             nvmeq:The queue that will be used for this command
*       OUTPUT: 0
*       RETURN:
*               0
*
***************************************************************************/
int cmdid_bit_clear(int bit, struct pnvme_queue *nvmeq)
{
    unsigned long data;
    unsigned long *pdata = nvmeq->cmdid_data + bit/ULONG_BIT;
    unsigned long mask = 1ul << bit%ULONG_BIT;
    unsigned long flags = 0;

    spin_lock_irqsave(&nvmeq->bit_lock, flags);
    data = *pdata;
    *pdata = data & ~mask;
    spin_unlock_irqrestore(&nvmeq->bit_lock, flags);
    return 0;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: check CQ if there are new CQE return, and then
*                      free cmdid for recycle use
*
*FUNCTION NAME: nexus_process_cq()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: The queue that will be used
*       OUTPUT:
*       RETURN:
*             0
*             1
*
***************************************************************************/
int pnvme_process_cq(struct pnvme_queue *nvmeq)
{
    u16 head, phase;
    struct pnvme_completion_queue *nvmecq = nvmeq->nvmecq;
    struct pnvme_queue *temp_nvmeq;

    head = nvmecq->cq_head;
    phase = nvmecq->cq_phase;

    for (;;) {
        void *ctx;
        nvme_completion_fn fn;
        struct nvme_completion cqe = nvmecq->cqes[head];

        if ((le16_to_cpu(cqe.status) & 1) != phase){
            break;
        }

        //print_dbg("> cqid:%d",nvmecq->qid);
        //[Edison]get cq entry
        cqe = nvmecq->cqes[head]; /* read again, incase CQE not atomic */

        if((le16_to_cpu(cqe.status) >> 1)){
            print_not("Dword0/1:0x%x, Dword2:0x%x, Dword3:0x%x", cqe.result.u64, (cqe.sq_id << 16) | cqe.sq_head, (cqe.status << 16) | cqe.command_id);
        }

        //if(((le16_to_cpu(cqe.status) >> 1) != 0) && ((cqe.result.u64) == 0)){
        //    print_not("Dword0/1:0x%x, Dword2:0x%x, Dword3:0x%x", cqe.result, (cqe.sq_id << 16) | cqe.sq_head, (cqe.status << 16) | cqe.command_id);
        //}
        //[Edison] get sq according to sqid in cqe
        temp_nvmeq = g_rsc.g_queue_rsc->queues[cqe.sq_id];
        if(temp_nvmeq == NULL) {
            print_err("The received cqe.sqid=%d is not exist!!!",cqe.sq_id);
            print_not("Dword0/1:0x%x, Dword2:0x%x, Dword3:0x%x", cqe.result.u64, (cqe.sq_id << 16) | cqe.sq_head, (cqe.status << 16) | cqe.command_id);
            return PROCESS_SUCCESS;
        }
            //return PROCESS_SUCCESS;
        //BUG_ON(temp_nvmeq == NULL);
        if(temp_nvmeq != nvmeq){
            //print_not("temp nvmeq : 0x%x",temp_nvmeq);
            print_not("processing qid=%d, received cqe.sqid=%d",nvmeq->qid,cqe.sq_id);
            spin_lock_irq(&temp_nvmeq->q_lock);
        }
        temp_nvmeq->sq_head = le16_to_cpu(cqe.sq_head);
        if (++head == nvmecq->q_depth) {
            head = 0;
            phase = !phase;
        }
        ctx = get_ctx_fn(temp_nvmeq, cqe.command_id, &fn);
        fn(temp_nvmeq->dev, ctx, &cqe);

        /* Release the command_id after the fn called */
        cmdid_bit_clear(cqe.command_id, temp_nvmeq);
        wake_up(&temp_nvmeq->sq_full);
        if(temp_nvmeq != nvmeq){
			print_dbg("release queue lock");
            spin_unlock_irq(&temp_nvmeq->q_lock);
        }
    }

    if (head == nvmecq->cq_head && phase == nvmecq->cq_phase)
        return PROCESS_WRAPAROUND;
    //[Edison]write cq header doorbell
    writel(head, nvmecq->q_db);
    nvmecq->cq_head = head;
    nvmecq->cq_phase = phase;

    /* interrupt shared so this flag can distinguish which nvmeq generate the interrupt */
    nvmecq->cqe_seen = 1;
    return PROCESS_SUCCESS;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: interrupt service routine, when new CQE post to
*                      CQ controller generate interrupt
*
*FUNCTION NAME: nexus_irq()
*
*PARAMTERS:
*       INPUT:
*             irq: MSI-X irq vector
*             data: pointer to correspond nvmeq
*       OUTPUT:
*       RETURN:
*             IRQ_HANDLED, interrupt was handled by this device
*             IRQ_NONE, interrupt was not from this device
*
***************************************************************************/
static irqreturn_t pnvme_irq(int irq, void *data)
{
    unsigned long flags = 0;
    irqreturn_t result;
    struct pnvme_queue *nvmeq = data;
    struct pnvme_completion_queue *nvmecq = nvmeq->nvmecq;

	//print_dbg("require queue lock");
    spin_lock_irqsave(&nvmeq->q_lock, flags);
    pnvme_process_cq(nvmeq);
    result = nvmecq->cqe_seen ? IRQ_HANDLED : IRQ_NONE;
    nvmecq->cqe_seen = 0;
	//print_dbg("release queue lock");
    spin_unlock_irqrestore(&nvmeq->q_lock, flags);
    return result;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: IO Queue interrupt
*
*FUNCTION NAME: queue_request_irq()
*
*PARAMTERS:
*       INPUT:
*             dev: pointer to the nexus_dev data structure
*             nvmeq: pointer to correspond nvmeq
*             name: interrupt name
*       OUTPUT:
*       RETURN:
*              0, setup interrupt service routine successful
*              negative value, setup interrupt service routine failed
*
***************************************************************************/
int queue_request_irq(struct nvme_dev *dev, struct pnvme_queue *nvmeq, const char *name)
{
    struct pnvme_completion_queue *nvmecq = nvmeq->nvmecq;
    
    //print_dbg("vector:%x, cqvec:%x",dev->entry[nvmecq->cq_vector].vector,nvmecq->cq_vector);

    //if (!dev->entry[nvmecq->cq_vector].vector) return 0;
    if (!nvmecq->irq_enable) return 0;

    //print_dbg("register irq:%x, dev_id:%x",dev->entry[nvmecq->cq_vector].vector,nvmeq);
    //return request_irq(dev->entry[nvmecq->cq_vector].vector, pnvme_irq,
    //             IRQF_SHARED, name, nvmeq);
    return pci_request_irq(to_pci_dev(dev->dev), nvmeq->nvmecq->cq_vector, pnvme_irq,
				NULL, nvmeq, "nvme0q%d", nvmeq->qid);
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: init a queue
*                       initialize every bit for cmdid
                        initialize every cmd_info for cmdid
*FUNCTION NAME: nexus_init_nvmeq()
*
*PARAMTERS:
*       INPUT:
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
void pnvme_init_nvmeq(struct pnvme_queue *nvmeq, u16 qid)
{
    struct nvme_dev *dev = nvmeq->dev;
    u32 extra = pnvme_queue_extra();

    nvmeq->sq_tail = 0;
    nvmeq->q_db = &dev->dbs[qid * 2 * dev->db_stride];
    memset(nvmeq->cmdid_data, 0, extra);
    pnvme_cancel_ios(nvmeq, false);
    nvmeq->q_suspended = 0;
}
/***************************************************************************
*
*FUNCTION DESCRIPTION: delete a admin CQE command
*
*FUNCTION NAME: nexus_delete_cq_cmd()
*
*PARAMTERS:
*       INPUT:
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
int pnvme_delete_cq_cmd(struct nvme_dev *dev, u16 qid)
{
    int status;
    struct nvme_command c;

    memset(&c, 0, sizeof(c));
    c.delete_queue.opcode = nvme_admin_delete_cq;
    c.delete_queue.qid = cpu_to_le16(qid);

    status = pnvme_submit_admin_cmd(&dev->ctrl, &c, NULL, 0);
    if (status)
        return -EIO;
    return 0;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: delete a admin SQE command
*
*FUNCTION NAME: nexus_delete_sq_cmd()
*
*PARAMTERS:
*       INPUT:
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
int pnvme_delete_sq_cmd(struct nvme_dev *dev, u16 qid)
{
    int status;
    struct nvme_command c;

    memset(&c, 0, sizeof(c));
    c.delete_queue.opcode = nvme_admin_delete_sq;
    c.delete_queue.qid = cpu_to_le16(qid);

    status = pnvme_submit_admin_cmd(&dev->ctrl, &c, NULL, 0);
    if (status)
        return -EIO;
    return 0;
}
/***************************************************************************
*
*FUNCTION DESCRIPTION: Delete the specified completion queue,
*                      and return until command execution is completed
*
*FUNCTION NAME: nexus_delete_cq_sync()
*
*PARAMTERS:
*       INPUT:
*             qid: the identifier of the completion queue to be deleted,
*                  and external caller cannot delete completion queue 0
*       OUTPUT:
*       RETURN:
*             0, when delete completion queue successful
*             -EINVAL, when input parameter error
*             -EIO, when delete completion queue failed
*
***************************************************************************/
int pnvme_delete_cq_sync(struct nvme_dev *dev, _u16 qid)
{
    int status;
    struct nvme_command c;
    struct pnvme_completion_queue *nvmecq;
    bool invalid_req = false;

    print_wrn(">");

    /*check paramter*/
    if(dev==NULL){
        print_err("there is no this device, please check it");
        return -ENODEV;
    }

    if (qid >= NVME_MAX_QUEUE) {
        print_err("qid too large, please check it");
        invalid_req = true;
    }
    else if (g_rsc.g_queue_rsc->cqueues[qid] == NULL) {
        invalid_req = true;
        print_err("the specified queue does not created or already deleted");
    }
    else if (qid == 0) {
        invalid_req = true;
        print_err("Admin Completion Queue can not be deleted");
    }
    else if (g_rsc.g_queue_rsc->cqueues[qid]->ref_cnt != 0){
        print_err("Please delete sq at first");
        invalid_req = true;
    }

    if(invalid_req){
        memset(&c, 0, sizeof(c));
        c.delete_queue.opcode = nvme_admin_delete_cq;
        c.delete_queue.qid = cpu_to_le16(qid);

        status = pnvme_submit_admin_cmd(&dev->ctrl, &c, NULL, 0);
        if (status)
            return -EIO;
        print_err("Status shoule be error!");
    }

    nvmecq = g_rsc.g_queue_rsc->cqueues[qid];
    memset(&c, 0, sizeof(c));
    c.delete_queue.opcode = nvme_admin_delete_cq;
    c.delete_queue.qid = cpu_to_le16(qid);

    status = pnvme_submit_admin_cmd(&dev->ctrl, &c, NULL, 0);
    if (status)
        return -EIO;

    nvmecq->valid = false;
    pnvme_free_nvmecq(nvmecq);
    g_rsc.g_queue_rsc->cqueues[qid] = NULL;

    return status;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: Delete the specified submission queue,
*                      and return until command execution is completed
*
*FUNCTION NAME:nexus_delete_sq_sync()
*
*PARAMTERS:
*       INPUT:
*             qid: the identifier of the submission queue to be deleted,
*                  and external caller cannot delete submission queue 0
*       OUTPUT:
*       RETURN:
*             0, when delete submission queue successful
*             -EINVAL, when input parameter error
*             -EIO, when delete submission queue failed
*
***************************************************************************/
int pnvme_delete_sq_sync(struct nvme_dev *dev, _u16 qid)
{
    int status;
    struct nvme_command c;
    struct pnvme_queue *nvmeq;
    struct pnvme_completion_queue *nvmecq;
    bool invalid_req = false;

    print_wrn(">");
    /*check paramter*/
    if(dev==NULL){
        print_err("there is no this device, please check it");
    }

    if (qid >= NVME_MAX_QUEUE) {
        print_err("qid too large, please check it");
        invalid_req = true;
    }
    else if (g_rsc.g_queue_rsc->queues[qid] == NULL) {
        print_err("the specified queue does not created or already deleted");
        invalid_req = true;
    }
    else if (qid == 0) {
        print_err("Admin Submission Queue can not be deleted");
        invalid_req = true;
    }

    if(invalid_req){
        /*can't delete admin completion queue*/
        memset(&c, 0, sizeof(c));
        c.delete_queue.opcode = nvme_admin_delete_sq;
        c.delete_queue.qid = cpu_to_le16(qid);

        status = pnvme_submit_admin_cmd(&dev->ctrl, &c, NULL, 0);
        if (status)
            return -EIO;
        print_err("Status shoule be error!");
    }

    /*can't delete admin completion queue*/
    memset(&c, 0, sizeof(c));
    c.delete_queue.opcode = nvme_admin_delete_sq;
    c.delete_queue.qid = cpu_to_le16(qid);

    status = pnvme_submit_admin_cmd(&dev->ctrl, &c, NULL, 0);
    if (status)
        return -EIO;
    nvmeq = g_rsc.g_queue_rsc->queues[qid];
    nvmecq = nvmeq->nvmecq;
    print_wrn("sq %x, cq %x",readl(&dev->dbs[(qid << (dev->db_stride + 1))]),readl(&dev->dbs[(qid << (dev->db_stride + 1)) + 1]));
    //print_wrn("cq ref_cnt:%x,unregister irq:%x, cq_vec:%x",nvmecq->ref_cnt,dev->entry[nvmecq->cq_vector].vector, nvmecq->cq_vector);
    nvmecq->ref_cnt--;
    if( nvmecq->ref_cnt == 0) {

        int vector;
        vector = nvmecq->cq_vector;
        print_wrn("unregister irq:%x",nvmecq->cq_vector);

        irq_set_affinity_hint(vector, NULL);

        if(vector && nvmecq->irq_enable)
            //free_irq( vector, nvmeq);
            pci_free_irq(to_pci_dev(dev->dev), vector, nvmeq);
    }

    //[Edison]:[190326]: if the sq deletion is done,
    //then just cancel all the submmited io command
    print_dbg("require queue lock");
    spin_lock_irq(&nvmeq->q_lock);
    pnvme_cancel_ios(nvmeq, false);
	print_dbg("release queue lock");
    spin_unlock_irq(&nvmeq->q_lock);

    pnvme_free_nvmesq(nvmeq);
    g_rsc.g_queue_rsc->queues[qid] = NULL;
    return status;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: Create a completion queue in host ram,
*                      and return until command execution is completed
*
*FUNCTION NAME:nexus_create_cq_sync()
*
*PARAMTERS:
*       INPUT:
*             qid: the identifier of the completion queue to be created,
*                  and external caller cannot create completion queue 0
*       OUTPUT:
*       RETURN:
*             0, when create completion queue successful
*             -EINVAL, when input parameter error
*             -EIO, when create completion queue failed
*
***************************************************************************/
int pnvme_create_cq_sync(struct nvme_dev *dev, int cqid , int vector, int qsize, u8 cq_where)//defaullt :  qid=vector  cq sq on host
{
    int result;
    u16 flags = NVME_QUEUE_PHYS_CONTIG | NVME_CQ_IRQ_ENABLED;
    struct pnvme_completion_queue *nvmecq;
    struct nvme_command c;
    int max_queue_size = NVME_MAX_QSIZE;
    bool invalid_req = false;

    print_dbg(">");

    /*check paramter*/
    if(dev==NULL){
        print_err("there is no this device, please check it");
        return -ENODEV;
    }

    if (cqid >= NVME_MAX_QUEUE) {
        print_err("qid too large, please check it");
        invalid_req = true;
    }
    else if (cqid == 0) {
        print_err("qid should not be 0");
        invalid_req = true;
    }
    else if (g_rsc.g_queue_rsc->cqueues[cqid] != NULL) {
        print_err("this queue was already created");
        invalid_req = true;
    }
    else if (qsize <= 0) {
        print_err("queue depth must be larger than 0");
        invalid_req = true;
    }
    else if (qsize > max_queue_size) {
        print_err("queue size too large exceed the limitted");
        invalid_req = true;
    }

    if(invalid_req)
    {
        /* submit create cq command */
        memset(&c, 0, sizeof(c));
        c.create_cq.opcode = nvme_admin_create_cq;
        c.create_cq.prp1 = cpu_to_le64(0);
        c.create_cq.cqid = cpu_to_le16(cqid);
        c.create_cq.qsize = cpu_to_le16(qsize);
        c.create_cq.cq_flags = cpu_to_le16(flags);
        c.create_cq.irq_vector = cpu_to_le16(0);
        result = pnvme_submit_admin_cmd(&dev->ctrl, &c, NULL, 0);
        return result;
    }

    nvmecq = pnvme_alloc_nvmecq(dev, cqid, qsize, vector % (dev->max_qid), cq_where);
    if (!nvmecq){
        return -ENOMEM;
    }
    nvmecq->irq_enable = 1;
    g_rsc.g_queue_rsc->cqueues[cqid] = nvmecq;      /* note for use in ioctl_alloc_sq */

    /* submit create cq command */
    memset(&c, 0, sizeof(c));
    c.create_cq.opcode = nvme_admin_create_cq;
    c.create_cq.prp1 = cpu_to_le64(nvmecq->cq_dma_addr);
    c.create_cq.cqid = cpu_to_le16(cqid);
    c.create_cq.qsize = cpu_to_le16(nvmecq->q_depth - 1);
    c.create_cq.cq_flags = cpu_to_le16(flags);
    c.create_cq.irq_vector = cpu_to_le16(nvmecq->cq_vector);

    result = pnvme_submit_admin_cmd(&dev->ctrl, &c, NULL, 0);
	print_dbg("create cq result: %x", result);
    if(result) 
        goto free_nvmecq;
    nvmecq->valid = true;

    print_dbg("<");
    return result;
free_nvmecq:
    pnvme_free_nvmecq(nvmecq);
    g_rsc.g_queue_rsc->cqueues[cqid] = NULL;
    return result;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: Create a submission queue in host ram,
*                      and return until command execution is completed
*
*FUNCTION NAME:nexus_create_sq_sync()
*
*PARAMTERS:
*       INPUT:
*             qid: the identifier of the submission queue to be created,
*                  and external caller cannot create submission queue 0
*             flags: bit0 indicates the submission queue is physically
*                    contiguous or not. if set to '1ï¿½ï¿½, then
*                    the Submission Queue is physically contiguous.
*                    If cleared to '0ï¿½ï¿½, then the Submission Queue is not
*                    physically contiguous
*                    bit[02:01] indicate the priority service class to use
*                    for commands within this Submission Queue.
*                    And other bits are reserved.
*       OUTPUT:
*       RETURN:
*             0, when create submission queue successful
*             -EINVAL, when input parameter error
*             -EIO, when create submission queue failed
*
***************************************************************************/
int pnvme_create_sq_sync(struct nvme_dev *dev, int sqid, int cqid, int sq_flags,
                                int qsize, u8 sq_where)  //defaullt :  cqid=sqid    qsize get from nvme_queue->q_depth
{
    int result;
    struct pnvme_queue *nvmeq;
    struct pnvme_completion_queue *nvmecq;
    struct nvme_command c;
    int max_queue_size = NVME_MAX_QSIZE;
    bool invalid_req = false;

    print_wrn(">");

    /*check paramter*/
    if(dev==NULL){
        print_err("there is no this device, please check it");
        return -ENODEV;
    }

    if (sqid >= NVME_MAX_QUEUE || cqid >= NVME_MAX_QUEUE) {
        print_err("qid too large, please check it");
        invalid_req = true;
    }
    else if ((sqid == 0) || (cqid == 0)) {
        print_err("qid should not be 0");
        invalid_req = true;

    }
    else if (g_rsc.g_queue_rsc->queues[sqid] != NULL) {
        invalid_req = true;
        print_err("this squeue was already created");
    }
    else if (qsize <= 0) {
        invalid_req = true;
        print_err("queue depth must be larger than 0");
    }
    else if (qsize > max_queue_size) {
        print_err("queue size too large exceed the limitted");
        invalid_req = true;
    }
    else if (g_rsc.g_queue_rsc->cqueues[cqid] == NULL) {
        print_err("Please create the corresponding completion queue firstly: %x",cqid);
        invalid_req = true;
    }

    if(invalid_req)
    {
        /* submit create sq command*/
        memset(&c, 0, sizeof(c));
        c.create_sq.opcode = nvme_admin_create_sq;
        c.create_sq.prp1 = cpu_to_le64(0);
        c.create_sq.sqid = cpu_to_le16(sqid);
        c.create_sq.qsize = cpu_to_le16(qsize);
        c.create_sq.sq_flags = cpu_to_le16(sq_flags);
        c.create_sq.cqid = cpu_to_le16(cqid);
        result = pnvme_submit_admin_cmd(&dev->ctrl, &c, NULL, 0);
        return result;
    }

    nvmeq = pnvme_alloc_nvmesq(dev, sqid, qsize, sq_where);
    if (!nvmeq){
        return -ENOMEM;
    }
    g_rsc.g_queue_rsc->queues[sqid] = nvmeq;      /* note for use in ioctl_alloc_sq */
	
    /* submit create sq command*/
    memset(&c, 0, sizeof(c));
    c.create_sq.opcode = nvme_admin_create_sq;
    c.create_sq.prp1 = cpu_to_le64(nvmeq->sq_dma_addr);
    c.create_sq.sqid = cpu_to_le16(sqid);
    c.create_sq.qsize = cpu_to_le16(nvmeq->q_depth - 1);
    c.create_sq.sq_flags = cpu_to_le16(sq_flags);
    c.create_sq.cqid = cpu_to_le16(cqid);
	print_dbg("dma_addr: %llx, prp1: %llx", (_u64)nvmeq->sq_dma_addr, (_u64)c.create_sq.prp1);
    result = pnvme_submit_admin_cmd(&dev->ctrl, &c, NULL, 0);
    if (result) 
        goto free_nvmeq;

    INIT_LIST_HEAD(&nvmeq->bio_resm_list);
    INIT_LIST_HEAD(&nvmeq->sp_bio_resm_list);
    bio_list_init(&nvmeq->sq_cong);
    bio_list_init(&nvmeq->sp_sq_cong);

    nvmecq = g_rsc.g_queue_rsc->cqueues[cqid];
    nvmeq->nvmecq = nvmecq;
    nvmeq->cqid = cqid;
    
    result = queue_request_irq(dev, nvmeq, nvmecq->irqname);
    if (result) {
        pnvme_delete_sq_cmd(dev, sqid);
        return result;
    }

   // { 
   //     print_wrn("[free_irq debug]unregister irq:%x",dev->entry[nvmecq->cq_vector].vector);
   //     free_irq(dev->entry[nvmecq->cq_vector].vector, nvmeq);
   //     print_wrn("[free_irq debug]register irq:%x",dev->entry[nvmecq->cq_vector].vector);
   //     result = queue_request_irq(dev, nvmeq, nvmecq->irqname);
   //     if (result) {
   //         pnvme_delete_sq_cmd(dev, sqid);
   //         return result;
   //     }
   // }
    nvmecq->ref_cnt ++;
	print_dbg("require queue lock");
    spin_lock(&nvmeq->q_lock);
    pnvme_init_nvmeq(nvmeq, sqid);
	print_dbg("release queue lock");
    spin_unlock(&nvmeq->q_lock);
    
    print_dbg("<");
    return result;

free_nvmeq:
    print_wrn("<");
    pnvme_free_nvmesq(nvmeq);
    g_rsc.g_queue_rsc->queues[sqid] = NULL;
    return result;
}

int get_data_size(struct nvme_ctrl *dev, _u32 nsid, _u32 *data_size, _u16 *meta_size)
{
    struct nvme_id_ns *id;
    int error;
    struct nvme_lbaf lbaf;
    
    error = pnvme_identify_ns(dev, nsid, &id);
    if (error){
        print_wrn("Identify Namespace failed[error:%d]", error);
        return -error;
    }
    lbaf = id->lbaf[(id->flbas)&0xf];
    *data_size = (lbaf.ds == 0)? 0:power(2, lbaf.ds);
    *meta_size = (lbaf.ms == 0)? 0:power(2, lbaf.ms);
    return ((id->flbas)&0x10 >> 4);
}

int lba_set_prplist(struct nvme_dev *dev, struct lba_handle_str *ptr)
{
    int i;
    _u16 nprps = ptr->fourk_num - 1;
    _u64 *mem = NULL;
    dma_addr_t dma_addr;
    struct device *dmadev = dev->dev;
    _u32 size = sizeof(u64) * nprps;



    if(nprps > MAX_NPRPS)
        size += sizeof(_u64);//two prplist
    mem = dma_alloc_coherent(dmadev, size, &dma_addr, GFP_KERNEL);
    if(!mem){
        return -ENOMEM;
    }

    memset(mem, 0, size);

    for(i = 0 ; i < size/sizeof(_u64) ; i ++){
        if((nprps<=MAX_NPRPS)||(i<MAX_NPRPS-1))
            *(mem + i) =  ptr->data_dma_addr + (1 + i) * PNVME_PAGE_SIZE;
        else{//nprps>512 and i>=511
            if(i==MAX_NPRPS-1)//prplist[511]=next prplist addr
                *(mem + i) = dma_addr + (1 + i) * sizeof(_u64);
            else
                *(mem + i) = ptr->data_dma_addr + i *  PNVME_PAGE_SIZE;
        }
    }
    /*return addr*/
    ptr->prp_list = mem;
    ptr->prp_dma = dma_addr;

    return 0;
}



void q_lock_test(struct pnvme_queue *nvmeq, int id)
{
	print_dbg("[%d]q_lock test qid: %d", id, nvmeq->qid);
	spin_lock_irq(&nvmeq->q_lock);
	print_dbg("go go go");
	spin_unlock_irq(&nvmeq->q_lock);
	print_dbg("q_lock release done");
}

void update_cmd_trace(u8 mode, u32 key, u32 lba)
{
    _u8 phase;
    if ((cid >= 0)|(cid >= TRACE_LENGTH-1)){
        phase = !debug_trace[TRACE_LENGTH - 1].phase;
    }
    else{
        phase = debug_trace[cid-1].phase;
    }
    //u64 command = (mode<<56 | (lba&0xffffff << 32)) + key;
    //print_wrn("cid:%d lba:0x%llx, mode:%d, new key:0x%x", cid, lba, mode, key);
    debug_trace[cid].key = key;
    debug_trace[cid].lba = lba;
    debug_trace[cid].mode = mode;
    debug_trace[cid].phase = phase;
    cid++;
    if(cid > TRACE_LENGTH){
        cid = cid%TRACE_LENGTH;
    }
}
void print_cmd_trace(void)
{  
    int i;
    for(i = 0; i < TRACE_LENGTH; i++)
    {
        print_wrn("trace[%d]: key:%08x, lba:%08x, mode:%x, phase:%d", i, debug_trace[i].key,debug_trace[i].lba,debug_trace[i].mode,debug_trace[i].phase);
    }
}

_u32 stat_update(_u32 stat, _u8 mode)
{
    _u32 new_s = stat&STAT_MASK;
    bool cflg = stat>>(STAT_BITN-1);
    if(mode == 3){//wr_sqe
        if ((new_s == 0)&&(cflg == 1))
            cflg = 0;
        new_s ++;
    }
    else if (mode == 2){//rd_sqe
        new_s ++;
    }
    else if ((mode == 1)|(mode == 0)){//wr_cqe
        new_s --;
    }
    if(new_s > 1)
        cflg = 1;
    new_s = (new_s | (cflg << (STAT_BITN-1)));
    //print_wrn("mode:%d, old_stat:%x, new_stat:%x, cflg:0x%x", mode,stat,new_s,cflg);
    return new_s;
}

/*
mode: bit[0]: wr:1 rd:0
      bit[1]: sqe:1 cqe:0
      wr_sqe: 0x3   rd_sqe: 0x2   wr_cqe: 0x1  rd_cqe: 0x0
*/
int key_operate(_u64 lba, _u32 *key, _u8 mode, bool keep_order)
{
    int max_mem = 0;
    int off;
    int idx;
    _u32 *p_key;
    _u16 stat;
    _u32 old_key;
    _u16 new_s;
    unsigned long flags;
    max_mem = lba_data_key->key_num_in_table;
    idx = lba/max_mem;
    off = lba%max_mem;
    if (lba_data_key->key[idx] == NULL){
        print_err("The key table not exist!!");
        return -1;
    }

    p_key = ((_u32 *)lba_data_key->key[idx]) + off;
    if(keep_order)
    {
        spin_lock_irqsave(&key_lock,flags);
        if(mode == 3){//wr_sqe
            (*p_key) ++;
        }
        *key = *(p_key);
        spin_unlock_irqrestore(&key_lock,flags);
        return 0;
    }
    spin_lock_irqsave(&key_lock,flags);
    old_key = *p_key;
    stat = ((*p_key)&(~KEY_MASK)) >> KEY_BITN;
    //if (stat == 0xffff)
    //    print_wrn("lba:0x%llx, old key:0x%x, mode:%x", lba,*p_key,mode);
    if(mode == 3){//wr_sqe
        old_key ++;
    }
    new_s = stat_update(stat, mode);
    *p_key = ((old_key)&KEY_MASK)|(new_s << KEY_BITN);
    //print_wrn("lba:0x%llx, mode:%d, old_stat:%d, new_stat:%d, new key:0x%x", lba,mode,stat,new_s,*p_key);
    update_cmd_trace(mode, *p_key, lba);
    *key = *(p_key);
    spin_unlock_irqrestore(&key_lock,flags);
    return 0;
}

void data_key_cleanup(void)
{
	int i = 0;

	for (i = 0; i < lba_data_key->table_num; i++) {
        //print_wrn("key addr[%d]:%p",i,lba_data_key->key[i]);
		kfree(lba_data_key->key[i]);
	}

	kfree(lba_data_key->key);
    kfree(lba_data_key);
}

int data_key_setup(int key_num_in_table, int num)
{
	int i = 0;
    int status = 0;
    lba_data_key = kzalloc(sizeof(*lba_data_key), GFP_ATOMIC);

    if (lba_data_key == NULL) {
		return -ENOMEM;
        goto free_structure;
	}
    lba_data_key->key_num_in_table = key_num_in_table;
    lba_data_key->table_num = num;
    print_wrn("void* size: [%d]", sizeof(void *));
    lba_data_key->key = kcalloc(num, sizeof(void *), GFP_ATOMIC);
    if (lba_data_key->key == NULL) {
		status = -ENOMEM;
        goto free_table;
	}
    print_wrn("key table num[%d]", num);
    for(i = 0;i < num;i++){
        lba_data_key->key[i] = kmalloc(key_num_in_table*4, GFP_ATOMIC);
        memset(lba_data_key->key[i],0,key_num_in_table*4);
        //print_wrn("key addr[%d]:%p",i,lba_data_key->key[i]);
        if (lba_data_key->key[i] == NULL) {
            lba_data_key->table_num = i;
		    status =  -ENOMEM;
            goto free_key;
	    }
    }
    debug_trace = kzalloc(TRACE_LENGTH*sizeof(struct debug_info), GFP_ATOMIC);
    return 0;

free_key:
    data_key_cleanup();
free_table:
    kfree(lba_data_key->key);
free_structure:
    kfree(lba_data_key);
   
    return status;
}

u64 get_data_pat(_u64 lba, _u32 key)
{
    _u64 data_pat;
    data_pat = ((lba*0x40)&0xffffffff)|((_u64)(key&KEY_MASK) << 32);
    return data_pat;
}

int set_async_data(void *pdata, _u64 slba, _u16 nlb, _u32 data_size, bool keep_order)
{
    int i,j;
    _u32 key;
    _u64 data_pat;
    //int ret;
    if(pdata == NULL)
        return 1;
    //print_wrn("set data[%llx] at lba:%llx",slba*0x40,slba);
    for(j = 0;j < nlb; j++){
        key_operate(slba+j,&key,3,keep_order);
        data_pat = get_data_pat(slba+j,key);
        for(i = 0;i < data_size/8; i++){
            *((_u64 *)pdata+data_size/8*j+i) = data_pat+i;
        }
    }
    return 0;
}

/* return crc value */
unsigned short calculate_crc(unsigned char *frame, unsigned long length) {
	unsigned short const poly = 0x8BB7L; /* Polynomial */
	unsigned const int poly_length = 16;
	unsigned short crc_gen;
	unsigned short x;
	unsigned int i, j, fb;
	unsigned const int invert = 0;/* 1=seed with 1s and invert the CRC */

	crc_gen = 0x0000;
	crc_gen ^= invert? 0xFFFF: 0x0000; /* seed generator */

	for (i = 0; i < length; i += 2) {
		/* assume little endian */
		x = (frame[i] << 8) | frame[i+1];

		/* serial shift register implementation */
		for (j = 0; j < poly_length; j++) {
			fb = ((x & 0x8000L) == 0x8000L) ^ ((crc_gen & 0x8000L) == 0x8000L);
			x <<= 1;
			crc_gen <<= 1;
			if (fb)
				crc_gen ^= poly;
		}
	}
	return crc_gen ^ (invert? 0xFFFF: 0x0000); /* invert output */
} /* calculate_crc */

void meta_copyfrom_pi(unsigned short nlb, unsigned short meta_size, unsigned int pil,
                                    unsigned long meta, struct lba_meta_pi pi){
    /*protection information location
    1: pi located in first 8 bytes of metadata;
    0: pi located in last 8 bytes of metadata)*/
    if(pil){
        *((unsigned char *)meta + meta_size*nlb) = (unsigned char)(pi.guard >> 8);
        *((unsigned char *)meta + meta_size*nlb + 1) = (unsigned char)pi.guard;
        *((unsigned char *)meta + meta_size*nlb + 2) = (unsigned char)(pi.app_tag >> 8);
        *((unsigned char *)meta + meta_size*nlb + 3) = (unsigned char)pi.app_tag;
        *((unsigned char *)meta + meta_size*nlb + 4) = (unsigned char)(pi.ref_tag >> 24);
        *((unsigned char *)meta + meta_size*nlb + 5) = (unsigned char)(pi.ref_tag >> 16);
        *((unsigned char *)meta + meta_size*nlb + 6) = (unsigned char)(pi.ref_tag >> 8);
        *((unsigned char *)meta + meta_size*nlb + 7) = (unsigned char)pi.ref_tag;
    }else{
        *((unsigned char *)meta + meta_size*(nlb + 1) - 8) = (unsigned char)(pi.guard >> 8);
        *((unsigned char *)meta + meta_size*(nlb + 1) - 7) = (unsigned char)pi.guard;
        *((unsigned char *)meta + meta_size*(nlb + 1) - 6) = (unsigned char)(pi.app_tag >> 8);
        *((unsigned char *)meta + meta_size*(nlb + 1) - 5) = (unsigned char)pi.app_tag;
        *((unsigned char *)meta + meta_size*(nlb + 1) - 4) = (unsigned char)(pi.ref_tag >> 24);
        *((unsigned char *)meta + meta_size*(nlb + 1) - 3) = (unsigned char)(pi.ref_tag >> 16);
        *((unsigned char *)meta + meta_size*(nlb + 1) - 2) = (unsigned char)(pi.ref_tag >> 8);
        *((unsigned char *)meta + meta_size*(nlb + 1) - 1) = (unsigned char)pi.ref_tag;
    }

    return;
}

static void pi_copyfrom_meta(unsigned short nlb, unsigned short meta_size, unsigned int pil,
                                    struct lba_meta_pi *pi, unsigned long meta){
    if(pil){
        pi->guard   = (*((unsigned char *)meta + meta_size*nlb) << 8) + *((unsigned char *)meta + meta_size*nlb + 1);
        pi->app_tag = (*((unsigned char *)meta + meta_size*nlb + 2) << 8) + *((unsigned char *)meta + meta_size*nlb + 3);
        pi->ref_tag = (*((unsigned char *)meta + meta_size*nlb + 4) << 24) + (*((unsigned char *)meta + meta_size*nlb + 5) << 16) \
                    + (*((unsigned char *)meta + meta_size*nlb + 6) << 8) + *((unsigned char *)meta + meta_size*nlb + 7);
    }else{
        pi->guard   = (*((unsigned char *)meta + meta_size*(nlb + 1) - 8) << 8) + *((unsigned char *)meta + meta_size*(nlb + 1) - 7);
        pi->app_tag = (*((unsigned char *)meta + meta_size*(nlb + 1) - 6) << 8) + *((unsigned char *)meta + meta_size*(nlb + 1) - 5);
        pi->ref_tag = (*((unsigned char *)meta + meta_size*(nlb + 1) - 4) << 24) + (*((unsigned char *)meta + meta_size*(nlb + 1) - 3) << 16) \
                    + (*((unsigned char *)meta + meta_size*(nlb + 1) - 2) << 8) + *((unsigned char *)meta + meta_size*(nlb + 1) - 1);
    }

    return;
}

bool get_lba_format(struct nvme_dev *dev, u32 nsid, struct nvm_format *lbaf)
{
    struct nvme_id_ns *id;
    int error;
    int dps;

    
    error = pnvme_identify_ns(&(dev->ctrl), nsid, &id);
    if (error)
        return error;
    dps = id->dps;
    lbaf->reg.lbaf = id->flbas;
    lbaf->reg.pi = dps&0x7;
    lbaf->reg.pil = (dps&0x8) >> 3;
    return 0;
}

void crt_pi(struct nvme_dev *dev, struct nvme_lba_command *nvme_lba_command, struct lba_handle_str *ptr){
    _u32 data_size;
    _u16 meta_size;
    unsigned char crc_buffer_flag;
    unsigned char *crc_buffer = NULL;
    unsigned int crc_buffer_length;
    unsigned int crc_value;
    struct dw12_control ctr;
    unsigned short i;
    struct lba_meta_pi pi;
    unsigned int tmp_reftag;
    struct nvm_format nvm_format;
    bool dif_flag = 0;
    //unsigned short piflag;/*0: create pi according pi enable bits; 1: create pi according PRCHK bits*/

    
    ctr.control = nvme_lba_command->control;
    get_lba_format(dev, 1, &nvm_format);
    nvm_format.reg.ses = nvme_lba_command->rsv_pi;
    //PRINT("ctr: 0x%x, guard: %d, apptag: %d, reftag: %d.\n", ctr.control, ctr.reg.guard, ctr.reg.apptag, ctr.reg.reftag);
    //piflag = ctr.reg.rsv;/*use the reserved bits of control as pi flag*/
    if(nvm_format.reg.pi && !ctr.reg.pract){
        tmp_reftag = nvme_lba_command->reftag;
        dif_flag = get_data_size(&(dev->ctrl), 1, &data_size, &meta_size);
        //PRINT("data_size: %d, meta_size: %d.\n", data_size, meta_size);
       if(0 == meta_size){
           print_err("error: metadata size = 0, can't create pi.\n");
           return;
       }

       /*create buffer if need*/
       if((0 == nvm_format.reg.pil) && (8 < meta_size)){
           crc_buffer_length = data_size + meta_size - 8;
           crc_buffer = (unsigned char*)kmalloc(crc_buffer_length*sizeof(unsigned char), GFP_KERNEL);
           if(NULL == crc_buffer){
               print_err("malloc crc buffer failed.\n");
               return;
           }
           crc_buffer_flag = 1;
       }else{
           crc_buffer_flag = 0;
           crc_buffer_length = data_size;
       }
       //PRINT("crc length: %d.\n", crc_buffer_length);
       //PRINT("reg.ses: %d.\n", nvm_format->reg.ses);
       /*create pi for each lba*/
       for(i=0; i<=nvme_lba_command->nlb; i++){
       //PRINT("number of lba: %d.\n", i);
            memset(&pi, 0, sizeof(pi));

            /*create pi guard*/
            if(crc_buffer_flag){
                if(dif_flag){
                    memcpy(crc_buffer, (unsigned char *)(ptr->mem_data+ i*(data_size+meta_size)), data_size+meta_size-8);
                }
                else{
                    memcpy(crc_buffer, (unsigned char *)(ptr->mem_data+ i*data_size), data_size);
                    memcpy(crc_buffer+data_size, (unsigned char *)ptr->mem_meta + i*meta_size, meta_size-8);
                }
            }
            else{
                crc_buffer = (unsigned char*)(ptr->mem_data+ i*data_size);
            }
            crc_value = calculate_crc(crc_buffer, crc_buffer_length);
			if(0x1 == nvm_format.reg.ses%2)
				pi.guard = 0x22;
			else
				pi.guard = crc_value;
            //PRINT("crc: 0x%x.\n", pi.guard);

            /*create pi application tag*/
            if(0x1 == (nvm_format.reg.ses%4)/2)
                pi.app_tag = 0x22;
            else
                pi.app_tag = nvme_lba_command->apptag;
            //PRINT("apptag: 0x%x.\n", pi.app_tag);

            /*create pi reference tag*/
			if(0x1 == nvm_format.reg.ses/4)
                pi.ref_tag = 0x22;
            else
                pi.ref_tag = tmp_reftag;
            if((PI_TYPE1 == nvm_format.reg.pi) || (PI_TYPE2 == nvm_format.reg.pi))
                tmp_reftag++;
            //PRINT("reftag: 0x%x.\n", pi.ref_tag);

            meta_copyfrom_pi(i, meta_size, nvm_format.reg.pil, ptr->mem_meta, pi);
       }

       if(crc_buffer_flag)
           kfree(crc_buffer);
   }
   return;
}

/*check protection information*/
_u32 chk_pi(struct nvme_dev *dev, struct nvme_lba_command * nvme_lba_command, struct lba_handle_str *ptr){
    _u32 data_size;
    _u16 meta_size;
    unsigned char crc_buffer_flag = 0;
    unsigned char *crc_buffer = NULL;
    unsigned int crc_buffer_length;
    unsigned int crc_value;
    struct dw12_control ctr;
    unsigned short i;
    struct lba_meta_pi pi;
    unsigned int tmp_reftag;
    bool dif_flag = 0;
    struct nvm_format nvm_format;
    unsigned int retval = CHKPI_SUCCESS;
    ctr.control = nvme_lba_command->control;
    
    
    get_lba_format(dev, 1, &nvm_format);
    nvm_format.reg.ses = nvme_lba_command->rsv_pi;
    if(nvm_format.reg.pi && !ctr.reg.pract){
    //if(nvm_format->reg.pi){
        /*certain condition don't check PI*/
        if((((PI_TYPE1 == nvm_format.reg.pi) || (PI_TYPE2 == nvm_format.reg.pi)) && (0xffff == nvme_lba_command->apptag))
            || ((PI_TYPE3 == nvm_format.reg.pi) && (0xffff == nvme_lba_command->apptag) && (0xffffffff == nvme_lba_command->reftag))){
            retval = CHKPI_SUCCESS;
            goto exit;
        }
        /*parse the vss type*/
        tmp_reftag = nvme_lba_command->reftag;
        dif_flag = get_data_size(&(dev->ctrl), 1, &data_size, &meta_size);
        //PRINT("data_size: %d, meta_size: %d.\n", data_size, meta_size);
        if(0 == meta_size){
        //PRINT("err: metadata size = 0, can't check pi.\n");
            retval = CHKPI_FAIL;
            goto exit;
        }
        /*create buffer if need*/
        if((0 == nvm_format.reg.pil) && (8 < meta_size)){
            crc_buffer_length = data_size + meta_size - 8;
            crc_buffer = (unsigned char*)kmalloc(crc_buffer_length*sizeof(unsigned char), GFP_KERNEL);
            if(NULL == crc_buffer){
                //PRINT("malloc crc buffer failed.\n");
                retval = CHKPI_FAIL;
                goto exit;
            }
            crc_buffer_flag = 1;
       }else{
            crc_buffer_flag = 0;
            crc_buffer_length = data_size;
       }

       ctr.control = nvme_lba_command->control;
       //PRINT("ctr: 0x%x, guard: %d, apptag: %d, reftag: %d.\n", ctr.control, ctr.reg.guard, ctr.reg.apptag, ctr.reg.reftag);
       /*check the PI for each lba*/
       for(i=0; i<=nvme_lba_command->nlb; i++){
           //PRINT("number of lba: %d.\n", i);
           memset(&pi, 0, sizeof(pi));
           pi_copyfrom_meta(i, meta_size, nvm_format.reg.pil, &pi, nvme_lba_command->metadata);
           if (ENABLE == ctr.reg.guard) {
               if(crc_buffer_flag){
                   if(dif_flag){
                       memcpy(crc_buffer, (unsigned char *)(ptr->mem_data+ i*(data_size+meta_size)), data_size+meta_size-8);
                   }
                   else{
                       memcpy(crc_buffer, (unsigned char *)(ptr->mem_data+ i*data_size), data_size);
                       memcpy(crc_buffer+data_size, (unsigned char *)ptr->mem_meta + i*meta_size, meta_size-8);
                   }
               }
               else{
                   crc_buffer = (unsigned char*)(ptr->mem_data + i*data_size);
               }
               crc_value = calculate_crc(crc_buffer, crc_buffer_length);
               if(pi.guard == crc_value)
                   retval = CHKPI_SUCCESS;
               else{
                   retval = CHKPI_FAIL;
                   //PRINT("PI CRC check fail, crc: 0x%x, pi.guard: 0x%x.\n", crc_value, pi.guard);
                   goto exit;
               }
           }

           if (ENABLE == ctr.reg.apptag) {
               if((pi.app_tag & nvme_lba_command->appmask) == (nvme_lba_command->apptag & nvme_lba_command->appmask))
                   retval = CHKPI_SUCCESS;
               else{
                   retval = CHKPI_FAIL;
                   //PRINT("PI apptag check fail, appmask: 0x%x, apptag: 0x%x, pi.apptag: 0x%x.\n", nvme_lba_command->appmask, nvme_lba_command->apptag, pi.app_tag);
                   goto exit;
               }
           }

           if (ENABLE == ctr.reg.reftag) {
               if(pi.ref_tag == tmp_reftag){
                   retval = CHKPI_SUCCESS;
                   if((PI_TYPE1 == nvm_format.reg.pi) || (PI_TYPE2 == nvm_format.reg.pi))
                      tmp_reftag++;
               }else{
                   retval = CHKPI_FAIL;
                   //PRINT("PI reftag check fail, reftag: 0x%x, pi.ref_tag: 0x%x.\n", tmp_reftag, pi.ref_tag);
                   goto exit;
               }
           }
       }
    }

exit:
    if(crc_buffer_flag)
        kfree(crc_buffer);
    return retval;
}

