/********************************************************************
* FILE NAME: ktest_lba.c
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
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/hdreg.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list_sort.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pr.h>
#include <linux/ptrace.h>
#include <linux/nvme_ioctl.h>
#include <linux/idr.h>
#include <scsi/sg.h>
#include <asm/unaligned.h>
#include <linux/nvme.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <asm/fcntl.h>
#include <linux/buffer_head.h>
#include <linux/fcntl.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/stddef.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include<linux/ktime.h>
#include <asm/dma-mapping.h>
#include "nvme.h"
#include "pnvme_drv.h"
#include "pnvme_if.h"
#include "pnvme_lba.h"



volatile _u8 async_test_fail = 0;
volatile _u64 com_cnt = 0;

struct pnvme_perf perf;

extern struct request *nvme_alloc_request(struct request_queue *q,
		struct nvme_command *cmd, blk_mq_req_flags_t flags, int qid);
extern int __nvme_submit_sync_cmd(struct request_queue *q, struct nvme_command *cmd,
		union nvme_result *result, void *buffer, unsigned bufflen,
		unsigned timeout, int qid, int at_head,
		blk_mq_req_flags_t flags);

/*
struct request *nvme_alloc_request(struct request_queue *q,
		struct nvme_command *cmd, unsigned int flags)
{
	bool write = cmd->common.opcode & 1;
	struct request *req;

	req = blk_mq_alloc_request(q, write, GFP_KERNEL, false);
	if (IS_ERR(req))
		return req;

	req->cmd_type = REQ_TYPE_DRV_PRIV;
	req->cmd_flags |= REQ_FAILFAST_DRIVER;
	req->__data_len = 0;
	req->__sector = (sector_t) -1;
	req->bio = req->biotail = NULL;

	req->cmd = (unsigned char *)cmd;
	req->cmd_len = sizeof(struct nvme_command);
	req->special = (void *)0;

	return req;
}
*/
/*
 * Returns 0 on success.  If the result is negative, it's a Linux error code;
 * if the result is positive, it's an NVM Express status code
 */
 /*
int __nvme_submit_sync_cmd(struct request_queue *q, struct nvme_command *cmd,
		void *buffer, unsigned bufflen, _u32 *result, unsigned timeout)
{
	struct request *req;
	int ret;

	req = nvme_alloc_request(q, cmd, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->timeout = timeout ? timeout : ADMIN_TIMEOUT;

	if (buffer && bufflen) {
		ret = blk_rq_map_kern(q, req, buffer, bufflen, __GFP_WAIT);
		if (ret)
			goto out;
	}
	print_dbg("prp1 : %llx", (_u64)cmd->create_sq.prp1);
	blk_execute_rq(req->q, NULL, req, 0);
	if (result)
		*result = (u32)(uintptr_t)req->special;
	ret = req->errors;
	print_dbg("admin cqe: result:%x, ret:%x", result, ret);
 out:
	blk_mq_free_request(req);
	return ret;
}
*/
int pnvme_submit_sync_cmd(struct request_queue *q, struct nvme_command *cmd,
		void *buffer, unsigned bufflen)
{
	//return __nvme_submit_sync_cmd(q, cmd, buffer, bufflen, NULL, 0);
    return __nvme_submit_sync_cmd(q, cmd, NULL, buffer, bufflen, 0,	NVME_QID_ANY, 0, 0);
}

int pnvme_submit_admin_cmd(struct nvme_ctrl *dev, struct nvme_command *cmd,
		void *buffer, unsigned bufflen)
{
	//return __nvme_submit_sync_cmd(dev->admin_q, cmd, buffer, bufflen, NULL, 0);
    return __nvme_submit_sync_cmd(dev->admin_q, cmd, NULL, buffer, bufflen, 0,	NVME_QID_ANY, 0, 0);
}

void *nvme_add_user_metadata(struct bio *bio, void __user *ubuf,
		unsigned len, u32 seed, bool write)
{
	struct bio_integrity_payload *bip;
	int ret = -ENOMEM;
	void *buf;

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		goto out;

	ret = -EFAULT;
	if (write && copy_from_user(buf, ubuf, len))
		goto out_free_meta;

	bip = bio_integrity_alloc(bio, GFP_KERNEL, 1);
	if (IS_ERR(bip)) {
		ret = PTR_ERR(bip);
		goto out_free_meta;
	}

	bip->bip_iter.bi_size = len;
	bip->bip_iter.bi_sector = seed;
	ret = bio_integrity_add_page(bio, virt_to_page(buf), len,
			offset_in_page(buf));
	if (ret == len)
		return buf;
	ret = -ENOMEM;
out_free_meta:
	kfree(buf);
out:
	return ERR_PTR(ret);
}

int __nvme_submit_user_cmd(struct request_queue *q,
		struct nvme_command *cmd, void __user *ubuffer,
		unsigned bufflen, void __user *meta_buffer, unsigned meta_len,
		u32 meta_seed, u32 *result, unsigned timeout)
{
	bool write = nvme_is_write(cmd);
	struct nvme_ns *ns = q->queuedata;
	struct gendisk *disk = ns ? ns->disk : NULL;
	struct request *req;
	struct bio *bio = NULL;
	void *meta = NULL;
	int ret;

	req = nvme_alloc_request(q, cmd, 0, NVME_QID_ANY);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->timeout = timeout ? timeout : ADMIN_TIMEOUT;

	if (ubuffer && bufflen) {
		ret = blk_rq_map_user(q, req, NULL, ubuffer, bufflen,
				GFP_KERNEL);
		if (ret)
			goto out;
		bio = req->bio;
		bio->bi_disk = disk;
		if (disk && meta_buffer && meta_len) {
			meta = nvme_add_user_metadata(bio, meta_buffer, meta_len,
					meta_seed, write);
			if (IS_ERR(meta)) {
				ret = PTR_ERR(meta);
				goto out_unmap;
			}
			req->cmd_flags |= REQ_INTEGRITY;
		}
	}

	blk_execute_rq(req->q, disk, req, 0);
	if (nvme_req(req)->flags & NVME_REQ_CANCELLED)
		ret = -EINTR;
	else
		ret = nvme_req(req)->status;
	if (result)
		*result = le32_to_cpu(nvme_req(req)->result.u32);
	if (meta && !ret && !write) {
		if (copy_to_user(meta_buffer, meta, meta_len))
			ret = -EFAULT;
	}
	kfree(meta);
 out_unmap:
	if (bio)
		blk_rq_unmap_user(bio);
 out:
	blk_mq_free_request(req);
	return ret;
}
/*
int __nvme_submit_user_cmd(struct request_queue *q, struct nvme_command *cmd,
		void __user *ubuffer, unsigned bufflen,
		void __user *meta_buffer, unsigned meta_len, _u32 meta_seed,
		_u32 *result, unsigned timeout)
{
	bool write = cmd->common.opcode & 1;
	struct nvme_ns *ns = q->queuedata;
	struct gendisk *disk = ns ? ns->disk : NULL;
	struct request *req;
	struct bio *bio = NULL;
	void *meta = NULL;
	int ret;

	req = nvme_alloc_request(q, cmd, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->timeout = timeout ? timeout : ADMIN_TIMEOUT;

	if (ubuffer && bufflen) {
		ret = blk_rq_map_user(q, req, NULL, ubuffer, bufflen, __GFP_WAIT);
		if (ret)
			goto out;
		bio = req->bio;

		if (!disk)
			goto submit;
		bio->bi_bdev = bdget_disk(disk, 0);
		if (!bio->bi_bdev) {
			ret = -ENODEV;
			goto out_unmap;
		}

		if (meta_buffer && meta_len) {
			struct bio_integrity_payload *bip;

			meta = kmalloc(meta_len, GFP_KERNEL);
			if (!meta) {
				ret = -ENOMEM;
				goto out_unmap;
			}

			if (write) {
				if (copy_from_user(meta, meta_buffer,
						meta_len)) {
					ret = -EFAULT;
					goto out_free_meta;
				}
			}

			bip = bio_integrity_alloc(bio, GFP_KERNEL, 1);
			if (!bip) {
				ret = -ENOMEM;
				goto out_free_meta;
			}

			bip->bip_size = meta_len;
			bip->bip_sector = meta_seed;

			ret = bio_integrity_add_page(bio, virt_to_page(meta),
					meta_len, offset_in_page(meta));
			if (ret != meta_len) {
				ret = -ENOMEM;
				goto out_free_meta;
			}
		}
	}
 submit:
	blk_execute_rq(req->q, disk, req, 0);
	ret = req->errors;
	if (result)
		*result = (u32)(uintptr_t)req->special;
	if (meta && !ret && !write) {
		if (copy_to_user(meta_buffer, meta, meta_len))
			ret = -EFAULT;
	}
 out_free_meta:
	kfree(meta);
 out_unmap:
	if (bio) {
		if (disk && bio->bi_bdev)
			bdput(bio->bi_bdev);
		blk_rq_unmap_user(bio);
	}
 out:
	blk_mq_free_request(req);
	return ret;
}
*/
int pnvme_submit_user_cmd(struct request_queue *q, struct nvme_command *cmd,
		void __user *ubuffer, unsigned bufflen, _u32 *result,
		unsigned timeout)
{
	return __nvme_submit_user_cmd(q, cmd, ubuffer, bufflen, NULL, 0, 0,
			result, timeout);
}

int pnvme_admin_passthrough(struct nvme_dev *dev, unsigned long ucmd)
{
	struct nvme_passthru_cmd cmd;
	struct nvme_command c;
	unsigned timeout = 0;
	int status;

    struct nvme_passthru_cmd *cmd_para = (struct nvme_passthru_cmd *)ucmd;
    
	struct nvme_ctrl *ctrl = &dev->ctrl;
	
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	if (copy_from_user(&cmd, cmd_para, sizeof(cmd)))
		return -EFAULT;
	if (cmd.flags)
		return -EINVAL;
    print_wrn("nvme_admin_cmd: opcode: %x, data address: %lx", cmd.opcode, (uintptr_t)cmd.addr);
	memset(&c, 0, sizeof(c));
	c.common.opcode = cmd.opcode;
	c.common.flags = cmd.flags;
	c.common.nsid = cpu_to_le32(cmd.nsid);
	c.common.cdw2[0] = cpu_to_le32(cmd.cdw2);
	c.common.cdw2[1] = cpu_to_le32(cmd.cdw3);
	c.common.cdw10[0] = cpu_to_le32(cmd.cdw10);
	c.common.cdw10[1] = cpu_to_le32(cmd.cdw11);
	c.common.cdw10[2] = cpu_to_le32(cmd.cdw12);
	c.common.cdw10[3] = cpu_to_le32(cmd.cdw13);
	c.common.cdw10[4] = cpu_to_le32(cmd.cdw14);
	c.common.cdw10[5] = cpu_to_le32(cmd.cdw15);

	if (cmd.timeout_ms)
		timeout = msecs_to_jiffies(cmd.timeout_ms);

	status = pnvme_submit_user_cmd(ctrl->admin_q, &c,
			(void __user *)(uintptr_t)cmd.addr, cmd.data_len,
			&cmd.result, timeout);
	if (status >= 0) {
		if (put_user(cmd.result, &cmd_para->result))
			return -EFAULT;
	}

	return status;
}

int pnvme_identify_ctrl(struct nvme_ctrl *dev, struct nvme_id_ctrl **id)
{
	struct nvme_command c = {
		.identify.opcode = nvme_admin_identify,
		.identify.cns = cpu_to_le32(1),
	};
	int error;

	*id = kmalloc(sizeof(struct nvme_id_ctrl), GFP_KERNEL);
	if (!*id)
		return -ENOMEM;

	error = pnvme_submit_sync_cmd(dev->admin_q, &c, *id,
			sizeof(struct nvme_id_ctrl));
	if (error)
		kfree(*id);
	return error;
}

int pnvme_identify_ns(struct nvme_ctrl *dev, unsigned nsid,
		struct nvme_id_ns **id)
{
	struct nvme_command c = {
		.identify.opcode = nvme_admin_identify,
		.identify.nsid = cpu_to_le32(nsid),
	};
	int error;

	*id = kmalloc(sizeof(struct nvme_id_ns), GFP_KERNEL);
	if (!*id)
		return -ENOMEM;

	error = nvme_submit_sync_cmd(dev->admin_q, &c, *id,
			sizeof(struct nvme_id_ns));
	if (error)
		kfree(*id);
	return error;
}

int pnvme_get_features(struct nvme_ctrl *dev, unsigned fid, unsigned nsid,
					dma_addr_t dma_addr, union nvme_result *result)
{
	struct nvme_command c;

	memset(&c, 0, sizeof(c));
	c.features.opcode = nvme_admin_get_features;
	c.features.nsid = cpu_to_le32(nsid);
	c.features.dptr.prp1 = cpu_to_le64(dma_addr);
	c.features.fid = cpu_to_le32(fid);

	//return __nvme_submit_sync_cmd(dev->admin_q, &c, NULL, 0, result, 0);
    return __nvme_submit_sync_cmd(dev->admin_q, &c, result, NULL, 0, 0,	NVME_QID_ANY, 0, 0);
}

int getMaxLBAByIdentify(struct nvme_ctrl *dev, int nsid, _u64* maxlba)
{
    int result = -1;
    struct nvme_id_ns *id_ns;

    result = pnvme_identify_ns(dev, nsid, &id_ns);
    if (result) {
        print_err("nexus_identify_sync failed\n");
        return -EIO;
    }

    *maxlba = id_ns->nsze;
    kfree(id_ns);
    return 0;
}

/*free prplist*/
int lba_free_prplist(struct nvme_dev *dev, struct lba_handle_str *ptr)
{
    _u64 *mem = ptr->prp_list;
    dma_addr_t dma_addr = ptr->prp_dma;
    struct device *dmadev = dev->dev;
	_u16 nprps = ptr->fourk_num - 1;
    _u32 size = sizeof(_u64) * nprps;

    if(nprps > MAX_NPRPS)
        size += sizeof(_u64);//two prplist
    dma_free_coherent(dmadev, size, mem, dma_addr);
    return 0;
}

int lba_alloc_meta_dma(struct nvme_dev *dev, struct lba_handle_str *ptr)
{
    void *mem = NULL;
    dma_addr_t dma_addr = 0;
    struct device *dmadev = dev->dev;
    _u32 size = ptr->nlb * ptr->meta_size;

    if(ptr->dif_flag){/*if dif mode, meta dma is invaid*/
        mem = ptr->mem_data + ptr->data_size;
        dma_addr = 0;
        memset(mem, 0, size);
    }else{/*dix mode*/
        if(ptr->meta_size){
            mem = dma_alloc_coherent(dmadev, size, &dma_addr, GFP_KERNEL);
            if(!mem){
                return -ENOMEM;
            }
        }
        memset(mem, 0, size);
    }
    /*return addr*/
    ptr->mem_meta = mem;
    ptr->meta_dma_addr = dma_addr;

    return 0;
}

int lba_free_meta_dma(struct nvme_dev *dev, struct lba_handle_str *ptr)
{
    void *mem = ptr->mem_meta;
    dma_addr_t dma_addr = ptr->meta_dma_addr;
    struct device *dmadev = dev->dev;
    _u32 size = ptr->nlb * ptr->meta_size;

    /*dif mode,do nothing*/
    if(ptr->dif_flag == 0){
        if(ptr->meta_size){
            dma_free_coherent(dmadev, size, mem, dma_addr);
        }
    }
    return 0;
}

/*alloc data dma buffer*/
int lba_alloc_data_dma(struct nvme_dev *dev, struct lba_handle_str *ptr)
{
    void *mem = NULL;
    dma_addr_t dma_addr;
    struct device *dmadev = dev->dev;
    _u32 size = ptr->fourk_num * PNVME_PAGE_SIZE;
    
    print_dbg("alloc data size:0x%x",size);

    //print_not("mem alloc data");
    mem = dma_alloc_coherent(dmadev, size, &dma_addr, GFP_KERNEL);
    if(!mem){
        return -ENOMEM;
    }
    memset(mem, 0xFF, size);

    /*return addr*/
    ptr->mem_data = mem;
    ptr->data_dma_addr = dma_addr;

    return 0;
}
/*free data dma buffer*/
int lba_free_data_dma(struct nvme_dev *dev, struct lba_handle_str *ptr)
{
    void *mem = ptr->mem_data;
    dma_addr_t dma_addr = ptr->data_dma_addr;
    struct device *dmadev = dev->dev;
    _u32 size = ptr->fourk_num * PNVME_PAGE_SIZE;

    dma_free_coherent(dmadev, size, mem, dma_addr);
    return 0;
}

int lba_data_copy_from_user(struct lba_handle_str *ptr)
{
    int i;
    _u32 data_offset = 0, meta_offset = 0;
    _u16 nlb = ptr->nlb;
    void *mem_data = ptr->mem_data;
    void *mem_meta = ptr->mem_meta;
    _u64 datafile = ptr->datafile;
    _u64 metafile = ptr->metafile;

    if(ptr->dif_flag){/*dif mode*/
        data_offset = ptr->data_size + ptr->meta_size;
        meta_offset = data_offset;
    }else{
        data_offset= ptr->data_size;
        meta_offset = ptr->meta_size;
    }
    print_dbg("dif:%d, data_off:%d, meta_off:%d", ptr->dif_flag, data_offset, meta_offset);
    for(i=0;i<nlb;i++){
        print_dbg("copy data for lba:%d, addr: 0x%x", i, (void *)datafile + ptr->data_size*i);
        if(copy_from_user(mem_data + data_offset*i,(void *)datafile + ptr->data_size*i, ptr->data_size)){
            return -EFAULT;
        }
        if(ptr->meta_size){
            if(copy_from_user(mem_meta + meta_offset*i,(void *)metafile + ptr->meta_size*i, ptr->meta_size)){
                return -EFAULT;
            }
        }
    }

    return 0;
}

/*copy data to user in dif mode*/
int lba_data_copy_to_user(struct lba_handle_str *ptr)
{
    int i = 0;
    _u32 data_offset = 0, meta_offset = 0;
    _u16 nlb = ptr->nlb;
    void *mem_data = ptr->mem_data;
    void *mem_meta = ptr->mem_meta;
    _u64 datafile = ptr->datafile;
    _u64 metafile = ptr->metafile;

    if(ptr->dif_flag){/*dif mode*/
        data_offset = ptr->data_size + ptr->meta_size;
        meta_offset = data_offset;
    }else{
        data_offset= ptr->data_size;
        meta_offset = ptr->meta_size;
    }

    for(i=0;i<nlb;i++){
        if(copy_to_user((void*)datafile + ptr->data_size*i, mem_data + data_offset*i, ptr->data_size)){
            return -EFAULT;
        }
        if(ptr->meta_size){
            if(copy_to_user((void *)metafile + ptr->meta_size*i, mem_meta + meta_offset*i, ptr->meta_size)){
                return -EFAULT;
            }
        }
    }
    return 0;
}
/***************************************************************************
*
*FUNCTION DESCRIPTION: If controller has not fetch this commmand within
*                      the given time, we shall cancel the cmdid this
*                      command occupy
*
*FUNCTION NAME: nexus_abort_command()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: pointer to correspond nvmeq
*             cmdid: The command id that not return in the limitted time
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
void pnvme_abort_command(struct pnvme_queue *nvmeq, u16 cmdid)
{
	print_dbg("require queue lock");
    spin_lock_irq(&nvmeq->q_lock);
    cancel_cmdid(nvmeq, cmdid, NULL);
	print_dbg("release queue lock");
    spin_unlock_irq(&nvmeq->q_lock);
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: Copy a command into a queue and ring the doorbell
*
*FUNCTION NAME: nexus_submit_cmd()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: The queue that will be used for this command
*             cmd: The command to send
*             q_db_enable: Write doorbell or not
*             lock_flag: Hold q_lock or not, when set to QUEUE_NEED_LOCK,
*                        the function need to hold q_lock
*       OUTPUT:
*       RETURN:
*             0, submit command successful
*
***************************************************************************/
/*int pnvme_submit_cmd(struct pnvme_queue *nvmeq, struct nvme_command *cmd, unsigned int q_db_enable, unsigned int lock_flag)
{
    unsigned long flags = 0;
    u16 tail;
    u16 temp;

    struct pnvme_cmd_info *cmd_info = get_this_cmdinfo(nvmeq,  cmd->common.command_id);
    cmd_info->opcode = cmd->common.opcode;
    cmd_info->nlb = cmd->rw.length;
	
	print_dbg("nsid : %d ", cmd->common.nsid);
    if (lock_flag==QUEUE_NEED_LOCK){
		print_dbg("require queue lock");
        spin_lock_irqsave(&nvmeq->q_lock, flags);
        //spin_lock(&nvmeq->q_lock);
    }

    tail = nvmeq->sq_tail;
	print_dbg("SQ address: %llx", nvmeq->sq_cmds);
    memcpy(&nvmeq->sq_cmds[tail], cmd, sizeof(*cmd));

    if (++tail == nvmeq->q_depth)
        tail = 0;

    if (q_db_enable)
		print_dbg("db address: %llx, value:%x", nvmeq->q_db, tail);
        writel(tail, nvmeq->q_db);

    nvmeq->sq_tail = tail;

    if (lock_flag==QUEUE_NEED_LOCK){
		print_dbg("release queue lock");
        spin_unlock_irqrestore(&nvmeq->q_lock, flags);
		//spin_unlock(&nvmeq->q_lock);
    }

    return 0;
}
*/

int pnvme_submit_cmd(struct pnvme_queue *nvmeq, struct nvme_command *cmd, unsigned int q_db_enable, unsigned int lock_flag)
{
    unsigned long flags = 0;
    _u16 tail;
    _u16 temp;

    struct pnvme_cmd_info *cmd_info = get_this_cmdinfo(nvmeq,  cmd->common.command_id);
    cmd_info->opcode = cmd->common.opcode;
    cmd_info->nlb = cmd->rw.length;

    if (lock_flag==QUEUE_NEED_LOCK){
        spin_lock_irqsave(&nvmeq->q_lock, flags);
    }

    tail = nvmeq->sq_tail;
    memcpy(&nvmeq->sq_cmds[tail], cmd, sizeof(*cmd));

    if (++tail == nvmeq->q_depth)
        tail = 0;
    if (db_swith == 0){
        writel(tail, nvmeq->q_db);
    }
    else
    {
        if (q_db_enable == 1){
            //printk("doorbell switch now is enable, will ring doorbell \n");
            writel(tail, nvmeq->q_db);
        }
        else if(q_db_enable == 2){
            printk("will write invalid(out of range) value to doorbell \n");
            writel(tail+1024, nvmeq->q_db);
        }
        else if(q_db_enable ==3){
            printk("will write invalid(same as previously) value to doorbell \n");
            temp = (tail-1)<0?0:(tail-1);
            printk("will write tail:%d\n", temp);
            writel(tail+1024, nvmeq->q_db);
        }
        else
            printk("doorbell switch now is disable, will not ring doorbell \n");

    }
    nvmeq->sq_tail = tail;

    if (lock_flag==QUEUE_NEED_LOCK){
        spin_unlock_irqrestore(&nvmeq->q_lock, flags);
    }

    return 0;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: submit nvme command, and return
*                      wait until command execute complete
*
*FUNCTION NAME: nexus_submit_cmd_sync()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: The queue that will be used for this command
*             cmd: The command to send
*             result: no used
*             timeout: The max time to wait command execution complete
*       OUTPUT:
*       RETURN:
*              0, when success
*              negative, a Linux error code
*              positive, an NVM Express status code
*
***************************************************************************/
int pnvme_submit_cmd_sync(struct pnvme_queue *nvmeq, struct nvme_command *cmd,
                        _u32 *result, unsigned timeout)
{
    int ret;
    struct sync_cmd_info cmdinfo;
    print_dbg(" ");
	print_dbg("nsid : %d ", cmd->common.nsid);

    cmdinfo.task = current;
    cmdinfo.status = -EINTR;
	q_lock_test(nvmeq, 1);
    ret = alloc_cmdid_killable(nvmeq, &cmdinfo, sync_completion, timeout);
    if (ret < 0){
        print_err("alloc_cmdid_killable failed ret 0x%x", ret);
        return ret;
    }
    cmd->common.command_id = ret;
    set_current_state(TASK_KILLABLE);
    pnvme_submit_cmd(nvmeq, cmd, 1, QUEUE_NEED_LOCK);
    schedule_timeout(timeout);

    if (cmdinfo.status == -EINTR) {
        print_err("cmdinfo.status == -EINTR");
        print_err("time out sq db:0x%x",nvmeq->sq_tail);
        pnvme_abort_command(nvmeq, cmd->common.command_id);
        return -EINTR;
    }

    if (result)
        *result = cmdinfo.result;           /*CQE DW0*/
    print_dbg("<");

    return cmdinfo.status;
}

int pnvme_pi_cmd(struct nvme_dev *dev, struct nvme_lba_command *kcmd_para)
{
		int result = 0;
		struct lba_handle_str *ptr = NULL;
		u32 page_size = PNVME_PAGE_SIZE;
		print_dbg("page_size:0x%x",page_size);
	
		ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
		if (ptr == NULL){
			return -EFAULT;
		}
	
		ptr->nlb = kcmd_para->nlb + 1;
	
		/*get flag*/
		if((kcmd_para->opcode == nvme_cmd_write)||(kcmd_para->opcode == nvme_cmd_compare))
			ptr->wr_flag = 1;
		else if(kcmd_para->opcode == nvme_cmd_read)
			ptr->wr_flag = 0;
		else{
			print_wrn("invaild opcode(ether not read or write");
			return -EINVAL;
		}
	
		ptr->qid = kcmd_para->rsv_qid;
		kcmd_para->rsv_qid = 0;
		ptr->dram_flag = kcmd_para->rsv_dram;
		kcmd_para->rsv_dram = 0;
		print_dbg("nsid 0x%x",kcmd_para->nsid);
	
		
		result = get_data_size(&(dev->ctrl), kcmd_para->nsid, &(ptr->data_size), &(ptr->meta_size));
        if(result < 0){
            return result;
        }
        ptr->dif_flag = result;

		ptr->fourk_num = CALC_PAGE_NUM(ptr->nlb, ptr->data_size, 0);
		print_dbg("nprp: %d,ds:0x%x,ms:0x%x",ptr->fourk_num,ptr->data_size,ptr->meta_size);

		if(ptr->fourk_num > 1024){
			print_err("Now this ioctl do not support 4k_num > 1024");
			return -EFAULT;
		}
		//print_wrn("dram_flag:0x%x, nlb:0x%x, datasize:0x%x, metasize:0x%x, forknum:0x%x", ptr->dram_flag, ptr->nlb, ptr->data_size, ptr->meta_size, ptr->fourk_num);
	
		if (ptr->dram_flag == 0) { // wr/rd lba from/to host
			/*alloc data dma buffer */
			result = lba_alloc_data_dma(dev, ptr);
			if(result){
				goto free_kmem;
			}
			result = lba_alloc_meta_dma(dev, ptr);
			if(result){
				goto free_prp;
			}
			ptr->datafile = kcmd_para->prp1;
			ptr->metafile = kcmd_para->metadata;
		}
	
		kcmd_para->prp1 = ptr->data_dma_addr;
		if(ptr->meta_size)
			kcmd_para->metadata = ptr->meta_dma_addr;
		else
			kcmd_para->metadata = 0;
	
		if(ptr->fourk_num == 1)
		{
			kcmd_para->prp2 = 0;
		}
		else
		{
			if(ptr->fourk_num == 2) /* prp2 as prp && PPA List */
			{
				kcmd_para->prp2 = cpu_to_le64(ptr->data_dma_addr + page_size);
			}
			else/* prp2 as prplist */
			{
				result = lba_set_prplist(dev, ptr);
				if(result){
					goto free_meta;
				}
				kcmd_para->prp2 = ptr->prp_dma;
			}
		}
	
		if(((kcmd_para->opcode == nvme_cmd_write)||(kcmd_para->opcode == nvme_cmd_compare)) && (ptr->dram_flag == 0)){// write lba from host data
	
			print_dbg("copy from user");
			result = lba_data_copy_from_user(ptr);
            crt_pi(dev, kcmd_para, ptr);
			if(result){
				goto free_prp_pool;
			}
		}
	
	
		print_dbg("send cmd");
	


		result = pnvme_submit_cmd_sync(g_rsc.g_queue_rsc->queues[ptr->qid], (struct nvme_command *)kcmd_para, NULL, PNVME_IO_TIMEOUT);

	
		if((kcmd_para->opcode == nvme_cmd_read) && (ptr->dram_flag == 0)){// read lba to host
	
			print_dbg("copy to user");
			if (lba_data_copy_to_user(ptr) && !result)
			{
				result = -EFAULT;
				print_wrn("copy meta to user fail");
				goto free_prp_pool;
			}
		}
	
	free_prp_pool:
		if(ptr->fourk_num > 2) {
			lba_free_prplist(dev, ptr);
		}
	free_meta:
		if ((!(kcmd_para->flags & 0x1) && (ptr->dram_flag == 0))){
			lba_free_meta_dma(dev, ptr);
		}
	free_prp:
		if (!(kcmd_para->flags & 0x1) && (ptr->dram_flag == 0)){
			lba_free_data_dma(dev, ptr);
		}
	free_kmem:
		kfree(ptr);
	
		return result;

}


int pnvme_execute_lba_cmd(struct nvme_dev *dev, struct nvme_lba_command *kcmd_para)
{
		int result = 0;
		struct lba_handle_str *ptr = NULL;
		_u32 page_size = PNVME_PAGE_SIZE;
		print_dbg("page_size:0x%x",page_size);
	
		ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
		if (ptr == NULL){
			return -EFAULT;
		}
	
		ptr->nlb = kcmd_para->nlb + 1;
	
		/*get flag*/
		if((kcmd_para->opcode == nvme_cmd_write)||(kcmd_para->opcode == nvme_cmd_compare))
			ptr->wr_flag = 1;
		else if(kcmd_para->opcode == nvme_cmd_read)
			ptr->wr_flag = 0;
		else{
			print_wrn("invaild opcode(ether not read or write");
			return -EINVAL;
		}
	
		ptr->qid = kcmd_para->rsv_qid;
		memset(&(kcmd_para->rsv_qid), 0, sizeof(kcmd_para->rsv_qid));
		ptr->dram_flag = kcmd_para->rsv_dram;
		memset(&(kcmd_para->rsv_dram), 0, sizeof(kcmd_para->rsv_dram));
		print_dbg("nsid 0x%x",kcmd_para->nsid);
	
		
		result = get_data_size(&(dev->ctrl), kcmd_para->nsid, &(ptr->data_size), &(ptr->meta_size));
        if(result < 0)
            return result;
        ptr->dif_flag = result;
		
		ptr->fourk_num = CALC_PAGE_NUM(ptr->nlb, ptr->data_size, 0);
		print_dbg("nprp: %d,ds:0x%x,ms:0x%x",ptr->fourk_num,ptr->data_size,ptr->meta_size);

		if(ptr->fourk_num > 1024){
			print_err("Now this ioctl do not support 4k_num > 1024");
			return -EFAULT;
		}
		//print_wrn("dram_flag:0x%x, nlb:0x%x, datasize:0x%x, metasize:0x%x, forknum:0x%x", ptr->dram_flag, ptr->nlb, ptr->data_size, ptr->meta_size, ptr->fourk_num);
	
		if (ptr->dram_flag == 0) { // wr/rd lba from/to host
			/*alloc data dma buffer */
			result = lba_alloc_data_dma(dev, ptr);
			if(result){
				goto free_kmem;
			}
			result = lba_alloc_meta_dma(dev, ptr);
			if(result){
				goto free_prp;
			}
			ptr->datafile = kcmd_para->prp1;
			ptr->metafile = kcmd_para->metadata;
		}
	
		kcmd_para->prp1 = ptr->data_dma_addr;
		if(ptr->meta_size)
			kcmd_para->metadata = ptr->meta_dma_addr;
		else
			kcmd_para->metadata = 0;
	
		if(ptr->fourk_num == 1)
		{
			kcmd_para->prp2 = 0;
		}
		else
		{
			if(ptr->fourk_num == 2) /* prp2 as prp && PPA List */
			{
				kcmd_para->prp2 = cpu_to_le64(ptr->data_dma_addr + page_size);
			}
			else/* prp2 as prplist */
			{
				result = lba_set_prplist(dev, ptr);
				if(result){
					goto free_meta;
				}
				kcmd_para->prp2 = ptr->prp_dma;
			}
		}
	
		if(((kcmd_para->opcode == nvme_cmd_write)||(kcmd_para->opcode == nvme_cmd_compare)) && (ptr->dram_flag == 0)){// write lba from host data
	
			print_dbg("copy from user");
			result = lba_data_copy_from_user(ptr);
			if(result){
				goto free_prp_pool;
			}
		}
	
	
		print_dbg("send cmd");
	


		result = pnvme_submit_cmd_sync(g_rsc.g_queue_rsc->queues[ptr->qid], (struct nvme_command *)kcmd_para, NULL, PNVME_IO_TIMEOUT);

	
		if((kcmd_para->opcode == nvme_cmd_read) && (ptr->dram_flag == 0)){// read lba to host
	
			print_dbg("copy to user");
			if (lba_data_copy_to_user(ptr) && !result)
			{
				result = -EFAULT;
				print_wrn("copy meta to user fail");
				goto free_prp_pool;
			}
            if(CHKPI_FAIL == chk_pi(dev, kcmd_para, ptr)){
                print_wrn("PI Check fail");
                result = 1;
            }
            
		}
	
	free_prp_pool:
		if(ptr->fourk_num > 2) {
			lba_free_prplist(dev, ptr);
		}
	free_meta:
		if ((!(kcmd_para->flags & 0x1) && (ptr->dram_flag == 0))){
			lba_free_meta_dma(dev, ptr);
		}
	free_prp:
		if (!(kcmd_para->flags & 0x1) && (ptr->dram_flag == 0)){
			lba_free_data_dma(dev, ptr);
		}
	free_kmem:
		kfree(ptr);
	
		return result;

}

void pnvme_perf_print(_u8 opcode, _u32 data_size)
{
    ktime_t delta, curtime;
    _u32 wr_bw, rd_bw;
    curtime = ktime_get();
    delta = ktime_sub(curtime, perf.oldtime);
    if (opcode == nvme_cmd_write)
        perf.wr_data += data_size;
    else
        perf.rd_data += data_size;
    if (ktime_to_ms(delta) > 1000)
    {
        perf.oldtime = curtime;
        wr_bw = perf.wr_data/1000/1000;
        rd_bw = perf.rd_data/1000/1000;
        print_wrn("Bandwidth:[WR: %d MB/s, RD: %d MB/s] compare_time: %d", wr_bw, rd_bw, com_cnt);
        perf.wr_data = 0;
        perf.rd_data = 0;
    }    
}

int data_compare_async(void *ctx)
{
    _u64 slba;
    _u64 exp,act;
    _u32 data_size;
    _u32 meta_size;
    _u16 nlb;
    int i,cnt,j;
    void *data_mem;
    dma_addr_t data_dma;
    _u32 key;
    _u64 data_pat;
    bool keep_order;
    
    struct lba_iodnode *iodnode = NULL;

    if (ctx == NULL) {
        print_err("ctx is null");
        return -EFAULT;
    }
    iodnode = (struct lba_iodnode *)ctx;
    data_size = iodnode->data_size;
    meta_size = iodnode->meta_size;
    slba = iodnode->slba;
    data_mem = iodnode->data_mem;
    data_dma = iodnode->data_dma;
    nlb = iodnode->nlb;
    keep_order = iodnode->compare_flag >> 1;
    if(!(iodnode->compare_flag&0x1)){
        //print_wrn("No need to compare data");
        for(j = 0;j < nlb; j++){
            key_operate(slba+j,&key,1,keep_order);
        }
        return 0;
    }


    cnt = 0;
    //print_wrn("data compare[data_size:%d,meta_size:%d]",data_size,meta_size);
    for(j = 0;j < nlb; j++){

        if(keep_order){
            key = *((_u32 *)(iodnode->key_pool)+j);
        }
        else{
            key_operate(slba+j,&key,0,keep_order);
            if ((key&(~KEY_MASK)) != 0x0)
                continue;
        }
        
        data_pat = get_data_pat(slba+j,key);
        com_cnt ++;
        for(i = 0;i < data_size/8; i++){
            exp = data_pat + i;
            act = *(((_u64 *)data_mem)+data_size/8*j+i);
            cnt += (exp^act)?1:0;
            
            if(act^exp){
                print_wrn("data compare fail[lba:0x%llx, idx:0d%d, exp:0x%llx, act:0x%llx,key:%x]",slba+j,i*8,exp,act,key);
                break;
            }
            //else{
            //    print_wrn("data compare pass[lba:0x%llx, idx:0d%d, exp:0x%llx, act:0x%llx,key:%x]",slba+j,i*8,exp,act,key);
            //}
        }
    }
    //com_cnt ++;
    //print_wrn("Data compare pass [lba: 0x%llx, nlb:0x%x, key: 0x%x, data:0x%llx]",slba, nlb, key, exp);
    if(cnt){
        print_err("data compare fail[lba:%llx,cnt:%x]",slba,cnt);
        async_test_fail = 1;
        //print_cmd_trace();
    }
    
    //if(com_cnt%50000 == 0){
    //    new_ts = current_kernel_time();
    //    start = (timespec_to_ns(&new_ts) - timespec_to_ns(&ts))/1000/1000;
    //    bw = (data_size*nlb*10000)/start*1000/1024/1024;
    //    print_wrn("Data compare pass at %llx times",com_cnt);
    //    ts = new_ts;
    //}
    //else
    //    print_wrn("data compare pass[lba:%llx,cnt:%x]",slba,cnt);
    return cnt;
}

void lba_ionode_prplist_free(void *ctx)
{
        struct lba_iodnode *iodnode = NULL;

        if (ctx == NULL) {
                print_err("ctx is null");
                return;
        }
        iodnode = (struct lba_iodnode *)ctx;

    if (iodnode->prppool_va) {
        dma_pool_free(g_rsc.prp_page_pool, iodnode->prppool_va, iodnode->prppool_dma);
    }
    if (iodnode->data_mem) {
        dma_pool_free(g_rsc.async_pool, iodnode->data_mem, iodnode->data_dma);
    }
    if (iodnode->key_pool) {
        kfree(iodnode->key_pool);
    }
    
    kfree(iodnode);
        return;
}


void lba_completion(struct nvme_dev *dev, void *ctx, struct nvme_completion *cqe)
{
        _u16 status, sq_id, sq_head, cmdid;
        _u32 result, dword1;
        struct pnvme_cmd_info *cmdinfo = NULL;

        result = le32_to_cpup(&cqe->result.u32);
        //dword1 = le32_to_cpup(&cqe->rsvd);
        status = le16_to_cpup(&cqe->status) >> 1;
        cmdid = le16_to_cpup(&cqe->command_id);
        sq_id = le16_to_cpup(&cqe->sq_id);
        sq_head = le16_to_cpup(&cqe->sq_head);
        //print_wrn("status: %x", status);

        //if (status == NVME_SC_ABORT_REQ) {
                //print_wrn("the command sq_id=%d cmdid=%d Was Cancelled by SW", sq_id, cmdid);
        //}
        cmdinfo = get_cmdinfo(g_rsc.g_queue_rsc->queues[sq_id]);
        data_compare_async(ctx);
        lba_ionode_prplist_free(ctx);

        return;
}


int pnvme_lba_sync(struct nvme_dev *dev, unsigned long cmd)
{
	struct nvme_lba_command *cmd_para = (struct nvme_lba_command *)cmd;
    struct nvme_lba_command kcmd_para;
    print_dbg(">");
    memset(&kcmd_para, 0 , sizeof(kcmd_para));
    if(copy_from_user(&kcmd_para, cmd_para, sizeof(kcmd_para))){
        return -EFAULT;
    }
    if (g_rsc.g_queue_rsc->queues[kcmd_para.rsv_qid] == NULL) {
        print_err("the specified queue does not created:%x",kcmd_para.rsv_qid);
        return -EINVAL;
    }
    return pnvme_execute_lba_cmd(dev, &kcmd_para);
}

int pnvme_pi_sync(struct nvme_dev *dev, unsigned long cmd)
{
	struct nvme_lba_command *cmd_para = (struct nvme_lba_command *)cmd;
    struct nvme_lba_command kcmd_para;
    print_dbg(">");
    memset(&kcmd_para, 0 , sizeof(kcmd_para));
    if(copy_from_user(&kcmd_para, cmd_para, sizeof(kcmd_para))){
        return -EFAULT;
    }
    if (g_rsc.g_queue_rsc->queues[kcmd_para.rsv_qid] == NULL) {
        print_err("the specified queue does not created:%x",kcmd_para.rsv_qid);
        return -EINVAL;
    }
    return pnvme_pi_cmd(dev, &kcmd_para);
}

int pnvme_lba_async(struct nvme_dev *dev, unsigned long cmd)
{
	struct nvme_lba_command *cmd_para = (struct nvme_lba_command *)cmd;
    struct nvme_lba_command kcmd_para;
    //print_dbg(">");
    memset(&kcmd_para, 0 , sizeof(kcmd_para));
    if(copy_from_user(&kcmd_para, cmd_para, sizeof(kcmd_para))){
        return -EFAULT;
    }
    if (g_rsc.g_queue_rsc->queues[kcmd_para.rsv_qid] == NULL) {
        print_err("the specified queue does not created:%x",kcmd_para.rsv_qid);
        return -EINVAL;
    }

    return pnvme_qat_async(dev, &kcmd_para);
}

int pnvme_atomic(struct nvme_dev *dev, unsigned long cmd)
{
	struct nvme_lba_command *cmd_para = (struct nvme_lba_command *)cmd;
    struct nvme_lba_command kcmd_para;
    //print_dbg(">");
    memset(&kcmd_para, 0 , sizeof(kcmd_para));
    if(copy_from_user(&kcmd_para, cmd_para, sizeof(kcmd_para))){
        return -EFAULT;
    }
    if (g_rsc.g_queue_rsc->queues[kcmd_para.rsv_qid] == NULL) {
        print_err("the specified queue does not created:%x",kcmd_para.rsv_qid);
        return -EINVAL;
    }

    return pnvme_qat_atomic(dev, &kcmd_para);
}

int pnvme_qat_async(struct nvme_dev *dev, struct nvme_lba_command *kcmd_para)
{
    int i;
    int cmdid = 0;
    int result = 0;
    _u16 index;
    _u16 nlb, qid, meta_size, dram_flag;
    _u64 datafile;
    _u64 metafile;
    _u32 data_size;
    _u32 sec_num_in_page;
    _u32 page_size;
    //u32 meta_size;
    //void *meta_mem;
    void *data_mem;
    //dma_addr_t meta_dma;
    dma_addr_t data_dma;
    _u32 key;
    bool keep_order = 0;
    bool do_compare = 1;
    struct lba_iodnode *iodnode = NULL;


    datafile = 0;
    metafile = 0;
    /*copy user parameter to kernel*/

    keep_order = kcmd_para->control;
    do_compare = !((kcmd_para->control & 0x2) >> 1);
    if(dev == NULL){
        return -ENODEV;
    }
    page_size = PNVME_PAGE_SIZE;
    if(page_size != 0x1000){
        print_err("Not support MPS in LBA asnyc now!");
        return -EFAULT;
    }
    /* comment out this code to improve efficiency, but this will need tester to make sure not change LBA format after insmod pnvme
    result = get_data_size(&(dev->ctrl), kcmd_para->nsid, &data_size, &meta_size);
    if (result < 0){
        return -ENODEV;
    }
    */
    data_size = g_rsc.data_size;
    meta_size = g_rsc.meta_size;
    sec_num_in_page = page_size/data_size;
    qid = kcmd_para->rsv_qid;
    kcmd_para->rsv_qid = 0;

    dram_flag = kcmd_para->rsv_dram;  /* val 1 note wr/rd lba from/to ddr, val 0 note wr/rd lba from/to host */
    kcmd_para->rsv_dram = 0;
    nlb = (kcmd_para->nlb + sec_num_in_page)/sec_num_in_page;


    datafile = kcmd_para->prp1;
    metafile = kcmd_para->metadata;
    //data_mem = dma_alloc_coherent(local_dmadev, nlb*PAGE_SIZE, &data_dma, GFP_KERNEL);
    data_mem = dma_pool_alloc(g_rsc.async_pool, GFP_KERNEL, &data_dma);
    if (data_mem == NULL) {
        print_err("data_mem alloc fail");
        return -ENOMEM;
    }
    iodnode = kzalloc(sizeof(struct lba_iodnode), GFP_KERNEL);
    //print_wrn("async pool alloc done! addr:%llx, dma:%llx",data_mem,data_dma);
    if (iodnode == NULL) {
        print_err("iodnode alloc fail");
        return -ENOMEM;
    }
    if(kcmd_para->opcode == nvme_cmd_write){
        //if (set_seq_data((data_mem),kcmd_para.slba,PAGE_SIZE*nlb, data_size)){
        if (set_async_data((data_mem),kcmd_para->slba,kcmd_para->nlb+1, data_size,keep_order)){
            result = -EFAULT;
            goto free_prp_pool;
        }
        iodnode->compare_flag = 0|(keep_order << 1);
    }
    else{
        iodnode->key_pool = kmalloc(4096,GFP_ATOMIC);
        for(i = 0;i < kcmd_para->nlb+1; i++){
            key_operate(kcmd_para->slba+i,&key,2,keep_order);
            *((_u32 *)(iodnode->key_pool)+i) = key;
        }
        iodnode->compare_flag = do_compare |(keep_order << 1);
    }

    /*write lba from host data*/
    //print_wrn("src data[%llx]",*((u64 *)data_mem[lba_data_index]));

    iodnode->nlb = kcmd_para->nlb+1;
    iodnode->data_mem = data_mem;
    iodnode->data_dma = data_dma;
    iodnode->data_size = data_size;
    iodnode->meta_size = meta_size;
    iodnode->slba = kcmd_para->slba;
    pnvme_perf_print(kcmd_para->opcode, (kcmd_para->nlb+1)*(data_size+meta_size));
    /*alloc cmdid*/
    cmdid = alloc_cmdid_killable(g_rsc.g_queue_rsc->queues[qid], (void *)iodnode, lba_completion, PNVME_IO_TIMEOUT);
    if (cmdid < 0){
        result = -EINTR;
        goto free_iodnode;
    }
    kcmd_para->command_id = cmdid;

    //print_wrn("prp1: add:%llx, dma:%llx",data_mem[lba_data_index],data_dma[lba_data_index]);
    /*set prp2*/

    /*set prp1 and metadata*/
    kcmd_para->prp1     = data_dma;
    //print_dbg("prp1 addr:0x%llx",kcmd_para->prp1);

    kcmd_para->metadata = 0;
    if(nlb == 1)
    {
        kcmd_para->prp2 = 0;
    }
    else
    {
        if(nlb == 2) /* prp2 as prp && PPA List */
        {
            kcmd_para->prp2 = data_dma + page_size;//cpu_to_le64(data_dma_addr + PAGE_SIZE);
            //print_dbg("nlb=1, prp2 addr:0x%llx",kcmd_para->prp2);
            //print_wrn("prp2 addr: logic:%x, dma:%x",rddata_va[index][1*8],rddata_dma[index][1*8]);
        }
        else/* prp2 as prplist */
        {
            iodnode->prppool_va = dma_pool_alloc(g_rsc.prp_page_pool, GFP_KERNEL, &iodnode->prppool_dma);
            if(!iodnode->prppool_va){
                print_err("dma pool alloc fail");
                result = -ENOMEM;
                goto free_cmdid;
            }
            for(i = 0; i < (nlb - 1); i ++){
                *((_u64 *)iodnode->prppool_va + i) =  data_dma + ( 1 + i) * page_size;//data_dma_addr + (1 + i)*PAGE_SIZE;
                //print_dbg("prp2[%x]=0x%llx", i, *((u64 *)iodnode->prppool_va + i));
            }
            kcmd_para->prp2 = iodnode->prppool_dma;
            //print_dbg("nlb>1, prp2 addr:0x%llx",kcmd_para->prp2);
         }
    }

    /*send sq async*/
    //result = pnvme_submit_cmd_async(dev, qid, (struct nvme_ppa_command *)(kcmd_para));
    result = pnvme_submit_cmd(g_rsc.g_queue_rsc->queues[qid], (struct nvme_command *)kcmd_para, 1, QUEUE_NEED_LOCK);
    /*index increase*/

    if(async_test_fail){
        async_test_fail = 0;
        return 1;
    }
    return (result);

free_prp_pool:
    if(nlb >2)
        dma_pool_free(g_rsc.prp_page_pool, iodnode->prppool_va, iodnode->prppool_dma);
free_cmdid:
    pnvme_free_cmdid(g_rsc.g_queue_rsc->queues[qid], cmdid, NULL);
free_iodnode:
    kfree(iodnode);

    return result;
}

int atomic_check(void *ctx)
{
    _u64 slba;
    _u64 exp,act;
    _u32 data_size;
    _u32 meta_size;
    _u16 nlb;
    _u32 step;
    int cnt,j;
    void *data_mem;
    dma_addr_t data_dma;

    struct lba_iodnode *iodnode = NULL;

    if (ctx == NULL) {
        print_err("ctx is null");
        return -EFAULT;
    }
    iodnode = (struct lba_iodnode *)ctx;
    data_size = iodnode->data_size;
    meta_size = iodnode->meta_size;
    slba = iodnode->slba;
    data_mem = iodnode->data_mem;
    data_dma = iodnode->data_dma;
    nlb = iodnode->nlb;
    step = data_size/nlb;
    
    cnt = 0;
    if(!(iodnode->compare_flag&0x1)){
        return 0;
    }

    //print_wrn("data compare[data_size:%d,meta_size:%d]",data_size,meta_size);
    for(j = 0;j < nlb-1; j++){
        act = *(((_u64 *)data_mem) + data_size/8*j);
        exp = *(((_u64 *)data_mem) + data_size/8*(j+1));
        cnt += (exp^act)?1:0;
        //print_wrn("[lba:0x%llx, exp:0x%llx, act:0x%llx]",slba+j,exp,act);
        if(act^exp){
            print_wrn("data compare fail[LBA[0x%llx:0x%llx], LBA[0x%llx:0x%llx]",slba+j,exp,slba+j+1,act);
            break;
        }

    }
    com_cnt ++;
    if(cnt){
        print_err("data compare fail[lba:%llx,cnt:%x]",slba,cnt);
        async_test_fail = 1;
    }
    if(com_cnt%50000 == 0){
        print_wrn("Data compare pass at %llx times",com_cnt);
    }
    return cnt;
}

void qat_atomic_completion(struct nvme_dev *dev, void *ctx, struct nvme_completion *cqe)
{
        _u16 status, sq_id, sq_head, cmdid;
        _u32 result, dword1;
        struct pnvme_cmd_info *cmdinfo = NULL;

        result = le32_to_cpup(&cqe->result.u32);
        //dword1 = le32_to_cpup(&cqe->rsvd);
        status = le16_to_cpup(&cqe->status) >> 1;
        cmdid = le16_to_cpup(&cqe->command_id);
        sq_id = le16_to_cpup(&cqe->sq_id);
        sq_head = le16_to_cpup(&cqe->sq_head);

        cmdinfo = get_cmdinfo(g_rsc.g_queue_rsc->queues[sq_id]);
        atomic_check(ctx);
        lba_ionode_prplist_free(ctx);

        return;
}

int pnvme_qat_atomic(struct nvme_dev *dev, struct nvme_lba_command *kcmd_para)
{
    int i;
    int cmdid = 0;
    int result = 0;
    _u16 nlb, qid, meta_size, dram_flag;
    _u64 datafile;
    _u64 metafile;
    _u32 data_size;
    _u32 sec_num_in_page;
    _u32 page_size;
    //u32 meta_size;
    //void *meta_mem;
    void *data_mem;
    //dma_addr_t meta_dma;
    dma_addr_t data_dma;
    bool do_compare = 1;
    struct lba_iodnode *iodnode = NULL;


    datafile = 0;
    metafile = 0;
    /*copy user parameter to kernel*/
    if(dev == NULL){
        return -ENODEV;
    }
    page_size = PNVME_PAGE_SIZE;
    if(page_size != 0x1000){
        print_err("Not support MPS in LBA asnyc now!");
        return -EFAULT;
    }
    /* comment out this code to improve efficiency, but this will need tester to make sure not change LBA format after insmod pnvme
    //send identify to get data size, this will block async IO, and low down efficiency 
    result = get_data_size(&(dev->ctrl), kcmd_para->nsid, &data_size, &meta_size);
    if (result < 0){
        return -ENODEV;
    }
    */
    data_size = g_rsc.data_size;
    meta_size = g_rsc.meta_size;
    sec_num_in_page = page_size/data_size;
    qid = kcmd_para->rsv_qid;
    kcmd_para->rsv_qid = 0;

    dram_flag = kcmd_para->rsv_dram;  /* val 1 note wr/rd lba from/to ddr, val 0 note wr/rd lba from/to host */
    kcmd_para->rsv_dram = 0;
    nlb = (kcmd_para->nlb + sec_num_in_page)/sec_num_in_page;

    datafile = kcmd_para->prp1;
    metafile = kcmd_para->metadata;
    //data_mem = dma_alloc_coherent(local_dmadev, nlb*PAGE_SIZE, &data_dma, GFP_KERNEL);
    data_mem = dma_pool_alloc(g_rsc.async_pool, GFP_KERNEL, &data_dma);
    if (data_mem == NULL) {
        print_err("data_mem alloc fail");
        return -ENOMEM;
    }
    iodnode = kzalloc(sizeof(struct lba_iodnode), GFP_KERNEL);
    //print_wrn("async pool alloc done! addr:%llx, dma:%llx",data_mem,data_dma);
    if (iodnode == NULL) {
        print_err("iodnode alloc fail");
        return -ENOMEM;
    }
    if(kcmd_para->opcode == nvme_cmd_write){
        memset(data_mem, kcmd_para->slba+kcmd_para->control, data_size*(kcmd_para->nlb+1));
        iodnode->compare_flag = 0;
    }
    else{
        iodnode->compare_flag = do_compare;
    }

    /*write lba from host data*/
    //print_wrn("src data[%llx]",*((u64 *)data_mem[lba_data_index]));

    iodnode->nlb = kcmd_para->nlb+1;
    iodnode->data_mem = data_mem;
    iodnode->data_dma = data_dma;
    iodnode->data_size = data_size;
    iodnode->meta_size = meta_size;
    iodnode->slba = kcmd_para->slba;
    /*alloc cmdid*/
    cmdid = alloc_cmdid_killable(g_rsc.g_queue_rsc->queues[qid], (void *)iodnode, qat_atomic_completion, PNVME_IO_TIMEOUT);
    if (cmdid < 0){
        result = -EINTR;
        goto free_iodnode;
    }
    kcmd_para->command_id = cmdid;

    //print_wrn("prp1: add:%llx, dma:%llx",data_mem[lba_data_index],data_dma[lba_data_index]);
    /*set prp2*/

    /*set prp1 and metadata*/
    kcmd_para->prp1     = data_dma;
    //print_dbg("prp1 addr:0x%llx",kcmd_para->prp1);

    kcmd_para->metadata = 0;
    if(nlb == 1)
    {
        kcmd_para->prp2 = 0;
    }
    else
    {
        if(nlb == 2) /* prp2 as prp && PPA List */
        {
            kcmd_para->prp2 = data_dma + page_size;//cpu_to_le64(data_dma_addr + PAGE_SIZE);
            //print_dbg("nlb=1, prp2 addr:0x%llx",kcmd_para->prp2);
            //print_wrn("prp2 addr: logic:%x, dma:%x",rddata_va[index][1*8],rddata_dma[index][1*8]);
        }
        else/* prp2 as prplist */
        {
            iodnode->prppool_va = dma_pool_alloc(g_rsc.prp_page_pool, GFP_KERNEL, &iodnode->prppool_dma);
            if(!iodnode->prppool_va){
                print_err("dma pool alloc fail");
                result = -ENOMEM;
                goto free_cmdid;
            }
            for(i = 0; i < (nlb - 1); i ++){
                *((_u64 *)iodnode->prppool_va + i) =  data_dma + ( 1 + i) * page_size;//data_dma_addr + (1 + i)*PAGE_SIZE;
                //print_dbg("prp2[%x]=0x%llx", i, *((u64 *)iodnode->prppool_va + i));
            }
            kcmd_para->prp2 = iodnode->prppool_dma;
            //print_dbg("nlb>1, prp2 addr:0x%llx",kcmd_para->prp2);
         }
    }

    /*send sq async*/
    result = pnvme_submit_cmd(g_rsc.g_queue_rsc->queues[qid], (struct nvme_command *)kcmd_para, 1, QUEUE_NEED_LOCK);

    if(async_test_fail){
        async_test_fail = 0;
        return 1;
    }
    return (result);

free_cmdid:
        pnvme_free_cmdid(g_rsc.g_queue_rsc->queues[qid], cmdid, NULL);
free_iodnode:
        kfree(iodnode);

    return result;
}

int pnvme_print_sqes(struct nvme_dev *dev, unsigned long qid)
{
	int i;
	unsigned int *cmd;
	struct nvme_queue *queue;
	struct nvme_common_command *sq_cmds;

	if (qid >= dev->max_qid) {
		print_dbg("queue id invalid: %d >= %d", qid, dev->max_qid);
		return 1;
	}

	queue = &(dev->queues[qid]);
	print_dbg("queue id: %d, depth: %d, head: %d, tail: %d", queue->qid, queue->q_depth, queue->sq_head, queue->sq_tail);
	
	sq_cmds = (struct nvme_common_command *)queue->sq_cmds;
	print_dbg("NO.   DW0      DW1      DW2      DW3      DW4      DW5      DW6      DW7      DW8      DW9      DW10     DW11     DW12     DW13     DW14      DW15");
	for (i=0; i<queue->q_depth; i++)
	{
		cmd = (unsigned int *)&(sq_cmds[i]);
		print_dbg("%.4x: %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x", 
			i, cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], cmd[5], cmd[6], cmd[7], cmd[8], cmd[9], cmd[10], cmd[11], cmd[12], cmd[13], cmd[14], cmd[15]);
	}

    return 0;
}


int pnvme_print_cqes(struct nvme_dev *dev, unsigned long qid)
{
	int i;
	struct nvme_queue *queue;
	struct nvme_completion *cqes;
	struct nvme_completion cqe;

	if (qid >= dev->max_qid) {
		print_dbg("queue id invalid: %d >= %d", qid, dev->max_qid);
		return 1;
	}

	queue = &(dev->queues[qid]);
	print_dbg("queue id: %d, depth: %d, head: %d, tail: %d", queue->qid, queue->q_depth, queue->sq_head, queue->sq_tail);

	cqes = (struct nvme_completion *)queue->cqes;
	print_dbg("NO.   CSPEC    DW1      SQHD SQID CID  P STATUS");
	for (i=0; i<queue->q_depth; i++)
	{
		cqe = cqes[i];
		print_dbg("%.8x: %.8llx %.4x %.4x %.4x %.1x %.4x", 
			i, cqe.result.u64, cqe.sq_head, cqe.sq_id, cqe.command_id, cqe.status & 0x1, cqe.status >> 1);
	}

    return 0;
}

int pnvme_debug_cmd(struct nvme_dev *dev, unsigned long cmd)
{
	struct pnvme_debug *cmd_para = (struct pnvme_debug *)cmd;
    struct pnvme_debug kcmd_para;
    print_wrn(">size:%d", TRACE_LENGTH*sizeof(struct debug_info));
    memset(&kcmd_para, 0 , sizeof(kcmd_para));
    if(copy_from_user(&kcmd_para, cmd_para, sizeof(kcmd_para))){
        print_wrn("1");
        return -EFAULT;
    }
    print_wrn("opcode: %d, data: %llx", kcmd_para.opcode, kcmd_para.data);
    if(kcmd_para.opcode == pnvme_async_trace){
        if(copy_to_user((void *)kcmd_para.data, (void *)debug_trace, TRACE_LENGTH*sizeof(struct debug_info))){
            print_wrn("2");
            return -EFAULT;
        }        
    }
    return 0;
}

int pnvme_qat_sgl(struct nvme_dev *dev, struct nvme_sgl_lba_command *kcmd_para)
{
    int result = 0;
    int dif_flg = 0;
    _u16 fourk_num = 0;
    struct sgl_full_desp *sgl_list = NULL;
    struct device *dmadev = dev->dev;
    _u8 wr_flag;/*1:write 0:read*/
    _u8 sgl_flag;
    _u8 qid;
    _u32 data_size = 0;
    _u16 meta_size= 0;

    _u16 nlb = kcmd_para->nlb + 1;
    void *mem_meta = NULL;
    void *mem_data = NULL;
    _u64 datafile = 0;
    _u64 metafile = 0;
    dma_addr_t meta_dma_addr;
    dma_addr_t data_dma_addr;
    dma_addr_t sgl_dma_addr;
    _u32 sgl_index = 0;
    _u32 data_bucket_len = 0;
    _u32 meta_bucket_len = 0;
    _u32 total_meta_len = 0;
    _u32 total_data_len = 0;

    dif_flg = get_data_size(&dev->ctrl, kcmd_para->nsid, &data_size, &meta_size);
    if (dif_flg < 0){
        print_wrn("Invalid data size, set default:%d", data_size);
        //return -ENODEV;
    }
    //[Edison] check the data direction
    if((kcmd_para->opcode == nvme_cmd_write) || (kcmd_para->opcode == nvme_cmd_compare)){
        wr_flag = 1;
    }
    else if(kcmd_para->opcode == nvme_cmd_read){
        wr_flag = 0;
    }
    else
    {
        print_wrn("invaild opcode(ether not read or write");
        return -EINVAL;
    }

    if (kcmd_para->sgl_data_desp_num < 1)
    {
        print_err("invalid segment numbers : sgl_data_desp_num %lld sgl_meta_desp_num %lld", kcmd_para->sgl_data_desp_num, kcmd_para->sgl_meta_desp_num);
        return -EINVAL;
    }

    kcmd_para->sgl_data_offset = kcmd_para->sgl_data_offset % PNVME_PAGE_SIZE;
    kcmd_para->sgl_meta_offset = kcmd_para->sgl_meta_offset % PNVME_PAGE_SIZE;
    qid = kcmd_para->rsv_qid;
    kcmd_para->rsv_qid = 0;
    
    //[Edison] check 4k num
    if(dif_flg == 0){
        total_data_len = (nlb * data_size) + data_bucket_len;
        total_meta_len = (nlb * meta_size) + meta_bucket_len;
    }
    else{
        total_data_len = (nlb * (data_size + meta_size)) + data_bucket_len;
        total_meta_len = 0;
    }
    print_dbg("flags: %x", kcmd_para->flags);
    if((kcmd_para->flags != 0x80)&(kcmd_para->flags != 0x40))
    {
        print_err("Invalid SGL flag");
        result = -EINVAL;
        return result;
    }
    sgl_flag = kcmd_para->flags;

    fourk_num = ((total_data_len + kcmd_para->sgl_data_offset) % PNVME_PAGE_SIZE) ? \
        ((total_data_len + kcmd_para->sgl_data_offset) / PNVME_PAGE_SIZE + 1) : ((total_data_len + kcmd_para->sgl_data_offset) / PNVME_PAGE_SIZE);

    {
        mem_data = dma_alloc_coherent(dmadev, PNVME_PAGE_SIZE * fourk_num, &data_dma_addr, GFP_KERNEL);
        if(!mem_data)
        {
            print_wrn("alloc data dma fail");
            result = -ENOMEM;
            return result;
        }
        memset(mem_data, 0, PNVME_PAGE_SIZE * fourk_num);

        if(total_meta_len)
        {/*if meta=0,do not alloc dma*/
            mem_meta = dma_alloc_coherent(dmadev, (PNVME_PAGE_SIZE + total_meta_len), &meta_dma_addr, GFP_KERNEL);
            if(!mem_meta)
            {
                print_wrn("alloc meta dma fail");
                result = -ENOMEM;
                goto free_prp;
            }
            memset(mem_meta + kcmd_para->sgl_meta_offset, 0, (PNVME_PAGE_SIZE + total_meta_len));
        }
    }
 
    datafile = kcmd_para->prp1;
    metafile = kcmd_para->metadata;

    {
        //malloc sgl descriptor memory
        sgl_list = dma_alloc_coherent(dmadev, PNVME_PAGE_SIZE * 16, &sgl_dma_addr, GFP_KERNEL);
        if (!sgl_list)
        {
            print_err("alloc sgl dma memory fail");
            result = -ENOMEM;
            goto free_meta;
        }
    }

    //[Edison] fill in the sgl list according to the sgl desp from user space
    if (kcmd_para->sgl_data_desp_num == 1){
        //print_wrn("kcmd_para->sgl_data_desp_num == 1\n");
        kcmd_para->prp1 = data_dma_addr + kcmd_para->sgl_data_offset;
        //print_wrn("kcmd_para->sgl_data_addr = 0x%llx\n",data_dma_addr + kcmd_para->sgl_data_offset);
        kcmd_para->sgl.len = data_size * nlb;
        if (kcmd_para->sgl_data_meta_segs[sgl_index].desp.len != data_size * nlb
         || 0 != kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn)
            print_err("kcmd_para->sgl_data_meta_segs[%d].desp.len %d idn %d", sgl_index, kcmd_para->sgl_data_meta_segs[sgl_index].desp.len, kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn);
        kcmd_para->sgl.idn = 0;
        //print_wrn("kcmd_para->sgl_data_meta_segs[%d].desp.len %d kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn %d\n", sgl_index, kcmd_para->sgl_data_meta_segs[sgl_index].desp.len, kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn);
        sgl_index++;
    }
    else{
        _u32 rest_seg_num = 0;
        _u32 consumed_data_len = 0;
        _u32 ignored_data_len = 0;
        //the first segment descriptor is saved into prp1/prp2 in command
        //print_wrn("kcmd_para->sgl_data_desp_num >= 2\n");
        kcmd_para->prp1 = sgl_dma_addr;
        kcmd_para->sgl.len = kcmd_para->sgl_data_meta_segs[sgl_index].desp.len;
        //TODO error handling
        if (kcmd_para->sgl.len % sizeof(struct sgl_full_desp))
            print_err("invalid kcmd_para->sgl.len %d", kcmd_para->sgl.len);
        rest_seg_num = kcmd_para->sgl.len / sizeof(struct sgl_full_desp);
        kcmd_para->sgl.idn = kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn;
        //print_wrn("kcmd_para->sgl_data_meta_segs[%d].desp.len %d kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn %d\n", sgl_index, kcmd_para->sgl_data_meta_segs[sgl_index].desp.len, kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn);
        //print_wrn("kcmd_para->sgl_data_addr = 0x%llx\n",kcmd_para->prp1);

        sgl_index++;
        //fill the rest data segment descriptor.
        for (; sgl_index < kcmd_para->sgl_data_desp_num; sgl_index++)
        {
            //sgl_list[sgl_index - 1].addr = (1 == rest_seg_num) ? sgl_dma_addr + sgl_index * sizeof(sgl_full_desp) : (u64)data_dma_addr + consumed_data_len;
            sgl_list[sgl_index - 1].desp.len = kcmd_para->sgl_data_meta_segs[sgl_index].desp.len;
            sgl_list[sgl_index - 1].desp.idn = kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn;

            if (1 == rest_seg_num && sgl_index != kcmd_para->sgl_data_desp_num - 1)
            {
                sgl_list[sgl_index - 1].addr = sgl_dma_addr + sgl_index * sizeof(struct sgl_full_desp);
                //print_wrn("kcmd_para->sgl_data_addr = 0x%llx\n",sgl_list[sgl_index - 1].addr);
                rest_seg_num = sgl_list[sgl_index - 1].desp.len / sizeof(struct sgl_full_desp);
                if (sgl_list[sgl_index - 1].desp.len % sizeof(struct sgl_full_desp))
                    print_err("invalid sgl_list[%d].desp.len %d", sgl_index - 1, sgl_list[sgl_index - 1].desp.len);
            }
            else
            {
                sgl_list[sgl_index - 1].addr = (u64)data_dma_addr + consumed_data_len + kcmd_para->sgl_data_offset;
                consumed_data_len += sgl_list[sgl_index - 1].desp.len;
                if ((sgl_list[sgl_index - 1].desp.idn == 0x10) && (kcmd_para->opcode == nvme_cmd_read))
                {
                    ignored_data_len += sgl_list[sgl_index - 1].desp.len;
                }
                rest_seg_num--;
            }
            //print_wrn("kcmd_para->sgl_data_meta_segs[%d].desp.len %d kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn %d\n", sgl_index, kcmd_para->sgl_data_meta_segs[sgl_index].desp.len, kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn);
            //print_wrn("kcmd_para->sgl_data_addr = 0x%llx\n",sgl_list[sgl_index - 1].addr);
            //statistics
            //consumed_data_len += (1 == rest_seg_num) ? 0 : sgl_list[sgl_index - 1].desp.len;
            //rest_seg_num = (1 == rest_seg_num) ? sgl_list[sgl_index - 1].desp.len / sizeof(sgl_full_desp) : rest_seg_num - 1;
        }

        if (0 != rest_seg_num || (consumed_data_len + ignored_data_len) != total_data_len)
            print_err("invalid rest_seg_num %d consumed_data_len %d ignored_data_len %d total_data_len %d after data segment processing",
            rest_seg_num, consumed_data_len, ignored_data_len, total_data_len);
    }
    //print_wrn("kcmd_para->prp1 0x%llx kcmd_para->sgl.len %d kcmd_para->sgl.idn %d\n", kcmd_para->prp1, kcmd_para->sgl.len, kcmd_para->sgl.idn);
    //[Edison]fill the meta segment descriptor, from the user space
    if(total_meta_len){
        if(sgl_flag == 0x80){
            kcmd_para->metadata = sgl_dma_addr + (sgl_index - 1) * sizeof(struct sgl_full_desp);
            if (1 == kcmd_para->sgl_meta_desp_num)
            {
                sgl_list[sgl_index - 1].addr = meta_dma_addr + kcmd_para->sgl_meta_offset;
                sgl_list[sgl_index - 1].desp.len = kcmd_para->sgl_data_meta_segs[sgl_index].desp.len;
                if (kcmd_para->sgl_data_meta_segs[sgl_index].desp.len != meta_size * nlb
                 || 0 != kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn)
                    print_err("kcmd_para->sgl_data_meta_segs[%d].desp.len %d idn %d", sgl_index, kcmd_para->sgl_data_meta_segs[sgl_index].desp.len, kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn);
                sgl_list[sgl_index - 1].desp.idn = 0;
                //print_wrn("kcmd_para->sgl_data_meta_segs[%d].desp.len %d kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn %d\n", sgl_index, kcmd_para->sgl_data_meta_segs[sgl_index].desp.len, kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn);
            }
            else{
                _u32 rest_seg_num = 0;
                _u32 consumed_data_len = 0;
                _u32 ignored_data_len = 0;
                
                sgl_list[sgl_index - 1].addr = (u64)sgl_dma_addr + (sgl_index) * sizeof(struct sgl_full_desp);
                sgl_list[sgl_index - 1].desp.len = kcmd_para->sgl_data_meta_segs[sgl_index].desp.len;
                if (sgl_list[sgl_index - 1].desp.len % sizeof(struct sgl_full_desp))
                    print_err("invalid sgl_list[%d].desp.len %d", sgl_index - 1, sgl_list[sgl_index - 1].desp.len);
                rest_seg_num = sgl_list[sgl_index - 1].desp.len / sizeof(struct sgl_full_desp);
                sgl_list[sgl_index - 1].desp.idn = kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn;
                //print_wrn("kcmd_para->sgl_data_meta_segs[%d].desp.len %d kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn %d\n", sgl_index, kcmd_para->sgl_data_meta_segs[sgl_index].desp.len, kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn);
                sgl_index++;
                //fill the rest meta segment descriptor.
                for (; sgl_index < kcmd_para->sgl_data_desp_num + kcmd_para->sgl_meta_desp_num; sgl_index++)
                {
                    //sgl_list[sgl_index - 1].addr = (1 == rest_seg_num) ? sgl_dma_addr + sgl_index * sizeof(sgl_full_desp) : (u64)data_dma_addr + consumed_data_len;
                    sgl_list[sgl_index - 1].desp.len = kcmd_para->sgl_data_meta_segs[sgl_index].desp.len;
                    sgl_list[sgl_index - 1].desp.idn = kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn;

                    if (1 == rest_seg_num && sgl_index != kcmd_para->sgl_meta_desp_num + kcmd_para->sgl_data_desp_num - 1)
                    {
                        sgl_list[sgl_index - 1].addr = sgl_dma_addr + sgl_index * sizeof(struct sgl_full_desp);
                        rest_seg_num = sgl_list[sgl_index - 1].desp.len / sizeof(struct sgl_full_desp);
                        //TODO error handling
                        if (sgl_list[sgl_index - 1].desp.len % sizeof(struct sgl_full_desp))
                            print_err("invalid sgl_list[%d].desp.len %d", sgl_index - 1, sgl_list[sgl_index - 1].desp.len);
                    }
                    else
                    {
                        sgl_list[sgl_index - 1].addr = (u64)meta_dma_addr + consumed_data_len + kcmd_para->sgl_meta_offset;
                        consumed_data_len += sgl_list[sgl_index - 1].desp.len;
                        if ((sgl_list[sgl_index - 1].desp.idn == 0x10) && (kcmd_para->opcode == nvme_cmd_read))
                        {
                            ignored_data_len += sgl_list[sgl_index - 1].desp.len;
                        }
                        rest_seg_num--;
                    }
                    //print_wrn("kcmd_para->sgl_data_meta_segs[%d].desp.len %d kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn %d\n", sgl_index, kcmd_para->sgl_data_meta_segs[sgl_index].desp.len, kcmd_para->sgl_data_meta_segs[sgl_index].desp.idn);
                    //statistics
                    //consumed_data_len += (1 == rest_seg_num) ? 0 : sgl_list[sgl_index - 1].desp.len;
                    //rest_seg_num = (1 == rest_seg_num) ? sgl_list[sgl_index - 1].desp.len / sizeof(sgl_full_desp) : rest_seg_num - 1;
                }
                if (0 != rest_seg_num || (consumed_data_len + ignored_data_len) != total_meta_len)
                    print_err("invalid rest_seg_num %d consumed_data_len %d ignored_data_len %d total_mete_len %d after data segment processing",
                    rest_seg_num, consumed_data_len, ignored_data_len ,total_meta_len);
            }
        }
        else{
            kcmd_para->metadata = meta_dma_addr + kcmd_para->sgl_meta_offset;
        }

    }
    //print_wrn("kcmd_para->metadata 0x%llx meta_dma_addr = 0x%llx data_dma_addr = 0x%llx sgl_dma_addr = 0x%llx\n", kcmd_para->metadata, meta_dma_addr, data_dma_addr, sgl_dma_addr);
    //for (i = 0; i < sgl_index; i++)
    //    print_wrn("sgl_list[%d].addr 0x%llx len %d idn %d\n", i, sgl_list[i].addr, sgl_list[i].desp.len, sgl_list[i].desp.idn);

    //[Edison] copy user data to the data buffer, if write command
    if(((kcmd_para->opcode == nvme_cmd_write)
      ||(kcmd_para->opcode == nvme_cmd_compare))){// write lba from host data
        //print_wrn("wr nlb 0x%x, data_size:0x%x, bitbuck:0x%x, sgl_data_offset:0x%x ,total len:0x%x" ,nlb , data_size, data_bucket_len, kcmd_para->sgl_data_offset, total_data_len );
        if(copy_from_user(mem_data  + kcmd_para->sgl_data_offset ,(void *)datafile, total_data_len)){
            print_wrn("wrf nlb 0x%x, data_size:0x%x, bitbuck:0x%x, sgl_data_offset:0x%x ,total len:0x%x" ,nlb , data_size, data_bucket_len, kcmd_para->sgl_data_offset, total_data_len );
            print_wrn("copy data from user fail");
            result = -EFAULT;
            goto free_meta;
        }
        if(total_meta_len){
            if(copy_from_user(mem_meta  + kcmd_para->sgl_meta_offset,(void *)metafile, total_meta_len)){
                print_wrn("copy meta from user fail");
                result = -EFAULT;
                goto free_meta;
            }
        }
    }


    //result = nexus_submit_ppa_cmd_sync(dev, 1, (struct nvme_ppa_command *)kcmd_para);
    result = pnvme_submit_cmd_sync(g_rsc.g_queue_rsc->queues[qid], (struct nvme_command *)kcmd_para, NULL, PNVME_IO_TIMEOUT);
    if(result)
        print_wrn("submit cmd fail");
    //[Edison] copy device data back to user data buffer, if read coomand
    if((kcmd_para->opcode == nvme_cmd_read)){
        //print_wrn("rd nlb 0x%x, data_size:0x%x, bitbuck:0x%x, sgl_data_offset:0x%x ,total len:0x%x" ,nlb , data_size, data_bucket_len, kcmd_para->sgl_data_offset, total_data_len );

        if (copy_to_user((void*)datafile, mem_data  + kcmd_para->sgl_data_offset, total_data_len) && !result){
            print_wrn("rdf nlb 0x%x, data_size:0x%x, bitbuck:0x%x, sgl_data_offset:0x%x ,total len:0x%x" ,nlb , data_size, data_bucket_len, kcmd_para->sgl_data_offset, total_data_len );
            print_wrn("copy data to user fail");
            result = -EFAULT;
            goto free_sgl;
        }
        if(total_meta_len){
            if (copy_to_user((void*)metafile, mem_meta  + kcmd_para->sgl_meta_offset, total_meta_len) && !result){
                print_wrn("copy meta to user fail");
                result = -EFAULT;
                goto free_sgl;
            }
        }
    }
    print_dbg("<");

free_sgl:
    dma_free_coherent(dmadev, PNVME_PAGE_SIZE * 16, sgl_list, sgl_dma_addr);
free_meta:
    if(total_meta_len){
       dma_free_coherent(dmadev, PNVME_PAGE_SIZE + total_meta_len, mem_meta, meta_dma_addr);
    }
free_prp:
    dma_free_coherent(dmadev, PNVME_PAGE_SIZE * fourk_num, mem_data, data_dma_addr);
    return result;
}


int pnvme_sgl_cmd(struct nvme_dev *dev, unsigned long cmd)
{
	struct nvme_sgl_lba_command *cmd_para = (struct nvme_sgl_lba_command *)cmd;
    struct nvme_sgl_lba_command *tcmd_para = NULL;
    struct nvme_sgl_lba_command *kcmd_para = NULL;
    int ret;
    print_dbg(">");
    tcmd_para = kmalloc(sizeof(*tcmd_para), GFP_KERNEL);
    if (NULL == tcmd_para)
        return -EFAULT;
    memset(tcmd_para, 0 , sizeof(*tcmd_para));
    
    if(copy_from_user(tcmd_para, cmd_para, sizeof(*tcmd_para)))
    {
        kfree(tcmd_para);
        return -EFAULT;
    }
    print_dbg("data sgl address: %llx", tcmd_para->sgl_data_desps);
    if (g_rsc.g_queue_rsc->queues[tcmd_para->rsv_qid] == NULL) {
        print_err("the specified queue does not created:%x",tcmd_para->rsv_qid);
        return -EINVAL;
    }

    kcmd_para = kmalloc(sizeof(*kcmd_para) + ((tcmd_para->sgl_data_desp_num + tcmd_para->sgl_meta_desp_num) * sizeof(struct
        sgl_full_desp)), GFP_KERNEL);
    if (NULL == kcmd_para)
        return -EFAULT;
    //print_dbg(">");
    memset(kcmd_para, 0 , sizeof(*kcmd_para));
    if(copy_from_user(kcmd_para, cmd_para, sizeof(*kcmd_para))){
        kfree(kcmd_para);
        print_dbg("copy parameter fail");
        return -EFAULT;
    }
    if(0 == kcmd_para->sgl_data_desp_num || copy_from_user(kcmd_para + 1, (struct sgl_full_desp*)kcmd_para->sgl_data_desps, sizeof(struct sgl_full_desp) * (kcmd_para->sgl_data_desp_num)))
    {
        kfree(kcmd_para);
        print_dbg("copy data SGL fail");
        return -EFAULT;
    }
    if(kcmd_para->sgl_meta_desp_num != 0){
        if(copy_from_user((struct sgl_full_desp*)(kcmd_para + 1) + kcmd_para->sgl_data_desp_num, (struct sgl_full_desp*)kcmd_para->sgl_meta_desps, sizeof(struct sgl_full_desp) * (kcmd_para->sgl_meta_desp_num)))
        {
            kfree(kcmd_para);
            print_dbg("copy meta SGL fail");
            return -EFAULT;
        }
    }

    ret = pnvme_qat_sgl(dev, kcmd_para);
    kfree(tcmd_para);
    kfree(kcmd_para);
    return ret;
}

int pnvme_crt_cq(struct nvme_dev *dev, unsigned long cmd)
{
	struct nvme_passthru_cmd *cmd_para = (struct nvme_passthru_cmd *)cmd;
    struct nvme_passthru_cmd kcmd_para;
    struct nvme_create_cq q_cmd;
    print_dbg(">");
    memset(&kcmd_para, 0 , sizeof(kcmd_para));
    if(copy_from_user(&kcmd_para, cmd_para, sizeof(kcmd_para))){
        return -EFAULT;
    }
    
    memcpy(&q_cmd, &kcmd_para, sizeof(struct nvme_create_cq));
    print_dbg("pnvme_crt_cq: qid:%d, qsize:%d", q_cmd.cqid, q_cmd.qsize);
    if(q_cmd.cqid < dev->max_qid){
        print_wrn("CQID[%d] should be in [%d, %d]", q_cmd.cqid, dev->max_qid, NVME_MAX_QUEUE);
        return -EFAULT;
    }
    
    //return 0;
    return pnvme_create_cq_sync(dev, q_cmd.cqid, q_cmd.cqid, q_cmd.qsize, ONHOST);
}

int pnvme_crt_sq(struct nvme_dev *dev, unsigned long cmd)
{
	struct nvme_passthru_cmd *cmd_para = (struct nvme_passthru_cmd *)cmd;
    struct nvme_passthru_cmd kcmd_para;
    struct nvme_create_sq q_cmd;
    print_dbg(">");
    memset(&kcmd_para, 0 , sizeof(kcmd_para));
    if(copy_from_user(&kcmd_para, cmd_para, sizeof(kcmd_para))){
        return -EFAULT;
    }
    
    memcpy(&q_cmd, &kcmd_para, sizeof(struct nvme_create_sq));
    print_dbg("pnvme_crt_sq: qid:%d, qsize:%d", q_cmd.sqid, q_cmd.qsize);
    if(q_cmd.cqid < dev->max_qid){
        print_wrn("CQID[%d] should be in [%d, %d]", q_cmd.sqid, dev->max_qid, NVME_MAX_QUEUE);
        return -EFAULT;
    }
    
    //return 0;
    return pnvme_create_sq_sync(dev, q_cmd.sqid, q_cmd.cqid, q_cmd.sq_flags,q_cmd.qsize, ONHOST);
}

int pnvme_del_cq(struct nvme_dev *dev, unsigned long cmd)
{
	struct nvme_passthru_cmd *cmd_para = (struct nvme_passthru_cmd *)cmd;
    struct nvme_passthru_cmd kcmd_para;
    struct nvme_delete_queue q_cmd;
    print_dbg(">");
    memset(&kcmd_para, 0 , sizeof(kcmd_para));
    if(copy_from_user(&kcmd_para, cmd_para, sizeof(kcmd_para))){
        return -EFAULT;
    }
    
    memcpy(&q_cmd, &kcmd_para, sizeof(struct nvme_delete_queue));
    print_dbg("pnvme_del_cq: qid:%d", q_cmd.qid);
    if(q_cmd.qid < dev->max_qid){
        print_wrn("CQID[%d] should be in bigger than[%d]", q_cmd.qid, dev->max_qid);
        return -EFAULT;
    }
   
    //return 0;
    return pnvme_delete_cq_sync(dev, q_cmd.qid);
}

int pnvme_del_sq(struct nvme_dev *dev, unsigned long cmd)
{
	struct nvme_passthru_cmd *cmd_para = (struct nvme_passthru_cmd *)cmd;
    struct nvme_passthru_cmd kcmd_para;
    struct nvme_delete_queue q_cmd;
    print_dbg(">");
    memset(&kcmd_para, 0 , sizeof(kcmd_para));
    if(copy_from_user(&kcmd_para, cmd_para, sizeof(kcmd_para))){
        return -EFAULT;
    }
    
    memcpy(&q_cmd, &kcmd_para, sizeof(struct nvme_delete_queue));
    print_dbg("pnvme_del_cq: qid:%d", q_cmd.qid);
    if(q_cmd.qid < dev->max_qid){
        print_wrn("CQID[%d] should be in bigger than[%d]", q_cmd.qid, dev->max_qid);
        return -EFAULT;
    }
   
    //return 0;
    return pnvme_delete_sq_sync(dev, q_cmd.qid);
}

