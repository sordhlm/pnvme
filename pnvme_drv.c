/********************************************************************
* FILE NAME: ktest_drv.c
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
#include "pnvme_if.h"
#include "pnvme_drv.h"
#include "pnvme_lba.h"
#include "pnvme_cmd.h"
#include "pnvme_proc.h"



int q_depth = NVME_Q_DEPTH;
module_param(q_depth, int, 0444);
MODULE_PARM_DESC(q_depth, "IO queue depth 2..65535, default is 1024");
_u8 debug_level = PRINT_DBG;
EXPORT_SYMBOL(debug_level);
bool db_swith = 0;
module_param(db_swith, bool, S_IRUGO);

//unsigned char admin_timeout = 60;
//module_param(admin_timeout, byte, 0644);
//MODULE_PARM_DESC(admin_timeout, "timeout in seconds for admin commands");

/* global variable */
volatile _u64 g_total_bytes = 0; /* total data in bytes for each test cases. */
volatile _u32 g_tc_total = 0; /* this is stop condition for each test cases. */
volatile _u32 g_tc_count = 0; /* this is stop condition for each test cases. */
volatile s64 submit_cmd_cnt = 0;
volatile s64 completion_cmd_cnt = 0;
volatile s64 g_start = 0; /* this is the start timestamp for a testcase */
s64 g_latency = 0; /* accumulated latency for all commands */
_u32 g_latency_max = 0, g_latency_min = -1; 
_u32 g_xor_count = 0; /* this is stop condition for each test cases. */
volatile _u64 gdata_index = 0;
volatile _u64 gmeta_index = 0;
static struct tc_dev *tdev;
//struct pnvme_queue_resource *g_queue_rsc;
//static struct file *file;
struct pnvme_global_resource g_rsc;
struct data_key *lba_data_key = NULL;

static inline struct nvme_dev *to_nvme_dev(struct nvme_ctrl *ctrl)
{
	return container_of(ctrl, struct nvme_dev, ctrl);
}

struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file *file) 
{
    filp_close(file, NULL);
}

int cmdid_bit_set(int bit, struct pnvme_queue *nvmeq)
{
    unsigned long data;
    unsigned long *pdata = nvmeq->cmdid_data + bit/ULONG_BIT;
    unsigned long mask = 1ul << bit%ULONG_BIT;
    unsigned long flags = 0;

    spin_lock_irqsave(&nvmeq->bit_lock, flags);
    data = *pdata;
    *pdata = data | mask;
    spin_unlock_irqrestore(&nvmeq->bit_lock, flags);
    return (data & mask) ? 1 : 0;
}

int cmdid_bit_set_no_lock(int bit, struct pnvme_queue *nvmeq)
{
    unsigned long data;
    unsigned long *pdata = nvmeq->cmdid_data + bit/ULONG_BIT;
    unsigned long mask = 1ul << bit%ULONG_BIT;
    //unsigned long flags = 0;

    //spin_lock_irqsave(&nvmeq->bit_lock, flags);
    data = *pdata;
    *pdata = data | mask;
    //spin_unlock_irqrestore(&nvmeq->bit_lock, flags);
    return (data & mask) ? 1 : 0;
}
/***************************************************************************
*
*FUNCTION DESCRIPTION: get the callback completion function and it's paramter
*                      when command not return in the limitted time
*
*FUNCTION NAME: cancel_cmdid()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: The queue that will be used for this command
*             cmdid: The command id that not return in the limitted time
*             handler: The function to call on completion
*       OUTPUT:
*       RETURN:
*             ctx, A pointer that will be passed to the completion handler
*
***************************************************************************/
void *cancel_cmdid(struct pnvme_queue *nvmeq, u16 cmdid,
                        nvme_completion_fn *fn)
{
    void *ctx;
    struct pnvme_cmd_info *info = pnvme_get_cmd_info(nvmeq);

    if (fn) {
        *fn = info[cmdid].fn;
    }
    ctx = info[cmdid].ctx;
    info[cmdid].fn = special_completion;
    info[cmdid].ctx = CMD_CTX_CANCELLED;
    return ctx;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: allocate a cmdid for this command when cmdid is
*                      available, and return immediately
*
*FUNCTION NAME: alloc_cmdid()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: The queue that will be used for this command
*             ctx: A pointer that will be passed to the handler
*             handler: The function to call on completion
*             timeout: The max time to wait allocation complete
*       OUTPUT:
*       RETURN:
*             cmdid, when alloc cmdid successful
*             -EBUSY, when alloc cmdid failed
*
***************************************************************************/
int alloc_cmdid(struct pnvme_queue *nvmeq, void *ctx,
            nvme_completion_fn handler, unsigned timeout)
{
    int depth = nvmeq->q_depth - 1;
    struct pnvme_cmd_info *info = pnvme_get_cmd_info(nvmeq);
    int cmdid;
    int no_zero = 0;
    unsigned long flags;
	//print_dbg("require bit_lock");
    spin_lock_irqsave(&nvmeq->bit_lock, flags);
    do {
        no_zero++;
        if(no_zero > nvmeq->q_depth) {
            spin_unlock_irqrestore(&nvmeq->bit_lock, flags);
            return -EBUSY;
        }
        cmdid = nvmeq->index;
        //print_dbg("dev qid[%d] cmid is:%d",nvmeq->qid,cmdid);
        nvmeq->index++;
        if(nvmeq->index >= depth)
            nvmeq->index = 0;
    } while (cmdid_bit_set_no_lock(cmdid, nvmeq));
    no_zero = 0;

    info[cmdid].fn = handler;
    info[cmdid].ctx = ctx;
    info[cmdid].org_ctx = ctx;
    info[cmdid].timeout = jiffies + timeout;
	//print_dbg("release bit_lock");
    spin_unlock_irqrestore(&nvmeq->bit_lock, flags);
    return cmdid;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: allocate a cmdid for this command when cmdid is
*                      available, or sleep until there is free cmdid when
*                      cmdid is fully used
*
*FUNCTION NAME: alloc_cmdid_killable()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: The queue that will be used for this command
*             ctx: A pointer that will be passed to the handler
*             handler: The function to call on completion
*             timeout: The max time to wait allocation complete
*       OUTPUT:
*       RETURN:
*             cmdid, when alloc cmdid successful
*             -EBUSY, when alloc cmdid failed
*
***************************************************************************/
int alloc_cmdid_killable(struct pnvme_queue *nvmeq, void *ctx,
                nvme_completion_fn handler, unsigned timeout)
{
    int cmdid;

    wait_event_killable(nvmeq->sq_full,
        (cmdid = alloc_cmdid(nvmeq, ctx, handler, timeout)) >= 0);

    return (cmdid < 0) ? -EINTR : cmdid;
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: free cmdid for recycle use
*
*FUNCTION NAME: free_cmdid()
*
*PARAMTERS:
*       INPUT:
*             nvmeq: The queue that will be used for this command
*             cmdid: The command id will be freed
*             handler: The function to call on completion
*       OUTPUT:
*       RETURN:
*             ctx, A pointer that will be passed to the completion handler
*             CMD_CTX_INVALID, when input parameter cmdid overlarge
*
***************************************************************************/
void *free_cmdid(struct pnvme_queue *nvmeq, u16 cmdid,
                        nvme_completion_fn *fn)
{
    void *ctx;
    struct pnvme_cmd_info *info = pnvme_get_cmd_info(nvmeq);

    if (cmdid >= nvmeq->q_depth) {
        print_dbg("[%s]>>\n", __FUNCTION__);
        *fn = special_completion;
        return CMD_CTX_INVALID;
    }
    if (fn)
        *fn = info[cmdid].fn;
    ctx = info[cmdid].ctx;
    info[cmdid].fn = special_completion;
    info[cmdid].ctx = CMD_CTX_COMPLETED;
    cmdid_bit_clear(cmdid, nvmeq);
    wake_up(&nvmeq->sq_full);
    return ctx;
}


void *pnvme_free_cmdid(struct pnvme_queue *nvmeq, u16 cmdid, nvme_completion_fn *fn)
{
    /*check paramter*/
    if(nvmeq==NULL){
        print_err("there is no this queue, please check it");
        return NULL;
    }

    return free_cmdid(nvmeq, cmdid, fn);
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: sync command completion callback routine
*
*FUNCTION NAME: sync_completion()
*
*PARAMTERS:
*       INPUT:
*             dev: pointer to the nexus_dev data structure
*             ctx: A pointer that will be passed to the handler
*             cqe: The function to call on completion
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
void sync_completion(struct nvme_dev *dev, void *ctx,
                        struct nvme_completion *cqe)
{
    struct sync_cmd_info *cmdinfo = ctx;
    u16 cmdid;
    u16 sq_id;
    u16 sq_head;
    cmdinfo->result = le32_to_cpup(&cqe->result.u32);
    cmdinfo->status = le16_to_cpup(&cqe->status) >> 1;
    cmdid = le16_to_cpup(&cqe->command_id);
    sq_id = le16_to_cpup(&cqe->sq_id);
    sq_head = le16_to_cpup(&cqe->sq_head);

    if(cmdinfo->status != 0){
        print_err("New CQE: sq_id=%d  cmdid=%d  result(dword0)=0x%x  status=0x%x  sq_head=%d",
                 sq_id, cmdid, cmdinfo->result, cmdinfo->status, sq_head);
    }
    wake_up_process(cmdinfo->task);
}

int pnvme_queue_init(struct nvme_ctrl *ctrl, int start_q, int q_num){
	int i;
	struct pci_dev *pdev = to_pci_dev(ctrl->dev);
	int sq_flags_medium = NVME_QUEUE_PHYS_CONTIG | NVME_SQ_PRIO_MEDIUM;
	print_dbg("msix: %x", pdev->msix_enabled);
	print_dbg("msi: %x", pdev->msi_enabled);
	if(pdev->msix_enabled != 1){
		print_wrn("pnvme only support msi-x");
		return -EPERM;
	}

    for (i = 0; i < q_num; i++) {
        print_dbg("create pnvme Q%d", start_q+i);
        pnvme_create_cq_sync(to_nvme_dev(ctrl), start_q + i, start_q + i, NVME_Q_DEPTH, ONHOST);
        pnvme_create_sq_sync(to_nvme_dev(ctrl), start_q + i, start_q + i, sq_flags_medium, NVME_Q_DEPTH, ONHOST);
    }
	
	return 0;
}

static int queue_resource_check(struct nvme_ctrl *ctrl){
	union nvme_result feature_resp;
	int res;
	int sq_num;
	int start_q;
	int i;
	struct nvme_dev *dev = to_nvme_dev(ctrl);

	res = pnvme_get_features(ctrl, NVME_FEAT_NUM_QUEUES, 0, 0,
								&feature_resp);
	if (res != NVME_SC_SUCCESS){
		print_wrn("Get Queue Number fail: %x", res);
		return -EPERM;
	}
	else{
		//for (i = 0; i < num_online_cpus(); i++) {
		//	print_dbg("Q%d vector is %d", i, dev->entry[i].vector);
		//}

		sq_num = (feature_resp.u32 & 0xFFFF);
		if (sq_num <= num_possible_cpus()+5){
			print_wrn("No More Queue resource for pnvme: sq_num:%x, cpu_number:%x", sq_num, num_possible_cpus());
			return -EPERM;
		}
		else{
			start_q = num_possible_cpus()+1;
			return pnvme_queue_init(ctrl, start_q, PNVME_QUEUE_NUM);
		}
	}

	return -EPERM;
}
/***************************************************************************
*
*FUNCTION DESCRIPTION: free the nvmeqs for a dev
*
*FUNCTION NAME: nexus_free_nvmeqs()
*
*PARAMTERS:
*       INPUT:
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
void pnvme_free_nvmeqs(struct nvme_dev *dev)
{
    int i;
    int start_q = num_possible_cpus()+1;
    print_dbg(">");
	for(i = start_q; i < start_q+PNVME_QUEUE_NUM; i++) {	
        struct pnvme_queue *nvmeq = g_rsc.g_queue_rsc->queues[i];
        struct pnvme_completion_queue *nvmecq = g_rsc.g_queue_rsc->cqueues[i];
        if (!nvmeq) {
            continue;  /* queue are not exist */
        }
        pnvme_free_nvmesq(g_rsc.g_queue_rsc->queues[i]);
        g_rsc.g_queue_rsc->queues[i] = NULL;

        if (!nvmecq) {
            continue;  /* queue are not exist */
        }
        nvmecq->valid = false;
        pnvme_free_nvmecq(g_rsc.g_queue_rsc->cqueues[i]);
        g_rsc.g_queue_rsc->cqueues[i] = NULL;
    }
}

/***************************************************************************
*
*FUNCTION DESCRIPTION: disable the nvmeq
*
*FUNCTION NAME: nexus_disable_nvmeq()
*
*PARAMTERS:
*       INPUT:
*       OUTPUT:
*       RETURN:
*
***************************************************************************/
void pnvme_disable_nvmeq(struct nvme_dev *dev, int qid)
{
    struct pnvme_queue *nvmeq = g_rsc.g_queue_rsc->queues[qid];
    struct pnvme_completion_queue *nvmecq = nvmeq->nvmecq;
	struct device *dmadev = dev->dev;
	print_dbg("disable nvme queue: %d", qid);
    print_not("> qid%x",qid);
	
	print_dbg("require queue lock");
    spin_lock_irq(&nvmeq->q_lock);
    if (nvmeq->q_suspended) {
		print_dbg("release queue lock");
        spin_unlock_irq(&nvmeq->q_lock);
        return;
    }
    nvmeq->q_suspended = 1;
	print_dbg("release queue lock");
    spin_unlock_irq(&nvmeq->q_lock);

	if(nvmecq->valid){
		int vector;
		vector = nvmecq->cq_vector;
        nvmecq->cq_vector = -1;
		print_dbg("free irq: vector:%d, dev_id:%x", vector, nvmeq);
        irq_set_affinity_hint(vector, NULL);
        if(vector && nvmecq->irq_enable)
            pci_free_irq(to_pci_dev(dev->dev), vector, nvmeq);
	}	
    /* Delete only IO queues */
    if (qid) {
        pnvme_delete_sq_cmd(dev, qid);
        nvmecq->ref_cnt--;
        if(nvmecq->ref_cnt == 0){
            pnvme_delete_cq_cmd(dev, nvmeq->cqid);
            nvmecq->valid = false;
        }
    }
	print_dbg("require queue lock");
    spin_lock_irq(&nvmeq->q_lock);
    pnvme_process_cq(nvmeq);
    pnvme_cancel_ios(nvmeq, false);
	print_dbg("release queue lock");
    spin_unlock_irq(&nvmeq->q_lock);
	//print_dbg("cq: dma_free[dev: 0x%x, size: %d]", dmadev, (2 * PNVME_PAGE_SIZE) + CQ_SIZE(nvmecq->q_depth));
	//print_dbg("sq: dma_free[dev: 0x%x, size: %d]", dmadev, (2 * PNVME_PAGE_SIZE) + CQ_SIZE(nvmeq->q_depth));
	//print_dbg("cq: dma_free[dev: 0x%x, size: %d][addr:%x, dma:%x]", \
	//	dmadev, (2 * PNVME_PAGE_SIZE) + CQ_SIZE(nvmecq->q_depth), nvmecq->cq_dma_base_addr, nvmecq->cq_dma_base);
	//print_dbg("sq: dma_free[dev: 0x%x, size: %d][addr:%x, dma:%x]", \
	//	dmadev, (2 * PNVME_PAGE_SIZE) + CQ_SIZE(nvmeq->q_depth), nvmeq->sq_dma_base_addr, nvmeq->sq_dma_base);
	//dma_free_coherent(dmadev, (2 * PNVME_PAGE_SIZE) + \
    //       SQ_SIZE(nvmeq->q_depth),nvmeq->sq_dma_base, nvmeq->sq_dma_base_addr);
	//dma_free_coherent(dmadev, (2 * PNVME_PAGE_SIZE) + \
    //        SQ_SIZE(nvmecq->q_depth),nvmecq->cq_dma_base, nvmecq->cq_dma_base_addr);
    print_dbg("<");
    return;
}

void queue_resource_free(struct nvme_ctrl *ctrl){
	int i;
	//int start_q;
	int qid;
    int start_q = num_possible_cpus()+1;
	
	for(i = start_q; i < start_q+PNVME_QUEUE_NUM; i++) {
		struct pnvme_queue *nvmeq = g_rsc.g_queue_rsc->queues[i];
		if (!nvmeq) {
			continue; /* queue are not exist */
		}
		pnvme_disable_nvmeq(to_nvme_dev(ctrl), i);
	}
	pnvme_free_nvmeqs(to_nvme_dev(ctrl));
	return;
}

static int tc_dev_open(struct inode *inode, struct file *f)
{
	struct nvme_ctrl *ctrl;
	//struct file *file;

	//file = file_open("/dev/nvme0", O_RDONLY, 0);
	ctrl = g_rsc.file->private_data;
	//print_wrn("open device: %x", ctrl->instance);
	f->private_data = ctrl;
	//file_close(file);
	return 0;
	//return queue_resource_check(ctrl);
}

static int tc_dev_release(struct inode *inode, struct file *f)
{
	//struct nvme_ctrl *ctrl;

	//ctrl = f->private_data;
	//return queue_resource_free(ctrl);
	return 0;
}

long tc_dev_ioctl(struct file *f, unsigned int cmd, unsigned long cmd_para)
{
	int i;
    struct timespec ts;
	struct nvme_ctrl *ctrl = f->private_data;
	struct nvme_dev *dev = to_nvme_dev(ctrl);
    ts = current_kernel_time();
    g_start = timespec_to_ns(&ts);

	for (i = 0; i < cmd_ioctl_list_size; i++)
	{
		if (cmd == cmd_ioctl_list[i].cmd)
			return cmd_ioctl_list[i].fn(dev, cmd_para);
	}
	
	print_err( "cmd=0x%x is undefined", cmd);
	return -ENOTTY;

}

static const struct file_operations tc_dev_fops = {
    .owner             = THIS_MODULE,
    .open              = tc_dev_open,
    .release           = tc_dev_release,
    .unlocked_ioctl    = tc_dev_ioctl,
    .compat_ioctl      = tc_dev_ioctl,
};

static int __init ktest_init(void)
{
    int ret = 0;
    int dev_cnt=0;
    struct nvme_ctrl *ctrl;
    int max_mem = 0x20000;
    int key_num_in_table = max_mem/4;
    _u64 maxlba;
    int table_num;
	//struct file *file;
	g_rsc.file = file_open("/dev/nvme0", O_RDONLY, 0);
    print_wrn("pnvme Version: %s\n", KTEST_VERSION);
	print_dbg("page_size %d", PAGE_SIZE);
    print_dbg("Key_para:[bitn:0x%x, mask:0x%x]", KEY_BITN, KEY_MASK);   
	g_rsc.g_queue_rsc = kzalloc(sizeof(struct pnvme_global_resource), GFP_ATOMIC);

    g_rsc.g_queue_rsc->queues = kcalloc(NVME_MAX_QUEUE, sizeof(void *), GFP_ATOMIC);
    if (!g_rsc.g_queue_rsc->queues)
        goto free_dev;

    g_rsc.g_queue_rsc->cqueues = kcalloc(NVME_MAX_QUEUE, sizeof(void *), GFP_ATOMIC);
    if (!g_rsc.g_queue_rsc->cqueues)
        goto free_sq;
    ctrl = g_rsc.file->private_data;
    //file_close(file);
    ret = queue_resource_check(ctrl);  
      
    if (ret < 0){
        goto free_q;
    }
    print_wrn("struct pointer size: %d", sizeof(struct sgl_full_desp*));
    g_rsc.async_pool = dma_pool_create("async page", ctrl->dev,
                    PNVME_PAGE_SIZE*256, PNVME_PAGE_SIZE, 0);
    if (!g_rsc.async_pool){
        print_err("creat async pool fail");
        ret = -ENOMEM;
        goto free_q;
    }
    ret = getMaxLBAByIdentify(ctrl,1,&maxlba);
    if (ret){
        print_wrn("Get maxlba fail[%d]",ret);
        ret =  -1;
        goto free_q;
    }
    g_rsc.is_dif = get_data_size(ctrl, 1, &(g_rsc.data_size), &(g_rsc.meta_size));
    /* for I/Os between 128k and 2MB */
    g_rsc.prp_page_pool = dma_pool_create("prp2list page", ctrl->dev,
                        PNVME_PAGE_SIZE, PNVME_PAGE_SIZE, 0);
    if (!g_rsc.prp_page_pool){
        print_err("creat prp pool fail");
        ret = -ENOMEM;
        goto free_pool;
    }

    table_num = (maxlba*4 + max_mem - 1)/max_mem;
    print_wrn("Max LBA from Identify[0x%llx], key_table_num:%d",maxlba,table_num);
    ret = data_key_setup(key_num_in_table, table_num);
    if (ret) {
        return ret;
    }

	tdev = kzalloc(sizeof(*tdev), GFP_KERNEL);
	if (!tdev) {
		ret = -ENOMEM;
		goto free_all_pool;
	}
	
	tdev->nexus_dev_cnt = dev_cnt;
	strcpy(tdev->name, KTEST_NAME); 
	tdev->miscdev.minor = MISC_DYNAMIC_MINOR;
	tdev->miscdev.name = tdev->name;
	tdev->miscdev.fops = &tc_dev_fops;
	ret = misc_register(&tdev->miscdev);
	if (ret < 0){
		goto cleanup;
	}
    print_wrn("misc device register success");

	//int i;
	//for(i = 0; i < NVME_MAX_QUEUE; i++) {
	//	struct pnvme_queue *nvmeq = g_rsc.g_queue_rsc->queues[i];
	//	if (!nvmeq) {
	//		continue; /* queue are not exist */
	//	}
	//	//spin_lock_irq(&nvmeq->q_lock);
	//	print_dbg("q_lock test qid: %d, idx:%d", nvmeq->qid, i);
	//	//spin_unlock_irq(&nvmeq->q_lock);
	//	q_lock_test(nvmeq, 0);
	//	//nexus_disable_nvmeq(to_nvme_dev(ctrl), i);
	//}
	ktest_proc_init();
    return 0;

cleanup:
    kfree(tdev);
free_all_pool:
    dma_pool_destroy(g_rsc.prp_page_pool);
free_pool:
    dma_pool_destroy(g_rsc.async_pool);
free_q:
    kfree(g_rsc.g_queue_rsc->cqueues);
free_sq:
    kfree(g_rsc.g_queue_rsc->queues);
free_dev:
	file_close(g_rsc.file);
    kfree(g_rsc.g_queue_rsc);
    
    return ret;
}

static void __exit ktest_exit(void)
{
    int dev_cnt;
    print_dbg("pnvme exit");
	struct nvme_ctrl *ctrl;
	//struct file *file;
	//file = file_open("/dev/nvme0", O_RDONLY, 0);
	
	ctrl = g_rsc.file->private_data;
	queue_resource_free(ctrl);
	file_close(g_rsc.file);
    ktest_proc_exit();
    dev_cnt = tdev->nexus_dev_cnt;
    misc_deregister(&tdev->miscdev);
	kfree(g_rsc.g_queue_rsc->queues);
	kfree(g_rsc.g_queue_rsc->cqueues);
	kfree(g_rsc.g_queue_rsc);
    dma_pool_destroy(g_rsc.async_pool);
    dma_pool_destroy(g_rsc.prp_page_pool);
    data_key_cleanup();
    kfree(tdev);

    return ;
}

module_init(ktest_init);
module_exit(ktest_exit);

MODULE_AUTHOR("Liangmin Huang <lhuang@cnexlabs.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION(KTEST_VERSION);

