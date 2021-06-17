#ifndef _KTEST_DRV_H
#define _KTEST_DRV_H
#include <linux/kernel.h>
#include <linux/nvme.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <asm/fcntl.h>
#include <linux/interrupt.h>
#include <linux/buffer_head.h>
#include <linux/fcntl.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <asm/dma-mapping.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/bitops.h>
#include <linux/time.h>
#include <linux/miscdevice.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/idr.h>
#include <linux/miscdevice.h>
#include <linux/stat.h>
#include "nvme.h"
#include "ioctl_cmd.h"

#define KTEST_VERSION    "R001 D20200819 9:39"

#define KTEST_NAME    "pnvme"
#define ULONG_BIT (sizeof(unsigned long)*8)
#define PNVME_PAGE_SIZE     4096
#define NVME_Q_DEPTH		1024
#define NVME_MAX_QUEUE      16
#define NVME_MAX_QSIZE      65535
#define ONHOST 0
#define MAX_NPRPS       512

#define PNVME_IO_TIMEOUT       (60 * HZ)


#define NVME_IO_QID (10)
#define NVME_HIGH_QID (11)

#define ARBITRATIONVAL 0x01010100

#define DW_SIZE 4

#define PAGE_SIZE_SHIFT_BITS    (12)
#define MSECONDS                1000000
#define USECONDS                1000

#define GBYTE   ((unsigned long)1 << 30)
#define MBYTE   ((unsigned long)1 << 20)
#define KBYTE   ((unsigned long)1 << 10)

#define PNVME_QUEUE_NUM 		1

//#define QUEUE_PRIO_TEST
#define PERFOMANCE

#define SEQ_ENTRY_NUM_MAX  (512)
#define RD_RETRY_TYPE_NUM_MAX  (256)
#define RD_RETRY_PARA_NUM_MAX  (512)
#define RD_RETRY_TYPE	0x80400
#define RD_RETRY_PARA	0x80800

#define PROCESS_WRAPAROUND   (1)
#define PROCESS_SUCCESS  (0)

#define QUEUE_NO_NEED_LOCK    0
#define QUEUE_NEED_LOCK       1

struct tc_dev {
    struct miscdevice miscdev;
	int nexus_dev_cnt;
    char name[12];
};
extern u8 debug_level;

struct sync_cmd_info {
    struct task_struct *task;
    u32 result;
    int status;
};

enum {
    PRINT_ERR = 1,
    PRINT_WRN = 2,
    PRINT_NOT = 3,
    PRINT_DBG = 4,
};        

#define print_dbg(fmt, arg...) if(debug_level>=PRINT_DBG) printk(KERN_WARNING "[%s][%d]"fmt"\n", __FUNCTION__, __LINE__, ##arg)
#define print_not(fmt, arg...) if(debug_level>=PRINT_NOT) printk(KERN_WARNING "[%s][%d]"fmt"\n", __FUNCTION__, __LINE__, ##arg)
#define print_wrn(fmt, arg...) if(debug_level>=PRINT_WRN) printk(KERN_WARNING "[%s][%d]"fmt"\n", __FUNCTION__, __LINE__, ##arg)
#define print_err(fmt, arg...) if(debug_level>=PRINT_ERR) printk(KERN_ERR "ERR [%s][%d]"fmt"\n", __FUNCTION__, __LINE__, ##arg)

extern volatile _u64 g_total_bytes; // total data in bytes for each test cases.
extern volatile _u32 g_tc_total; // this is stop condition for each test cases.
extern volatile _u32 g_tc_count; // this is stop condition for each test cases.
volatile extern s64 g_start; // this is the start timestamp for a testcase
extern volatile s64 submit_cmd_cnt;
extern volatile s64 completion_cmd_cnt;
extern volatile _u64 gdata_index;
extern volatile _u64 gmeta_index;

//extern struct pnvme_queue_resource *g_queue_rsc;
extern struct pnvme_global_resource g_rsc;

extern _u32 g_xor_count; // this is stop condition for each test cases.
extern s64 g_latency; // accumulated latency for all commands
extern _u32 g_latency_max, g_latency_min;

extern struct sqe_info **sqe;
extern bool db_swith;

extern struct device *local_dmadev;

#define KEY_BITN 16
#define STAT_BITN 32-KEY_BITN
#define KEY_MASK ((1<<KEY_BITN)-1)
#define STAT_MASK ((1<<(STAT_BITN-1))-1)
#define TRACE_LENGTH 5000

/*
struct nvme_ctrl {
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct device *dev;
	struct kref kref;
	int instance;
	struct blk_mq_tag_set *tagset;
	struct list_head namespaces;
	struct mutex namespaces_mutex;
	struct device *device;	
	struct list_head node;
	struct ida ns_ida;

	char name[12];
	char serial[20];
	char model[40];
	char firmware_rev[8];

	_u32 ctrl_config;

	_u32 page_size;
	_u32 max_hw_sectors;
	_u32 stripe_size;
	_u16 oncs;
	atomic_t abort_limit;
	_u8 event_limit;
	_u8 vwc;
	_u32 vs;
	bool subsystem;
	unsigned long quirks;
};


 // An NVM Express namespace is equivalent to a SCSI LUN

struct nvme_ns {
	struct list_head list;

	struct nvme_ctrl *ctrl;
	struct request_queue *queue;
	struct gendisk *disk;
	struct kref kref;
	int instance;

	_u8 eui[8];
	_u8 uuid[16];

	unsigned ns_id;
	int lba_shift;
	_u16 ms;
	bool ext;
	_u8 pi_type;
	unsigned long flags;

#define NVME_NS_REMOVING 0
#define NVME_NS_DEAD     1

	_u64 mode_select_num_blocks;
	_u32 mode_select_block_len;
};

*/
struct nvme_queue {
	struct device *q_dmadev;
	struct nvme_dev *dev;
	char irqname[24];	/* nvme4294967295-65535\0 */
	spinlock_t q_lock;
	struct nvme_command *sq_cmds;
	struct nvme_command __iomem *sq_cmds_io;
	volatile struct nvme_completion *cqes;
	struct blk_mq_tags **tags;
	dma_addr_t sq_dma_addr;
	dma_addr_t cq_dma_addr;
	_u32 __iomem *q_db;
	_u16 q_depth;
	s16 cq_vector;
	_u16 sq_head;
	_u16 sq_tail;
	_u16 cq_head;
	_u16 qid;
	_u8 cq_phase;
	_u8 cqe_seen;
};
/*
struct nvme_dev {
	struct nvme_queue **queues;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	_u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	unsigned queue_count;
	unsigned online_queues;
	unsigned max_qid;
	int q_depth;
	_u32 db_stride;
	struct msix_entry *entry;
	void __iomem *bar;
	struct work_struct reset_work;
	struct work_struct scan_work;
	struct work_struct remove_work;
	struct work_struct async_work;
	struct timer_list watchdog_timer;
	struct mutex shutdown_lock;
	bool subsystem;
	void __iomem *cmb;
	dma_addr_t cmb_dma_addr;
	_u64 cmb_size;
	_u32 cmbsz;
	unsigned long flags;

#define NVME_CTRL_RESETTING    0
#define NVME_CTRL_REMOVING     1

	struct nvme_ctrl ctrl;
	struct completion ioq_wait;
};
*/
/*
 * Represents an NVM Express device.  Each nvme_dev is a PCI function.
 */
struct nvme_dev {
	struct nvme_queue *queues;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	unsigned online_queues;
	unsigned max_qid;
	int q_depth;
	u32 db_stride;
	void __iomem *bar;
	unsigned long bar_mapped_size;
	struct work_struct remove_work;
	struct mutex shutdown_lock;
	bool subsystem;
	void __iomem *cmb;
	pci_bus_addr_t cmb_bus_addr;
	u64 cmb_size;
	u32 cmbsz;
	u32 cmbloc;
	struct nvme_ctrl ctrl;
	struct completion ioq_wait;
	u32 last_ps;

	/* shadow doorbell buffer support: */
	u32 *dbbuf_dbs;
	dma_addr_t dbbuf_dbs_dma_addr;
	u32 *dbbuf_eis;
	dma_addr_t dbbuf_eis_dma_addr;

	/* host memory buffer support: */
	u64 host_mem_size;
	u32 nr_host_mem_descs;
	dma_addr_t host_mem_descs_dma;
	struct nvme_host_mem_buf_desc *host_mem_descs;
	void **host_mem_desc_bufs;
};

typedef void (*nvme_completion_fn)(struct nvme_dev *, void *,
                        struct nvme_completion *);
/* Special values must be less than 0x1000 */
#define CMD_CTX_BASE         ((void *)POISON_POINTER_DELTA)
#define CMD_CTX_CANCELLED    (0x30C + CMD_CTX_BASE)
#define CMD_CTX_COMPLETED    (0x310 + CMD_CTX_BASE)
#define CMD_CTX_INVALID      (0x314 + CMD_CTX_BASE)
#define CMD_CTX_FLUSH        (0x318 + CMD_CTX_BASE)
#define CMD_CTX_THROTTLED    (0x31C + CMD_CTX_BASE)   // fake cancel means read cmd should throttled

struct pnvme_cmd_info {
    nvme_completion_fn fn;
    void *ctx;
    void *org_ctx;
    unsigned long timeout;
    _u8 opcode;
    _u8 nlb;
};

struct debug_info{
    _u8 phase;
    _u8 mode;
    _u16 rsv;
    _u32 lba;
    _u32 key;
};

struct pnvme_completion_queue {
    struct device *q_dmadev;
    struct nvme_dev *dev;
    char irqname[24];
    volatile struct nvme_completion *cqes;
    dma_addr_t cq_dma_addr;
    void *cq_dma_base;
    dma_addr_t cq_dma_base_addr;
    _u32 __iomem *q_db;
    _u32 ref_cnt;
    _u16 q_depth;
    _u16 cq_vector;
    _u16 cq_head;
    _u16 qid;
    _u8 cq_phase;
    _u8 cqe_seen;
    _u8 valid;
    _u8 cq_where;
    _u32 irq_enable;
};

struct pnvme_queue {
    struct device *q_dmadev;
    struct nvme_dev *dev;
    //char irqname[24];
    spinlock_t q_lock;
    struct nvme_command *sq_cmds;
    dma_addr_t sq_dma_addr;
    void *sq_dma_base;
    dma_addr_t sq_dma_base_addr;
    wait_queue_head_t sq_full;
    struct bio_list sq_cong;
    struct bio_list sp_sq_cong; //for 512;
    //	struct list_head bio_resubmit_list;
    struct list_head bio_resm_list; //resubmit list head, for base ftl, iostat enable
    struct list_head sp_bio_resm_list; //sp resubmit list head, for 512 layer, iostat enable
    struct pnvme_completion_queue *nvmecq;
    _u32 __iomem *q_db;
    _u16 q_depth;
    _u16 cqid;
    _u16 sq_head;
    _u16 sq_tail;
    _u16 qid;
    _u8 q_suspended;
    _u8 sq_where;
    spinlock_t bit_lock;
    unsigned long index;
    unsigned long cmdid_data[NVME_Q_DEPTH/ULONG_BIT];
    struct pnvme_cmd_info cmd_info[NVME_Q_DEPTH];
};

struct pnvme_queue_resource {
    struct pnvme_queue **queues;
    struct pnvme_completion_queue **cqueues;
};

struct pnvme_global_resource{
    struct pnvme_queue_resource *g_queue_rsc;
    struct file *file;
    struct dma_pool *async_pool;
    struct dma_pool *prp_page_pool;
    _u32 data_size;
    _u16 meta_size;
    bool is_dif;
};

struct data_key{
    int key_num_in_table;
    int table_num;
    volatile void **key;
};

extern struct data_key *lba_data_key;

#define SQ_SIZE(depth)        (depth * sizeof(struct nvme_command))
#define CQ_SIZE(depth)        (depth * sizeof(struct nvme_completion))

void sync_completion(struct nvme_dev *dev, void *ctx, struct nvme_completion *cqe);
int alloc_cmdid_killable(struct pnvme_queue *nvmeq, void *ctx, nvme_completion_fn handler, unsigned timeout);
int alloc_cmdid(struct pnvme_queue *nvmeq, void *ctx, nvme_completion_fn handler, unsigned timeout);
void *cancel_cmdid(struct pnvme_queue *nvmeq, u16 cmdid, nvme_completion_fn *fn);
void *pnvme_free_cmdid(struct pnvme_queue *nvmeq, u16 cmdid, nvme_completion_fn *fn);
void data_key_cleanup(void);


#endif
