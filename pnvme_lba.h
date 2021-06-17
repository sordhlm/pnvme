#ifndef _KTEST_LBA_H
#define _KTEST_LBA_H

#include <linux/types.h>
#include "pnvme_drv.h"

struct lba_iodnode{
    void *prppool_va;
    dma_addr_t prppool_dma;
    _u16 rev;
    _u64 slba;
    _u32 data_size;
    _u16 nlb;
    _u32 meta_size;
    void *data_mem;
    dma_addr_t data_dma; 
    _u8 compare_flag;
    void *key_pool;

};
//extern unsigned char admin_timeout;
#define ADMIN_TIMEOUT	(admin_timeout * HZ)
struct lba_handle_str{
    _u16 qid;
    _u16 nlb;
    _u16 fourk_num;
    _u16 dram_flag;
    _u16 dif_flag;/*1:dif mode,0: dix mode*/
    _u16 meta_size;
    _u32 data_size;
    _u64 datafile;
    _u64 metafile;
    void *mem_data;
    void *mem_meta;
    dma_addr_t data_dma_addr;
    dma_addr_t meta_dma_addr;
    dma_addr_t prp_dma;
    _u64 *prp_list;
    _u32 cmbsz;
    _u32 pmrcap;
    _u32 wr_flag;
};
struct sgl_desp
{
	__le32	len;
	__u8	rsv[3];
	__u8	idn;
};

struct nvme_lba_command {
    __u8            opcode ;
    __u8            flags;
    __u16           command_id;
    __le32          nsid;
    __le32          cdw2;
    __u8            rsv_dram;
    __u8            rsv_pi;
    __u8            ksel7_4 : 4;
    __u8            rsv : 4;
    __u8            rsv2;
    __le64          metadata;
    __le64          prp1;
    union
    {
        __le64  prp2;
        struct	sgl_desp sgl;
    };
    __le64          slba;
    __le16          nlb;
    __le16          control;
    __u8            dsmgmt ;
    __u8            rsv_qid;
    __le16          directive_spec;
    __le32          reftag;
    __le16          apptag;
    __le16          appmask;
};

enum debug_opcode {
	pnvme_async_trace   = 0x00,
	pnvme_cqe  		= 0x01,
	pnvme_sqe  		= 0x02,
};

struct pnvme_debug {
    __u32           opcode ;
    __u32           rsv ;
    __le64          data;
};
    
struct pnvme_perf {
    __u32   wr_data ;
    __u32   rd_data ;
    ktime_t oldtime ;
};
struct sgl_full_desp
{
	__le64	addr;
	struct sgl_desp desp;
};

struct nvme_sgl_lba_command {
    __u8            opcode ;
    __u8            flags;
    __u16           command_id;
    __le32          nsid;
    __le32          cdw2[2];
    __le64          metadata;
    __le64          prp1;
    union
    {
        __le64  prp2;
        struct  sgl_desp sgl;
    };
    __le64          slba;
    __le16          nlb;
    __le16          control;
    __u8            dsmgmt ;
    __u8            rsv_qid ;
    __le16          directive_spec;
    __le32          reftag;
    __le16          apptag;
    __le16          appmask;
    //[Edison]indicate the offset of address in data block descriptor
    //if not specified, the data address will be 4k align
    __le32          sgl_data_offset;
    //[Edison]indicate the offset of address in meta data block descriptor
    //if not specified,the data address will be 4k align
    __le32          sgl_meta_offset;
    //if 1 != sgl_data_segs_num, the first segment descriptor should be next or last with zero data.
    __le64          sgl_data_desp_num;
    // sgl_meta_segs_num should never be less than 1.
    __le64          sgl_meta_desp_num;
    __le64          sgl_data_desps;
    __le64          sgl_meta_desps;
    struct sgl_full_desp   sgl_data_meta_segs[0];
};


#define CALC_PAGE_NUM(nlb, data_size, meta_size) \
    (nlb*(data_size+meta_size)%PNVME_PAGE_SIZE)?(nlb*(data_size+meta_size)/PNVME_PAGE_SIZE + 1):(nlb*(data_size+meta_size)/PNVME_PAGE_SIZE)

/*LBA async*/

int pnvme_lba_sync(struct nvme_dev *dev, unsigned long cmd);
int pnvme_admin_passthrough(struct nvme_dev *dev, unsigned long ucmd);
int pnvme_submit_user_cmd(struct request_queue *q, struct nvme_command *cmd,
		void __user *ubuffer, unsigned bufflen, _u32 *result, unsigned timeout);
int pnvme_get_features(struct nvme_ctrl *dev, unsigned fid, unsigned nsid,
					dma_addr_t dma_addr, union nvme_result *result);
int pnvme_submit_sync_cmd(struct request_queue *q, struct nvme_command *cmd,
		void *buffer, unsigned bufflen);
int pnvme_submit_admin_cmd(struct nvme_ctrl *dev, struct nvme_command *cmd,
		void *buffer, unsigned bufflen);
int getMaxLBAByIdentify(struct nvme_ctrl *dev, int nsid, _u64* maxlba);
int pnvme_qat_async(struct nvme_dev *dev, struct nvme_lba_command *kcmd_para);
int pnvme_lba_async(struct nvme_dev *dev, unsigned long cmd);
int pnvme_qat_atomic(struct nvme_dev *dev, struct nvme_lba_command *kcmd_para);
int pnvme_atomic(struct nvme_dev *dev, unsigned long cmd);
int pnvme_pi_sync(struct nvme_dev *dev, unsigned long cmd);


void lba_ionode_prplist_free(void *ctx);
int pnvme_identify_ns(struct nvme_ctrl *dev, unsigned nsid, struct nvme_id_ns **id);

int pnvme_print_sqes(struct nvme_dev *dev, unsigned long qid);
int pnvme_print_cqes(struct nvme_dev *dev, unsigned long qid);
int pnvme_debug_cmd(struct nvme_dev *dev, unsigned long cmd);
void pnvme_perf_print(_u8 opcode, _u32 data_size);
int pnvme_sgl_cmd(struct nvme_dev *dev, unsigned long cmd);
int pnvme_crt_cq(struct nvme_dev *dev, unsigned long cmd);
int pnvme_crt_sq(struct nvme_dev *dev, unsigned long cmd);
int pnvme_del_cq(struct nvme_dev *dev, unsigned long cmd);
int pnvme_del_sq(struct nvme_dev *dev, unsigned long cmd);






#endif/*end ktest_lba*/

