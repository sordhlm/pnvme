/********************************************************************
* FILE NAME: ioctl_str.h
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
#ifndef _IOCTL_STR_H
#define _IOCTL_STR_H

#include <linux/types.h>

#ifndef _u8
#define _u8 unsigned char
#endif
#ifndef _u16
#define _u16 unsigned short
#endif
#ifndef _u32
#define _u32 unsigned int
#endif
#ifndef _u64
#define _u64 unsigned long long
#endif

struct ppa_cmd {
	_u32      nsid;
	_u16      qid;
	_u16      nlb;
	_u64      addr;
	_u64      meta_id;
	_u64      data_id;
	__le64   metadata;
	__le64   prp1;
	__le64   prp2;
	_u32      dsmgmt;
	_u16      addr_field;  //which ppa addr field is given priority
	_u8       opcode;
	_u8       localdram;
	_u32      file_len;   // file length
	_u16      index;
	_u16      xorid;	
	_u16      xornum;
	_u16      ctrl;
	_u16      *file;      // bad block mark 
	_u16       hint;
};


struct ppa_performance {
	int         type;	
	int         nlb;
	int         block;
	int         addr_field;
	_u16*        file;
	_u32         length;
	_u16         index;
	_u16         qid;
	_u32         nsid;
	_u16         chmask_sw;	
	_u16         pgmask_sw;
	_u32         xor_id;	
	_u16         ctrl;
	_u8			random;
	_u8          line_cnt;
};

struct nvme_read_dma {
	int      dmanum;
	int      type;     /*D data M metadata*/
	int      length;
	_u32*     pdata; /* pointer to the data */
	_u16      index;
};

struct issue_cmd_stru {
	int instance;
	_u16 qid;
	_u8 opcode;
	_u32 nsid;
	_u32 cdw2;
	_u32 cdw3;
	_u64 metadata;
	_u64 prp1;
	_u64 prp2;
	_u32 dw10_dw15[6];
};

struct rd_wr_id {
	int    devid;	
	_u16 	xorid;
	_u16 	xornum;
	int    rdid;
	int    wrid;
	_u32    *pdata;
};

struct nexus_update_seqram
{
	_u32 index;
	_u32 length;
	_u16 ch_mask;
	_u16 reserved[3];
	_u32 *cfg_array;
};

struct nexus_retry_ram {
	_u32 index;
	_u32 *cfg_array_type;
	_u32 *cfg_array_para;
	_u32 reserved;
};

struct ppa_func_test {
	_u16       addr_field;             // ch inc or ep inc
	_u16       index;
	_u16       qid;
	_u16       rsvd;
	int       nlb;
	int       rand;
	int       block;
	_u32       nsid;
	void      *wr_src;
	void      *rd_dst;
	int       offset;
	_u16       ctrl;
};

struct xor_func_test {
  	int       type;  
	int       block;
	_u16       index;
	_u16       qid;
	_u32       nsid;
	_u32       xor_id;
	_u16       ctrl;
	_u16       xor_mask;
	_u16       line_cnt;	
};

struct ppa_perf_test {
	_u32         type;
	_u16         block;          // block address to use
	_u16         ngb;            // number of GBs the tests will run
	_u8          opcode;         // rd/wr ppa; rd/wr ppa raw; rd/wr ppa xor
	_u8          addr_field;     // which ppa addr field is given priority
	_u8          nlb;            // the length of ppa_list in each ppa cmd
	_u8          reserved;
	_u32         length;
	_u32*        addr;           // address of bad block list
	_u16         index;
	_u16         qid;
	_u32         nsid;
};

struct dev_loop {
	_u16 devid;
	_u16 loop;
	_u32 blknum;
};

struct interrupt_coalesce {
	_u16 devid;
	_u16 qid;
	_u32 coalesc_cfg;	
	_u32 cmd_count;
};


struct nvme_lnvm_identify {
	__u8            opcode;
	__u8            flags;
	__u16           command_id;
	__le32          nsid;
	__u64           rsvd1[2];
	__le64          metadata;
	__le64          prp1;
	__le64          prp2;
	__u32           cdw10_15_rsvd2[6];
};


struct nvme_write_zero{
	__u8            opcode;
	__u8            flags; /*bit[1:0]:normal or fused operation///bit[7:6]:PRP or SGL data transfer*/
	__u16           command_id;
	__le32          nsid;
	__le32          cdw2[2];
	__le64          metadata;
	__le64          prp1;
	__le64          prp2;
	__le64		slba;/*dw10~dw11*/
	__le16		nlb;
	__le16		control;/*dw12*/
	__le32          cdw13;
	__le32          reftag;
	__le16          apptag;
	__le16          appmask;
};

#endif

