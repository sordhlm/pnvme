  PWD := $(shell pwd)
  KVER := $(shell uname -r)
  KDIR := /lib/modules/$(KVER)/build
  ccflags-y += -g
  
  pnvme-objs := pnvme_if.o pnvme_drv.o pnvme_proc.o 
  pnvme-objs += pnvme_cmd.o pnvme_lba.o
  obj-m := pnvme.o
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
.PHONY: aLL clean
