obj-m := firewall_logger.o

all:
	make -C $(KERNEL_SRC) M=$(PWD) modules

clean:
	make -C $(KERNEL_SRC) M=$(PWD) clean

modules_install:
	make -C $(KERNEL_SRC) M=$(PWD) modules_install

