all:
	../backfire/staging_dir/toolchain-mips_r2_gcc-4.3.3+cs_uClibc-0.9.30.1/usr/bin/mips-openwrt-linux-gcc -g -O0 -Wall -I ../backfire/staging_dir/target-mips_r2_uClibc-0.9.30.1/usr/include/ -I ../backfire/staging_dir/target-mips_uClibc-0.9.30.1/usr/include/ -Wl,--export-dynamic -L`pwd`/libs/ capcom.c linklist.c hashmap.c queue.c hashmap_generic.c injector.c injector_data.c helper.c libs/libpcap.so.1.0.0 libs/libgcc_s.so libs/ld-uClibc.so.0 -o capcom6 -lpthread

