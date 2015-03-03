#build after one time running full_build.sh
#use when you change your source code
rm log
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- bcmrpi_autosar_slave_defconfig
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -j5 > log
