#clean latest build result then build all source code and modules
rm log
rm -r make_modules
mkdir make_modules
make clean
make mrproper
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- bcmrpi_autosar_defconfig
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -j5 > log
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- modules > log
export MODULES_PATH=./make_modules
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- INSTALL_MOD_PATH=${MODULES_PATH} modules_install > log