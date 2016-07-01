#UBUNTU Raspberry pi build shell                                                                               

#make clean                                                                                                   
#make mrproper                                                                                                

make ARCH=arm CROSS_COMPILE=arm-none-eabi- bcmrpi_defconfig
# cpu=$(grep -c processor /proc/cpuinfo)                                                                        
# cpum1=$($cpu-1)                                                                                               
make ARCH=arm CROSS_COMPILE=arm-none-eabi- #-j$cpum1

# make ARCH=arm CROSS_COMPILE=arm-none-eabi- modules                                                           
# rm -rf make_modules                                                                                          
# mkdir make_modules                                                                                           
# export MODULES_PATH=./make_modules                                                                           
# make ARCH=arm CROSS_COMPILE=arm-none-eabi- INSTALL_MOD_PATH=${MODULES_PATH} modules_install                  
# rm -r make_modules.tar.gz                                                                                    
# tar czvf make_modules.tar.gz make_modules
