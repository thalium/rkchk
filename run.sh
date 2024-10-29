cd kernel
make LLVM=1 KDIR=../../linux-next
sudo rmmod rkchk
sudo insmod rkchk.ko

cd ..
cd user
sudo target/debug/user
