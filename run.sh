cd kernel
rm *.o*
rm *.ko
rm *.mod*
rm .*
make LLVM=1 KDIR=../../linux-next
sudo rmmod rkchk
sudo insmod rkchk.ko

cd ..
cd user
cargo build
sudo target/debug/user
